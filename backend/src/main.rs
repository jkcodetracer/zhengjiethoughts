use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use time::OffsetDateTime;
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::PeerIpKeyExtractor,
};
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};
use uuid::Uuid;

mod security;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    admin: security::AdminAuth,
    cors_allowed_origins: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // Note: dotenv treats `$FOO` as variable expansion. Argon2 hashes contain `$`.
    // For local dev, prefer escaping `$` in `.env` as `\$`.

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL missing")?;
    let admin_username = std::env::var("ADMIN_USERNAME").context("ADMIN_USERNAME missing")?;
    let admin_password_hash =
        std::env::var("ADMIN_PASSWORD_HASH").context("ADMIN_PASSWORD_HASH missing")?;
    let jwt_secret = std::env::var("JWT_SECRET").context("JWT_SECRET missing")?;

    let cors_allowed_origins = std::env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:4321".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let db = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await
        .context("connect to DATABASE_URL")?;

    sqlx::migrate!().run(&db).await.context("run migrations")?;

    let admin = security::AdminAuth::new(admin_username, admin_password_hash, jwt_secret)?;

    let state = AppState {
        db,
        admin,
        cors_allowed_origins,
    };

    let cors_layer = build_cors_layer(&state.cors_allowed_origins);

    let rate_limit_enabled = std::env::var("RATE_LIMIT_ENABLED")
        .ok()
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);

    let governor_layer = if rate_limit_enabled {
        let config = GovernorConfigBuilder::default()
            // In local dev, this uses the TCP peer address (via ConnectInfo).
            // In prod behind proxies, you can switch to a header-based extractor.
            .key_extractor(PeerIpKeyExtractor)
            .per_second(2)
            .burst_size(5)
            .finish()
            .expect("valid governor config");

        Some(GovernorLayer {
            config: Arc::new(config),
        })
    } else {
        None
    };

    let comments_get = Router::new().route("/api/comments", get(list_comments));

    let comments_post = {
        let r = Router::new().route("/api/comments", post(create_comment));
        if let Some(layer) = governor_layer {
            r.layer(layer)
        } else {
            r
        }
    };

    let app = Router::new()
        .merge(comments_get)
        .merge(comments_post)
        .route("/healthz", get(healthz))
        .route("/api/admin/login", post(admin_login))
        .route("/api/admin/comments", get(admin_list_comments))
        .route("/api/admin/comments/:id/hide", post(admin_hide_comment))
        .route("/api/admin/comments/:id/unhide", post(admin_unhide_comment))
        .route("/api/admin/comments/:id", delete(admin_delete_comment))
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer)
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, "starting server");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("bind listener")?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("serve")?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn build_cors_layer(origins: &[String]) -> CorsLayer {
    if origins.is_empty() {
        return CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::DELETE])
            .allow_headers(Any);
    }

    let mut allow = Vec::with_capacity(origins.len());
    for o in origins {
        match HeaderValue::from_str(o) {
            Ok(v) => allow.push(v),
            Err(_) => warn!(origin = %o, "invalid CORS origin"),
        }
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allow))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers(Any)
}

async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

#[derive(Debug, Deserialize)]
struct CommentsQuery {
    slug: String,
}

#[derive(Debug, Serialize)]
struct PublicComment {
    id: Uuid,
    display_name: String,
    content: String,
    created_at: OffsetDateTime,
}

async fn list_comments(
    State(state): State<AppState>,
    Query(q): Query<CommentsQuery>,
) -> Result<Json<Vec<PublicComment>>, ApiError> {
    let rows = sqlx::query(
        r#"
        select id, display_name, content, created_at
        from comments
        where post_slug = $1 and is_hidden = false
        order by created_at asc
        "#,
    )
    .bind(q.slug)
    .fetch_all(&state.db)
    .await
    .context("query comments")?;

    Ok(Json(
        rows.into_iter()
            .map(|r| PublicComment {
                id: r.get("id"),
                display_name: r.get("display_name"),
                content: r.get("content"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct CreateCommentRequest {
    slug: String,
    display_name: String,
    email: String,
    content: String,
    // honeypot field: should be empty
    hp: Option<String>,
}

async fn create_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCommentRequest>,
) -> Result<StatusCode, ApiError> {
    if req
        .hp
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        // pretend success for bots
        return Ok(StatusCode::CREATED);
    }

    validate_comment(&req)?;

    // We don't store raw IPs. Keeping a simple hash can help with abuse handling later.
    // In local dev there may be no proxy headers, so this can be None.
    let ip_hash = security::client_ip_hash(&headers).ok();

    tracing::info!("attempting insert");

    let result = sqlx::query(
        r#"
        insert into comments (id, post_slug, display_name, email, content, ip_hash)
        values ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(req.slug)
    .bind(req.display_name.trim())
    .bind(req.email.trim())
    .bind(req.content.trim())
    .bind(ip_hash)
    .execute(&state.db)
    .await;

    if let Err(ref e) = result {
        tracing::error!(error = ?e, "insert comment failed");
    }

    result.context("insert comment")?;

    Ok(StatusCode::CREATED)
}

fn validate_comment(req: &CreateCommentRequest) -> Result<(), ApiError> {
    let slug = req.slug.trim();
    let name = req.display_name.trim();
    let email = req.email.trim();
    let content = req.content.trim();

    if slug.is_empty() || slug.len() > 200 {
        return Err(ApiError::bad_request("invalid slug"));
    }
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::bad_request("invalid display_name"));
    }
    if email.is_empty() || email.len() > 254 || !email.contains('@') {
        return Err(ApiError::bad_request("invalid email"));
    }
    if content.is_empty() || content.len() > 5000 {
        return Err(ApiError::bad_request("invalid content"));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct AdminLoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AdminLoginResponse {
    token: String,
    expires_at: OffsetDateTime,
}

async fn admin_login(
    State(state): State<AppState>,
    Json(req): Json<AdminLoginRequest>,
) -> Result<Json<AdminLoginResponse>, ApiError> {
    let token = state
        .admin
        .login(&req.username, &req.password)
        .await
        .map_err(|_| ApiError::unauthorized("invalid credentials"))?;

    Ok(Json(AdminLoginResponse {
        token: token.token,
        expires_at: token.expires_at,
    }))
}

#[derive(Debug, Deserialize)]
struct AdminCommentsQuery {
    slug: String,
    include_hidden: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AdminComment {
    id: Uuid,
    post_slug: String,
    display_name: String,
    email: String,
    content: String,
    created_at: OffsetDateTime,
    is_hidden: bool,
}

async fn admin_list_comments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdminCommentsQuery>,
) -> Result<Json<Vec<AdminComment>>, ApiError> {
    state.admin.require_auth(&headers)?;

    let include_hidden = q.include_hidden.unwrap_or(true);

    let rows = if include_hidden {
        sqlx::query(
            r#"
            select id, post_slug, display_name, email, content, created_at, is_hidden
            from comments
            where post_slug = $1
            order by created_at desc
            "#,
        )
        .bind(q.slug)
        .fetch_all(&state.db)
        .await
        .context("admin query comments")?
    } else {
        sqlx::query(
            r#"
            select id, post_slug, display_name, email, content, created_at, is_hidden
            from comments
            where post_slug = $1 and is_hidden = false
            order by created_at desc
            "#,
        )
        .bind(q.slug)
        .fetch_all(&state.db)
        .await
        .context("admin query comments")?
    };

    Ok(Json(
        rows.into_iter()
            .map(|r| AdminComment {
                id: r.get("id"),
                post_slug: r.get("post_slug"),
                display_name: r.get("display_name"),
                email: r.get("email"),
                content: r.get("content"),
                created_at: r.get("created_at"),
                is_hidden: r.get("is_hidden"),
            })
            .collect(),
    ))
}

async fn admin_hide_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.admin.require_auth(&headers)?;

    sqlx::query("update comments set is_hidden = true where id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .context("hide comment")?;

    Ok(StatusCode::NO_CONTENT)
}

async fn admin_unhide_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.admin.require_auth(&headers)?;

    sqlx::query("update comments set is_hidden = false where id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .context("unhide comment")?;

    Ok(StatusCode::NO_CONTENT)
}

async fn admin_delete_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.admin.require_auth(&headers)?;

    sqlx::query("delete from comments where id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .context("delete comment")?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn unauthorized(message: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message,
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(_: anyhow::Error) -> Self {
        // Avoid leaking internal errors.
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(serde_json::json!({"error": self.message}));
        (self.status, body).into_response()
    }
}
