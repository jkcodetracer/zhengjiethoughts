use anyhow::Context;
use argon2::{Argon2, PasswordVerifier, password_hash::PasswordHash};
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};

#[derive(Clone)]
pub struct AdminAuth {
    username: String,
    password_hash: PasswordHash<'static>,
    #[allow(dead_code)]
    password_hash_str: String,
    enc: EncodingKey,
    dec: DecodingKey,
}

pub struct AdminToken {
    pub token: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

impl AdminAuth {
    pub fn new(
        username: String,
        password_hash: String,
        jwt_secret: String,
    ) -> anyhow::Result<Self> {
        // PasswordHash borrows from its input. Store the string and leak a clone for a stable lifetime.
        let owned = password_hash;
        let parsed_static = PasswordHash::new(Box::leak(owned.clone().into_boxed_str()))
            .context("parse ADMIN_PASSWORD_HASH")?;

        Ok(Self {
            username,
            password_hash: parsed_static,
            password_hash_str: owned,
            enc: EncodingKey::from_secret(jwt_secret.as_bytes()),
            dec: DecodingKey::from_secret(jwt_secret.as_bytes()),
        })
    }

    pub async fn login(&self, username: &str, password: &str) -> anyhow::Result<AdminToken> {
        if username != self.username {
            anyhow::bail!("bad username")
        }

        Argon2::default()
            .verify_password(password.as_bytes(), &self.password_hash)
            .context("verify password")?;

        let expires_at = OffsetDateTime::now_utc() + TimeDuration::hours(12);
        let claims = Claims {
            sub: self.username.clone(),
            exp: expires_at.unix_timestamp() as usize,
        };

        let token =
            jsonwebtoken::encode(&Header::default(), &claims, &self.enc).context("encode jwt")?;

        Ok(AdminToken { token, expires_at })
    }

    pub fn require_auth(&self, headers: &HeaderMap) -> Result<(), crate::ApiError> {
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| crate::ApiError::unauthorized("missing authorization"))?;

        let token = auth
            .strip_prefix("Bearer ")
            .ok_or_else(|| crate::ApiError::unauthorized("invalid authorization"))?;

        let mut validation = Validation::default();
        validation.validate_exp = true;

        let data = jsonwebtoken::decode::<Claims>(token, &self.dec, &validation)
            .map_err(|_| crate::ApiError::unauthorized("invalid token"))?;

        if data.claims.sub != self.username {
            return Err(crate::ApiError::unauthorized("invalid token"));
        }

        Ok(())
    }
}

pub fn client_ip_hash(headers: &HeaderMap) -> anyhow::Result<String> {
    // Prefer Fly's header; fall back to X-Forwarded-For.
    let ip = headers
        .get("Fly-Client-IP")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            headers
                .get("X-Forwarded-For")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim())
        })
        .context("no client ip header")?;

    // Lightweight stable hash; enough to avoid storing raw IP.
    // Not for cryptographic uses.
    let mut h: u64 = 1469598103934665603;
    for b in ip.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }

    Ok(format!("fnv1a64:{h:016x}"))
}

pub fn _status_from_error(_: anyhow::Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}
