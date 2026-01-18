# syntax=docker/dockerfile:1

FROM rust:1.85-bookworm AS builder
WORKDIR /app

# Cache dependencies
COPY backend/Cargo.toml backend/Cargo.lock ./backend/
COPY backend/src ./backend/src
COPY backend/migrations ./backend/migrations
COPY backend/rust-toolchain.toml ./backend/rust-toolchain.toml

WORKDIR /app/backend
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/backend/target/release/backend /app/backend

ENV RUST_LOG=info
EXPOSE 8080
CMD ["/app/backend"]
