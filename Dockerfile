# Stage 1: Build
FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY src/ src/
COPY benches/ benches/
RUN cargo build --release -p gvm-proxy

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/gvm-proxy /usr/local/bin/gvm-proxy
COPY config/ /app/config/
RUN mkdir -p /app/data
WORKDIR /app

ENV GVM_CONFIG=/app/config/proxy.toml
EXPOSE 8080

ENTRYPOINT ["gvm-proxy"]
