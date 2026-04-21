# --- Builder Stage ---
FROM rust:alpine AS builder
WORKDIR /app
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp /app/target/release/voltius-server /usr/local/bin/voltius-server


# --- Runtime Stage ---
FROM alpine:3.23
RUN apk add --no-cache ca-certificates openssl tzdata
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
COPY --from=builder /usr/local/bin/voltius-server /usr/local/bin/
ENV PORT=8080
EXPOSE 8080
CMD ["voltius-server"]