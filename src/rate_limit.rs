use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;

/// Per-IP sliding window rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    async fn check(&self, ip: IpAddr) -> bool {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let entries = state.entry(ip).or_default();

        // Remove expired entries
        entries.retain(|t| now.duration_since(*t) < self.window);

        if entries.len() >= self.max_requests {
            return false;
        }

        entries.push(now);
        true
    }
}

fn extract_ip(req: &Request) -> IpAddr {
    // Try X-Forwarded-For first (behind reverse proxy), fall back to peer addr
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip())
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

/// Auth endpoints: 10 requests/minute per IP.
pub async fn auth_rate_limit(
    axum::Extension(limiter): axum::Extension<RateLimiter>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = extract_ip(&req);
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    if !limiter.check(ip).await {
        warn!(%ip, method = %method, path = %path, "Auth rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}

/// Sync endpoints: 60 requests/hour per IP.
pub async fn sync_rate_limit(
    axum::Extension(limiter): axum::Extension<RateLimiter>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = extract_ip(&req);
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    if !limiter.check(ip).await {
        warn!(%ip, method = %method, path = %path, "Sync rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}
