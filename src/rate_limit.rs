use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;

/// Per-key sliding window rate limiter. Key is typically IpAddr or Uuid.
pub struct RateLimiter<K = IpAddr> {
    state: Arc<Mutex<HashMap<K, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

// Manual Clone: Arc clone is always valid regardless of K.
impl<K> Clone for RateLimiter<K> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            max_requests: self.max_requests,
            window: self.window,
        }
    }
}

impl<K: Eq + Hash + Send + 'static> RateLimiter<K> {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    pub async fn check(&self, key: K) -> bool {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let entries = state.entry(key).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);
        if entries.len() >= self.max_requests {
            return false;
        }
        entries.push(now);
        true
    }
}

fn extract_ip(req: &Request) -> IpAddr {
    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());

    // Only trust X-Forwarded-For when the direct connection is from the configured trusted proxy.
    // Without TRUSTED_PROXY_IP set, fall back to the real peer address to prevent spoofing.
    let trusted: Option<IpAddr> = std::env::var("TRUSTED_PROXY_IP")
        .ok()
        .and_then(|s| s.parse().ok());

    let behind_proxy = matches!((peer_ip, trusted), (Some(peer), Some(t)) if peer == t);

    if behind_proxy {
        req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok())
            .or(peer_ip)
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    } else {
        peer_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    }
}

/// Newtype so each limiter can coexist as a distinct Extension type.
#[derive(Clone)]
pub struct RegisterRateLimiter(pub RateLimiter<IpAddr>);

/// Per-user (not per-IP) so shared office NAT doesn't block legitimate users.
#[derive(Clone)]
pub struct InviteRateLimiter(pub RateLimiter<Uuid>);

#[derive(Clone)]
pub struct SyncRateLimiter(pub RateLimiter<Uuid>);

#[derive(Clone)]
pub struct WaitlistRateLimiter(pub RateLimiter<IpAddr>);

/// Register endpoint: N registrations/day per IP.
pub async fn register_rate_limit(
    axum::Extension(RegisterRateLimiter(limiter)): axum::Extension<RegisterRateLimiter>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = extract_ip(&req);
    if !limiter.check(ip).await {
        warn!(%ip, "Register rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(req).await)
}

/// Invite endpoint: N invitations/hour per user (auth_middleware must run first).
pub async fn invite_rate_limit(
    axum::Extension(InviteRateLimiter(limiter)): axum::Extension<InviteRateLimiter>,
    axum::Extension(auth): axum::Extension<crate::auth::AuthUser>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !limiter.check(auth.0).await {
        warn!(user_id = %auth.0, "Invite rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(req).await)
}

/// Sync endpoints: N requests/hour per user (auth_middleware must run first).
pub async fn sync_rate_limit(
    axum::Extension(SyncRateLimiter(limiter)): axum::Extension<SyncRateLimiter>,
    axum::Extension(auth): axum::Extension<crate::auth::AuthUser>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !limiter.check(auth.0).await {
        warn!(user_id = %auth.0, "Sync rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(req).await)
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

/// Public waitlist endpoint: N submissions/hour per IP.
pub async fn waitlist_rate_limit(
    axum::Extension(WaitlistRateLimiter(limiter)): axum::Extension<WaitlistRateLimiter>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = extract_ip(&req);
    if !limiter.check(ip).await {
        warn!(%ip, "Waitlist rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(req).await)
}

