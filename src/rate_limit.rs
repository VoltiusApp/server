use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;

/// Per-key sliding window rate limiter. Key is typically IpAddr or Uuid.
pub struct RateLimiter<K = IpAddr> {
    state: Arc<Mutex<Buckets<K>>>,
    max_requests: usize,
    window: Duration,
}

struct Buckets<K> {
    by_key: HashMap<K, Vec<Instant>>,
    last_sweep: Instant,
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
            state: Arc::new(Mutex::new(Buckets {
                by_key: HashMap::new(),
                last_sweep: Instant::now(),
            })),
            max_requests,
            window,
        }
    }

    pub async fn check(&self, key: K) -> bool {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let window = self.window;
        // A key that never returns is only reclaimed here.
        if now.duration_since(state.last_sweep) >= window {
            state
                .by_key
                .retain(|_, hits| hits.last().is_some_and(|t| now.duration_since(*t) < window));
            state.last_sweep = now;
        }
        let entries = state.by_key.entry(key).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() >= self.max_requests {
            return false;
        }
        entries.push(now);
        true
    }

    #[cfg(test)]
    async fn tracked_keys(&self) -> usize {
        self.state.lock().await.by_key.len()
    }
}

/// A trusted proxy address or subnet. A containerised reverse proxy gets a new
/// address on every recreate, so a bare IP cannot be the only accepted form.
#[derive(Clone, Copy, Debug)]
pub struct TrustedNet {
    addr: IpAddr,
    prefix: u8,
}

impl TrustedNet {
    pub fn parse(spec: &str) -> Option<Self> {
        let (host, prefix) = match spec.split_once('/') {
            Some((host, prefix)) => (host, Some(prefix.trim().parse::<u8>().ok()?)),
            None => (spec, None),
        };
        let addr: IpAddr = host.trim().parse().ok()?;
        let host_bits = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(host_bits);
        (prefix <= host_bits).then_some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_matches(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_matches(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_matches(net: &[u8], ip: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    if net[..whole] != ip[..whole] {
        return false;
    }
    let remainder = prefix % 8;
    if remainder == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remainder);
    net[whole] & mask == ip[whole] & mask
}

fn trusted_proxies() -> &'static [TrustedNet] {
    static NETS: OnceLock<Vec<TrustedNet>> = OnceLock::new();
    NETS.get_or_init(|| {
        let raw = std::env::var("TRUSTED_PROXIES")
            .or_else(|_| std::env::var("TRUSTED_PROXY_IP"))
            .unwrap_or_default();
        raw.split(',')
            .map(str::trim)
            .filter(|spec| !spec.is_empty())
            .filter_map(|spec| {
                let net = TrustedNet::parse(spec);
                if net.is_none() {
                    warn!(entry = spec, "Ignoring unparseable trusted proxy entry");
                }
                net
            })
            .collect()
    })
}

pub fn trusted_proxy_count() -> usize {
    trusted_proxies().len()
}

fn client_ip(peer: Option<IpAddr>, forwarded_for: Option<&str>, trusted: &[TrustedNet]) -> IpAddr {
    let Some(peer) = peer else {
        return IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    };
    let trusts = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !trusts(peer) {
        return peer;
    }
    // Rightmost entry that is not itself a trusted proxy. Proxies append, so
    // everything left of that is caller-supplied and forgeable.
    forwarded_for
        .and_then(|header| {
            header
                .split(',')
                .rev()
                .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
                .find(|ip| !trusts(*ip))
        })
        .unwrap_or(peer)
}

fn extract_ip(req: &Request) -> IpAddr {
    client_ip(
        req.extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip()),
        req.headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok()),
        trusted_proxies(),
    )
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

/// Directory search, keyed by user id rather than IP: the endpoint is
/// authenticated, and an IP key would throttle a whole office at once.
#[derive(Clone)]
pub struct SearchRateLimiter(pub RateLimiter<Uuid>);

/// Stranger knocks per sender. Configurable because a hardcoded limiter has
/// cost real time in every end-to-end run since the auth one shipped.
#[derive(Clone)]
pub struct KnockRateLimiter(pub RateLimiter<Uuid>);

/// Short-code mints per host. Regenerate-spam must not become a mint oracle.
#[derive(Clone)]
pub struct SessionCodeRateLimiter(pub RateLimiter<Uuid>);

/// Code redemptions per user. Keyed by user because the endpoint is
/// authenticated, so brute force costs accounts, not just addresses.
#[derive(Clone)]
pub struct RedeemRateLimiter(pub RateLimiter<Uuid>);

/// Team join-grant mints per creator. A grant is unattended credential
/// material, so minting is budgeted the same way short codes are.
#[derive(Clone)]
pub struct GrantMintRateLimiter(pub RateLimiter<Uuid>);

/// Join-grant previews and redemptions per user. Kept separate from
/// [`RedeemRateLimiter`] so exhausting one path cannot lock a user out of the
/// other — they are different features that merely share a verb.
#[derive(Clone)]
pub struct GrantRedeemRateLimiter(pub RateLimiter<Uuid>);

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

/// Checks a per-user limiter, warning and returning 429 on exhaustion. The
/// one place this shape is expressed; middlewares and handlers alike call it.
pub async fn check_user_budget(
    limiter: &RateLimiter<Uuid>,
    user: Uuid,
    label: &str,
) -> Result<(), StatusCode> {
    if !limiter.check(user).await {
        warn!(user_id = %user, limiter = label, "Rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(())
}

/// Shared body for the per-user middlewares below: check the limiter keyed on
/// the authenticated caller, or reject with 429.
async fn user_keyed_limit(
    limiter: &RateLimiter<Uuid>,
    user: Uuid,
    label: &str,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    check_user_budget(limiter, user, label).await?;
    Ok(next.run(req).await)
}

/// Invite endpoint: N invitations/hour per user (auth_middleware must run first).
pub async fn invite_rate_limit(
    axum::Extension(InviteRateLimiter(limiter)): axum::Extension<InviteRateLimiter>,
    axum::Extension(auth): axum::Extension<crate::auth::AuthUser>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    user_keyed_limit(&limiter, auth.0, "invite", req, next).await
}

/// Sync endpoints: N requests/hour per user (auth_middleware must run first).
pub async fn sync_rate_limit(
    axum::Extension(SyncRateLimiter(limiter)): axum::Extension<SyncRateLimiter>,
    axum::Extension(auth): axum::Extension<crate::auth::AuthUser>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    user_keyed_limit(&limiter, auth.0, "sync", req, next).await
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

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(specs: &[&str]) -> Vec<TrustedNet> {
        specs.iter().filter_map(|s| TrustedNet::parse(s)).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_bare_addresses_as_single_hosts() {
        let net = TrustedNet::parse("172.22.0.5").unwrap();
        assert!(net.contains(ip("172.22.0.5")));
        assert!(!net.contains(ip("172.22.0.6")));
    }

    #[test]
    fn parses_cidr_ranges() {
        let net = TrustedNet::parse("172.22.0.0/16").unwrap();
        assert!(net.contains(ip("172.22.0.5")));
        assert!(net.contains(ip("172.22.255.255")));
        assert!(!net.contains(ip("172.23.0.1")));
    }

    #[test]
    fn honours_prefixes_that_do_not_land_on_a_byte() {
        let net = TrustedNet::parse("10.0.0.0/12").unwrap();
        assert!(net.contains(ip("10.15.1.1")));
        assert!(!net.contains(ip("10.16.0.1")));
    }

    #[test]
    fn matches_ipv6_and_never_across_families() {
        let net = TrustedNet::parse("fd00::/8").unwrap();
        assert!(net.contains(ip("fd00::1")));
        assert!(!net.contains(ip("fe80::1")));
        assert!(!net.contains(ip("10.0.0.1")));
        assert!(!TrustedNet::parse("10.0.0.0/8")
            .unwrap()
            .contains(ip("fd00::1")));
    }

    #[test]
    fn rejects_nonsense_specs() {
        assert!(TrustedNet::parse("").is_none());
        assert!(TrustedNet::parse("not-an-ip").is_none());
        assert!(TrustedNet::parse("10.0.0.0/33").is_none());
        assert!(TrustedNet::parse("10.0.0.0/x").is_none());
    }

    #[test]
    fn ignores_forwarded_for_from_an_untrusted_peer() {
        let ip_used = client_ip(
            Some(ip("203.0.113.9")),
            Some("198.51.100.1"),
            &nets(&["172.22.0.0/16"]),
        );
        assert_eq!(ip_used, ip("203.0.113.9"));
    }

    #[test]
    fn with_no_trusted_proxies_every_caller_keys_on_the_peer() {
        let a = client_ip(Some(ip("172.22.0.5")), Some("198.51.100.1"), &[]);
        let b = client_ip(Some(ip("172.22.0.5")), Some("198.51.100.2"), &[]);
        assert_eq!(
            a, b,
            "this is the shared-bucket behaviour a proxy setup must avoid"
        );
    }

    #[test]
    fn takes_the_client_address_from_a_trusted_proxy() {
        let ip_used = client_ip(
            Some(ip("172.22.0.5")),
            Some("198.51.100.1"),
            &nets(&["172.22.0.0/16"]),
        );
        assert_eq!(ip_used, ip("198.51.100.1"));
    }

    #[test]
    fn a_forged_prefix_cannot_change_the_key() {
        let trusted = nets(&["172.22.0.0/16"]);
        let honest = client_ip(Some(ip("172.22.0.5")), Some("198.51.100.1"), &trusted);
        let forged = client_ip(
            Some(ip("172.22.0.5")),
            Some("1.2.3.4, 9.9.9.9, 198.51.100.1"),
            &trusted,
        );
        assert_eq!(honest, forged);
    }

    #[test]
    fn skips_chained_trusted_hops() {
        let ip_used = client_ip(
            Some(ip("172.22.0.5")),
            Some("198.51.100.1, 172.22.0.9"),
            &nets(&["172.22.0.0/16"]),
        );
        assert_eq!(ip_used, ip("198.51.100.1"));
    }

    #[test]
    fn falls_back_to_the_peer_when_the_header_is_missing_or_junk() {
        let trusted = nets(&["172.22.0.0/16"]);
        assert_eq!(
            client_ip(Some(ip("172.22.0.5")), None, &trusted),
            ip("172.22.0.5")
        );
        assert_eq!(
            client_ip(Some(ip("172.22.0.5")), Some("not-an-ip"), &trusted),
            ip("172.22.0.5")
        );
    }

    #[tokio::test]
    async fn limiter_admits_up_to_the_configured_maximum() {
        let limiter = RateLimiter::<IpAddr>::new(3, Duration::from_secs(60));
        let key = ip("198.51.100.1");
        for _ in 0..3 {
            assert!(limiter.check(key).await);
        }
        assert!(!limiter.check(key).await);
        assert!(
            limiter.check(ip("198.51.100.2")).await,
            "a different key has its own budget"
        );
    }

    #[tokio::test]
    async fn keys_that_go_quiet_are_evicted() {
        let window = Duration::from_millis(30);
        let limiter = RateLimiter::<IpAddr>::new(3, window);
        for last_octet in 1..=50 {
            assert!(limiter.check(ip(&format!("198.51.100.{last_octet}"))).await);
        }
        assert_eq!(limiter.tracked_keys().await, 50);

        tokio::time::sleep(window * 2).await;
        assert!(limiter.check(ip("203.0.113.1")).await);
        assert_eq!(limiter.tracked_keys().await, 1);
    }

    #[tokio::test]
    async fn eviction_keeps_keys_still_inside_their_window() {
        let window = Duration::from_millis(200);
        let limiter = RateLimiter::<IpAddr>::new(1, window);
        let quiet = ip("198.51.100.1");
        let busy = ip("198.51.100.2");
        assert!(limiter.check(quiet).await);

        tokio::time::sleep(window * 6 / 10).await;
        assert!(limiter.check(busy).await);

        tokio::time::sleep(window / 2).await;
        assert!(limiter.check(ip("203.0.113.1")).await);
        assert_eq!(limiter.tracked_keys().await, 2);
        assert!(!limiter.check(busy).await, "budget survived the sweep");
    }
}
