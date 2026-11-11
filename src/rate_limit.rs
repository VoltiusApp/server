use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use sqlx::PgPool;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{error, warn, Instrument};
use uuid::Uuid;

/// The daily sweep deletes durable hits older than this, so no durable window may exceed it.
pub const DURABLE_WINDOW_MAX: Duration = Duration::from_secs(86_400);

/// Per-key sliding window rate limiter. Key is typically IpAddr or Uuid.
pub struct RateLimiter<K = IpAddr> {
    state: Arc<Mutex<Buckets<K>>>,
    max_requests: usize,
    window: Duration,
    durable: Option<Durable>,
}

#[derive(Clone)]
struct Durable {
    pool: PgPool,
    bucket: &'static str,
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
            durable: self.durable.clone(),
        }
    }
}

impl<K: Eq + Hash + Display + Send + 'static> RateLimiter<K> {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(Buckets {
                by_key: HashMap::new(),
                last_sweep: Instant::now(),
            })),
            max_requests,
            window,
            durable: None,
        }
    }

    /// Also counts hits in Postgres under `bucket`, so the budget survives restarts and is
    /// shared by every instance. The in-memory check stays in front to absorb floods.
    pub fn durable(mut self, pool: PgPool, bucket: &'static str) -> Self {
        assert!(self.window <= DURABLE_WINDOW_MAX, "{bucket}: window outlives the hit sweep");
        self.durable = Some(Durable { pool, bucket });
        self
    }

    pub async fn check(&self, key: K) -> bool {
        let shown = self.durable.as_ref().map(|_| key.to_string());
        if !self.check_memory(key).await {
            return false;
        }
        let (Some(durable), Some(key)) = (&self.durable, shown) else {
            return true;
        };
        match admit_durable(durable, &key, self.max_requests, self.window).await {
            Ok(admitted) => admitted,
            Err(e) => {
                error!(error = %e, bucket = durable.bucket, "Durable rate limit check failed; using the in-memory count");
                true
            }
        }
    }

    async fn check_memory(&self, key: K) -> bool {
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

async fn admit_durable(durable: &Durable, key: &str, max_requests: usize, window: Duration) -> sqlx::Result<bool> {
    let mut tx = durable.pool.begin().await?;
    // The two-key form has its own key space, apart from the single-key instance lock.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind(durable.bucket)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    let recent: i64 = sqlx::query_scalar(
        "WITH expired AS ( \
             DELETE FROM rate_limit_hits \
             WHERE bucket = $1 AND key = $2 AND at <= now() - make_interval(secs => $3) \
         ) \
         SELECT count(*) FROM rate_limit_hits \
         WHERE bucket = $1 AND key = $2 AND at > now() - make_interval(secs => $3)",
    )
    .bind(durable.bucket)
    .bind(key)
    .bind(window.as_secs_f64())
    .fetch_one(&mut *tx)
    .await?;
    let admitted = (recent as usize) < max_requests;
    if admitted {
        sqlx::query("INSERT INTO rate_limit_hits (bucket, key) VALUES ($1, $2)")
            .bind(durable.bucket)
            .bind(key)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(admitted)
}

pub async fn sweep_durable_hits(pool: &PgPool) -> sqlx::Result<u64> {
    sqlx::query("DELETE FROM rate_limit_hits WHERE at <= now() - make_interval(secs => $1)")
        .bind(DURABLE_WINDOW_MAX.as_secs_f64())
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
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

/// Enrolment-token redemptions per user, so a leaked token cannot be probed through one account.
#[derive(Clone)]
pub struct EnrollmentRedeemRateLimiter(pub RateLimiter<Uuid>);

/// Handlers that charge IP limiters themselves read the address from here.
#[derive(Clone, Copy)]
pub struct ClientIp(pub IpAddr);

pub async fn attach_client_ip(mut req: Request, next: Next) -> Response {
    let ip = extract_ip(&req);
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

/// Public token lookups (resolve, and the token branch of register), per IP.
#[derive(Clone)]
pub struct EnrollmentResolveLimiter(pub RateLimiter<IpAddr>);

#[derive(Clone)]
pub struct EnrollmentPolicyLimiter(pub RateLimiter<IpAddr>);

/// Sign-ups through one enrolment token, so a fleet rollout behind one NAT is not capped per IP.
#[derive(Clone)]
pub struct EnrollmentRegisterLimiter(pub RateLimiter<Uuid>);

#[derive(Clone)]
pub struct ResendVerificationRateLimiter(pub RateLimiter<Uuid>);

pub async fn check_budget<K: Eq + Hash + Send + std::fmt::Display + 'static>(
    limiter: &RateLimiter<K>,
    key: K,
    label: &str,
) -> Result<(), StatusCode> {
    let shown = format!("{key}");
    if !limiter.check(key).await {
        warn!(key = %shown, limiter = label, "Rate limit exceeded");
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
    check_budget(limiter, user, label).await?;
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
    let span = tracing::warn_span!("auth_request", method = %req.method(), path = %req.uri().path());
    check_budget(&limiter, extract_ip(&req), "auth").instrument(span).await?;
    Ok(next.run(req).await)
}

/// Public waitlist endpoint: N submissions/hour per IP.
pub async fn waitlist_rate_limit(
    axum::Extension(WaitlistRateLimiter(limiter)): axum::Extension<WaitlistRateLimiter>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    check_budget(&limiter, extract_ip(&req), "waitlist").await?;
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

    fn durable(pool: &PgPool, max: usize) -> RateLimiter<Uuid> {
        RateLimiter::<Uuid>::new(max, Duration::from_secs(3600)).durable(pool.clone(), "test")
    }

    async fn hits_for(pool: &PgPool, key: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM rate_limit_hits WHERE bucket = 'test' AND key = $1")
            .bind(key.to_string())
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn seed_hit(pool: &PgPool, key: Uuid, age: &str) {
        sqlx::query("INSERT INTO rate_limit_hits (bucket, key, at) VALUES ('test', $1, now() - $2::interval)")
            .bind(key.to_string())
            .bind(age)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_durable_budget_survives_a_restart_and_is_shared_between_instances() {
        let pool = crate::test_pool_or_skip!();
        let key = Uuid::new_v4();
        let before = durable(&pool, 2);
        assert!(before.check(key).await);
        assert!(before.check(key).await);

        let after = durable(&pool, 2);
        assert!(!after.check(key).await);
        assert!(after.check(Uuid::new_v4()).await, "budgets are per key");
    }

    #[tokio::test]
    async fn concurrent_checks_never_overshoot_the_durable_budget() {
        let pool = crate::test_pool_or_skip!();
        let key = Uuid::new_v4();
        let checks = (0..12).map(|_| {
            let limiter = durable(&pool, 5);
            tokio::spawn(async move { limiter.check(key).await })
        });
        let admitted = futures_util::future::join_all(checks)
            .await
            .into_iter()
            .filter(|admitted| *admitted.as_ref().unwrap())
            .count();
        assert_eq!(admitted, 5);
        assert_eq!(hits_for(&pool, key).await, 5);
    }

    #[tokio::test]
    async fn hits_outside_the_window_neither_count_nor_survive() {
        let pool = crate::test_pool_or_skip!();
        let key = Uuid::new_v4();
        seed_hit(&pool, key, "2 hours").await;
        assert!(durable(&pool, 1).check(key).await);
        assert_eq!(hits_for(&pool, key).await, 1, "the expired hit is pruned on check");

        let quiet = Uuid::new_v4();
        seed_hit(&pool, quiet, "2 days").await;
        sweep_durable_hits(&pool).await.unwrap();
        assert_eq!(hits_for(&pool, quiet).await, 0);
        assert_eq!(hits_for(&pool, key).await, 1, "the sweep keeps live hits");
    }

    #[tokio::test]
    async fn an_unreachable_database_falls_back_to_the_in_memory_count() {
        let pool = crate::test_pool_or_skip!();
        let limiter = durable(&pool, 1);
        pool.close().await;
        let key = Uuid::new_v4();
        assert!(limiter.check(key).await);
        assert!(!limiter.check(key).await);
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
