use std::collections::HashMap;

use futures_util::StreamExt;
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use rand::RngCore;
use sqlx::PgPool;
use uuid::Uuid;

use crate::cloudflare::{
    generate_ice_servers, revoke_credential, turn_usage, CfConfig, CfError, IceServers,
};

pub const CREDENTIAL_TTL_SECS: u64 = 3600;
const STALE_POLL_MINUTES: i64 = 30;
const GB: u64 = 1_000_000_000;
const DEFAULT_BUDGET_GB: u64 = 800;
const BUDGET_WINDOW_DAYS: i64 = 31;
const REVOKE_CONCURRENCY: usize = 8;
const REVOKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Debug, PartialEq, Eq)]
pub enum RelayRefusal {
    NotPaid,
    Limit,
    Unavailable,
}

pub fn relay_cap_bytes(tier: &str) -> Option<u64> {
    match tier {
        "pro" => Some(25 * GB),
        "teams" => Some(50 * GB),
        "business" => Some(100 * GB),
        _ => None,
    }
}

async fn current_usage(pool: &PgPool, user_id: Uuid) -> Result<u64, sqlx::Error> {
    let bytes: Option<i64> = sqlx::query_scalar(
        "SELECT egress_bytes FROM relay_usage \
         WHERE user_id = $1 AND month = date_trunc('month', now() AT TIME ZONE 'UTC')::date",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(bytes.unwrap_or(0).max(0) as u64)
}

async fn budget_open(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let open: Option<bool> = sqlx::query_scalar(
        "SELECT NOT tripped AND last_ok_at IS NOT NULL \
                AND last_ok_at > now() - make_interval(mins => $1) \
         FROM relay_budget WHERE id = 1",
    )
    .bind(STALE_POLL_MINUTES as i32)
    .fetch_optional(pool)
    .await?;
    Ok(open.unwrap_or(false))
}

async fn identifier_for(pool: &PgPool, user_id: Uuid) -> Result<String, sqlx::Error> {
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    sqlx::query("INSERT INTO relay_identities (user_id, ident) VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING")
        .bind(user_id)
        .bind(hex::encode(raw))
        .execute(pool)
        .await?;
    sqlx::query_scalar("SELECT ident FROM relay_identities WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

fn unavailable(what: &str, e: impl std::fmt::Debug) -> RelayRefusal {
    tracing::error!(error = ?e, "Relay mint failed: {what}");
    RelayRefusal::Unavailable
}

pub async fn mint(
    pool: &PgPool,
    cf: Option<&CfConfig>,
    user_id: Uuid,
) -> Result<IceServers, RelayRefusal> {
    let tier = crate::entitlement::benefit_tier_for_user(pool, user_id).await;
    let cap = relay_cap_bytes(&tier).ok_or(RelayRefusal::NotPaid)?;
    let used = current_usage(pool, user_id)
        .await
        .map_err(|e| unavailable("usage", e))?;
    if used >= cap {
        return Err(RelayRefusal::Limit);
    }
    let cf = cf.ok_or(RelayRefusal::Unavailable)?;
    if !budget_open(pool).await.map_err(|e| unavailable("budget", e))? {
        return Err(RelayRefusal::Unavailable);
    }

    let ident = identifier_for(pool, user_id)
        .await
        .map_err(|e| unavailable("identity", e))?;
    let ice = generate_ice_servers(cf, CREDENTIAL_TTL_SECS, &ident)
        .await
        .map_err(|e| unavailable("cloudflare", e))?;
    let recorded = sqlx::query(
        "INSERT INTO relay_credentials (username, user_id, expires_at) \
         VALUES ($1, $2, now() + make_interval(secs => $3))",
    )
    .bind(&ice.username)
    .bind(user_id)
    .bind(CREDENTIAL_TTL_SECS as f64)
    .execute(pool)
    .await;
    if let Err(e) = recorded {
        let _ = revoke_credential(cf, &ice.username).await;
        return Err(unavailable("record", e));
    }
    Ok(ice)
}

pub fn budget_bytes() -> u64 {
    std::env::var("RELAY_MONTHLY_BUDGET_GB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_BUDGET_GB)
        .saturating_mul(GB)
}

#[derive(Debug)]
pub enum PollError {
    Cloudflare(CfError),
    Db(sqlx::Error),
}

impl std::fmt::Display for PollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PollError::Cloudflare(e) => std::fmt::Display::fmt(e, f),
            PollError::Db(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

impl From<CfError> for PollError {
    fn from(e: CfError) -> Self {
        PollError::Cloudflare(e)
    }
}

impl From<sqlx::Error> for PollError {
    fn from(e: sqlx::Error) -> Self {
        PollError::Db(e)
    }
}

fn month_start(now: DateTime<Utc>) -> (NaiveDate, DateTime<Utc>) {
    let day = now.date_naive().with_day(1).expect("day 1 exists");
    (day, day.and_hms_opt(0, 0, 0).expect("midnight exists").and_utc())
}

fn clamp_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

async fn record_usage(pool: &PgPool, cf: &CfConfig, now: DateTime<Utc>) -> Result<(), PollError> {
    let (month, month_from) = month_start(now);
    let by_user = turn_usage(cf, month_from, now).await?;
    let window: u64 = turn_usage(cf, now - Duration::days(BUDGET_WINDOW_DAYS), now)
        .await?
        .iter()
        .fold(0u64, |a, (_, b)| a.saturating_add(*b));

    let idents: Vec<String> = by_user.iter().map(|(i, _)| i.clone()).collect();
    let bytes: Vec<i64> = by_user.iter().map(|(_, b)| clamp_i64(*b)).collect();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO relay_usage (user_id, month, egress_bytes) \
         SELECT i.user_id, $3, u.bytes \
         FROM UNNEST($1::text[], $2::bigint[]) AS u(ident, bytes) \
         JOIN relay_identities i ON i.ident = u.ident \
         ON CONFLICT (user_id, month) DO UPDATE SET egress_bytes = EXCLUDED.egress_bytes",
    )
    .bind(&idents)
    .bind(&bytes)
    .bind(month)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO relay_budget (id, window_bytes, last_ok_at, tripped) \
         VALUES (1, $1, now(), $2) \
         ON CONFLICT (id) DO UPDATE SET \
             window_bytes = EXCLUDED.window_bytes, \
             last_ok_at = EXCLUDED.last_ok_at, \
             tripped = EXCLUDED.tripped",
    )
    .bind(clamp_i64(window))
    .bind(window >= budget_bytes())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn revoke_one(pool: &PgPool, cf: &CfConfig, username: String, now: DateTime<Utc>) {
    if let Err(e) = revoke_credential(cf, &username).await {
        tracing::warn!(error = ?e, "Relay credential revoke failed; retrying next poll");
        return;
    }
    if let Err(e) = sqlx::query("UPDATE relay_credentials SET revoked_at = $2 WHERE username = $1")
        .bind(&username)
        .bind(now)
        .execute(pool)
        .await
    {
        tracing::warn!(error = %e, "Relay credential revoked but not recorded; retrying next poll");
    }
}

async fn revoke_over_limit(pool: &PgPool, cf: &CfConfig, now: DateTime<Utc>) -> Result<(), PollError> {
    let (month, _) = month_start(now);
    let tripped: bool = sqlx::query_scalar("SELECT tripped FROM relay_budget WHERE id = 1")
        .fetch_optional(pool)
        .await?
        .unwrap_or(true);
    let live: Vec<(String, Option<Uuid>, i64)> = sqlx::query_as(
        "SELECT c.username, c.user_id, COALESCE(u.egress_bytes, 0) \
         FROM relay_credentials c \
         LEFT JOIN relay_usage u ON u.user_id = c.user_id AND u.month = $2 \
         WHERE c.revoked_at IS NULL AND c.expires_at > $1",
    )
    .bind(now)
    .bind(month)
    .fetch_all(pool)
    .await?;

    let mut caps: HashMap<Uuid, u64> = HashMap::new();
    let mut doomed = Vec::new();
    for (username, user_id, used) in live {
        let cap = match user_id {
            None => 0,
            Some(id) => match caps.get(&id) {
                Some(c) => *c,
                None => {
                    let tier = crate::entitlement::benefit_tier_for_user(pool, id).await;
                    let c = relay_cap_bytes(&tier).unwrap_or(0);
                    caps.insert(id, c);
                    c
                }
            },
        };
        if tripped || (used.max(0) as u64) >= cap {
            doomed.push(username);
        }
    }

    let revoking = futures_util::stream::iter(doomed)
        .for_each_concurrent(REVOKE_CONCURRENCY, |u| revoke_one(pool, cf, u, now));
    if tokio::time::timeout(REVOKE_DEADLINE, revoking).await.is_err() {
        tracing::warn!("Relay revocation hit its deadline; remaining credentials retry next poll");
    }
    Ok(())
}

pub async fn sweep_expired(pool: &PgPool) {
    if let Err(e) = sqlx::query(
        "DELETE FROM relay_credentials WHERE expires_at < now() - interval '1 day'",
    )
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, "Relay credential sweep failed");
    }
}

pub async fn poll_once(pool: &PgPool, cf: &CfConfig, now: DateTime<Utc>) -> Result<(), PollError> {
    let usage = record_usage(pool, cf, now).await;
    let revoked = revoke_over_limit(pool, cf, now).await;
    usage.and(revoked)
}

pub fn expiry_from(issued: DateTime<Utc>) -> DateTime<Utc> {
    issued + Duration::seconds(CREDENTIAL_TTL_SECS as i64)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{env_lock, seed_user, set_user_tier, EnvLockGuard};
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct MockState {
        pub generated: Vec<(String, String)>,
        pub revoked: Vec<String>,
        pub generate_status: u16,
        pub revoke_status: u16,
        pub usage_status: u16,
        pub month_usage: Vec<(String, u64)>,
        pub window_usage: Vec<(String, u64)>,
        pub now: Option<DateTime<Utc>>,
    }

    type Shared = Arc<Mutex<MockState>>;

    async fn handle(
        State(s): State<Shared>,
        uri: axum::http::Uri,
        body: Option<Json<Value>>,
    ) -> (StatusCode, Json<Value>) {
        let mut s = s.lock().unwrap();
        let path = uri.path().to_string();
        let body = body.map(|b| b.0).unwrap_or(Value::Null);
        if path.ends_with("/generate-ice-servers") {
            let status = s.generate_status;
            if status != 201 {
                return (StatusCode::from_u16(status).unwrap(), Json(json!({})));
            }
            let username = format!("u-{}", Uuid::new_v4());
            let ident = body["customIdentifier"].as_str().unwrap().to_string();
            s.generated.push((username.clone(), ident));
            return (
                StatusCode::CREATED,
                Json(json!({"iceServers": [
                    {"urls": ["stun:stun.cloudflare.com:3478"]},
                    {"urls": ["turn:turn.cloudflare.com:3478"], "username": username, "credential": "secret"}
                ]})),
            );
        }
        if path.ends_with("/revoke") {
            let status = s.revoke_status;
            if status < 300 {
                let name = path.rsplit('/').nth(1).unwrap().to_string();
                s.revoked.push(name);
            }
            return (StatusCode::from_u16(status).unwrap(), Json(Value::Null));
        }
        if s.usage_status != 200 {
            return (StatusCode::from_u16(s.usage_status).unwrap(), Json(json!({})));
        }
        let from: DateTime<Utc> = body["variables"]["from"].as_str().unwrap().parse().unwrap();
        let is_window = s.now.is_some_and(|n| from == n - Duration::days(31));
        let rows = if is_window { &s.window_usage } else { &s.month_usage };
        let groups: Vec<Value> = rows
            .iter()
            .map(|(id, b)| json!({"dimensions": {"customIdentifier": id}, "sum": {"egressBytes": b}}))
            .collect();
        (
            StatusCode::OK,
            Json(json!({"data": {"viewer": {"accounts": [{"callsTurnUsageAdaptiveGroups": groups}]}}, "errors": null})),
        )
    }

    pub struct Harness {
        pub state: Shared,
        pub cf: CfConfig,
        _guard: EnvLockGuard,
    }

    pub async fn harness(pool: &PgPool) -> Harness {
        let guard = EnvLockGuard(env_lock());
        let state: Shared = Arc::new(Mutex::new(MockState {
            generate_status: 201,
            revoke_status: 204,
            usage_status: 200,
            ..Default::default()
        }));
        let app = Router::new().fallback(post(handle)).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        std::env::set_var("CF_RTC_BASE", &base);
        std::env::set_var("CF_API_BASE", &base);
        sqlx::query("UPDATE relay_credentials SET revoked_at = now() WHERE revoked_at IS NULL")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM relay_budget").execute(pool).await.unwrap();
        Harness {
            state,
            cf: CfConfig {
                account_id: "acct".into(),
                turn_key_id: "key1".into(),
                turn_key_token: "t".into(),
                analytics_token: "a".into(),
            },
            _guard: guard,
        }
    }

    pub async fn set_budget(pool: &PgPool, tripped: bool, age_minutes: i32) {
        sqlx::query(
            "INSERT INTO relay_budget (id, window_bytes, last_ok_at, tripped) \
             VALUES (1, 0, now() - make_interval(mins => $1), $2) \
             ON CONFLICT (id) DO UPDATE SET last_ok_at = EXCLUDED.last_ok_at, tripped = EXCLUDED.tripped",
        )
        .bind(age_minutes)
        .bind(tripped)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn paid_user(pool: &PgPool, tier: &str) -> Uuid {
        let user = seed_user(pool).await;
        set_user_tier(pool, user, tier).await;
        user
    }

    pub async fn set_usage(pool: &PgPool, user: Uuid, month_offset: i32, bytes: i64) {
        sqlx::query(
            "INSERT INTO relay_usage (user_id, month, egress_bytes) \
             VALUES ($1, (date_trunc('month', now() AT TIME ZONE 'UTC') + make_interval(months => $2))::date, $3) \
             ON CONFLICT (user_id, month) DO UPDATE SET egress_bytes = EXCLUDED.egress_bytes",
        )
        .bind(user)
        .bind(month_offset)
        .bind(bytes)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn user_with_ident(pool: &PgPool, tier: &str) -> (Uuid, String) {
        let user = paid_user(pool, tier).await;
        let ident = format!("ident-{}", user.simple());
        sqlx::query("INSERT INTO relay_identities (user_id, ident) VALUES ($1, $2)")
            .bind(user)
            .bind(&ident)
            .execute(pool)
            .await
            .unwrap();
        (user, ident)
    }

    async fn live_credential(pool: &PgPool, user: Uuid) -> String {
        let username = format!("cred-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO relay_credentials (username, user_id, expires_at) \
             VALUES ($1, $2, now() + interval '1 hour')",
        )
        .bind(&username)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
        username
    }

    async fn is_revoked(pool: &PgPool, username: &str) -> bool {
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM relay_credentials WHERE username = $1")
            .bind(username)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn budget_row(pool: &PgPool) -> (i64, Option<DateTime<Utc>>, bool) {
        sqlx::query_as("SELECT window_bytes, last_ok_at, tripped FROM relay_budget WHERE id = 1")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn month_usage(pool: &PgPool, user: Uuid) -> Option<i64> {
        sqlx::query_scalar(
            "SELECT egress_bytes FROM relay_usage WHERE user_id = $1 \
             AND month = date_trunc('month', now() AT TIME ZONE 'UTC')::date",
        )
        .bind(user)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    fn whole_seconds_now() -> DateTime<Utc> {
        DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
    }

    fn feed(h: &Harness, now: DateTime<Utc>, month: Vec<(String, u64)>, window: Vec<(String, u64)>) {
        let mut s = h.state.lock().unwrap();
        s.now = Some(now);
        s.month_usage = month;
        s.window_usage = window;
    }

    #[tokio::test]
    async fn poll_updates_usage_and_budget() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let (user, ident) = user_with_ident(&pool, "pro").await;
        let now = whole_seconds_now();
        feed(&h, now, vec![(ident.clone(), 5_000), ("unknown".into(), 9)], vec![(ident, 7_000), ("unknown".into(), 9)]);
        poll_once(&pool, &h.cf, now).await.unwrap();
        assert_eq!(month_usage(&pool, user).await, Some(5_000));
        let (window, last_ok, tripped) = budget_row(&pool).await;
        assert_eq!(window, 7_009);
        assert!(last_ok.unwrap() > Utc::now() - Duration::minutes(1));
        assert!(!tripped);
        let ice = mint(&pool, Some(&h.cf), user).await;
        assert!(ice.is_ok());
    }

    #[tokio::test]
    async fn poll_trips_budget_and_revokes_all_live() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let (a, ident_a) = user_with_ident(&pool, "pro").await;
        let (b, _) = user_with_ident(&pool, "business").await;
        let (ca, cb) = (live_credential(&pool, a).await, live_credential(&pool, b).await);
        let expired = live_credential(&pool, a).await;
        sqlx::query("UPDATE relay_credentials SET expires_at = now() - interval '1 minute' WHERE username = $1")
            .bind(&expired)
            .execute(&pool)
            .await
            .unwrap();
        let now = whole_seconds_now();
        feed(&h, now, vec![], vec![(ident_a, 800_000_000_000)]);
        poll_once(&pool, &h.cf, now).await.unwrap();
        assert!(budget_row(&pool).await.2);
        assert!(is_revoked(&pool, &ca).await);
        assert!(is_revoked(&pool, &cb).await);
        assert!(!is_revoked(&pool, &expired).await);
        assert_eq!(mint(&pool, Some(&h.cf), a).await.unwrap_err(), RelayRefusal::Unavailable);

        feed(&h, now, vec![], vec![]);
        poll_once(&pool, &h.cf, now).await.unwrap();
        assert!(!budget_row(&pool).await.2);
    }

    #[tokio::test]
    async fn poll_revokes_only_capped_users() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let (capped, capped_ident) = user_with_ident(&pool, "pro").await;
        let (fine, fine_ident) = user_with_ident(&pool, "pro").await;
        let (teams, teams_ident) = user_with_ident(&pool, "teams").await;
        let cc = live_credential(&pool, capped).await;
        let cf_ = live_credential(&pool, fine).await;
        let ct = live_credential(&pool, teams).await;
        let now = whole_seconds_now();
        let month = vec![
            (capped_ident, 25_000_000_000),
            (fine_ident, 24_999_999_999),
            (teams_ident, 30_000_000_000),
        ];
        feed(&h, now, month.clone(), month);
        poll_once(&pool, &h.cf, now).await.unwrap();
        assert!(is_revoked(&pool, &cc).await);
        assert!(!is_revoked(&pool, &cf_).await);
        assert!(!is_revoked(&pool, &ct).await);
        assert_eq!(h.state.lock().unwrap().revoked, vec![cc]);
    }

    #[tokio::test]
    async fn revoke_failure_retried_next_poll() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let (user, ident) = user_with_ident(&pool, "pro").await;
        let cred = live_credential(&pool, user).await;
        let now = whole_seconds_now();
        feed(&h, now, vec![(ident.clone(), 26_000_000_000)], vec![(ident, 26_000_000_000)]);
        h.state.lock().unwrap().revoke_status = 503;
        poll_once(&pool, &h.cf, now).await.unwrap();
        assert!(!is_revoked(&pool, &cred).await);
        assert_eq!(month_usage(&pool, user).await, Some(26_000_000_000));
        assert_eq!(budget_row(&pool).await.0, 26_000_000_000);

        h.state.lock().unwrap().revoke_status = 204;
        poll_once(&pool, &h.cf, now).await.unwrap();
        assert!(is_revoked(&pool, &cred).await);
    }

    #[tokio::test]
    async fn usage_failure_keeps_last_ok_at() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        set_budget(&pool, false, 10).await;
        let before = budget_row(&pool).await.1;
        h.state.lock().unwrap().usage_status = 502;
        assert!(poll_once(&pool, &h.cf, Utc::now()).await.is_err());
        assert_eq!(budget_row(&pool).await.1, before);

        set_budget(&pool, false, 31).await;
        let (user, _) = user_with_ident(&pool, "pro").await;
        assert_eq!(mint(&pool, Some(&h.cf), user).await.unwrap_err(), RelayRefusal::Unavailable);
    }

    #[tokio::test]
    async fn usage_failure_still_revokes_from_stored_usage() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let (user, _) = user_with_ident(&pool, "pro").await;
        let cred = live_credential(&pool, user).await;
        set_usage(&pool, user, 0, 30_000_000_000).await;
        h.state.lock().unwrap().usage_status = 500;
        assert!(poll_once(&pool, &h.cf, Utc::now()).await.is_err());
        assert!(is_revoked(&pool, &cred).await);
    }

    #[test]
    fn month_start_is_utc_calendar_month() {
        let now: DateTime<Utc> = "2026-10-31T23:59:59Z".parse().unwrap();
        let (day, from) = month_start(now);
        assert_eq!(day.to_string(), "2026-10-01");
        assert_eq!(from.to_rfc3339(), "2026-10-01T00:00:00+00:00");
    }

    #[tokio::test]
    async fn window_counts_unattributed_egress() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let now = whole_seconds_now();
        feed(&h, now, vec![], vec![("".into(), 801_000_000_000)]);
        poll_once(&pool, &h.cf, now).await.unwrap();
        let (window, _, tripped) = budget_row(&pool).await;
        assert_eq!(window, 801_000_000_000);
        assert!(tripped);
    }

    #[tokio::test]
    async fn orphaned_credential_is_revoked_after_account_deletion() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let (user, _) = user_with_ident(&pool, "pro").await;
        let cred = live_credential(&pool, user).await;
        sqlx::query("DELETE FROM users WHERE id = $1").bind(user).execute(&pool).await.unwrap();
        let now = whole_seconds_now();
        feed(&h, now, vec![], vec![]);
        poll_once(&pool, &h.cf, now).await.unwrap();
        assert!(is_revoked(&pool, &cred).await);
    }

    #[tokio::test]
    async fn missing_budget_row_revokes_everything() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let (user, _) = user_with_ident(&pool, "pro").await;
        let cred = live_credential(&pool, user).await;
        h.state.lock().unwrap().usage_status = 500;
        assert!(poll_once(&pool, &h.cf, Utc::now()).await.is_err());
        assert!(is_revoked(&pool, &cred).await);
    }

    #[tokio::test]
    async fn sweep_drops_credentials_expired_over_a_day() {
        let pool = test_pool_or_skip!();
        let _h = harness(&pool).await;
        let (user, _) = user_with_ident(&pool, "pro").await;
        let old = live_credential(&pool, user).await;
        let recent = live_credential(&pool, user).await;
        sqlx::query("UPDATE relay_credentials SET expires_at = now() - interval '25 hours' WHERE username = $1")
            .bind(&old).execute(&pool).await.unwrap();
        sqlx::query("UPDATE relay_credentials SET expires_at = now() - interval '1 hour' WHERE username = $1")
            .bind(&recent).execute(&pool).await.unwrap();
        sweep_expired(&pool).await;
        let left: Vec<String> = sqlx::query_scalar("SELECT username FROM relay_credentials WHERE username = ANY($1)")
            .bind(vec![old, recent.clone()]).fetch_all(&pool).await.unwrap();
        assert_eq!(left, vec![recent]);
    }

    #[test]
    fn cap_values_per_plan() {
        assert_eq!(relay_cap_bytes("pro"), Some(25_000_000_000));
        assert_eq!(relay_cap_bytes("teams"), Some(50_000_000_000));
        assert_eq!(relay_cap_bytes("business"), Some(100_000_000_000));
        assert_eq!(relay_cap_bytes("free"), None);
        assert_eq!(relay_cap_bytes("anything-else"), None);
    }

    #[tokio::test]
    async fn mint_refuses_free() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        set_budget(&pool, false, 0).await;
        let user = paid_user(&pool, "free").await;
        assert_eq!(mint(&pool, Some(&h.cf), user).await.unwrap_err(), RelayRefusal::NotPaid);
        assert!(h.state.lock().unwrap().generated.is_empty());
    }

    #[tokio::test]
    async fn mint_refuses_over_cap() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        set_budget(&pool, false, 0).await;
        let user = paid_user(&pool, "pro").await;
        set_usage(&pool, user, 0, 25_000_000_000).await;
        assert_eq!(mint(&pool, Some(&h.cf), user).await.unwrap_err(), RelayRefusal::Limit);
        set_usage(&pool, user, 0, 24_999_999_999).await;
        assert!(mint(&pool, Some(&h.cf), user).await.is_ok());
    }

    #[tokio::test]
    async fn mint_refuses_when_budget_tripped() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        set_budget(&pool, true, 0).await;
        let user = paid_user(&pool, "pro").await;
        assert_eq!(mint(&pool, Some(&h.cf), user).await.unwrap_err(), RelayRefusal::Unavailable);
        assert!(h.state.lock().unwrap().generated.is_empty());
    }

    #[tokio::test]
    async fn mint_refuses_when_poll_stale_or_never_ran() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        let user = paid_user(&pool, "pro").await;
        assert_eq!(mint(&pool, Some(&h.cf), user).await.unwrap_err(), RelayRefusal::Unavailable);
        set_budget(&pool, false, 31).await;
        assert_eq!(mint(&pool, Some(&h.cf), user).await.unwrap_err(), RelayRefusal::Unavailable);
        set_budget(&pool, false, 29).await;
        assert!(mint(&pool, Some(&h.cf), user).await.is_ok());
    }

    #[tokio::test]
    async fn mint_refuses_without_config() {
        let pool = test_pool_or_skip!();
        let _h = harness(&pool).await;
        set_budget(&pool, false, 0).await;
        let user = paid_user(&pool, "pro").await;
        assert_eq!(mint(&pool, None, user).await.unwrap_err(), RelayRefusal::Unavailable);
    }

    #[tokio::test]
    async fn mint_unavailable_when_cloudflare_fails() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        set_budget(&pool, false, 0).await;
        h.state.lock().unwrap().generate_status = 500;
        let user = paid_user(&pool, "pro").await;
        assert_eq!(mint(&pool, Some(&h.cf), user).await.unwrap_err(), RelayRefusal::Unavailable);
    }

    #[tokio::test]
    async fn mint_records_credential_with_opaque_identifier() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        set_budget(&pool, false, 0).await;
        let user = paid_user(&pool, "pro").await;
        let ice = mint(&pool, Some(&h.cf), user).await.unwrap();
        let second = mint(&pool, Some(&h.cf), user).await.unwrap();

        let (ttl, revoked): (f64, bool) = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM expires_at - issued_at)::float8, revoked_at IS NOT NULL \
             FROM relay_credentials WHERE username = $1 AND user_id = $2",
        )
        .bind(&ice.username)
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!((ttl - 3600.0).abs() < 1.0);
        assert!(!revoked);

        let ident: String =
            sqlx::query_scalar("SELECT ident FROM relay_identities WHERE user_id = $1")
                .bind(user)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(ident.len(), 32);
        assert!(ident.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!ident.contains(&user.simple().to_string()));
        let state = h.state.lock().unwrap();
        assert!(state.generated.iter().all(|(_, i)| *i == ident));
        assert_ne!(ice.username, second.username);
    }

    #[tokio::test]
    async fn month_rollover_resets_user_cap() {
        let pool = test_pool_or_skip!();
        let h = harness(&pool).await;
        set_budget(&pool, false, 0).await;
        let user = paid_user(&pool, "pro").await;
        set_usage(&pool, user, -1, 40_000_000_000).await;
        assert!(mint(&pool, Some(&h.cf), user).await.is_ok());
    }
}
