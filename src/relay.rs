use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use sqlx::PgPool;
use uuid::Uuid;

use crate::cloudflare::{generate_ice_servers, revoke_credential, CfConfig, IceServers};

pub const CREDENTIAL_TTL_SECS: u64 = 3600;
const STALE_POLL_MINUTES: i64 = 30;
const GB: u64 = 1_000_000_000;

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
