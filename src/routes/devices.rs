#![allow(clippy::result_large_err)]

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::coded_error;
use crate::auth::AuthUser;
use crate::cloudflare::{CfConfig, IceServer};
use crate::rate_limit::{check_user_budget, RateLimiter, RendezvousRateLimiter};
use crate::relay::{self, RelayRefusal};
use crate::sync_notifier::SyncNotifier;

const MAX_SEALED_BYTES: usize = 8 * 1024;
const LIFETIME_SECS: i64 = 60;

#[derive(Deserialize)]
pub struct CreateRendezvous {
    pub from_device: String,
    pub to_device: String,
    pub offer: String,
}

#[derive(Serialize)]
pub struct CreatedRendezvous {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct RendezvousView {
    pub from_device: String,
    pub to_device: String,
    pub offer: String,
    pub answer: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct RendezvousRow {
    from_device: String,
    to_device: String,
    offer: Vec<u8>,
    answer: Option<Vec<u8>>,
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct AnswerRendezvous {
    pub answer: String,
}

fn internal(e: sqlx::Error) -> Response {
    tracing::error!(error = %e, "Device rendezvous query failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn rendezvous_budget(limiter: &RateLimiter<Uuid>, user: Uuid) -> Result<(), Response> {
    check_user_budget(limiter, user, "device_rendezvous")
        .await
        .map_err(IntoResponse::into_response)
}

fn decode_sealed(encoded: &str) -> Result<Vec<u8>, Response> {
    if encoded.len() > MAX_SEALED_BYTES.div_ceil(3) * 4 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let bytes = B64.decode(encoded).map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    if bytes.is_empty() {
        return Err(StatusCode::BAD_REQUEST.into_response());
    }
    if bytes.len() > MAX_SEALED_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    Ok(bytes)
}

pub async fn create_rendezvous(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Extension(RendezvousRateLimiter(limiter)): Extension<RendezvousRateLimiter>,
    Json(body): Json<CreateRendezvous>,
) -> Result<(StatusCode, Json<CreatedRendezvous>), Response> {
    rendezvous_budget(&limiter, auth.0).await?;
    crate::entitlement::require_paid(&pool, auth.0).await?;
    let offer = decode_sealed(&body.offer)?;

    let both_known = body.to_device != body.from_device
        && sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM sync_blobs WHERE user_id = $1 AND device_id = ANY($2)",
        )
        .bind(auth.0)
        .bind(vec![body.from_device.clone(), body.to_device.clone()])
        .fetch_one(&pool)
        .await
        .map_err(internal)?
            == 2;
    if !both_known {
        return Err(coded_error(StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND"));
    }

    let (id, expires_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO device_rendezvous (user_id, from_device, to_device, offer, expires_at) \
         VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5)) \
         RETURNING id, expires_at",
    )
    .bind(auth.0)
    .bind(&body.from_device)
    .bind(&body.to_device)
    .bind(&offer)
    .bind(LIFETIME_SECS as f64)
    .fetch_one(&pool)
    .await
    .map_err(internal)?;

    notifier.notify_device_rendezvous(auth.0, id, body.to_device);
    Ok((StatusCode::CREATED, Json(CreatedRendezvous { id, expires_at })))
}

#[derive(Deserialize)]
pub struct PendingQuery {
    pub to_device: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PendingRendezvous {
    pub id: Uuid,
    pub from_device: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn list_pending(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(RendezvousRateLimiter(limiter)): Extension<RendezvousRateLimiter>,
    axum::extract::Query(query): axum::extract::Query<PendingQuery>,
) -> Result<Json<Vec<PendingRendezvous>>, Response> {
    rendezvous_budget(&limiter, auth.0).await?;
    crate::entitlement::require_paid(&pool, auth.0).await?;
    let rows = sqlx::query_as::<_, PendingRendezvous>(
        "SELECT id, from_device, expires_at FROM device_rendezvous \
         WHERE user_id = $1 AND to_device = $2 AND answer IS NULL AND expires_at > now() \
         ORDER BY created_at",
    )
    .bind(auth.0)
    .bind(&query.to_device)
    .fetch_all(&pool)
    .await
    .map_err(internal)?;
    Ok(Json(rows))
}

pub async fn get_rendezvous(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<RendezvousView>, Response> {
    let row: Option<RendezvousRow> = sqlx::query_as(
        "SELECT from_device, to_device, offer, answer, expires_at FROM device_rendezvous \
         WHERE id = $1 AND user_id = $2 AND expires_at > now()",
    )
    .bind(id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(internal)?;
    let row = row.ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;
    Ok(Json(RendezvousView {
        from_device: row.from_device,
        to_device: row.to_device,
        offer: B64.encode(row.offer),
        answer: row.answer.map(|a| B64.encode(a)),
        expires_at: row.expires_at,
    }))
}

pub async fn answer_rendezvous(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path(id): Path<Uuid>,
    Json(body): Json<AnswerRendezvous>,
) -> Result<StatusCode, Response> {
    crate::entitlement::require_paid(&pool, auth.0).await?;
    let answer = decode_sealed(&body.answer)?;

    let updated = sqlx::query(
        "UPDATE device_rendezvous SET answer = $3 \
         WHERE id = $1 AND user_id = $2 AND expires_at > now() AND answer IS NULL",
    )
    .bind(id)
    .bind(auth.0)
    .bind(&answer)
    .execute(&pool)
    .await
    .map_err(internal)?;

    if updated.rows_affected() == 0 {
        let live: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM device_rendezvous WHERE id = $1 AND user_id = $2 AND expires_at > now()",
        )
        .bind(id)
        .bind(auth.0)
        .fetch_optional(&pool)
        .await
        .map_err(internal)?;
        return Err(if live.is_some() { StatusCode::CONFLICT } else { StatusCode::NOT_FOUND }.into_response());
    }

    notifier.notify_device_rendezvous_answer(auth.0, id);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct RelayCredentials {
    pub ice_servers: Vec<IceServer>,
    pub expires_at: i64,
}

pub async fn relay_credentials(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(RendezvousRateLimiter(limiter)): Extension<RendezvousRateLimiter>,
) -> Result<Json<RelayCredentials>, Response> {
    rendezvous_budget(&limiter, auth.0).await?;
    let cf = CfConfig::from_env();
    let issued = Utc::now();
    match relay::mint(&pool, cf.as_ref(), auth.0).await {
        Ok(ice) => Ok(Json(RelayCredentials {
            ice_servers: ice.ice_servers,
            expires_at: relay::expiry_from(issued).timestamp(),
        })),
        Err(RelayRefusal::NotPaid) => Err(StatusCode::PAYMENT_REQUIRED.into_response()),
        Err(RelayRefusal::Limit) => Err(coded_error(StatusCode::TOO_MANY_REQUESTS, "RELAY_LIMIT")),
        Err(RelayRefusal::Unavailable) => {
            Err(coded_error(StatusCode::SERVICE_UNAVAILABLE, "RELAY_UNAVAILABLE"))
        }
    }
}

pub async fn sweep_expired(pool: &PgPool) {
    if let Err(e) = sqlx::query(
        "DELETE FROM device_rendezvous WHERE expires_at < now() - interval '5 minutes'",
    )
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, "Device rendezvous sweep failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::RateLimiter;
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_user, set_user_tier};
    use std::time::Duration;

    async fn seed_device(pool: &PgPool, user: Uuid, device: &str) {
        sqlx::query(
            "INSERT INTO sync_blobs (user_id, device_id, blob, metadata, size_bytes) \
             VALUES ($1, $2, '\\x00', '{}', 1)",
        )
        .bind(user)
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn paid_user_with_devices(pool: &PgPool) -> Uuid {
        let user = seed_user(pool).await;
        set_user_tier(pool, user, "pro").await;
        seed_device(pool, user, "laptop").await;
        seed_device(pool, user, "phone").await;
        user
    }

    fn limiter(max: usize) -> Extension<RendezvousRateLimiter> {
        Extension(RendezvousRateLimiter(RateLimiter::new(max, Duration::from_secs(3600))))
    }

    fn body(from: &str, to: &str, offer: &[u8]) -> Json<CreateRendezvous> {
        Json(CreateRendezvous {
            from_device: from.into(),
            to_device: to.into(),
            offer: B64.encode(offer),
        })
    }

    async fn create(
        pool: &PgPool,
        user: Uuid,
        notifier: &SyncNotifier,
        b: Json<CreateRendezvous>,
    ) -> Result<(StatusCode, Json<CreatedRendezvous>), Response> {
        create_rendezvous(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(notifier.clone()),
            limiter(100),
            b,
        )
        .await
    }

    fn status_of<T>(r: Result<T, Response>) -> StatusCode {
        r.err().expect("expected refusal").status()
    }

    async fn answer(
        pool: &PgPool,
        user: Uuid,
        notifier: &SyncNotifier,
        id: Uuid,
        bytes: &[u8],
    ) -> Result<StatusCode, Response> {
        answer_rendezvous(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(notifier.clone()),
            Path(id),
            Json(AnswerRendezvous { answer: B64.encode(bytes) }),
        )
        .await
    }

    #[tokio::test]
    async fn rendezvous_round_trip() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let notifier = SyncNotifier::new();

        let (code, Json(created)) =
            create(&pool, user, &notifier, body("laptop", "phone", b"sealed-offer")).await.unwrap();
        assert_eq!(code, StatusCode::CREATED);
        assert!(created.expires_at > Utc::now());

        let Json(view) =
            get_rendezvous(State(pool.clone()), Extension(AuthUser(user)), Path(created.id))
                .await
                .unwrap();
        assert_eq!(view.from_device, "laptop");
        assert_eq!(view.to_device, "phone");
        assert_eq!(B64.decode(&view.offer).unwrap(), b"sealed-offer");
        assert!(view.answer.is_none());

        assert_eq!(
            answer(&pool, user, &notifier, created.id, b"sealed-answer").await.unwrap(),
            StatusCode::NO_CONTENT
        );
        let Json(view) =
            get_rendezvous(State(pool.clone()), Extension(AuthUser(user)), Path(created.id))
                .await
                .unwrap();
        assert_eq!(B64.decode(view.answer.unwrap()).unwrap(), b"sealed-answer");
    }

    #[tokio::test]
    async fn rendezvous_refuses_other_accounts_device() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let other = paid_user_with_devices(&pool).await;
        seed_device(&pool, other, "other-only").await;
        let notifier = SyncNotifier::new();

        let err = create(&pool, user, &notifier, body("laptop", "other-only", b"x"))
            .await
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(err.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], br#"{"error":"DEVICE_NOT_FOUND"}"#);

        let same = create(&pool, user, &notifier, body("laptop", "laptop", b"x")).await;
        assert_eq!(status_of(same), StatusCode::NOT_FOUND);

        let (_, Json(created)) =
            create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        let foreign =
            get_rendezvous(State(pool.clone()), Extension(AuthUser(other)), Path(created.id)).await;
        assert_eq!(status_of(foreign), StatusCode::NOT_FOUND);
        assert_eq!(
            status_of(answer(&pool, other, &notifier, created.id, b"a").await),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn rendezvous_refuses_free_user() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        seed_device(&pool, user, "laptop").await;
        seed_device(&pool, user, "phone").await;
        let notifier = SyncNotifier::new();

        let created = create(&pool, user, &notifier, body("laptop", "phone", b"x")).await;
        assert_eq!(status_of(created), StatusCode::PAYMENT_REQUIRED);

        let paid = paid_user_with_devices(&pool).await;
        let (_, Json(c)) =
            create(&pool, paid, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        sqlx::query("UPDATE users SET subscription_tier = 'free' WHERE id = $1")
            .bind(paid)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            status_of(answer(&pool, paid, &notifier, c.id, b"a").await),
            StatusCode::PAYMENT_REQUIRED
        );
    }

    #[tokio::test]
    async fn rendezvous_expires() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let notifier = SyncNotifier::new();
        let (_, Json(c)) =
            create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();

        sqlx::query("UPDATE device_rendezvous SET expires_at = now() - interval '1 second' WHERE id = $1")
            .bind(c.id)
            .execute(&pool)
            .await
            .unwrap();
        let got = get_rendezvous(State(pool.clone()), Extension(AuthUser(user)), Path(c.id)).await;
        assert_eq!(status_of(got), StatusCode::NOT_FOUND);
        assert_eq!(
            status_of(answer(&pool, user, &notifier, c.id, b"a").await),
            StatusCode::NOT_FOUND
        );

        sweep_expired(&pool).await;
        let still: i64 = sqlx::query_scalar("SELECT count(*) FROM device_rendezvous WHERE id = $1")
            .bind(c.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(still, 1, "inside the grace window");

        sqlx::query("UPDATE device_rendezvous SET expires_at = now() - interval '6 minutes' WHERE id = $1")
            .bind(c.id)
            .execute(&pool)
            .await
            .unwrap();
        sweep_expired(&pool).await;
        let gone: i64 = sqlx::query_scalar("SELECT count(*) FROM device_rendezvous WHERE id = $1")
            .bind(c.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(gone, 0);
    }

    #[tokio::test]
    async fn answer_twice_conflicts() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let notifier = SyncNotifier::new();
        let (_, Json(c)) =
            create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        answer(&pool, user, &notifier, c.id, b"first").await.unwrap();
        assert_eq!(
            status_of(answer(&pool, user, &notifier, c.id, b"second").await),
            StatusCode::CONFLICT
        );
        let Json(view) =
            get_rendezvous(State(pool.clone()), Extension(AuthUser(user)), Path(c.id))
                .await
                .unwrap();
        assert_eq!(B64.decode(view.answer.unwrap()).unwrap(), b"first");
    }

    #[tokio::test]
    async fn oversized_offer_rejected() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let notifier = SyncNotifier::new();
        let big = vec![7u8; MAX_SEALED_BYTES + 1];
        let r = create(&pool, user, &notifier, body("laptop", "phone", &big)).await;
        assert_eq!(status_of(r), StatusCode::PAYLOAD_TOO_LARGE);
        let at_limit = vec![7u8; MAX_SEALED_BYTES];
        assert!(create(&pool, user, &notifier, body("laptop", "phone", &at_limit)).await.is_ok());

        let (_, Json(c)) =
            create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        assert_eq!(
            status_of(answer(&pool, user, &notifier, c.id, &big).await),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn creation_is_rate_limited() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let notifier = SyncNotifier::new();
        let lim = limiter(1);
        let call = || {
            create_rendezvous(
                State(pool.clone()),
                Extension(AuthUser(user)),
                Extension(notifier.clone()),
                lim.clone(),
                body("laptop", "phone", b"x"),
            )
        };
        assert!(call().await.is_ok());
        assert_eq!(status_of(call().await), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn sse_event_reaches_only_owner() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let stranger = Uuid::new_v4();
        let notifier = SyncNotifier::new();
        let mut rx = notifier.subscribe();

        let (_, Json(c)) =
            create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        answer(&pool, user, &notifier, c.id, b"a").await.unwrap();

        let first = rx.try_recv().unwrap();
        let second = rx.try_recv().unwrap();
        assert_eq!(
            crate::routes::sync::event_data(&first, user),
            Some(format!("device_rendezvous:{}:phone", c.id))
        );
        assert_eq!(
            crate::routes::sync::event_data(&second, user),
            Some(format!("device_rendezvous_answer:{}", c.id))
        );
        assert_eq!(crate::routes::sync::event_data(&first, stranger), None);
        assert_eq!(crate::routes::sync::event_data(&second, stranger), None);
    }

    #[tokio::test]
    async fn create_requires_both_devices_on_the_account() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let notifier = SyncNotifier::new();
        let r = create(&pool, user, &notifier, body("ghost", "phone", b"x")).await;
        assert_eq!(status_of(r), StatusCode::NOT_FOUND);
    }

    async fn pending(pool: &PgPool, user: Uuid, to: &str, lim: usize) -> Result<Vec<PendingRendezvous>, Response> {
        list_pending(
            State(pool.clone()),
            Extension(AuthUser(user)),
            limiter(lim),
            axum::extract::Query(PendingQuery { to_device: to.into() }),
        )
        .await
        .map(|Json(v)| v)
    }

    #[tokio::test]
    async fn pending_lists_unanswered_for_the_target_device_only() {
        let pool = test_pool_or_skip!();
        let user = paid_user_with_devices(&pool).await;
        let other = paid_user_with_devices(&pool).await;
        let notifier = SyncNotifier::new();

        let (_, Json(open)) = create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        let (_, Json(done)) = create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        answer(&pool, user, &notifier, done.id, b"a").await.unwrap();
        let (_, Json(expired)) = create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        sqlx::query("UPDATE device_rendezvous SET expires_at = now() - interval '1 second' WHERE id = $1")
            .bind(expired.id)
            .execute(&pool)
            .await
            .unwrap();
        let _ = create(&pool, user, &notifier, body("phone", "laptop", b"x")).await.unwrap();

        let got = pending(&pool, user, "phone", 100).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].id, got[0].from_device.as_str()), (open.id, "laptop"));

        assert!(pending(&pool, other, "phone", 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn pending_is_paid_gated_and_rate_limited() {
        let pool = test_pool_or_skip!();
        let free = seed_user(&pool).await;
        assert_eq!(status_of(pending(&pool, free, "phone", 100).await), StatusCode::PAYMENT_REQUIRED);
        let paid = paid_user_with_devices(&pool).await;
        let lim = limiter(1);
        let call = || {
            list_pending(
                State(pool.clone()),
                Extension(AuthUser(paid)),
                lim.clone(),
                axum::extract::Query(PendingQuery { to_device: "phone".into() }),
            )
        };
        assert!(call().await.is_ok());
        assert_eq!(status_of(call().await), StatusCode::TOO_MANY_REQUESTS);
    }

    async fn relay_status(pool: &PgPool, user: Uuid) -> StatusCode {
        match relay_credentials(State(pool.clone()), Extension(AuthUser(user)), limiter(100)).await {
            Ok(_) => StatusCode::OK,
            Err(r) => r.status(),
        }
    }

    #[tokio::test]
    async fn relay_credentials_status_mapping() {
        let pool = test_pool_or_skip!();
        let h = crate::relay::tests::harness(&pool).await;
        std::env::set_var("CF_ACCOUNT_ID", "acct");
        std::env::set_var("CF_TURN_KEY_ID", "key1");
        std::env::set_var("CF_TURN_KEY_TOKEN", "t");
        std::env::set_var("CF_ANALYTICS_TOKEN", "a");
        let free = seed_user(&pool).await;
        let pro = seed_user(&pool).await;
        set_user_tier(&pool, pro, "pro").await;

        crate::relay::tests::set_budget(&pool, false, 0).await;
        assert_eq!(relay_status(&pool, free).await, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(relay_status(&pool, pro).await, StatusCode::OK);

        let Json(out) = relay_credentials(State(pool.clone()), Extension(AuthUser(pro)), limiter(100))
            .await
            .unwrap();
        assert!(out.expires_at > Utc::now().timestamp() + 3000);
        assert_eq!(out.ice_servers.len(), 2);

        crate::relay::tests::set_usage(&pool, pro, 0, 25_000_000_000).await;
        let err = relay_credentials(State(pool.clone()), Extension(AuthUser(pro)), limiter(100))
            .await
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(err.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), br#"{"error":"RELAY_LIMIT"}"#);

        crate::relay::tests::set_budget(&pool, true, 0).await;
        crate::relay::tests::set_usage(&pool, pro, 0, 0).await;
        assert_eq!(relay_status(&pool, pro).await, StatusCode::SERVICE_UNAVAILABLE);
        drop(h);
    }
}
