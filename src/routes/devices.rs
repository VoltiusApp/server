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
use crate::rate_limit::{check_user_budget, RendezvousRateLimiter};
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

#[derive(Debug)]
pub struct Refusal(StatusCode, Option<&'static str>);

impl From<StatusCode> for Refusal {
    fn from(status: StatusCode) -> Self {
        Self(status, None)
    }
}

impl From<sqlx::Error> for Refusal {
    fn from(_: sqlx::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, None)
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self.1 {
            Some(code) => coded_error(self.0, code),
            None => self.0.into_response(),
        }
    }
}

async fn require_paid(pool: &PgPool, user: Uuid) -> Result<(), Refusal> {
    if crate::entitlement::benefit_tier_for_user(pool, user).await == "free" {
        return Err(StatusCode::PAYMENT_REQUIRED.into());
    }
    Ok(())
}

fn decode_sealed(encoded: &str) -> Result<Vec<u8>, Refusal> {
    if encoded.len() > MAX_SEALED_BYTES.div_ceil(3) * 4 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE.into());
    }
    let bytes = B64.decode(encoded).map_err(|_| Refusal::from(StatusCode::BAD_REQUEST))?;
    if bytes.is_empty() {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    if bytes.len() > MAX_SEALED_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE.into());
    }
    Ok(bytes)
}

pub async fn create_rendezvous(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Extension(RendezvousRateLimiter(limiter)): Extension<RendezvousRateLimiter>,
    Json(body): Json<CreateRendezvous>,
) -> Result<(StatusCode, Json<CreatedRendezvous>), Refusal> {
    check_user_budget(&limiter, auth.0, "device_rendezvous").await?;
    require_paid(&pool, auth.0).await?;
    let offer = decode_sealed(&body.offer)?;

    let target_known = body.to_device != body.from_device
        && sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM sync_blobs WHERE user_id = $1 AND device_id = $2",
        )
        .bind(auth.0)
        .bind(&body.to_device)
        .fetch_optional(&pool)
        .await
        .map_err(Refusal::from)?
        .is_some();
    if !target_known {
        return Err(Refusal(StatusCode::NOT_FOUND, Some("DEVICE_NOT_FOUND")));
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
    .map_err(Refusal::from)?;

    notifier.notify_device_rendezvous(auth.0, id, body.to_device);
    Ok((StatusCode::CREATED, Json(CreatedRendezvous { id, expires_at })))
}

pub async fn get_rendezvous(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<RendezvousView>, Refusal> {
    let row: Option<RendezvousRow> = sqlx::query_as(
        "SELECT from_device, to_device, offer, answer, expires_at FROM device_rendezvous \
         WHERE id = $1 AND user_id = $2 AND expires_at > now()",
    )
    .bind(id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(Refusal::from)?;
    let row = row.ok_or(StatusCode::NOT_FOUND)?;
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
) -> Result<StatusCode, Refusal> {
    require_paid(&pool, auth.0).await?;
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
    .map_err(Refusal::from)?;

    if updated.rows_affected() == 0 {
        let live: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM device_rendezvous WHERE id = $1 AND user_id = $2 AND expires_at > now()",
        )
        .bind(id)
        .bind(auth.0)
        .fetch_optional(&pool)
        .await
        .map_err(Refusal::from)?;
        return Err(if live.is_some() { StatusCode::CONFLICT } else { StatusCode::NOT_FOUND }.into());
    }

    notifier.notify_device_rendezvous_answer(auth.0, id);
    Ok(StatusCode::NO_CONTENT)
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
    use crate::sync_notifier::SyncEvent;
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
    ) -> Result<(StatusCode, Json<CreatedRendezvous>), Refusal> {
        create_rendezvous(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(notifier.clone()),
            limiter(100),
            b,
        )
        .await
    }

    fn status_of<T>(r: Result<T, Refusal>) -> StatusCode {
        r.err().expect("expected refusal").0
    }

    async fn answer(
        pool: &PgPool,
        user: Uuid,
        notifier: &SyncNotifier,
        id: Uuid,
        bytes: &[u8],
    ) -> Result<StatusCode, Refusal> {
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
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(err.into_response().into_body(), 1024).await.unwrap();
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
        let notifier = SyncNotifier::new();
        let mut rx = notifier.subscribe();

        let (_, Json(c)) =
            create(&pool, user, &notifier, body("laptop", "phone", b"x")).await.unwrap();
        answer(&pool, user, &notifier, c.id, b"a").await.unwrap();

        let stranger = Uuid::new_v4();
        let mut seen = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            seen.push(ev);
        }
        assert_eq!(seen.len(), 2);
        for ev in &seen {
            match ev {
                SyncEvent::DeviceRendezvous { user_id, rendezvous_id, to_device } => {
                    assert_eq!((*user_id, *rendezvous_id, to_device.as_str()), (user, c.id, "phone"));
                    assert_ne!(*user_id, stranger);
                }
                SyncEvent::DeviceRendezvousAnswer { user_id, rendezvous_id } => {
                    assert_eq!((*user_id, *rendezvous_id), (user, c.id));
                }
                other => panic!("unexpected event {other:?}"),
            }
        }
    }
}
