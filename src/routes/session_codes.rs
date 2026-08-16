use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::rate_limit::{RedeemRateLimiter, SessionCodeRateLimiter};
use crate::session_grants;

#[derive(Debug, Serialize)]
pub struct CreateCodeResponse {
    pub code: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct RedeemRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct RedeemResponse {
    pub session_id: Uuid,
    pub invite_token: String,
}

pub async fn create_code(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(SessionCodeRateLimiter(limiter)): Extension<SessionCodeRateLimiter>,
    Path(session_id): Path<Uuid>,
) -> Result<(StatusCode, Json<CreateCodeResponse>), StatusCode> {
    if !limiter.check(auth.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    crate::routes::terminal::require_active_session_host(&pool, session_id, auth.0).await?;

    // Only invite_link sessions serve raw keys through the short-code/grant
    // path (get_my_session_key, is_authorized_participant); minting for a
    // vault or direct session would hand out a grant nothing can redeem it into.
    let visibility: String =
        sqlx::query_scalar("SELECT visibility FROM terminal_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if visibility != "invite_link" {
        return Err(StatusCode::FORBIDDEN);
    }

    let (code, expires_at) = session_grants::rotate_short_code(&pool, session_id, auth.0)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateCodeResponse { code, expires_at }),
    ))
}

pub async fn redeem_code(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(RedeemRateLimiter(limiter)): Extension<RedeemRateLimiter>,
    Json(body): Json<RedeemRequest>,
) -> Result<Json<RedeemResponse>, StatusCode> {
    if !limiter.check(auth.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Unknown, malformed, expired and revoked all answer 404: no response
    // distinguishes a real code from a wrong one.
    let Some(grant) = session_grants::resolve_short_code(&pool, &body.code).await else {
        warn!(user_id = %auth.0, "Short code redemption failed");
        return Err(StatusCode::NOT_FOUND);
    };

    let secret = session_grants::new_token_secret();
    session_grants::insert_grant(
        &pool,
        grant.session_id,
        "guest",
        &secret,
        None,
        auth.0,
        Some(auth.0),
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(RedeemResponse {
        session_id: grant.session_id,
        invite_token: secret,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::{RateLimiter, RedeemRateLimiter, SessionCodeRateLimiter};
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_session, seed_user};
    use axum::extract::{Path, State};
    use axum::{Extension, Json};
    use std::time::Duration;
    use uuid::Uuid;

    fn code_budget() -> SessionCodeRateLimiter {
        SessionCodeRateLimiter(RateLimiter::new(30, Duration::from_secs(3600)))
    }

    fn redeem_budget() -> RedeemRateLimiter {
        RedeemRateLimiter(RateLimiter::new(20, Duration::from_secs(3600)))
    }

    async fn seed_host_and_session(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
        let host = seed_user(pool).await;
        let session = seed_session(pool, host, "invite_link").await;
        (host, session)
    }

    #[tokio::test]
    async fn only_the_host_can_mint_a_code() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;
        let (stranger, _) = seed_host_and_session(&pool).await;

        assert!(create_code(
            State(pool.clone()),
            Extension(AuthUser(stranger)),
            Extension(code_budget()),
            Path(session),
        )
        .await
        .is_err());

        assert!(create_code(
            State(pool.clone()),
            Extension(AuthUser(host)),
            Extension(code_budget()),
            Path(session),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn only_invite_link_sessions_can_mint_a_code() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let vault_session = seed_session(&pool, host, "vault").await;
        let direct_session = seed_session(&pool, host, "direct").await;

        for session in [vault_session, direct_session] {
            let err = create_code(
                State(pool.clone()),
                Extension(AuthUser(host)),
                Extension(code_budget()),
                Path(session),
            )
            .await
            .unwrap_err();
            assert_eq!(err, StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn redeeming_returns_a_working_guest_secret() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;
        let (guest, _) = seed_host_and_session(&pool).await;

        let (_, Json(minted)) = create_code(
            State(pool.clone()),
            Extension(AuthUser(host)),
            Extension(code_budget()),
            Path(session),
        )
        .await
        .unwrap();

        let Json(redeemed) = redeem_code(
            State(pool.clone()),
            Extension(AuthUser(guest)),
            Extension(redeem_budget()),
            Json(RedeemRequest {
                code: minted.code.clone(),
            }),
        )
        .await
        .unwrap();

        assert_eq!(redeemed.session_id, session);
        assert!(
            crate::session_grants::resolve_join_grant(&pool, session, &redeemed.invite_token)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn one_code_admits_several_guests_until_it_expires() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;
        let (first, _) = seed_host_and_session(&pool).await;
        let (second, _) = seed_host_and_session(&pool).await;

        let (_, Json(minted)) = create_code(
            State(pool.clone()),
            Extension(AuthUser(host)),
            Extension(code_budget()),
            Path(session),
        )
        .await
        .unwrap();

        for guest in [first, second] {
            assert!(redeem_code(
                State(pool.clone()),
                Extension(AuthUser(guest)),
                Extension(redeem_budget()),
                Json(RedeemRequest {
                    code: minted.code.clone()
                }),
            )
            .await
            .is_ok());
        }

        let guests: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM terminal_session_grants WHERE session_id = $1 AND kind = 'guest'",
        )
        .bind(session)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(guests, 2, "each redemption gets its own revocable grant");
    }

    #[tokio::test]
    async fn unknown_and_malformed_codes_are_indistinguishable() {
        let pool = test_pool_or_skip!();
        let (guest, _) = seed_host_and_session(&pool).await;

        for candidate in ["K7M2-P9QX-3B", "nonsense"] {
            let err = redeem_code(
                State(pool.clone()),
                Extension(AuthUser(guest)),
                Extension(redeem_budget()),
                Json(RedeemRequest {
                    code: candidate.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err, axum::http::StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn exhausted_budgets_return_too_many_requests() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;

        let exhausted_mint = SessionCodeRateLimiter(RateLimiter::new(0, Duration::from_secs(3600)));
        assert_eq!(
            create_code(
                State(pool.clone()),
                Extension(AuthUser(host)),
                Extension(exhausted_mint),
                Path(session)
            )
            .await
            .unwrap_err(),
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );

        let exhausted_redeem = RedeemRateLimiter(RateLimiter::new(0, Duration::from_secs(3600)));
        assert_eq!(
            redeem_code(
                State(pool.clone()),
                Extension(AuthUser(host)),
                Extension(exhausted_redeem),
                Json(RedeemRequest {
                    code: "K7M2-P9QX-3B".to_string()
                }),
            )
            .await
            .unwrap_err(),
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );
    }
}
