use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::handles::{validate_custom_handle, HandleError};
use crate::routes::email_not_verified_response;

const RENAME_COOLDOWN_DAYS: i64 = 30;

#[derive(Deserialize)]
pub struct ClaimHandleRequest {
    pub handle: String,
}

/// The whole claim, factored out of the axum handler so the tests can drive it
/// without building a router.
pub(crate) async fn claim_handle_inner(
    pool: &PgPool,
    user_id: Uuid,
    requested: &str,
) -> Result<(), StatusCode> {
    let handle = validate_custom_handle(requested).map_err(|e| match e {
        HandleError::Reserved
        | HandleError::Charset
        | HandleError::EdgeSeparator
        | HandleError::TooShort
        | HandleError::TooLong => StatusCode::UNPROCESSABLE_ENTITY,
    })?;

    let (current, is_custom, updated_at, email_verified): (
        String,
        bool,
        Option<DateTime<Utc>>,
        bool,
    ) = sqlx::query_as(
        "SELECT handle, handle_is_custom, handle_updated_at, email_verified FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to read user before handle claim");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // A verified email, not a tier. Claiming is free (G1): every hosted
    // registration gets a 14-day Pro trial, so a tier gate here made anyone who
    // claimed in their first fortnight permanently custom-handled anyway. A
    // claim is permanent and `retired_handles` never recycles, so the only
    // brake left on mass claiming is that each handle costs one working inbox.
    //
    // The ONLY 403 this function returns — `claim_handle` maps it to the
    // EMAIL_NOT_VERIFIED body on that assumption.
    if !email_verified {
        return Err(StatusCode::FORBIDDEN);
    }
    if handle == current {
        return Ok(());
    }
    if is_custom {
        if let Some(last) = updated_at {
            if Utc::now() - last < Duration::days(RENAME_COOLDOWN_DAYS) {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to open handle claim transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let retired: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM retired_handles WHERE handle = $1)")
            .bind(&handle)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if retired {
        return Err(StatusCode::CONFLICT);
    }

    sqlx::query(
        "INSERT INTO retired_handles (handle, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&current)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let update = sqlx::query(
        "UPDATE users SET handle = $1, handle_is_custom = TRUE, handle_updated_at = now() WHERE id = $2",
    )
    .bind(&handle)
    .bind(user_id)
    .execute(&mut *tx)
    .await;

    match update {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(StatusCode::CONFLICT)
        }
        Err(e) => {
            error!(error = %e, "Failed to claim handle");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit handle claim");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(())
}

pub async fn claim_handle(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<ClaimHandleRequest>,
) -> Result<StatusCode, Response> {
    claim_handle_inner(&pool, auth.0, &body.handle)
        .await
        .map_err(|status| match status {
            // Distinct from every other refusal so a client can say "verify
            // your email first" instead of "invalid handle".
            StatusCode::FORBIDDEN => email_not_verified_response(),
            other => other.into_response(),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PreferencesRequest {
    pub allow_stranger_invites: bool,
}

/// Deliberately its own endpoint rather than part of the handle claim: it is
/// available to every tier, free included, and must never be tier-gated.
pub async fn update_preferences(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<PreferencesRequest>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE users SET allow_stranger_invites = $1 WHERE id = $2")
        .bind(body.allow_stranger_invites)
        .bind(auth.0)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to update invite preferences");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserKeyResponse {
    pub user_id: Uuid,
    /// ALIAS for pre-0.26 clients. Value is the handle. Delete in 0.27.
    pub display_name: String,
    pub handle: String,
    pub public_key: String,
}

/// One user's current X25519 key, read at wrap time. Deliberately a lookup by a
/// known id rather than a field on search: search is callable by anyone who
/// types two characters, and #66's live run proved that wrapping to a key from
/// any other source than a fresh read fails with `aead::Error`.
pub(crate) async fn user_public_key_inner(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<UserKeyResponse, StatusCode> {
    sqlx::query_as::<_, UserKeyResponse>(
        "SELECT id AS user_id, handle AS display_name, handle, public_key
           FROM users WHERE id = $1 AND deleted_at IS NULL AND public_key IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to read user public key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)
}

pub async fn get_user_public_key(
    State(pool): State<PgPool>,
    Extension(_auth): Extension<AuthUser>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserKeyResponse>, StatusCode> {
    Ok(Json(user_public_key_inner(&pool, user_id).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::unique_handle;
    use uuid::Uuid;

    /// Seeds on the free tier: claiming no longer reads the tier at all, so
    /// `free` is the case every test here wants. `email_verified` is the axis
    /// that now matters and is the only parameter.
    async fn user(pool: &sqlx::PgPool, email_verified: bool) -> Uuid {
        // `generate_unique_handle`, like every other seeding path: the test
        // database is persistent and accumulates users, so an unchecked
        // `generate_handle` eventually collides on the unique index.
        let handle = crate::handles::generate_unique_handle(pool)
            .await
            .expect("generate handle");
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO users (email, account_id, auth_hash, subscription_tier, handle, email_verified)
             VALUES ($1, gen_random_uuid(), 'h', 'free', $2, $3) RETURNING id",
        )
        .bind(format!("{}@example.test", Uuid::new_v4()))
        .bind(&handle)
        .bind(email_verified)
        .fetch_one(pool)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn an_unverified_email_cannot_claim_a_custom_handle() {
        let pool = crate::test_pool_or_skip!();
        let id = user(&pool, false).await;
        let err = claim_handle_inner(&pool, id, &unique_handle("kevin-p"))
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_free_verified_user_can_claim_and_becomes_fuzzy_searchable() {
        let pool = crate::test_pool_or_skip!();
        let id = user(&pool, true).await;
        let searcher = user(&pool, true).await;
        let target = unique_handle("kevin-p");
        claim_handle_inner(&pool, id, &target).await.unwrap();

        // The whole point of G2: no entitlement check anywhere in search, so a
        // free account that claims is discoverable on a handle substring.
        // A substring spanning `unique_handle`'s random suffix, so the LIMIT 8
        // cannot be crowded out by handles other tests left in the shared DB.
        let fragment: String = target.chars().skip(target.chars().count() - 10).collect();
        let found = crate::routes::teams::search_users_inner(&pool, searcher, &fragment)
            .await
            .unwrap();
        assert!(
            found.iter().any(|u| u.user_id == id),
            "a free user's custom handle must be fuzzy-searchable"
        );
    }

    #[tokio::test]
    async fn a_generated_handle_is_never_matched_by_a_substring() {
        let pool = crate::test_pool_or_skip!();
        // G3, asserted directly: generated handles stay exact-match only, or a
        // wordlist walk over `adjective-noun` enumerates the whole namespace.
        let id = user(&pool, true).await;
        let searcher = user(&pool, true).await;
        let generated: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let middle: String = generated.chars().skip(2).take(6).collect();

        let found = crate::routes::teams::search_users_inner(&pool, searcher, &middle)
            .await
            .unwrap();
        assert!(
            !found.iter().any(|u| u.user_id == id),
            "a generated handle must not be reachable by substring"
        );

        let exact = crate::routes::teams::search_users_inner(&pool, searcher, &generated)
            .await
            .unwrap();
        assert!(
            exact.iter().any(|u| u.user_id == id),
            "the exact generated handle must still resolve"
        );
    }

    #[tokio::test]
    async fn claim_sets_custom_and_retires_the_previous_handle() {
        let pool = crate::test_pool_or_skip!();
        let id = user(&pool, true).await;
        let before: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();

        let target = unique_handle("kevin-p");
        claim_handle_inner(&pool, id, &format!("@{}", target.to_uppercase()))
            .await
            .unwrap();

        let (handle, custom): (String, bool) =
            sqlx::query_as("SELECT handle, handle_is_custom FROM users WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(handle, target);
        assert!(custom);

        let retired: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM retired_handles WHERE handle = $1)")
                .bind(&before)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            retired,
            "the previous handle must be retired, never recycled"
        );
    }

    #[tokio::test]
    async fn a_retired_handle_can_never_be_claimed_again() {
        let pool = crate::test_pool_or_skip!();
        let first = user(&pool, true).await;
        let target = unique_handle("kevin-p");
        let next = unique_handle("kevin-q");
        claim_handle_inner(&pool, first, &target).await.unwrap();
        // Outside the rename cooldown, or the second claim below is refused
        // with 429 before it ever gets a chance to retire `target`.
        sqlx::query(
            "UPDATE users SET handle_updated_at = now() - interval '31 days' WHERE id = $1",
        )
        .bind(first)
        .execute(&pool)
        .await
        .unwrap();
        claim_handle_inner(&pool, first, &next).await.unwrap();

        let second = user(&pool, true).await;
        let err = claim_handle_inner(&pool, second, &target)
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn renaming_twice_inside_thirty_days_is_refused() {
        let pool = crate::test_pool_or_skip!();
        let id = user(&pool, true).await;
        claim_handle_inner(&pool, id, &unique_handle("kevin-a"))
            .await
            .unwrap();
        let err = claim_handle_inner(&pool, id, &unique_handle("kevin-b"))
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn an_expired_trial_can_still_claim() {
        let pool = crate::test_pool_or_skip!();
        // The finding that killed the tier gate, kept as a regression: a lapsed
        // trial is `free` on the effective tier, and claiming must not care.
        let id = user(&pool, true).await;
        sqlx::query("UPDATE users SET trial_ends_at = now() - interval '1 day' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        let target = unique_handle("kevin-p");
        claim_handle_inner(&pool, id, &target).await.unwrap();
        let handle: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(handle, target);
    }

    #[tokio::test]
    async fn reserved_names_are_refused() {
        let pool = crate::test_pool_or_skip!();
        let id = user(&pool, true).await;
        let err = claim_handle_inner(&pool, id, "voltius-support")
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn public_key_lookup_returns_identity_and_key_or_404() {
        let pool = crate::test_pool_or_skip!();
        let me = user(&pool, true).await;
        let them = user(&pool, true).await;
        sqlx::query("UPDATE users SET public_key = 'pk-them' WHERE id = $1")
            .bind(them)
            .execute(&pool)
            .await
            .unwrap();

        let found = user_public_key_inner(&pool, them).await.unwrap();
        assert_eq!(found.public_key, "pk-them");
        assert!(!found.handle.is_empty());

        sqlx::query("UPDATE users SET deleted_at = now() WHERE id = $1")
            .bind(them)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            user_public_key_inner(&pool, them).await.unwrap_err(),
            StatusCode::NOT_FOUND
        );

        let _ = me;
    }
}
