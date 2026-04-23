use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::{
    jwt::{create_access_token, create_refresh_token, validate_token},
    password::{hash_auth_key, verify_auth_key},
    AuthUser,
};

// ─── Tier helper ─────────────────────────────────────────────────────────────

struct TierInfo {
    tier: String,
    trial_ends_at: Option<i64>,
    trial_used: bool,
    is_admin: bool,
    is_banned: bool,
}

async fn fetch_tier(pool: &PgPool, user_id: Uuid) -> Result<TierInfo, StatusCode> {
    let row = sqlx::query_as::<_, (String, Option<DateTime<Utc>>, bool, bool, bool)>(
        "SELECT subscription_tier, trial_ends_at, trial_used, is_admin, is_banned FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to fetch tier info");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(TierInfo {
        tier: row.0,
        trial_ends_at: row.1.map(|t| t.timestamp()),
        trial_used: row.2,
        is_admin: row.3,
        is_banned: row.4,
    })
}

// ─── Challenge ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ChallengeQuery {
    pub email: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub account_id: Uuid,
}

pub async fn challenge(
    State(pool): State<PgPool>,
    axum::extract::Query(query): axum::extract::Query<ChallengeQuery>,
) -> Result<Json<ChallengeResponse>, StatusCode> {
    let row = sqlx::query_as::<_, (Uuid,)>("SELECT account_id FROM users WHERE email = $1")
        .bind(&query.email)
        .fetch_optional(&pool)
        .await
        .map_err(|err| {
            error!(error = %err, "Failed to fetch challenge account");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            warn!("Challenge requested for unknown account");
            StatusCode::NOT_FOUND
        })?;

    Ok(Json(ChallengeResponse {
        account_id: row.0,
    }))
}

// ─── Register ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub account_id: Uuid,
    pub auth_key: String,
    #[serde(default)]
    pub public_key: Option<String>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub jwt_token: String,
    pub refresh_token: String,
    pub tier: String,
    pub trial_ends_at: Option<i64>,
}

pub async fn register(
    State(pool): State<PgPool>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), StatusCode> {
    let auth_hash = hash_auth_key(&body.auth_key).map_err(|err| {
        error!(error = %err, "Failed to hash auth key during registration");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let trial_ends_at = Utc::now() + Duration::days(14);

    let row = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO users (email, account_id, auth_hash, public_key, subscription_tier, trial_ends_at)
         VALUES ($1, $2, $3, $4, 'pro', $5) RETURNING id",
    )
    .bind(&body.email)
    .bind(body.account_id)
    .bind(&auth_hash)
    .bind(body.public_key.as_deref())
    .bind(trial_ends_at)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.constraint() == Some("users_email_key") {
                warn!("Registration conflict for existing account");
                return StatusCode::CONFLICT;
            }
        }
        error!(error = %e, "Failed to register user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user_id = row.0;
    let jwt_token = create_access_token(
        user_id,
        "pro",
        Some(trial_ends_at.timestamp()),
        false,
        false,
        false,
    )
    .map_err(|err| {
        error!(error = %err, user_id = %user_id, "Failed to create access token during registration");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let refresh_token = create_refresh_token(user_id).map_err(|err| {
        error!(error = %err, user_id = %user_id, "Failed to create refresh token during registration");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(user_id = %user_id, account_id = %body.account_id, "User registered with 14-day trial");

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user_id,
            jwt_token,
            refresh_token,
            tier: "pro".to_string(),
            trial_ends_at: Some(trial_ends_at.timestamp()),
        }),
    ))
}

// ─── Login ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: String,
}

pub async fn login(
    State(pool): State<PgPool>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let user = sqlx::query_as::<_, (Uuid, String, bool)>("SELECT id, auth_hash, is_banned FROM users WHERE email = $1")
        .bind(&body.email)
        .fetch_optional(&pool)
        .await
        .map_err(|err| {
            error!(error = %err, "Failed to query user during login");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            warn!("Login failed: unknown user");
            StatusCode::UNAUTHORIZED
        })?;

    let (user_id, auth_hash, is_banned) = user;

    if is_banned {
        warn!(user_id = %user_id, "Login attempt by banned user");
        return Err(StatusCode::FORBIDDEN);
    }

    let valid = verify_auth_key(&body.auth_key, &auth_hash).map_err(|err| {
        error!(error = %err, user_id = %user_id, "Failed to verify auth key during login");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !valid {
        warn!(user_id = %user_id, "Login failed: invalid credentials");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tier = fetch_tier(&pool, user_id).await?;
    let jwt_token = create_access_token(user_id, &tier.tier, tier.trial_ends_at, tier.trial_used, tier.is_admin, tier.is_banned)
        .map_err(|err| {
            error!(error = %err, user_id = %user_id, "Failed to create access token during login");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let refresh_token = create_refresh_token(user_id).map_err(|err| {
        error!(error = %err, user_id = %user_id, "Failed to create refresh token during login");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(user_id = %user_id, tier = %tier.tier, "User logged in");

    Ok(Json(AuthResponse {
        user_id,
        jwt_token,
        refresh_token,
        tier: tier.tier,
        trial_ends_at: tier.trial_ends_at,
    }))
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub jwt_token: String,
}

pub async fn refresh(
    State(pool): State<PgPool>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, StatusCode> {
    let claims = validate_token(&body.refresh_token, "refresh").map_err(|_| {
        warn!("Refresh failed: invalid refresh token");
        StatusCode::UNAUTHORIZED
    })?;

    let tier = fetch_tier(&pool, claims.sub).await?;
    let jwt_token = create_access_token(claims.sub, &tier.tier, tier.trial_ends_at, tier.trial_used, tier.is_admin, tier.is_banned)
        .map_err(|err| {
            error!(error = %err, user_id = %claims.sub, "Failed to create access token during refresh");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(user_id = %claims.sub, tier = %tier.tier, "Access token refreshed");

    Ok(Json(RefreshResponse { jwt_token }))
}

// ─── Delete account ──────────────────────────────────────────────────────────

pub async fn delete_account(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(auth.0)
        .execute(&pool)
        .await
        .map_err(|err| {
            error!(error = %err, user_id = %auth.0, "Failed to delete account");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(user_id = %auth.0, "Account deleted");

    Ok(StatusCode::NO_CONTENT)
}
