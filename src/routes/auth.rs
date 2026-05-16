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
use crate::email::send_verification_email;

// ─── Tier helper ─────────────────────────────────────────────────────────────

struct TierInfo {
    tier: String,
    trial_ends_at: Option<i64>,
    trial_used: bool,
    is_admin: bool,
    is_banned: bool,
    email_verified: bool,
}

async fn fetch_tier(pool: &PgPool, user_id: Uuid) -> Result<TierInfo, StatusCode> {
    let row = sqlx::query_as::<_, (String, Option<DateTime<Utc>>, bool, bool, bool, bool)>(
        "SELECT subscription_tier, trial_ends_at, trial_used, is_admin, is_banned, email_verified FROM users WHERE id = $1",
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
        email_verified: row.5,
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

    Ok(Json(ChallengeResponse { account_id: row.0 }))
}

// ─── Register ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub account_id: Uuid,
    pub auth_key: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub machine_fingerprint: Option<String>,
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

    // Check if this machine already used a trial
    let trial_blocked = if let Some(ref fp) = body.machine_fingerprint {
        sqlx::query_as::<_, (bool,)>(
            "SELECT EXISTS(SELECT 1 FROM trial_fingerprints WHERE fingerprint = $1)",
        )
        .bind(fp)
        .fetch_one(&pool)
        .await
        .map(|r| r.0)
        .unwrap_or(false)
    } else {
        false
    };

    let (initial_tier, trial_ends_at) = if trial_blocked {
        warn!(fingerprint = ?body.machine_fingerprint, "Trial blocked: machine fingerprint already used");
        ("free", None)
    } else {
        ("pro", Some(Utc::now() + Duration::days(14)))
    };

    let row = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO users (email, account_id, auth_hash, public_key, subscription_tier, trial_ends_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&body.email)
    .bind(body.account_id)
    .bind(&auth_hash)
    .bind(body.public_key.as_deref())
    .bind(initial_tier)
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

    // Record fingerprint so future accounts from this machine don't get a trial
    if !trial_blocked {
        if let Some(ref fp) = body.machine_fingerprint {
            if let Err(e) = sqlx::query(
                "INSERT INTO trial_fingerprints (fingerprint) VALUES ($1) ON CONFLICT DO NOTHING",
            )
            .bind(fp)
            .execute(&pool)
            .await
            {
                error!(error = %e, "Failed to record trial fingerprint");
            }
        }
    }

    let user_id = row.0;
    let email_verified = if std::env::var("RESEND_API_KEY")
        .unwrap_or_default()
        .is_empty()
    {
        sqlx::query(
            "UPDATE users SET email_verified = TRUE, email_verified_at = now() WHERE id = $1",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Failed to auto-verify user email");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        true
    } else {
        let token: String = sqlx::query_scalar(
            "INSERT INTO email_verification_tokens (user_id) VALUES ($1) RETURNING token",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Failed to create email verification token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let app_url = std::env::var("VOLTIUS_APP_URL")
            .unwrap_or_else(|_| "https://app.voltius.app".to_string());
        if let Err(e) = send_verification_email(&body.email, &token, &app_url).await {
            error!(error = %e, user_id = %user_id, "Failed to send verification email");
        }
        false
    };

    // Auto-accept any pending invitations for this email
    let pending = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT team_id, role FROM pending_invitations
         WHERE email = $1 AND accepted_at IS NULL AND expires_at > now()",
    )
    .bind(&body.email)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    for (team_id, role) in &pending {
        let _ = sqlx::query(
            "INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(team_id)
        .bind(user_id)
        .bind(role)
        .execute(&pool)
        .await;
    }
    if !pending.is_empty() {
        let _ = sqlx::query(
            "UPDATE pending_invitations SET accepted_at = now()
             WHERE email = $1 AND accepted_at IS NULL AND expires_at > now()",
        )
        .bind(&body.email)
        .execute(&pool)
        .await;
        info!(user_id = %user_id, count = pending.len(), "Auto-accepted pending invitations on registration");
    }

    let trial_ends_ts = trial_ends_at.map(|t| t.timestamp());
    let jwt_token = create_access_token(
        user_id,
        initial_tier,
        trial_ends_ts,
        false,
        false,
        false,
        email_verified,
    )
    .map_err(|err| {
        error!(error = %err, user_id = %user_id, "Failed to create access token during registration");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let refresh_token = create_refresh_token(user_id).map_err(|err| {
        error!(error = %err, user_id = %user_id, "Failed to create refresh token during registration");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if trial_blocked {
        info!(user_id = %user_id, account_id = %body.account_id, "User registered on free tier (trial already used)");
    } else {
        info!(user_id = %user_id, account_id = %body.account_id, "User registered with 14-day trial");
    }

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user_id,
            jwt_token,
            refresh_token,
            tier: initial_tier.to_string(),
            trial_ends_at: trial_ends_ts,
        }),
    ))
}

// ─── Login ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub account_id: Uuid,
    pub auth_key: String,
}

pub async fn login(
    State(pool): State<PgPool>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let user = sqlx::query_as::<_, (Uuid, String, bool)>(
        "SELECT id, auth_hash, is_banned FROM users WHERE account_id = $1",
    )
    .bind(body.account_id)
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
    let jwt_token = create_access_token(
        user_id,
        &tier.tier,
        tier.trial_ends_at,
        tier.trial_used,
        tier.is_admin,
        tier.is_banned,
        tier.email_verified,
    )
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
    let jwt_token = create_access_token(
        claims.sub,
        &tier.tier,
        tier.trial_ends_at,
        tier.trial_used,
        tier.is_admin,
        tier.is_banned,
        tier.email_verified,
    )
    .map_err(|err| {
        error!(error = %err, user_id = %claims.sub, "Failed to create access token during refresh");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(user_id = %claims.sub, tier = %tier.tier, "Access token refreshed");

    Ok(Json(RefreshResponse { jwt_token }))
}

// ─── Email verification ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyEmailResponse {
    pub email: String,
}

pub async fn verify_email(
    State(pool): State<PgPool>,
    Json(body): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>, StatusCode> {
    let email = sqlx::query_scalar::<_, String>(
        "WITH consumed AS (
           UPDATE email_verification_tokens
           SET consumed_at = now()
           WHERE token = $1 AND consumed_at IS NULL AND expires_at > now()
           RETURNING user_id
         )
         UPDATE users
         SET email_verified = TRUE, email_verified_at = COALESCE(email_verified_at, now())
         FROM consumed
         WHERE users.id = consumed.user_id
         RETURNING users.email",
    )
    .bind(&body.token)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to verify email token");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some(email) = email {
        info!(email = %email, "User email verified");
        return Ok(Json(VerifyEmailResponse { email }));
    }

    let token_status = sqlx::query_as::<_, (DateTime<Utc>, Option<DateTime<Utc>>)>(
        "SELECT expires_at, consumed_at FROM email_verification_tokens WHERE token = $1",
    )
    .bind(&body.token)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch rejected email verification token status");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match token_status {
        Some((expires_at, None)) if expires_at <= Utc::now() => Err(StatusCode::GONE),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

pub async fn resend_verification_email(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<StatusCode, StatusCode> {
    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin verification resend transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let row = sqlx::query_as::<_, (String, bool)>(
        "SELECT email, email_verified FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(auth.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to lock user for verification resend");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if row.1 {
        tx.commit().await.map_err(|e| {
            error!(error = %e, "Failed to commit verified email resend no-op");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        return Ok(StatusCode::OK);
    }

    let token: String = sqlx::query_scalar(
        "INSERT INTO email_verification_tokens (user_id) VALUES ($1) RETURNING token",
    )
    .bind(auth.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to create email verification token");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "UPDATE email_verification_tokens SET consumed_at = now()
         WHERE user_id = $1 AND consumed_at IS NULL AND token <> $2",
    )
    .bind(auth.0)
    .bind(&token)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to consume prior email verification tokens");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit verification resend transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let app_url =
        std::env::var("VOLTIUS_APP_URL").unwrap_or_else(|_| "https://app.voltius.app".to_string());
    if let Err(e) = send_verification_email(&row.0, &token, &app_url).await {
        error!(error = %e, user_id = %auth.0, "Failed to resend verification email");
    }

    Ok(StatusCode::OK)
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
