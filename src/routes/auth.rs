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
use crate::self_host;

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
    let row = sqlx::query_as::<_, (String, Option<DateTime<Utc>>, bool, bool, bool, bool, bool, Option<String>, Option<DateTime<Utc>>)>(
        "SELECT subscription_tier, trial_ends_at, trial_used, is_admin, is_banned, email_verified, admin_override, ls_subscription_id, deleted_at FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to fetch tier info");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (stored_tier, trial_ends_at, trial_used, is_admin, is_banned, email_verified, admin_override, ls_subscription_id, deleted_at) =
        row;

    // Soft-deleted accounts are locked: no session may be issued or renewed from one.
    // Gating here covers every token-issuing path (login, refresh, password change) at once.
    if deleted_at.is_some() {
        warn!(user_id = %user_id, "Rejected request for soft-deleted account");
        return Err(StatusCode::FORBIDDEN);
    }

    let effective = crate::entitlement::effective_tier(
        &stored_tier,
        trial_ends_at,
        ls_subscription_id.is_some(),
        admin_override,
        Utc::now(),
    );
    // An expired trial has been consumed and no longer has a live countdown.
    let downgraded = effective != stored_tier;

    Ok(TierInfo {
        tier: effective.to_string(),
        trial_ends_at: if downgraded { None } else { trial_ends_at.map(|t| t.timestamp()) },
        trial_used: trial_used || downgraded,
        is_admin,
        is_banned,
        email_verified,
    })
}

/// True when a write lost the race for an address already on file — either the
/// plain unique key or the lower-case index added with the normalization migration.
fn is_email_taken(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => matches!(
            db_err.constraint(),
            Some("users_email_key") | Some("users_email_lower_key")
        ),
        _ => false,
    }
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
    let row = sqlx::query_as::<_, (Uuid,)>(
        "SELECT account_id FROM users WHERE email = $1 AND deleted_at IS NULL",
    )
    .bind(crate::email::normalize(&query.email))
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
    pub wrapped_user_secrets: Option<String>,
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
    pub wrapped_user_secrets: Option<String>,
}

pub async fn register(
    State(pool): State<PgPool>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), StatusCode> {
    let email = crate::email::normalize(&body.email);

    let auth_hash = hash_auth_key(&body.auth_key).map_err(|err| {
        error!(error = %err, "Failed to hash auth key during registration");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let self_hosted = self_host::is_self_hosted();

    // Check if this machine already used a trial (skipped in self-hosted mode)
    let trial_blocked = if self_hosted {
        false
    } else if let Some(ref fp) = body.machine_fingerprint {
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

    // Self-hosted: everyone gets business tier with no trial countdown.
    let (initial_tier, trial_ends_at) = if self_hosted {
        ("business", None)
    } else if trial_blocked {
        warn!(fingerprint = ?body.machine_fingerprint, "Trial blocked: machine fingerprint already used");
        ("free", None)
    } else {
        ("pro", Some(Utc::now() + Duration::days(14)))
    };

    let handle = crate::handles::generate_unique_handle(&pool).await;

    let row = sqlx::query_as::<_, (Uuid,)>(
        "INSERT INTO users (email, display_name, account_id, auth_hash, public_key, wrapped_user_secrets, subscription_tier, trial_ends_at, handle)
         VALUES ($1, split_part($1, '@', 1), $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(&email)
    .bind(body.account_id)
    .bind(&auth_hash)
    .bind(body.public_key.as_deref())
    .bind(body.wrapped_user_secrets.as_deref())
    .bind(initial_tier)
    .bind(trial_ends_at)
    .bind(&handle)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        if is_email_taken(&e) {
            warn!("Registration conflict for existing account");
            return StatusCode::CONFLICT;
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
        if let Err(e) = send_verification_email(&email, &token, &app_url).await {
            error!(error = %e, user_id = %user_id, "Failed to send verification email");
        }
        false
    };

    // Auto-accept any pending invitations for this email
    let pending = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT team_id, role FROM pending_invitations
         WHERE email = $1 AND accepted_at IS NULL AND expires_at > now()",
    )
    .bind(&email)
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
        .bind(&email)
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
            wrapped_user_secrets: body.wrapped_user_secrets,
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
    let user = sqlx::query_as::<_, (Uuid, String, bool, Option<String>)>(
        "SELECT id, auth_hash, is_banned, wrapped_user_secrets FROM users WHERE account_id = $1",
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

    let (user_id, auth_hash, is_banned, wrapped_user_secrets) = user;

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
        wrapped_user_secrets,
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

    // A refreshed session means the account is still live. Fire-and-forget.
    crate::last_seen::touch(&pool, claims.sub);

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

// ─── Me ─────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MeResponse {
    pub email: String,
    pub display_name: String,
    pub account_id: Uuid,
    pub tier: String,
    pub trial_ends_at: Option<i64>,
    pub email_verified: bool,
    pub wrapped_user_secrets: Option<String>,
}

pub async fn get_me(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<MeResponse>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, Uuid, Option<String>)>(
        "SELECT email, display_name, account_id, wrapped_user_secrets FROM users WHERE id = $1",
    )
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to fetch user in get_me");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let tier = fetch_tier(&pool, auth.0).await?;

    Ok(Json(MeResponse {
        email: row.0,
        display_name: row.1,
        account_id: row.2,
        tier: tier.tier,
        trial_ends_at: tier.trial_ends_at,
        email_verified: tier.email_verified,
        wrapped_user_secrets: row.3,
    }))
}

// ─── Update display name ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateDisplayNameRequest {
    pub display_name: String,
}

pub async fn update_display_name(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<UpdateDisplayNameRequest>,
) -> Result<StatusCode, StatusCode> {
    let display_name = body.display_name.trim().to_string();
    if display_name.is_empty() || display_name.len() > 50 {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
        .bind(&display_name)
        .bind(auth.0)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %auth.0, "Failed to update display name");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(user_id = %auth.0, display_name = %display_name, "Display name updated");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Update email ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateEmailRequest {
    pub new_email: String,
    pub auth_key: String,
}

pub async fn update_email(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<UpdateEmailRequest>,
) -> Result<StatusCode, StatusCode> {
    let auth_hash = sqlx::query_scalar::<_, String>("SELECT auth_hash FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %auth.0, "Failed to fetch auth_hash in update_email");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let valid = verify_auth_key(&body.auth_key, &auth_hash).map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to verify auth key in update_email");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_email = crate::email::normalize(&body.new_email);

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin update_email transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "UPDATE users SET email = $1, email_verified = FALSE, email_verified_at = NULL, updated_at = now() WHERE id = $2",
    )
    .bind(&new_email)
    .bind(auth.0)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if is_email_taken(&e) {
            return StatusCode::CONFLICT;
        }
        error!(error = %e, user_id = %auth.0, "Failed to update email");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let token: String = sqlx::query_scalar(
        "INSERT INTO email_verification_tokens (user_id) VALUES ($1) RETURNING token",
    )
    .bind(auth.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to create verification token for email update");
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
        error!(error = %e, user_id = %auth.0, "Failed to consume prior tokens in update_email");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit update_email transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let app_url =
        std::env::var("VOLTIUS_APP_URL").unwrap_or_else(|_| "https://app.voltius.app".to_string());
    if let Err(e) = send_verification_email(&new_email, &token, &app_url).await {
        error!(error = %e, user_id = %auth.0, "Failed to send verification email after email update");
    }

    info!(user_id = %auth.0, new_email = %new_email, "User email updated");

    Ok(StatusCode::NO_CONTENT)
}

// ─── Update password ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub old_auth_key: String,
    pub new_auth_key: String,
    pub new_wrapped_user_secrets: String,
}

pub async fn update_password(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<UpdatePasswordRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let auth_hash = sqlx::query_scalar::<_, String>("SELECT auth_hash FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %auth.0, "Failed to fetch auth_hash in update_password");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let valid = verify_auth_key(&body.old_auth_key, &auth_hash).map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to verify old auth key in update_password");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_auth_hash = hash_auth_key(&body.new_auth_key).map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to hash new auth key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "UPDATE users SET auth_hash = $1, wrapped_user_secrets = $2, updated_at = now() WHERE id = $3",
    )
    .bind(&new_auth_hash)
    .bind(&body.new_wrapped_user_secrets)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to update password");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let tier = fetch_tier(&pool, auth.0).await?;
    let jwt_token = create_access_token(
        auth.0,
        &tier.tier,
        tier.trial_ends_at,
        tier.trial_used,
        tier.is_admin,
        tier.is_banned,
        tier.email_verified,
    )
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to create access token after password update");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let refresh_token = create_refresh_token(auth.0).map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to create refresh token after password update");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(user_id = %auth.0, "User password updated");

    Ok(Json(AuthResponse {
        user_id: auth.0,
        jwt_token,
        refresh_token,
        tier: tier.tier,
        trial_ends_at: tier.trial_ends_at,
        wrapped_user_secrets: Some(body.new_wrapped_user_secrets),
    }))
}

// ─── Upload wrapped user secrets (migration) ──────────────────────────────────

#[derive(Deserialize)]
pub struct UploadWrappedSecretsRequest {
    pub wrapped_user_secrets: String,
}

pub async fn upload_wrapped_user_secrets(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<UploadWrappedSecretsRequest>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query(
        "UPDATE users SET wrapped_user_secrets = $1, updated_at = now() WHERE id = $2",
    )
    .bind(&body.wrapped_user_secrets)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to upload wrapped_user_secrets");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(user_id = %auth.0, "Uploaded wrapped_user_secrets (migration)");
    Ok(StatusCode::NO_CONTENT)
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

#[cfg(test)]
mod handler_tests {
    //! DB-backed characterization of the `register` / `login` handler bodies,
    //! focused on the effective tier baked into the issued session (response +
    //! decoded JWT claim). Registration tier depends on self-hosted mode; login
    //! reflects `entitlement::effective_tier` (the shipped expired-trial fix).
    //! Requires TEST_DATABASE_URL.
    use super::*;
    use crate::auth::jwt::validate_token;
    use crate::test_pool_or_skip;
    use crate::test_support::{
        env_lock, seed_user_with_credentials, set_user_tier, set_user_trial,
    };
    use axum::extract::State;

    /// Holds the env lock, pins JWT_SECRET so issued tokens decode, and toggles
    /// LEMONSQUEEZY_API_KEY (the self-hosted signal), restoring it on drop.
    /// Wrapping the guard in a struct field keeps clippy's `await_holding_lock`
    /// quiet while the lock is held across the handler's `.await` points.
    #[allow(dead_code)]
    struct EnvGuard {
        lock: std::sync::MutexGuard<'static, ()>,
        prev_ls: Option<String>,
    }
    impl EnvGuard {
        fn new(self_hosted: bool) -> Self {
            let lock = env_lock();
            std::env::set_var("JWT_SECRET", "ci-test-secret");
            let prev_ls = std::env::var("LEMONSQUEEZY_API_KEY").ok();
            if self_hosted {
                std::env::remove_var("LEMONSQUEEZY_API_KEY");
            } else {
                std::env::set_var("LEMONSQUEEZY_API_KEY", "test-key");
            }
            EnvGuard { lock, prev_ls }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev_ls {
                Some(v) => std::env::set_var("LEMONSQUEEZY_API_KEY", v),
                None => std::env::remove_var("LEMONSQUEEZY_API_KEY"),
            }
        }
    }

    fn register_req(email: &str, account_id: Uuid, fp: Option<&str>) -> RegisterRequest {
        RegisterRequest {
            email: email.to_string(),
            account_id,
            auth_key: "auth-key-secret".to_string(),
            public_key: None,
            wrapped_user_secrets: None,
            machine_fingerprint: fp.map(str::to_string),
        }
    }

    async fn stored_tier(pool: &PgPool, id: Uuid) -> (String, Option<DateTime<Utc>>) {
        sqlx::query_as::<_, (String, Option<DateTime<Utc>>)>(
            "SELECT subscription_tier, trial_ends_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("fetch stored tier")
    }

    // ── register ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn register_self_hosted_grants_business_no_trial() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let email = format!("{}@ex.test", Uuid::new_v4());

        let (status, Json(resp)) = register(State(pool.clone()), Json(register_req(&email, account_id, None)))
            .await
            .expect("register ok");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(resp.tier, "business");
        assert_eq!(resp.trial_ends_at, None);

        let (db_tier, db_trial) = stored_tier(&pool, resp.user_id).await;
        assert_eq!(db_tier, "business");
        assert_eq!(db_trial, None);

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "business");
        assert_eq!(claims.trial_ends_at, None);
    }

    #[tokio::test]
    async fn register_saas_grants_pro_with_trial() {
        let _env = EnvGuard::new(false);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let email = format!("{}@ex.test", Uuid::new_v4());
        let before = Utc::now().timestamp();

        let (status, Json(resp)) = register(State(pool.clone()), Json(register_req(&email, account_id, None)))
            .await
            .expect("register ok");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(resp.tier, "pro");
        let ends = resp.trial_ends_at.expect("trial should be set");
        // ~14 days out, allowing generous slack.
        assert!(ends > before + 13 * 86_400, "trial ends too soon: {ends}");
        assert!(ends < before + 15 * 86_400, "trial ends too late: {ends}");

        let (db_tier, db_trial) = stored_tier(&pool, resp.user_id).await;
        assert_eq!(db_tier, "pro");
        assert!(db_trial.is_some());

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "pro");
        assert_eq!(claims.trial_ends_at, Some(ends));
    }

    #[tokio::test]
    async fn register_saas_trial_blocked_grants_free() {
        let _env = EnvGuard::new(false);
        let pool = test_pool_or_skip!();
        let fp = format!("fp-{}", Uuid::new_v4());
        sqlx::query("INSERT INTO trial_fingerprints (fingerprint) VALUES ($1)")
            .bind(&fp)
            .execute(&pool)
            .await
            .expect("seed fingerprint");
        let account_id = Uuid::new_v4();
        let email = format!("{}@ex.test", Uuid::new_v4());

        let (status, Json(resp)) =
            register(State(pool.clone()), Json(register_req(&email, account_id, Some(&fp))))
                .await
                .expect("register ok");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(resp.tier, "free");
        assert_eq!(resp.trial_ends_at, None);

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "free");
    }

    #[tokio::test]
    async fn register_duplicate_email_conflicts() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let email = format!("{}@ex.test", Uuid::new_v4());

        let (status, _) = register(
            State(pool.clone()),
            Json(register_req(&email, Uuid::new_v4(), None)),
        )
        .await
        .expect("first register ok");
        assert_eq!(status, StatusCode::CREATED);

        match register(
            State(pool.clone()),
            Json(register_req(&email, Uuid::new_v4(), None)),
        )
        .await
        {
            Err(s) => assert_eq!(s, StatusCode::CONFLICT),
            Ok(_) => panic!("expected CONFLICT on duplicate email"),
        }
    }

    // ── login: effective tier in the issued session ───────────────────────────

    async fn login_of(pool: &PgPool, account_id: Uuid) -> Result<AuthResponse, StatusCode> {
        login(
            State(pool.clone()),
            Json(LoginRequest {
                account_id,
                auth_key: "auth-key-secret".to_string(),
            }),
        )
        .await
        .map(|Json(r)| r)
    }

    #[tokio::test]
    async fn login_active_trial_pro_issues_pro() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;
        set_user_tier(&pool, uid, "pro").await;
        set_user_trial(&pool, uid, 30).await;

        let resp = login_of(&pool, account_id).await.expect("login ok");
        assert_eq!(resp.tier, "pro");
        assert!(resp.trial_ends_at.is_some());

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "pro");
        assert!(claims.trial_ends_at.is_some());
    }

    #[tokio::test]
    async fn login_expired_trial_pro_downgrades_to_free() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;
        set_user_tier(&pool, uid, "pro").await;
        set_user_trial(&pool, uid, -1).await; // trial already ended

        let resp = login_of(&pool, account_id).await.expect("login ok");
        // Session reflects EFFECTIVE tier, not the stored "pro".
        assert_eq!(resp.tier, "free");
        assert_eq!(resp.trial_ends_at, None);

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "free");
        assert_eq!(claims.trial_ends_at, None);
        assert!(claims.trial_used, "expired trial should be marked consumed");

        // The stored tier is untouched — only the issued session is downgraded.
        let (db_tier, _) = stored_tier(&pool, uid).await;
        assert_eq!(db_tier, "pro");
    }

    #[tokio::test]
    async fn login_expired_business_trial_downgrades_to_free() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;
        set_user_tier(&pool, uid, "business").await;
        set_user_trial(&pool, uid, -1).await;

        let resp = login_of(&pool, account_id).await.expect("login ok");
        assert_eq!(resp.tier, "free");

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "free");
    }

    #[tokio::test]
    async fn login_paid_pro_survives_stale_trial() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;
        set_user_tier(&pool, uid, "pro").await;
        set_user_trial(&pool, uid, -30).await; // stale trial timestamp
        sqlx::query("UPDATE users SET ls_subscription_id = 'sub_paid' WHERE id = $1")
            .bind(uid)
            .execute(&pool)
            .await
            .expect("set paid sub");

        let resp = login_of(&pool, account_id).await.expect("login ok");
        // Paid subscription keeps the tier despite the past trial timestamp.
        assert_eq!(resp.tier, "pro");

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "pro");
    }

    #[tokio::test]
    async fn login_admin_override_survives_expired_trial() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;
        set_user_tier(&pool, uid, "pro").await;
        set_user_trial(&pool, uid, -30).await;
        sqlx::query("UPDATE users SET admin_override = TRUE WHERE id = $1")
            .bind(uid)
            .execute(&pool)
            .await
            .expect("set admin override");

        let resp = login_of(&pool, account_id).await.expect("login ok");
        assert_eq!(resp.tier, "pro");

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "pro");
    }

    // ── login: auth gates ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn login_banned_user_forbidden() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;
        sqlx::query("UPDATE users SET is_banned = TRUE WHERE id = $1")
            .bind(uid)
            .execute(&pool)
            .await
            .expect("ban user");

        match login_of(&pool, account_id).await {
            Err(s) => assert_eq!(s, StatusCode::FORBIDDEN),
            Ok(_) => panic!("expected FORBIDDEN for banned user"),
        }
    }

    #[tokio::test]
    async fn login_wrong_auth_key_unauthorized() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;

        let res = login(
            State(pool.clone()),
            Json(LoginRequest {
                account_id,
                auth_key: "wrong-key".to_string(),
            }),
        )
        .await;

        match res {
            Err(s) => assert_eq!(s, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("expected UNAUTHORIZED for wrong auth key"),
        }
    }

    #[tokio::test]
    async fn login_unknown_account_unauthorized() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();

        match login_of(&pool, Uuid::new_v4()).await {
            Err(s) => assert_eq!(s, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("expected UNAUTHORIZED for unknown account"),
        }
    }

    // ── email case: storage is canonical, lookup is case-insensitive ─────────

    #[tokio::test]
    async fn register_stores_email_lowercased() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let typed = format!("  MiXeD.{}@Ex.Test  ", Uuid::new_v4());

        let (_, Json(resp)) = register(
            State(pool.clone()),
            Json(register_req(&typed, Uuid::new_v4(), None)),
        )
        .await
        .expect("register ok");

        let stored: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(resp.user_id)
            .fetch_one(&pool)
            .await
            .expect("fetch stored email");
        assert_eq!(stored, typed.trim().to_lowercase());
    }

    #[tokio::test]
    async fn challenge_resolves_email_regardless_of_case() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let email = format!("case.{}@ex.test", Uuid::new_v4());
        let _ = register(
            State(pool.clone()),
            Json(register_req(&email, account_id, None)),
        )
        .await
        .expect("register ok");

        let Json(resp) = challenge(
            State(pool.clone()),
            axum::extract::Query(ChallengeQuery {
                email: email.to_uppercase(),
            }),
        )
        .await
        .expect("challenge should match an upper-cased address");

        assert_eq!(resp.account_id, account_id);
    }

    #[tokio::test]
    async fn register_conflicts_on_email_differing_only_in_case() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let email = format!("dup.{}@ex.test", Uuid::new_v4());

        let _ = register(
            State(pool.clone()),
            Json(register_req(&email, Uuid::new_v4(), None)),
        )
        .await
        .expect("first register ok");

        match register(
            State(pool.clone()),
            Json(register_req(&email.to_uppercase(), Uuid::new_v4(), None)),
        )
        .await
        {
            Err(s) => assert_eq!(s, StatusCode::CONFLICT),
            Ok(_) => panic!("expected CONFLICT for the same mailbox in a different case"),
        }
    }

    // ── soft delete: a deleted account is locked out of every auth path ───────

    async fn soft_delete(pool: &PgPool, user_id: Uuid) {
        sqlx::query("UPDATE users SET deleted_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("soft-delete user");
    }

    #[tokio::test]
    async fn login_soft_deleted_user_forbidden() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;
        soft_delete(&pool, uid).await;

        match login_of(&pool, account_id).await {
            Err(s) => assert_eq!(s, StatusCode::FORBIDDEN),
            Ok(_) => panic!("expected FORBIDDEN for soft-deleted user"),
        }
    }

    #[tokio::test]
    async fn refresh_soft_deleted_user_forbidden() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(&pool, account_id, "auth-key-secret").await;

        // Take a refresh token while the account is live, then delete underneath it.
        let session = login_of(&pool, account_id).await.expect("login ok");
        soft_delete(&pool, uid).await;

        let res = refresh(
            State(pool.clone()),
            Json(RefreshRequest {
                refresh_token: session.refresh_token,
            }),
        )
        .await;

        match res {
            Err(s) => assert_eq!(s, StatusCode::FORBIDDEN),
            Ok(_) => panic!("expected FORBIDDEN when refreshing a soft-deleted account"),
        }
    }

    #[tokio::test]
    async fn challenge_soft_deleted_user_not_found() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let uid = seed_user_with_credentials(&pool, Uuid::new_v4(), "auth-key-secret").await;
        let email = format!("{uid}@test.local");

        let live = challenge(
            State(pool.clone()),
            axum::extract::Query(ChallengeQuery {
                email: email.clone(),
            }),
        )
        .await;
        assert!(live.is_ok(), "challenge should resolve a live account");

        soft_delete(&pool, uid).await;

        let res = challenge(
            State(pool.clone()),
            axum::extract::Query(ChallengeQuery { email }),
        )
        .await;

        match res {
            Err(s) => assert_eq!(s, StatusCode::NOT_FOUND),
            Ok(_) => panic!("expected NOT_FOUND for soft-deleted account"),
        }
    }
}
