use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::{
    jwt::{
        create_access_token, create_pending_token, create_refresh_token, validate_token, PlanClaims,
        SeatTeamClaim, PENDING_SECOND_FACTOR,
    },
    password::{hash_auth_key, verify_auth_key},
    AuthUser,
};
use crate::email::{send_password_changed_email, send_verification_email};
use crate::routes::email_undeliverable_response;
use crate::routes::invitations::{accept_pending_invitation, PendingInvitation, PENDING_INVITATION_COLUMNS};
use crate::self_host;
use crate::sync_notifier::SyncNotifier;
use crate::passkeys::Passkeys;
use crate::two_factor::{self, Refusal, SecondFactorProof, SeedCipher};

// ─── Tier helper ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeatTeam {
    pub id: Uuid,
    pub name: String,
    pub trial: bool,
}

impl SeatTeam {
    fn claim(&self) -> SeatTeamClaim {
        SeatTeamClaim { id: self.id, trial: self.trial }
    }
}

struct TierInfo {
    tier: String,
    billing_tier: String,
    seat_team: Option<SeatTeam>,
    trial_ends_at: Option<i64>,
    trial_used: bool,
    is_admin: bool,
    is_banned: bool,
    email_verified: bool,
    token_version: i32,
}

fn access_token_for(user_id: Uuid, tier: &TierInfo) -> Result<String, StatusCode> {
    create_access_token(
        user_id,
        PlanClaims {
            tier: tier.tier.clone(),
            billing_tier: tier.billing_tier.clone(),
            seat_team: tier.seat_team.as_ref().map(SeatTeam::claim),
        },
        tier.trial_ends_at,
        tier.trial_used,
        tier.is_admin,
        tier.is_banned,
        tier.email_verified,
    )
    .map_err(|err| {
        error!(error = %err, user_id = %user_id, "Failed to create access token");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

fn issue_session(user_id: Uuid, tier: &TierInfo) -> Result<(String, String), StatusCode> {
    let refresh_token = create_refresh_token(user_id, tier.token_version).map_err(|err| {
        error!(error = %err, user_id = %user_id, "Failed to create refresh token");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok((access_token_for(user_id, tier)?, refresh_token))
}

async fn bump_token_version(pool: &PgPool, user_id: Uuid) -> Result<(), StatusCode> {
    sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Failed to bump token version");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(())
}

fn auth_response(
    user_id: Uuid,
    tier: TierInfo,
    wrapped_user_secrets: Option<String>,
) -> Result<AuthResponse, StatusCode> {
    let (jwt_token, refresh_token) = issue_session(user_id, &tier)?;
    Ok(AuthResponse {
        user_id,
        jwt_token,
        refresh_token,
        tier: tier.tier,
        billing_tier: tier.billing_tier,
        seat_team: tier.seat_team,
        trial_ends_at: tier.trial_ends_at,
        wrapped_user_secrets,
    })
}

#[derive(Serialize)]
pub struct SessionTokens {
    pub jwt_token: String,
    pub refresh_token: String,
}

/// A pair at the user's current token version, for the device that just moved it.
pub(crate) async fn fresh_session(pool: &PgPool, user_id: Uuid) -> Result<SessionTokens, StatusCode> {
    let tier = fetch_tier(pool, user_id).await?;
    let (jwt_token, refresh_token) = issue_session(user_id, &tier)?;
    Ok(SessionTokens { jwt_token, refresh_token })
}

pub(crate) async fn require_auth_key(pool: &PgPool, user_id: Uuid, auth_key: &str) -> Result<(), StatusCode> {
    let auth_hash = sqlx::query_scalar::<_, String>("SELECT auth_hash FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Failed to fetch auth_hash");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let valid = verify_auth_key(auth_key, &auth_hash).map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to verify auth key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if valid {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn fetch_tier(pool: &PgPool, user_id: Uuid) -> Result<TierInfo, StatusCode> {
    let row = sqlx::query_as::<_, (String, Option<DateTime<Utc>>, bool, bool, bool, bool, bool, Option<String>, Option<DateTime<Utc>>, i32)>(
        "SELECT subscription_tier, trial_ends_at, trial_used, is_admin, is_banned, email_verified, admin_override, ls_subscription_id, deleted_at, token_version FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to fetch tier info");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (stored_tier, trial_ends_at, trial_used, is_admin, is_banned, email_verified, admin_override, ls_subscription_id, deleted_at, token_version) =
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

    let own = effective.to_string();
    let seat = crate::entitlement::seat_upgrade(
        &own,
        crate::entitlement::seat_plan_for_user(pool, user_id).await,
    );
    let tier = seat.as_ref().map_or_else(|| own.clone(), |s| s.tier.clone());

    Ok(TierInfo {
        tier,
        billing_tier: own,
        seat_team: seat.map(|s| SeatTeam { id: s.team_id, name: s.team_name, trial: s.trial }),
        trial_ends_at: if downgraded { None } else { trial_ends_at.map(|t| t.timestamp()) },
        trial_used: trial_used || downgraded,
        is_admin,
        is_banned,
        email_verified,
        token_version,
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
    pub billing_tier: String,
    pub seat_team: Option<SeatTeam>,
    pub trial_ends_at: Option<i64>,
    pub wrapped_user_secrets: Option<String>,
}

struct NewUser<'a> {
    email: &'a str,
    account_id: Uuid,
    auth_hash: &'a str,
    public_key: Option<&'a str>,
    wrapped_user_secrets: Option<&'a str>,
    tier: &'a str,
    trial_ends_at: Option<DateTime<Utc>>,
}

fn is_handle_taken(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(e) if e.constraint() == Some("idx_users_handle"))
}

async fn insert_user(
    pool: &PgPool,
    u: &NewUser<'_>,
    handle: &str,
    handle_is_custom: bool,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO users (email, account_id, auth_hash, public_key, wrapped_user_secrets, subscription_tier, trial_ends_at, handle, handle_is_custom)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(u.email)
    .bind(u.account_id)
    .bind(u.auth_hash)
    .bind(u.public_key)
    .bind(u.wrapped_user_secrets)
    .bind(u.tier)
    .bind(u.trial_ends_at)
    .bind(handle)
    .bind(handle_is_custom)
    .fetch_one(pool)
    .await
}

async fn insert_user_with_handle_fallback(
    pool: &PgPool,
    u: &NewUser<'_>,
    handle: &str,
    handle_is_custom: bool,
) -> Result<Uuid, sqlx::Error> {
    match insert_user(pool, u, handle, handle_is_custom).await {
        Err(e) if is_handle_taken(&e) => {
            let generated = crate::handles::generate_unique_handle(pool).await?;
            insert_user(pool, u, &generated, false).await
        }
        other => other,
    }
}

fn email_delivery_configured() -> bool {
    !std::env::var("RESEND_API_KEY").unwrap_or_default().is_empty()
}

pub async fn register(
    State(pool): State<PgPool>,
    axum::Extension(features): axum::Extension<crate::features::Features>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), StatusCode> {
    register_with(pool, &notifier, features, email_delivery_configured(), body).await
}

async fn register_with(
    pool: PgPool,
    notifier: &SyncNotifier,
    features: crate::features::Features,
    delivery_configured: bool,
    body: RegisterRequest,
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

    let (handle, handle_is_custom) =
        crate::handles::registration_handle(&pool, &email, features.handles_from_email && !delivery_configured)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to choose a handle for registration");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    let new_user = NewUser {
        email: &email,
        account_id: body.account_id,
        auth_hash: &auth_hash,
        public_key: body.public_key.as_deref(),
        wrapped_user_secrets: body.wrapped_user_secrets.as_deref(),
        tier: initial_tier,
        trial_ends_at,
    };
    let user_id = insert_user_with_handle_fallback(&pool, &new_user, &handle, handle_is_custom)
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

    if !delivery_configured {
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
    } else {
        let mut conn = pool.acquire().await.map_err(|e| {
            error!(error = %e, "Failed to acquire connection for verification token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let token = issue_verification_token(&mut conn, user_id).await?;
        drop(conn);
        if let Err(e) = send_verification_email(&email, &token).await {
            error!(error = %e, user_id = %user_id, "Failed to send verification email");
        }
    }

    let pending = sqlx::query_as::<_, PendingInvitation>(&format!(
        "SELECT {PENDING_INVITATION_COLUMNS} FROM pending_invitations
         WHERE email = $1 AND accepted_at IS NULL AND expires_at > now()"
    ))
    .bind(&email)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    for invitation in &pending {
        if let Err(status) =
            accept_pending_invitation(&pool, notifier, invitation, user_id, Some(email.clone()), "registration").await
        {
            error!(user_id = %user_id, ?status, "Failed to auto-accept invitation on registration");
        }
    }

    let session = auth_response(user_id, fetch_tier(&pool, user_id).await?, body.wrapped_user_secrets)?;

    // `account_id` is deliberately absent: despite the name it is the KDF salt
    // passed to derive_keys, so a log line carrying it hands anyone who can read
    // the logs an offline precompute against that user's password. `user_id`
    // identifies the registration, and the two are joinable in the database.
    if trial_blocked {
        info!(user_id = %user_id, "User registered on free tier (trial already used)");
    } else {
        info!(user_id = %user_id, "User registered with 14-day trial");
    }

    Ok((StatusCode::CREATED, Json(session)))
}

// ─── Login ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub account_id: Uuid,
    pub auth_key: String,
}

#[derive(Serialize)]
pub struct SecondFactorChallenge {
    pub error: &'static str,
    pub pending_token: String,
    pub methods: Vec<&'static str>,
}

pub enum LoginOutcome {
    Session(AuthResponse),
    SecondFactorRequired(SecondFactorChallenge),
}

impl IntoResponse for LoginOutcome {
    fn into_response(self) -> Response {
        match self {
            LoginOutcome::Session(session) => Json(session).into_response(),
            // A status released clients report as a server error, never as a wrong password.
            LoginOutcome::SecondFactorRequired(challenge) => {
                (StatusCode::PRECONDITION_REQUIRED, Json(challenge)).into_response()
            }
        }
    }
}

pub async fn login(
    State(pool): State<PgPool>,
    axum::Extension(cipher): axum::Extension<SeedCipher>,
    axum::Extension(passkeys): axum::Extension<Passkeys>,
    Json(body): Json<LoginRequest>,
) -> Result<LoginOutcome, StatusCode> {
    let user = sqlx::query_as::<_, (Uuid, String, bool, Option<String>, bool)>(&format!(
        "SELECT id, auth_hash, is_banned, wrapped_user_secrets, {} FROM users WHERE account_id = $1",
        two_factor::ENABLED_SQL
    ))
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

    let (user_id, auth_hash, is_banned, wrapped_user_secrets, two_factor_enabled) = user;

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

    if two_factor_enabled {
        let pending_token = create_pending_token(user_id, tier.token_version).map_err(|err| {
            error!(error = %err, user_id = %user_id, "Failed to create pending token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        info!(user_id = %user_id, "Login awaiting second factor");
        return Ok(LoginOutcome::SecondFactorRequired(SecondFactorChallenge {
            error: "TWO_FACTOR_REQUIRED",
            pending_token,
            methods: two_factor::methods(&pool, &cipher, &passkeys, user_id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        }));
    }

    info!(user_id = %user_id, tier = %tier.tier, "User logged in");

    Ok(LoginOutcome::Session(auth_response(user_id, tier, wrapped_user_secrets)?))
}

#[derive(Deserialize)]
pub struct SecondFactorLoginRequest {
    pub pending_token: String,
    #[serde(flatten)]
    pub proof: SecondFactorProof,
}

pub struct PendingSignIn {
    pub user_id: Uuid,
    tier: TierInfo,
    wrapped_user_secrets: Option<String>,
}

/// The account a pending token still stands for: password accepted, second factor owed.
pub async fn pending_sign_in(pool: &PgPool, pending_token: &str) -> Result<PendingSignIn, Refusal> {
    let claims = validate_token(pending_token, PENDING_SECOND_FACTOR).map_err(|_| {
        warn!("Second factor login failed: invalid pending token");
        StatusCode::UNAUTHORIZED
    })?;
    let user_id = claims.sub;

    let (two_factor_enabled, wrapped_user_secrets): (bool, Option<String>) = sqlx::query_as(&format!(
        "SELECT {}, wrapped_user_secrets FROM users WHERE id = $1",
        two_factor::ENABLED_SQL
    ))
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(two_factor::db_failure)?
    .ok_or(StatusCode::UNAUTHORIZED)?;
    let tier = fetch_tier(pool, user_id).await?;

    if tier.is_banned {
        return Err(StatusCode::FORBIDDEN.into());
    }
    if !two_factor_enabled || claims.ver != tier.token_version {
        return Err(StatusCode::UNAUTHORIZED.into());
    }
    Ok(PendingSignIn { user_id, tier, wrapped_user_secrets })
}

pub async fn login_second_factor(
    State(pool): State<PgPool>,
    axum::Extension(cipher): axum::Extension<SeedCipher>,
    Json(body): Json<SecondFactorLoginRequest>,
) -> Result<Json<AuthResponse>, Refusal> {
    let PendingSignIn { user_id, tier, wrapped_user_secrets } = pending_sign_in(&pool, &body.pending_token).await?;
    let context = two_factor::Context::SignIn { pending_token: &body.pending_token };
    two_factor::verify_in(&pool, &cipher, user_id, &body.proof, context).await?;

    info!(user_id = %user_id, tier = %tier.tier, "User logged in with second factor");

    Ok(Json(auth_response(user_id, tier, wrapped_user_secrets)?))
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
    if claims.ver != tier.token_version {
        warn!(user_id = %claims.sub, "Refresh failed: session revoked");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let jwt_token = access_token_for(claims.sub, &tier)?;

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
    /// Lets the portal build `voltius://verified?u=…` so the app can refresh the
    /// right account. This is `users.id`, not the client's `account_id` — that
    /// one is a KDF salt and must never leave the device.
    pub user_id: Uuid,
}

async fn derive_handle_on_verify(tx: &mut sqlx::PgConnection, user_id: Uuid, email: &str, current: &str) {
    let Ok(candidate) = crate::handles::derive_handle_candidate(email) else {
        return;
    };
    let Ok(mut savepoint) = sqlx::Acquire::begin(&mut *tx).await else {
        return;
    };
    let free = crate::handles::handle_is_free(&mut *savepoint, &candidate).await;
    if matches!(free, Ok(true))
        && crate::routes::users::set_handle(&mut savepoint, user_id, current, &candidate).await.is_ok()
    {
        let _ = savepoint.commit().await;
    }
}

pub async fn verify_email(
    State(pool): State<PgPool>,
    axum::Extension(features): axum::Extension<crate::features::Features>,
    Json(body): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>, StatusCode> {
    let db_err = |what: &'static str| {
        move |e: sqlx::Error| {
            error!(error = %e, "{what}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    let mut tx = pool.begin().await.map_err(db_err("Failed to begin email verification"))?;
    let verified = sqlx::query_as::<_, (String, Uuid, String, bool)>(
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
         RETURNING users.email, users.id, users.handle, users.handle_is_custom",
    )
    .bind(&body.token)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err("Failed to verify email token"))?;

    if let Some((email, user_id, handle, handle_is_custom)) = verified {
        if features.handles_from_email && !handle_is_custom {
            derive_handle_on_verify(&mut tx, user_id, &email, &handle).await;
        }
        tx.commit().await.map_err(db_err("Failed to commit email verification"))?;
        info!(email = %email, "User email verified");
        return Ok(Json(VerifyEmailResponse { email, user_id }));
    }
    drop(tx);

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

async fn issue_verification_token(conn: &mut sqlx::PgConnection, user_id: Uuid) -> Result<String, StatusCode> {
    let token: String = sqlx::query_scalar(
        "INSERT INTO email_verification_tokens (user_id) VALUES ($1) RETURNING token",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to create email verification token");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "UPDATE email_verification_tokens SET consumed_at = now()
         WHERE user_id = $1 AND consumed_at IS NULL AND token <> $2",
    )
    .bind(user_id)
    .bind(&token)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to consume prior email verification tokens");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(token)
}

pub async fn resend_verification_email(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Response, StatusCode> {
    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin verification resend transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (email, verified, undeliverable) = sqlx::query_as::<_, (String, bool, bool)>(
        "SELECT email, email_verified, email_undeliverable_at IS NOT NULL FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(auth.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to lock user for verification resend");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if verified {
        return Ok(StatusCode::OK.into_response());
    }
    if undeliverable {
        return Ok(email_undeliverable_response());
    }

    let token = issue_verification_token(&mut tx, auth.0).await?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit verification resend transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Err(e) = send_verification_email(&email, &token).await {
        error!(error = %e, user_id = %auth.0, "Failed to resend verification email");
        return Err(StatusCode::BAD_GATEWAY);
    }

    Ok(StatusCode::OK.into_response())
}

// ─── Me ─────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MeResponse {
    pub email: String,
    /// ALIAS for pre-0.26 clients. Value is the handle. Delete in 0.27.
    pub display_name: String,
    pub account_id: Uuid,
    pub tier: String,
    pub billing_tier: String,
    pub seat_team: Option<SeatTeam>,
    pub trial_ends_at: Option<i64>,
    pub email_verified: bool,
    pub email_undeliverable: bool,
    pub wrapped_user_secrets: Option<String>,
    pub handle: String,
    pub handle_is_custom: bool,
    pub allow_stranger_invites: bool,
    pub handle_managed: bool,
    pub two_factor_enabled: bool,
}

pub(crate) async fn fetch_me_inner(
    pool: &PgPool,
    user_id: Uuid,
    handle_managed: bool,
) -> Result<MeResponse, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, Uuid, Option<String>, String, bool, bool, bool, bool)>(
        &format!("SELECT email, handle AS display_name, account_id, wrapped_user_secrets, handle, handle_is_custom, allow_stranger_invites, email_undeliverable_at IS NOT NULL, {} FROM users WHERE id = $1", two_factor::ENABLED_SQL),
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to fetch user in get_me");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let tier = fetch_tier(pool, user_id).await?;

    Ok(MeResponse {
        email: row.0,
        display_name: row.1,
        account_id: row.2,
        tier: tier.tier,
        billing_tier: tier.billing_tier,
        seat_team: tier.seat_team,
        trial_ends_at: tier.trial_ends_at,
        email_verified: tier.email_verified,
        email_undeliverable: row.7,
        wrapped_user_secrets: row.3,
        handle: row.4,
        handle_is_custom: row.5,
        allow_stranger_invites: row.6,
        handle_managed,
        two_factor_enabled: row.8,
    })
}

pub async fn get_me(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(features): axum::Extension<crate::features::Features>,
) -> Result<Json<MeResponse>, StatusCode> {
    Ok(Json(fetch_me_inner(&pool, auth.0, features.handles_from_email).await?))
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
    require_auth_key(&pool, auth.0, &body.auth_key).await?;

    let new_email = crate::email::normalize(&body.new_email);

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin update_email transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "UPDATE users SET email = $1, email_verified = FALSE, email_verified_at = NULL, email_undeliverable_at = NULL, updated_at = now() WHERE id = $2",
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

    let token = issue_verification_token(&mut tx, auth.0).await?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit update_email transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Err(e) = send_verification_email(&new_email, &token).await {
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
    #[serde(flatten)]
    pub proof: SecondFactorProof,
}

pub async fn update_password(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::Extension(cipher): axum::Extension<SeedCipher>,
    Json(body): Json<UpdatePasswordRequest>,
) -> Result<Json<AuthResponse>, Refusal> {
    require_auth_key(&pool, auth.0, &body.old_auth_key).await?;
    two_factor::verify_if_enabled(&pool, &cipher, auth.0, &body.proof).await?;

    let new_auth_hash = hash_auth_key(&body.new_auth_key).map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to hash new auth key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (email, undeliverable) = sqlx::query_as::<_, (String, bool)>(
        "UPDATE users SET auth_hash = $1, wrapped_user_secrets = $2, token_version = token_version + 1, updated_at = now() WHERE id = $3 RETURNING email, email_undeliverable_at IS NOT NULL",
    )
    .bind(&new_auth_hash)
    .bind(&body.new_wrapped_user_secrets)
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to update password");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let tier = fetch_tier(&pool, auth.0).await?;
    notifier.notify(auth.0, "token_invalidated".to_string());
    if !undeliverable {
        let user_id = auth.0;
        tokio::spawn(async move {
            if let Err(e) = send_password_changed_email(&email).await {
                error!(error = %e, user_id = %user_id, "Failed to send password change notice");
            }
        });
    }

    info!(user_id = %auth.0, "User password updated");

    Ok(Json(auth_response(auth.0, tier, Some(body.new_wrapped_user_secrets))?))
}

// ─── Log out everywhere ───────────────────────────────────────────────────────

pub async fn logout_all(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
) -> Result<Json<SessionTokens>, StatusCode> {
    bump_token_version(&pool, auth.0).await?;
    let session = fresh_session(&pool, auth.0).await?;
    notifier.notify(auth.0, "token_invalidated".to_string());

    info!(user_id = %auth.0, "User signed out every other session");

    Ok(Json(session))
}

// ─── Upload wrapped user secrets ──────────────────────────────────

#[derive(Deserialize)]
pub struct UploadWrappedSecretsRequest {
    pub wrapped_user_secrets: String,
    #[serde(default)]
    pub expected_wrapped_user_secrets: Option<String>,
}

pub async fn upload_wrapped_user_secrets(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<UploadWrappedSecretsRequest>,
) -> Result<StatusCode, StatusCode> {
    // No expectation means NULL: the legacy migration, the only caller that sends none, runs only then.
    let updated = sqlx::query(
        "UPDATE users SET wrapped_user_secrets = $1, updated_at = now()
         WHERE id = $2 AND wrapped_user_secrets IS NOT DISTINCT FROM $3",
    )
    .bind(&body.wrapped_user_secrets)
    .bind(auth.0)
    .bind(&body.expected_wrapped_user_secrets)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to upload wrapped_user_secrets");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    if updated == 0 {
        warn!(user_id = %auth.0, "Refused a wrapped_user_secrets upload that expected another value");
        return Err(StatusCode::CONFLICT);
    }

    info!(user_id = %auth.0, "Uploaded wrapped_user_secrets");
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
        add_member, seed_team, seed_user, seed_user_with_credentials, set_user_tier, set_user_trial,
    };
    use axum::extract::State;
    use axum::Extension;

    #[allow(dead_code)]
    struct EnvGuard(crate::test_support::BillingMode);
    impl EnvGuard {
        fn new(self_hosted: bool) -> Self {
            let billing = if self_hosted {
                crate::test_support::BillingMode::self_hosted()
            } else {
                crate::test_support::BillingMode::hosted()
            };
            std::env::set_var("JWT_SECRET", "ci-test-secret");
            EnvGuard(billing)
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

    use crate::features::Features;
    use crate::test_support::unique_handle;

    fn features(handles_from_email: bool) -> Extension<Features> {
        Extension(Features { handles_from_email, ..Features::open() })
    }

    fn test_new_user(email: &str) -> NewUser<'_> {
        NewUser {
            email,
            account_id: Uuid::new_v4(),
            auth_hash: "hash",
            public_key: None,
            wrapped_user_secrets: None,
            tier: "free",
            trial_ends_at: None,
        }
    }

    async fn handle_row(pool: &PgPool, id: Uuid) -> (String, bool) {
        sqlx::query_as("SELECT handle, handle_is_custom FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn register_derives_the_handle_when_switched_on() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let local = unique_handle("jn");
        let email = format!("{local}@corp.test");
        let (_, Json(resp)) = register(State(pool.clone()), features(true), Extension(SyncNotifier::new()), Json(register_req(&email, Uuid::new_v4(), None)))
            .await
            .unwrap();
        assert_eq!(handle_row(&pool, resp.user_id).await, (local, true));
    }

    #[tokio::test]
    async fn register_falls_back_when_the_derived_handle_is_taken_or_retired() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let local = unique_handle("jn");
        let first = register(State(pool.clone()), features(true), Extension(SyncNotifier::new()), Json(register_req(&format!("{local}@a.test"), Uuid::new_v4(), None)))
            .await
            .unwrap()
            .1
             .0;
        let second = register(State(pool.clone()), features(true), Extension(SyncNotifier::new()), Json(register_req(&format!("{local}@b.test"), Uuid::new_v4(), None)))
            .await
            .unwrap()
            .1
             .0;
        assert_eq!(handle_row(&pool, first.user_id).await.0, local);
        let (h2, custom2) = handle_row(&pool, second.user_id).await;
        assert_ne!(h2, local);
        assert!(!custom2, "a fallback is a generated handle");

        let retired = unique_handle("jr");
        sqlx::query("INSERT INTO retired_handles (handle, user_id) VALUES ($1, $2)")
            .bind(&retired)
            .bind(first.user_id)
            .execute(&pool)
            .await
            .unwrap();
        let third = register(State(pool.clone()), features(true), Extension(SyncNotifier::new()), Json(register_req(&format!("{retired}@c.test"), Uuid::new_v4(), None)))
            .await
            .unwrap()
            .1
             .0;
        assert_ne!(handle_row(&pool, third.user_id).await.0, retired);
    }

    #[tokio::test]
    async fn register_generates_when_switched_off() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let local = unique_handle("jn");
        let (_, Json(resp)) = register(State(pool.clone()), features(false), Extension(SyncNotifier::new()), Json(register_req(&format!("{local}@corp.test"), Uuid::new_v4(), None)))
            .await
            .unwrap();
        let (h, custom) = handle_row(&pool, resp.user_id).await;
        assert_ne!(h, local);
        assert!(!custom);
    }

    #[tokio::test]
    async fn register_self_hosted_grants_business_no_trial() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let account_id = Uuid::new_v4();
        let email = format!("{}@ex.test", Uuid::new_v4());

        let (status, Json(resp)) = register(State(pool.clone()), Extension(Features::open()), Extension(SyncNotifier::new()), Json(register_req(&email, account_id, None)))
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

        let (status, Json(resp)) = register(State(pool.clone()), Extension(Features::open()), Extension(SyncNotifier::new()), Json(register_req(&email, account_id, None)))
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
            register(State(pool.clone()), Extension(Features::open()), Extension(SyncNotifier::new()), Json(register_req(&email, account_id, Some(&fp))))
                .await
                .expect("register ok");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(resp.tier, "free");
        assert_eq!(resp.trial_ends_at, None);

        let claims = validate_token(&resp.jwt_token, "access").expect("decode session");
        assert_eq!(claims.tier, "free");
    }

    #[tokio::test]
    async fn register_with_pending_invitation_issues_seat_token() {
        let _env = EnvGuard::new(false);
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "teams").await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        let email = format!("{}@ex.test", Uuid::new_v4());
        crate::test_support::seed_invitation(&pool, team, &email, "member", None).await;

        let (_, Json(resp)) = register_with(
            pool.clone(),
            &SyncNotifier::new(),
            Features::open(),
            true,
            register_req(&email, Uuid::new_v4(), None),
        )
        .await
        .expect("register ok");

        assert_eq!(resp.tier, "teams");
        assert_eq!(resp.billing_tier, "pro");
        assert_eq!(resp.seat_team.as_ref().map(|s| s.id), Some(team));
        let claims = validate_token(&resp.jwt_token, "access").unwrap();
        assert_eq!(claims.tier, "teams");
        assert_eq!(claims.seat_team, resp.seat_team.as_ref().map(SeatTeam::claim));
    }

    #[tokio::test]
    async fn register_duplicate_email_conflicts() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let email = format!("{}@ex.test", Uuid::new_v4());

        let (status, _) = register(
            State(pool.clone()),
            Extension(Features::open()),
            Extension(SyncNotifier::new()),
            Json(register_req(&email, Uuid::new_v4(), None)),
        )
        .await
        .expect("first register ok");
        assert_eq!(status, StatusCode::CREATED);

        match register(
            State(pool.clone()),
            Extension(Features::open()),
            Extension(SyncNotifier::new()),
            Json(register_req(&email, Uuid::new_v4(), None)),
        )
        .await
        {
            Err(s) => assert_eq!(s, StatusCode::CONFLICT),
            Ok(_) => panic!("expected CONFLICT on duplicate email"),
        }
    }

    #[tokio::test]
    async fn register_auto_accept_admits_audits_and_tells_the_team() {
        use crate::sync_notifier::SyncEvent;
        use crate::test_support::{add_member, seed_invitation, seed_team, seed_user};

        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        let email = format!("{}@ex.test", Uuid::new_v4());
        let (invitation_id, _token) = seed_invitation(&pool, team, &email, "member", None).await;

        let notifier = SyncNotifier::new();
        let mut rx = notifier.subscribe();
        let (_, Json(resp)) = register(
            State(pool.clone()),
            Extension(Features::open()),
            Extension(notifier.clone()),
            Json(register_req(&email, Uuid::new_v4(), None)),
        )
        .await
        .unwrap();

        let (accepted, member, joined): (bool, bool, i64) = sqlx::query_as(
            "SELECT
               (SELECT accepted_at IS NOT NULL FROM pending_invitations WHERE id = $1),
               EXISTS(SELECT 1 FROM team_members WHERE team_id = $2 AND user_id = $3),
               (SELECT COUNT(*) FROM audit_logs WHERE team_id = $2 AND actor_id = $3 AND action = 'member.joined')",
        )
        .bind(invitation_id)
        .bind(team)
        .bind(resp.user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(accepted && member);
        assert_eq!(joined, 1);

        let roster_event = format!("team_members:{team}");
        let mut owner_told = false;
        while let Ok(ev) = rx.try_recv() {
            if let SyncEvent::BlobPushed { user_id, device_id } = ev {
                owner_told |= user_id == owner && device_id == roster_event;
            }
        }
        assert!(owner_told, "the inviter's roster must hear about the sign-up");
    }

    async fn seat_of(pool: &PgPool, owner_tier: &str, member: Uuid) {
        let owner = seed_user(pool).await;
        set_user_tier(pool, owner, owner_tier).await;
        let team = seed_team(pool, owner).await;
        add_member(pool, team, owner).await;
        add_member(pool, team, member).await;
    }

    #[tokio::test]
    async fn fetch_tier_grants_seat_plan() {
        let _env = EnvGuard::new(false);
        let pool = test_pool_or_skip!();
        let member = seed_user(&pool).await;
        seat_of(&pool, "teams", member).await;
        let info = fetch_tier(&pool, member).await.unwrap();
        assert_eq!(info.tier, "teams");
        assert_eq!(info.billing_tier, "free");
        let seat = info.seat_team.clone().unwrap();
        assert_eq!(seat.name, "test-team");
        assert!(!seat.trial);

        let token = access_token_for(member, &info).unwrap();
        let claims = validate_token(&token, "access").unwrap();
        assert_eq!(claims.tier, "teams");
        assert_eq!(claims.billing_tier(), "free");
        assert_eq!(claims.seat_team, info.seat_team.as_ref().map(SeatTeam::claim));
    }

    #[tokio::test]
    async fn access_token_payload_carries_no_team_name() {
        use base64::Engine;
        let _env = EnvGuard::new(false);
        let pool = test_pool_or_skip!();
        let member = seed_user(&pool).await;
        seat_of(&pool, "teams", member).await;
        sqlx::query("UPDATE teams SET name = 'Команда?' WHERE id IN (SELECT team_id FROM team_members WHERE user_id = $1)")
            .bind(member)
            .execute(&pool)
            .await
            .unwrap();
        let info = fetch_tier(&pool, member).await.unwrap();
        assert_eq!(info.seat_team.as_ref().unwrap().name, "Команда?");
        let token = access_token_for(member, &info).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let seat = json.get("seat_team").and_then(|v| v.as_object()).expect("seat_team claim");
        assert!(!seat.contains_key("name"));
        assert!(!String::from_utf8(bytes).unwrap().contains("Команда"));
    }

    #[tokio::test]
    async fn fetch_tier_no_seat_team_when_own_plan_wins() {
        let _env = EnvGuard::new(false);
        let pool = test_pool_or_skip!();
        let member = seed_user(&pool).await;
        set_user_tier(&pool, member, "business").await;
        seat_of(&pool, "teams", member).await;
        let info = fetch_tier(&pool, member).await.unwrap();
        assert_eq!(info.tier, "business");
        assert_eq!(info.billing_tier, "business");
        assert!(info.seat_team.is_none());
    }

    // ── login: effective tier in the issued session ───────────────────────────

    async fn login_with(pool: &PgPool, account_id: Uuid, auth_key: &str) -> Result<AuthResponse, StatusCode> {
        let outcome = login(
            State(pool.clone()),
            Extension(SeedCipher::for_tests()),
            Extension(Passkeys::for_tests()),
            Json(LoginRequest {
                account_id,
                auth_key: auth_key.to_string(),
            }),
        )
        .await?;
        match outcome {
            LoginOutcome::Session(session) => Ok(session),
            LoginOutcome::SecondFactorRequired(_) => panic!("account has no second factor"),
        }
    }

    async fn login_of(pool: &PgPool, account_id: Uuid) -> Result<AuthResponse, StatusCode> {
        login_with(pool, account_id, "auth-key-secret").await
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

        let res = login_with(&pool, account_id, "wrong-key").await;

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
            Extension(Features::open()),
            Extension(SyncNotifier::new()),
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
            Extension(Features::open()),
            Extension(SyncNotifier::new()),
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
            Extension(Features::open()),
            Extension(SyncNotifier::new()),
            Json(register_req(&email, Uuid::new_v4(), None)),
        )
        .await
        .expect("first register ok");

        match register(
            State(pool.clone()),
            Extension(Features::open()),
            Extension(SyncNotifier::new()),
            Json(register_req(&email.to_uppercase(), Uuid::new_v4(), None)),
        )
        .await
        {
            Err(s) => assert_eq!(s, StatusCode::CONFLICT),
            Ok(_) => panic!("expected CONFLICT for the same mailbox in a different case"),
        }
    }

    // ── revocation: a refresh token dies when token_version moves ────────────

    async fn refresh_with(pool: &PgPool, refresh_token: &str) -> Result<String, StatusCode> {
        refresh(
            State(pool.clone()),
            Json(RefreshRequest {
                refresh_token: refresh_token.to_string(),
            }),
        )
        .await
        .map(|Json(r)| r.jwt_token)
    }

    async fn signed_in_twice(pool: &PgPool) -> (Uuid, AuthResponse, AuthResponse) {
        let account_id = Uuid::new_v4();
        let uid = seed_user_with_credentials(pool, account_id, "auth-key-secret").await;
        let here = login_of(pool, account_id).await.expect("login ok");
        let elsewhere = login_of(pool, account_id).await.expect("login ok");
        (uid, here, elsewhere)
    }

    #[tokio::test]
    async fn password_change_revokes_earlier_refresh_tokens() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let (uid, _, elsewhere) = signed_in_twice(&pool).await;

        let Json(changed) = update_password(
            State(pool.clone()),
            Extension(AuthUser(uid)),
            Extension(SyncNotifier::new()),
            Extension(SeedCipher::for_tests()),
            Json(UpdatePasswordRequest {
                old_auth_key: "auth-key-secret".to_string(),
                new_auth_key: "new-auth-key".to_string(),
                new_wrapped_user_secrets: "wrapped".to_string(),
                proof: SecondFactorProof::default(),
            }),
        )
        .await
        .expect("password change ok");

        assert_eq!(
            refresh_with(&pool, &elsewhere.refresh_token).await,
            Err(StatusCode::UNAUTHORIZED)
        );
        assert!(refresh_with(&pool, &changed.refresh_token).await.is_ok());
    }

    #[tokio::test]
    async fn logout_all_revokes_other_sessions_and_keeps_the_caller() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        use crate::sync_notifier::SyncEvent;
        let (uid, here, elsewhere) = signed_in_twice(&pool).await;
        let notifier = SyncNotifier::new();
        let mut events = notifier.subscribe();

        let Json(fresh) = logout_all(State(pool.clone()), Extension(AuthUser(uid)), Extension(notifier))
            .await
            .expect("logout-all ok");

        for revoked in [&here.refresh_token, &elsewhere.refresh_token] {
            assert_eq!(refresh_with(&pool, revoked).await, Err(StatusCode::UNAUTHORIZED));
        }
        assert!(refresh_with(&pool, &fresh.refresh_token).await.is_ok());
        assert!(validate_token(&fresh.jwt_token, "access").is_ok());
        assert!(matches!(
            events.try_recv(),
            Ok(SyncEvent::BlobPushed { user_id, device_id }) if user_id == uid && device_id == "token_invalidated"
        ));
    }

    #[tokio::test]
    async fn refresh_token_from_before_the_version_claim_works_until_a_bump() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let uid = seed_user_with_credentials(&pool, Uuid::new_v4(), "auth-key-secret").await;
        let legacy = crate::auth::jwt::tests::legacy_token(uid, "refresh", "ci-test-secret");

        assert!(refresh_with(&pool, &legacy).await.is_ok());
        bump_token_version(&pool, uid).await.expect("bump");
        assert_eq!(refresh_with(&pool, &legacy).await, Err(StatusCode::UNAUTHORIZED));
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

    #[tokio::test]
    async fn me_reports_the_handle_under_both_names() {
        let pool = test_pool_or_skip!();
        let user = crate::test_support::seed_user(&pool).await;
        let handle = crate::test_support::unique_handle("merry-quartz");
        sqlx::query("UPDATE users SET handle = $1 WHERE id = $2")
            .bind(&handle)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();

        let me = fetch_me_inner(&pool, user, false).await.unwrap();
        assert_eq!(me.handle, handle);
        // ALIAS for pre-0.26 clients.
        assert_eq!(me.display_name, handle);
    }

    #[tokio::test]
    async fn me_reports_whether_handles_are_managed() {
        let pool = test_pool_or_skip!();
        let user = crate::test_support::seed_user(&pool).await;
        assert!(!fetch_me_inner(&pool, user, false).await.unwrap().handle_managed);
        assert!(fetch_me_inner(&pool, user, true).await.unwrap().handle_managed);
    }

    #[tokio::test]
    async fn insert_falls_back_to_a_generated_handle_when_the_chosen_one_is_taken() {
        let pool = test_pool_or_skip!();
        let other = crate::test_support::seed_user(&pool).await;
        let taken: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
            .bind(other)
            .fetch_one(&pool)
            .await
            .unwrap();
        let email = format!("{}@race.test", Uuid::new_v4());
        let new_user = test_new_user(&email);
        let id = insert_user_with_handle_fallback(&pool, &new_user, &taken.to_uppercase(), true)
            .await
            .unwrap();
        let (handle, custom) = handle_row(&pool, id).await;
        assert_ne!(handle.to_lowercase(), taken.to_lowercase());
        assert!(!custom);
    }

    #[tokio::test]
    async fn insert_still_reports_a_taken_email() {
        let pool = test_pool_or_skip!();
        let other = crate::test_support::seed_user(&pool).await;
        let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(other)
            .fetch_one(&pool)
            .await
            .unwrap();
        let new_user = test_new_user(&email);
        let err = insert_user_with_handle_fallback(&pool, &new_user, "fresh-handle-xyz", false)
            .await
            .unwrap_err();
        assert!(is_email_taken(&err));
    }

    async fn registered_unverified(pool: &PgPool, switch: bool, email: &str) -> (Uuid, String) {
        let (_, Json(resp)) = register_with(pool.clone(), &SyncNotifier::new(), features(switch).0, true, register_req(email, Uuid::new_v4(), None))
            .await
            .unwrap();
        let token = sqlx::query_scalar("SELECT token FROM email_verification_tokens WHERE user_id = $1")
            .bind(resp.user_id)
            .fetch_one(pool)
            .await
            .unwrap();
        (resp.user_id, token)
    }

    async fn verify(pool: &PgPool, switch: bool, token: String) {
        let _ = verify_email(State(pool.clone()), features(switch), Json(VerifyEmailRequest { token })).await.unwrap();
    }

    #[tokio::test]
    async fn derivation_waits_for_email_verification_when_delivery_is_configured() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let local = unique_handle("jv");
        let (id, token) = registered_unverified(&pool, true, &format!("{local}@corp.test")).await;
        let (before, custom) = handle_row(&pool, id).await;
        assert_ne!(before, local);
        assert!(!custom);
        verify(&pool, true, token).await;
        assert_eq!(handle_row(&pool, id).await, (local, true));
    }

    #[tokio::test]
    async fn verification_never_touches_a_custom_handle_or_renames_with_the_switch_off() {
        let _env = EnvGuard::new(true);
        let pool = test_pool_or_skip!();
        let custom_local = unique_handle("jc");
        let (custom_id, custom_token) = registered_unverified(&pool, true, &format!("{custom_local}@corp.test")).await;
        let mine = unique_handle("mine");
        sqlx::query("UPDATE users SET handle = $1, handle_is_custom = TRUE WHERE id = $2")
            .bind(&mine)
            .bind(custom_id)
            .execute(&pool)
            .await
            .unwrap();
        verify(&pool, true, custom_token).await;
        assert_eq!(handle_row(&pool, custom_id).await, (mine, true));

        let off_local = unique_handle("jo");
        let (off_id, off_token) = registered_unverified(&pool, false, &format!("{off_local}@corp.test")).await;
        let (generated, _) = handle_row(&pool, off_id).await;
        verify(&pool, false, off_token).await;
        assert_eq!(handle_row(&pool, off_id).await, (generated, false));
    }

    async fn stored_wrapped(pool: &PgPool, id: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT wrapped_user_secrets FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn upload_wrapped(pool: &PgPool, id: Uuid, next: &str, expected: Option<&str>) -> Result<StatusCode, StatusCode> {
        upload_wrapped_user_secrets(
            State(pool.clone()),
            Extension(AuthUser(id)),
            Json(UploadWrappedSecretsRequest {
                wrapped_user_secrets: next.to_string(),
                expected_wrapped_user_secrets: expected.map(str::to_string),
            }),
        )
        .await
    }

    #[tokio::test]
    async fn wrapped_secrets_first_upload_needs_no_expectation() {
        let pool = test_pool_or_skip!();
        let id = crate::test_support::seed_user(&pool).await;
        assert_eq!(upload_wrapped(&pool, id, "W1", None).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(stored_wrapped(&pool, id).await.as_deref(), Some("W1"));
    }

    #[tokio::test]
    async fn wrapped_secrets_replace_only_the_value_they_expect() {
        let pool = test_pool_or_skip!();
        let id = crate::test_support::seed_user(&pool).await;
        upload_wrapped(&pool, id, "W1", None).await.unwrap();
        assert_eq!(upload_wrapped(&pool, id, "W2", Some("W1")).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(upload_wrapped(&pool, id, "W3", Some("W1")).await, Err(StatusCode::CONFLICT));
        assert_eq!(stored_wrapped(&pool, id).await.as_deref(), Some("W2"));
    }

    #[tokio::test]
    async fn wrapped_secrets_are_never_overwritten_without_an_expectation() {
        let pool = test_pool_or_skip!();
        let id = crate::test_support::seed_user(&pool).await;
        upload_wrapped(&pool, id, "W1", None).await.unwrap();
        assert_eq!(upload_wrapped(&pool, id, "W2", None).await, Err(StatusCode::CONFLICT));
        assert_eq!(stored_wrapped(&pool, id).await.as_deref(), Some("W1"));
    }
}
