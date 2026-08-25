//! Team-vault join grants (the server half of VoltiusApp/voltius#68).
//!
//! A grant confers *membership*, never vault access: the vault key is wrapped
//! per member with X25519, so it can only follow once an online key-holder
//! runs the client's `reconcileTeamVaultKeys`. Redemption's job is therefore
//! to insert the membership row, make sure the roster carries the joiner's
//! public key, and fire the `team_members` event that wakes those key-holders.
//!
//! `account_id` appears nowhere in this module. Despite the name it is the KDF
//! salt passed to `derive_keys`; emitting it would hand an attacker offline
//! precompute against that user's password.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::permissions::{require_all_team_permissions, PERM_INVITE_MEMBERS};
use crate::rate_limit::{check_user_budget, GrantMintRateLimiter, GrantRedeemRateLimiter};
use crate::routes::audit::write_audit_event;
use crate::routes::invitations::admit_member;
use crate::routes::teams::{notify_team_members_changed, owner_seat_cap, owner_seats_used, team_owner};
use crate::sync_notifier::SyncNotifier;
use crate::team_join_grants::{self as grants, GrantRejection, GrantRow};

/// Length ceiling on a submitted X25519 public key. Base64 of 32 bytes is 44
/// characters; the slack is for future key formats, not for arbitrary blobs.
const MAX_PUBLIC_KEY_LEN: usize = 256;

/// The create/list/revoke gate, in one place: the same permission bit that
/// guards `POST /v1/teams/:team_id/invite`. Preview and redeem are deliberately
/// not gated on it — they are authenticated as whoever holds the link.
async fn require_grant_admin(pool: &PgPool, team_id: Uuid, user: Uuid) -> Result<(), StatusCode> {
    require_all_team_permissions(pool, team_id, user, &[PERM_INVITE_MEMBERS]).await
}

fn reject(rejection: GrantRejection) -> StatusCode {
    match rejection {
        // Wrong id and wrong secret answer alike: nothing distinguishes a real
        // grant from a guess.
        GrantRejection::NotFound => StatusCode::NOT_FOUND,
        // The remaining variants are only reachable by someone who already
        // presented the correct secret, so naming the reason leaks nothing and
        // lets the client say something true.
        GrantRejection::Revoked | GrantRejection::Expired => StatusCode::GONE,
        GrantRejection::Exhausted => StatusCode::CONFLICT,
    }
}

// ─── Create ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateGrantRequest {
    pub role: Option<String>,
    pub max_uses: Option<i32>,
    pub expires_in_secs: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateGrantResponse {
    pub id: Uuid,
    /// Returned exactly once. Only its sha256 is stored, so this response is
    /// the sole opportunity to read it — there is no endpoint that can show it
    /// again.
    pub secret: String,
    pub role: String,
    pub max_uses: i32,
    pub uses: i32,
    pub expires_at: DateTime<Utc>,
}

/// Hand-written so the secret can never reach a log through a stray `{:?}`.
/// The response body is the only place it is ever meant to appear.
impl std::fmt::Debug for CreateGrantResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateGrantResponse")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("role", &self.role)
            .field("max_uses", &self.max_uses)
            .field("uses", &self.uses)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub async fn create_grant(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Extension(GrantMintRateLimiter(limiter)): Extension<GrantMintRateLimiter>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<CreateGrantRequest>,
) -> Result<(StatusCode, Json<CreateGrantResponse>), StatusCode> {
    check_user_budget(&limiter, auth.0, "team_grant_mint").await?;
    require_grant_admin(&pool, team_id, auth.0).await?;

    let role = body.role.as_deref().unwrap_or("member").to_string();
    if !grants::is_grantable_role(&role) {
        warn!(team_id = %team_id, user_id = %auth.0, role = %role, "Rejected non-grantable role");
        return Err(StatusCode::BAD_REQUEST);
    }

    let max_uses = grants::clamp_max_uses(body.max_uses);
    let ttl = grants::clamp_ttl(body.expires_in_secs);

    let (grant, secret) = grants::create(&pool, team_id, &role, max_uses, ttl, auth.0)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, "Failed to create team join grant");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(team_id = %team_id, grant_id = %grant.id, role = %role, max_uses, "Team join grant created");
    write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "join_grant.created",
        Some("join_grant"),
        Some(grant.id.to_string()),
        None,
        Some(json!({ "role": role, "max_uses": max_uses, "expires_at": grant.expires_at })),
    )
    .await;

    // Managers watching the roster see the new link without a refetch prompt.
    notify_team_members_changed(&pool, &notifier, team_id).await;

    Ok((
        StatusCode::CREATED,
        Json(CreateGrantResponse {
            id: grant.id,
            secret,
            role: grant.role,
            max_uses: grant.max_uses,
            uses: grant.uses,
            expires_at: grant.expires_at,
        }),
    ))
}

// ─── List ─────────────────────────────────────────────────────────────────────

pub async fn list_grants(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<Vec<GrantRow>>, StatusCode> {
    require_grant_admin(&pool, team_id, auth.0).await?;

    grants::list_live(&pool, team_id).await.map(Json).map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to list team join grants");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

// ─── Revoke ───────────────────────────────────────────────────────────────────

pub async fn revoke_grant(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path((team_id, grant_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    require_grant_admin(&pool, team_id, auth.0).await?;

    let revoked = grants::revoke(&pool, team_id, grant_id).await.map_err(|e| {
        error!(error = %e, team_id = %team_id, grant_id = %grant_id, "Failed to revoke team join grant");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !revoked {
        return Err(StatusCode::NOT_FOUND);
    }

    info!(team_id = %team_id, grant_id = %grant_id, "Team join grant revoked");
    write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "join_grant.revoked",
        Some("join_grant"),
        Some(grant_id.to_string()),
        None,
        None,
    )
    .await;

    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Preview ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SecretRequest {
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct PreviewResponse {
    pub team_name: String,
    pub role: String,
    pub inviter_handle: Option<String>,
}

pub async fn preview_grant(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(GrantRedeemRateLimiter(limiter)): Extension<GrantRedeemRateLimiter>,
    Path(grant_id): Path<Uuid>,
    Json(body): Json<SecretRequest>,
) -> Result<Json<PreviewResponse>, StatusCode> {
    check_user_budget(&limiter, auth.0, "team_grant_preview").await?;

    let preview = grants::preview(&pool, grant_id, &body.secret)
        .await
        .map_err(reject)?;

    Ok(Json(PreviewResponse {
        team_name: preview.team_name,
        role: preview.role,
        inviter_handle: preview.inviter_handle,
    }))
}

// ─── Redeem ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedeemGrantRequest {
    pub secret: String,
    /// The redeemer's X25519 public key, so the roster row a key-holder reads
    /// can be wrapped for immediately. There is deliberately no user field:
    /// who joins is decided by the bearer token, never by the body.
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RedeemGrantResponse {
    pub team_id: Uuid,
    pub team_name: String,
    pub role: String,
}

pub async fn redeem_grant(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Extension(GrantRedeemRateLimiter(limiter)): Extension<GrantRedeemRateLimiter>,
    Path(grant_id): Path<Uuid>,
    Json(body): Json<RedeemGrantRequest>,
) -> Result<Json<RedeemGrantResponse>, StatusCode> {
    check_user_budget(&limiter, auth.0, "team_grant_redeem").await?;

    if let Some(key) = body.public_key.as_deref() {
        if key.trim().is_empty() || key.len() > MAX_PUBLIC_KEY_LEN {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin transaction for grant redemption");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let locked = grants::lock_for_redemption(&mut tx, grant_id, &body.secret, auth.0)
        .await
        .map_err(reject)?;

    let response = RedeemGrantResponse {
        team_id: locked.team_id,
        team_name: locked.team_name.clone(),
        role: locked.role.clone(),
    };

    // Already a member: a success, and not a consumed use. Someone re-opening
    // their own link must not burn a seat on the next person.
    if locked.already_member {
        tx.commit().await.map_err(|e| {
            error!(error = %e, "Failed to commit no-op grant redemption");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        info!(user_id = %auth.0, team_id = %locked.team_id, "Join grant redeemed by an existing member; no-op");
        return Ok(Json(response));
    }

    // A link must not be a way around the owner's seat cap. Membership in any
    // other team of the same owner already occupies the seat, so those users
    // are exempt.
    let owner_id = team_owner(&pool, locked.team_id).await?;
    if let Some(effective_cap) = owner_seat_cap(&pool, owner_id).await? {
        let holds_a_seat = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_members tm JOIN teams t ON t.id = tm.team_id \
             WHERE t.owner_id = $1 AND tm.user_id = $2)",
        )
        .bind(owner_id)
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to check seat occupancy"); StatusCode::INTERNAL_SERVER_ERROR })?;

        if !holds_a_seat {
            let used = owner_seats_used(&pool, owner_id).await?;
            if used >= effective_cap {
                warn!(owner_id = %owner_id, effective_cap, used, "Seat limit reached on grant redemption");
                return Err(StatusCode::PAYMENT_REQUIRED);
            }
        }
    }

    // Validity and consumption are the same statement. Losing this race means
    // another redeemer took the last use between the lock and here, which the
    // lock makes impossible — it stays as the backstop that keeps the invariant
    // true if the locking above is ever weakened.
    if !grants::consume_use(&mut tx, grant_id).await.map_err(|e| {
        error!(error = %e, grant_id = %grant_id, "Failed to consume join grant use");
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        return Err(reject(GrantRejection::Exhausted));
    }

    // `invited_by` is the grant's creator, so the roster attributes the joiner
    // to whoever minted the link.
    admit_member(&mut tx, locked.team_id, auth.0, Some(locked.created_by), &locked.role).await?;

    // Fill a missing key only. Overwriting a key a user already published
    // would orphan every vault key already wrapped to it, in this team and
    // every other; rotation belongs to PUT /v1/auth/public-key.
    if let Some(key) = body.public_key.as_deref() {
        sqlx::query(
            "UPDATE users SET public_key = $1, updated_at = now() \
             WHERE id = $2 AND (public_key IS NULL OR public_key = '')",
        )
        .bind(key)
        .bind(auth.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to record redeemer public key");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Without a key on the roster row, no key-holder can wrap for this member
    // and the joiner lands in a vault that can never fill. Refuse the join
    // rather than create that state.
    let has_key = sqlx::query_scalar::<_, bool>(
        "SELECT public_key IS NOT NULL AND public_key <> '' FROM users WHERE id = $1",
    )
    .bind(auth.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| { error!(error = %e, "Failed to verify redeemer public key"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !has_key {
        warn!(user_id = %auth.0, "Join grant redemption without a public key");
        return Err(StatusCode::BAD_REQUEST);
    }

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit grant redemption");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let joiner_handle = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    info!(user_id = %auth.0, team_id = %locked.team_id, role = %locked.role, "Team joined via join grant");
    write_audit_event(
        pool.clone(),
        locked.team_id,
        auth.0,
        "member.joined",
        Some("user"),
        Some(auth.0.to_string()),
        joiner_handle,
        Some(json!({ "role": locked.role, "via": "join_grant", "grant_id": grant_id })),
    )
    .await;

    // The joiner's own devices refetch their team list; every member — the
    // joiner included — gets `team_members:<team_id>`, which is the event an
    // online key-holder's reconcileTeamVaultKeys listens for.
    notifier.notify_membership_changed(auth.0);
    notify_team_members_changed(&pool, &notifier, locked.team_id).await;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::RateLimiter;
    use crate::sync_notifier::SyncEvent;
    use crate::test_pool_or_skip;
    use crate::test_support::{
        member_with_role, seed_team_with_roles, seed_user, set_user_seats,
    };
    use crate::permissions::PERM_CONNECT;
    use std::time::Duration;

    fn mint_budget() -> GrantMintRateLimiter {
        GrantMintRateLimiter(RateLimiter::new(100, Duration::from_secs(3600)))
    }

    fn redeem_budget() -> GrantRedeemRateLimiter {
        GrantRedeemRateLimiter(RateLimiter::new(100, Duration::from_secs(3600)))
    }

    /// A team with builtin roles, its owner, and a manager who holds
    /// PERM_INVITE_MEMBERS — the same gate `POST /v1/teams/:id/invite` uses.
    async fn seed_team_with_manager(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
        let owner = seed_user(pool).await;
        let team = seed_team_with_roles(pool, owner).await;
        let manager = member_with_role(pool, team, PERM_INVITE_MEMBERS).await;
        (team, owner, manager)
    }

    async fn mint(
        pool: &PgPool,
        team: Uuid,
        actor: Uuid,
        role: &str,
        max_uses: i32,
    ) -> CreateGrantResponse {
        let (_, Json(created)) = create_grant(
            State(pool.clone()),
            Extension(AuthUser(actor)),
            Extension(SyncNotifier::new()),
            Extension(mint_budget()),
            Path(team),
            Json(CreateGrantRequest {
                role: Some(role.to_string()),
                max_uses: Some(max_uses),
                expires_in_secs: Some(3600),
            }),
        )
        .await
        .expect("mint grant");
        created
    }

    async fn redeem(
        pool: &PgPool,
        grant_id: Uuid,
        secret: &str,
        user: Uuid,
    ) -> Result<Json<RedeemGrantResponse>, StatusCode> {
        redeem_with_notifier(pool, grant_id, secret, user, SyncNotifier::new()).await
    }

    async fn redeem_with_notifier(
        pool: &PgPool,
        grant_id: Uuid,
        secret: &str,
        user: Uuid,
        notifier: SyncNotifier,
    ) -> Result<Json<RedeemGrantResponse>, StatusCode> {
        redeem_grant(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(notifier),
            Extension(redeem_budget()),
            Path(grant_id),
            Json(RedeemGrantRequest {
                secret: secret.to_string(),
                public_key: Some("test-pubkey".to_string()),
            }),
        )
        .await
    }

    async fn assigned_role(pool: &PgPool, team: Uuid, user: Uuid) -> Option<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT tr.name FROM team_member_roles tmr \
             JOIN team_roles tr ON tr.id = tmr.role_id \
             WHERE tmr.team_id = $1 AND tmr.user_id = $2",
        )
        .bind(team)
        .bind(user)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    async fn uses_of(pool: &PgPool, grant_id: Uuid) -> i32 {
        sqlx::query_scalar::<_, i32>("SELECT uses FROM team_join_grants WHERE id = $1")
            .bind(grant_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn audit_actions(pool: &PgPool, team: Uuid) -> Vec<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT action FROM audit_logs WHERE team_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind(team)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    // ─── Gating ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn creating_listing_and_revoking_need_the_invite_permission() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        // A member with a permission bit that is not PERM_INVITE_MEMBERS.
        let plain = member_with_role(&pool, team, PERM_CONNECT).await;

        for actor in [plain, seed_user(&pool).await] {
            let err = create_grant(
                State(pool.clone()),
                Extension(AuthUser(actor)),
                Extension(SyncNotifier::new()),
                Extension(mint_budget()),
                Path(team),
                Json(CreateGrantRequest { role: None, max_uses: None, expires_in_secs: None }),
            )
            .await
            .unwrap_err();
            assert_eq!(err, StatusCode::FORBIDDEN);

            assert_eq!(
                list_grants(State(pool.clone()), Extension(AuthUser(actor)), Path(team))
                    .await
                    .unwrap_err(),
                StatusCode::FORBIDDEN
            );
        }

        let created = mint(&pool, team, manager, "member", 1).await;
        let err = revoke_grant(
            State(pool.clone()),
            Extension(AuthUser(plain)),
            Extension(SyncNotifier::new()),
            Path((team, created.id)),
        )
        .await
        .unwrap_err();
        assert_eq!(err, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_grant_can_never_confer_ownership() {
        // A link that mints owners is a privilege-escalation primitive, and the
        // create gate is held by managers who are not owners themselves.
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;

        let err = create_grant(
            State(pool.clone()),
            Extension(AuthUser(manager)),
            Extension(SyncNotifier::new()),
            Extension(mint_budget()),
            Path(team),
            Json(CreateGrantRequest {
                role: Some("owner".to_string()),
                max_uses: None,
                expires_in_secs: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn revoking_a_grant_from_another_team_is_not_found() {
        let pool = test_pool_or_skip!();
        let (team, _o, manager) = seed_team_with_manager(&pool).await;
        let (other_team, _oo, other_manager) = seed_team_with_manager(&pool).await;

        let created = mint(&pool, team, manager, "member", 1).await;

        let err = revoke_grant(
            State(pool.clone()),
            Extension(AuthUser(other_manager)),
            Extension(SyncNotifier::new()),
            Path((other_team, created.id)),
        )
        .await
        .unwrap_err();
        assert_eq!(err, StatusCode::NOT_FOUND);
        assert!(grants::preview(&pool, created.id, &created.secret).await.is_ok());
    }

    // ─── The role is fixed at creation ───────────────────────────────────────

    #[tokio::test]
    async fn the_redeemer_cannot_override_the_baked_in_role() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let joiner = seed_user(&pool).await;

        let created = mint(&pool, team, manager, "member", 1).await;

        // A body that tries to name its own role. The request type has no such
        // field, so serde drops it; this asserts that stays true.
        let body: RedeemGrantRequest = serde_json::from_value(serde_json::json!({
            "secret": created.secret,
            "public_key": "test-pubkey",
            "role": "owner",
            "user_id": Uuid::new_v4(),
        }))
        .expect("extra fields are ignored, not rejected");

        let Json(redeemed) = redeem_grant(
            State(pool.clone()),
            Extension(AuthUser(joiner)),
            Extension(SyncNotifier::new()),
            Extension(redeem_budget()),
            Path(created.id),
            Json(body),
        )
        .await
        .expect("redeem");

        assert_eq!(redeemed.role, "member");
        assert_eq!(assigned_role(&pool, team, joiner).await.as_deref(), Some("member"));
    }

    #[tokio::test]
    async fn the_caller_token_decides_who_joins_not_the_body() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let joiner = seed_user(&pool).await;
        let victim = seed_user(&pool).await;

        let created = mint(&pool, team, manager, "member", 1).await;
        let body: RedeemGrantRequest = serde_json::from_value(serde_json::json!({
            "secret": created.secret,
            "public_key": "test-pubkey",
            "user_id": victim,
        }))
        .unwrap();

        let _ = redeem_grant(
            State(pool.clone()),
            Extension(AuthUser(joiner)),
            Extension(SyncNotifier::new()),
            Extension(redeem_budget()),
            Path(created.id),
            Json(body),
        )
        .await
        .expect("redeem");

        assert!(assigned_role(&pool, team, joiner).await.is_some());
        assert!(
            assigned_role(&pool, team, victim).await.is_none(),
            "a body field must never be able to enrol someone else"
        );
    }

    // ─── Expiry, revocation, exhaustion ──────────────────────────────────────

    #[tokio::test]
    async fn an_expired_grant_neither_previews_nor_redeems() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let joiner = seed_user(&pool).await;

        let created = mint(&pool, team, manager, "member", 5).await;
        sqlx::query("UPDATE team_join_grants SET expires_at = now() - interval '1 second' WHERE id = $1")
            .bind(created.id)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            grants::preview(&pool, created.id, &created.secret).await.unwrap_err(),
            GrantRejection::Expired
        );
        assert_eq!(
            redeem(&pool, created.id, &created.secret, joiner).await.unwrap_err(),
            StatusCode::GONE
        );
        assert!(assigned_role(&pool, team, joiner).await.is_none());
        assert_eq!(uses_of(&pool, created.id).await, 0);
    }

    #[tokio::test]
    async fn revocation_takes_effect_on_the_live_redeem_path() {
        // The failure this guards against: a revoked-in-DB grant that still
        // authorises because something upstream resolved it earlier.
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let first = seed_user(&pool).await;
        let second = seed_user(&pool).await;

        let created = mint(&pool, team, manager, "member", 5).await;
        assert!(redeem(&pool, created.id, &created.secret, first).await.is_ok());

        assert_eq!(
            revoke_grant(
                State(pool.clone()),
                Extension(AuthUser(manager)),
                Extension(SyncNotifier::new()),
                Path((team, created.id)),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );

        assert_eq!(
            redeem(&pool, created.id, &created.secret, second).await.unwrap_err(),
            StatusCode::GONE
        );
        assert_eq!(
            grants::preview(&pool, created.id, &created.secret).await.unwrap_err(),
            GrantRejection::Revoked
        );
        assert!(assigned_role(&pool, team, second).await.is_none());
        assert_eq!(uses_of(&pool, created.id).await, 1, "the refused redemption consumed nothing");

        // Revoked grants leave the list; a second revoke has nothing to do.
        let Json(live) = list_grants(State(pool.clone()), Extension(AuthUser(manager)), Path(team))
            .await
            .unwrap();
        assert!(live.iter().all(|g| g.id != created.id));
    }

    #[tokio::test]
    async fn uses_are_exhausted_at_max_uses() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let created = mint(&pool, team, manager, "member", 2).await;

        for _ in 0..2 {
            let joiner = seed_user(&pool).await;
            assert!(redeem(&pool, created.id, &created.secret, joiner).await.is_ok());
        }

        let late = seed_user(&pool).await;
        assert_eq!(
            redeem(&pool, created.id, &created.secret, late).await.unwrap_err(),
            StatusCode::CONFLICT
        );
        assert!(assigned_role(&pool, team, late).await.is_none());
        assert_eq!(uses_of(&pool, created.id).await, 2);
    }

    #[tokio::test]
    async fn two_clients_racing_the_last_use_cannot_both_succeed() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let created = mint(&pool, team, manager, "member", 1).await;

        let a = seed_user(&pool).await;
        let b = seed_user(&pool).await;

        let (ra, rb) = tokio::join!(
            redeem(&pool, created.id, &created.secret, a),
            redeem(&pool, created.id, &created.secret, b),
        );

        let winners = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
        assert_eq!(winners, 1, "exactly one redemption may take the last use");
        for loser in [&ra, &rb].into_iter().filter(|r| r.is_err()) {
            assert_eq!(*loser.as_ref().unwrap_err(), StatusCode::CONFLICT);
        }

        assert_eq!(uses_of(&pool, created.id).await, 1);
        let members: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM team_members WHERE team_id = $1 AND user_id = ANY($2)",
        )
        .bind(team)
        .bind(vec![a, b])
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(members, 1);
    }

    // ─── Already a member ────────────────────────────────────────────────────

    #[tokio::test]
    async fn redeeming_as_an_existing_member_succeeds_without_consuming_a_use() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let created = mint(&pool, team, manager, "member", 1).await;

        // The manager is already on the team.
        let Json(redeemed) = redeem(&pool, created.id, &created.secret, manager)
            .await
            .expect("an existing member gets a success, not an error");
        assert_eq!(redeemed.team_id, team);
        assert_eq!(uses_of(&pool, created.id).await, 0);

        // The single use is therefore still available to a real joiner.
        let joiner = seed_user(&pool).await;
        assert!(redeem(&pool, created.id, &created.secret, joiner).await.is_ok());
        assert_eq!(uses_of(&pool, created.id).await, 1);
    }

    #[tokio::test]
    async fn an_existing_member_keeps_the_role_they_already_have() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let created = mint(&pool, team, manager, "connect-only", 5).await;
        let before = assigned_role(&pool, team, manager).await;

        let _ = redeem(&pool, created.id, &created.secret, manager).await.unwrap();

        assert_eq!(
            assigned_role(&pool, team, manager).await,
            before,
            "a no-op redemption must not re-role an existing member"
        );
    }

    // ─── Secrets, previews and lookups ───────────────────────────────────────

    #[tokio::test]
    async fn the_secret_is_stored_only_as_a_hash() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let created = mint(&pool, team, manager, "member", 1).await;

        let matches: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM team_join_grants \
             WHERE id = $1 AND secret_hash = sha256(convert_to($2, 'UTF8'))",
        )
        .bind(created.id)
        .bind(&created.secret)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(matches, 1, "the column holds sha256(secret), nothing else");

        // Nothing on the read paths can hand the secret back.
        let Json(live) = list_grants(State(pool.clone()), Extension(AuthUser(manager)), Path(team))
            .await
            .unwrap();
        let listed = serde_json::to_string(&live).unwrap();
        assert!(!listed.contains(&created.secret));
        assert!(!listed.contains("account_id"));
    }

    #[tokio::test]
    async fn a_wrong_secret_is_indistinguishable_from_an_unknown_grant() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let joiner = seed_user(&pool).await;
        let created = mint(&pool, team, manager, "member", 1).await;

        for (id, secret) in [
            (created.id, "wrong-secret"),
            (Uuid::new_v4(), created.secret.as_str()),
        ] {
            assert_eq!(
                preview_grant(
                    State(pool.clone()),
                    Extension(AuthUser(joiner)),
                    Extension(redeem_budget()),
                    Path(id),
                    Json(SecretRequest { secret: secret.to_string() }),
                )
                .await
                .unwrap_err(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                redeem(&pool, id, secret, joiner).await.unwrap_err(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn preview_names_the_team_role_and_inviter_without_joining() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let joiner = seed_user(&pool).await;
        let created = mint(&pool, team, manager, "editor", 3).await;

        let Json(preview) = preview_grant(
            State(pool.clone()),
            Extension(AuthUser(joiner)),
            Extension(redeem_budget()),
            Path(created.id),
            Json(SecretRequest { secret: created.secret.clone() }),
        )
        .await
        .unwrap();

        assert_eq!(preview.team_name, "test-team");
        assert_eq!(preview.role, "editor");
        let manager_handle =
            sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE id = $1")
                .bind(manager)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(preview.inviter_handle.as_deref(), Some(manager_handle.as_str()));

        assert!(assigned_role(&pool, team, joiner).await.is_none());
        assert_eq!(uses_of(&pool, created.id).await, 0);
    }

    // ─── Key distribution ────────────────────────────────────────────────────

    #[tokio::test]
    async fn redemption_records_a_missing_public_key_but_never_replaces_one() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let created = mint(&pool, team, manager, "member", 5).await;

        let keyless = seed_user(&pool).await;
        sqlx::query("UPDATE users SET public_key = NULL WHERE id = $1")
            .bind(keyless)
            .execute(&pool)
            .await
            .unwrap();

        let _ = redeem_grant(
            State(pool.clone()),
            Extension(AuthUser(keyless)),
            Extension(SyncNotifier::new()),
            Extension(redeem_budget()),
            Path(created.id),
            Json(RedeemGrantRequest {
                secret: created.secret.clone(),
                public_key: Some("fresh-x25519-key".to_string()),
            }),
        )
        .await
        .unwrap();

        let stored = sqlx::query_scalar::<_, Option<String>>("SELECT public_key FROM users WHERE id = $1")
            .bind(keyless)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored.as_deref(), Some("fresh-x25519-key"));

        // A user who already published a key keeps it: overwriting would orphan
        // every vault key already wrapped to it.
        let established = seed_user(&pool).await;
        let _ = redeem_grant(
            State(pool.clone()),
            Extension(AuthUser(established)),
            Extension(SyncNotifier::new()),
            Extension(redeem_budget()),
            Path(created.id),
            Json(RedeemGrantRequest {
                secret: created.secret.clone(),
                public_key: Some("a-different-key".to_string()),
            }),
        )
        .await
        .unwrap();

        let unchanged = sqlx::query_scalar::<_, Option<String>>("SELECT public_key FROM users WHERE id = $1")
            .bind(established)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(unchanged.as_deref(), Some("test-pubkey"));
    }

    #[tokio::test]
    async fn a_keyless_redeemer_who_supplies_no_key_is_refused() {
        // Admitting them would produce a member no key-holder can ever wrap
        // for: an account permanently staring at an empty vault.
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let created = mint(&pool, team, manager, "member", 5).await;

        let keyless = seed_user(&pool).await;
        sqlx::query("UPDATE users SET public_key = NULL WHERE id = $1")
            .bind(keyless)
            .execute(&pool)
            .await
            .unwrap();

        let err = redeem_grant(
            State(pool.clone()),
            Extension(AuthUser(keyless)),
            Extension(SyncNotifier::new()),
            Extension(redeem_budget()),
            Path(created.id),
            Json(RedeemGrantRequest { secret: created.secret.clone(), public_key: None }),
        )
        .await
        .unwrap_err();

        assert_eq!(err, StatusCode::BAD_REQUEST);
        assert!(assigned_role(&pool, team, keyless).await.is_none());
        assert_eq!(uses_of(&pool, created.id).await, 0, "a refused join consumes nothing");
    }

    #[tokio::test]
    async fn redemption_fires_the_team_members_event_key_holders_listen_for() {
        // This is what stops a joiner sitting in an empty vault: an online
        // key-holder's reconcileTeamVaultKeys wakes on `team_members:<id>`.
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let created = mint(&pool, team, manager, "member", 1).await;
        let joiner = seed_user(&pool).await;

        let notifier = SyncNotifier::new();
        let mut rx = notifier.subscribe();

        let _ = redeem_with_notifier(&pool, created.id, &created.secret, joiner, notifier)
            .await
            .unwrap();

        let mut roster_events = Vec::new();
        let mut membership_events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            match event {
                SyncEvent::BlobPushed { user_id, device_id }
                    if device_id == format!("team_members:{team}") =>
                {
                    roster_events.push(user_id)
                }
                SyncEvent::MembershipChanged { user_id } => membership_events.push(user_id),
                _ => {}
            }
        }

        assert!(
            roster_events.contains(&manager),
            "the existing key-holder must be told the roster changed"
        );
        assert!(
            roster_events.contains(&joiner),
            "the joiner must be told too, so their client can wait for a key"
        );
        assert_eq!(membership_events, vec![joiner]);
    }

    // ─── Seats ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_link_cannot_carry_a_team_past_the_owners_seat_cap() {
        let pool = test_pool_or_skip!();
        let (team, owner, manager) = seed_team_with_manager(&pool).await;
        // Owner and manager already occupy both seats.
        set_user_seats(&pool, owner, 2).await;

        let created = mint(&pool, team, manager, "member", 5).await;
        let joiner = seed_user(&pool).await;

        assert_eq!(
            redeem(&pool, created.id, &created.secret, joiner).await.unwrap_err(),
            StatusCode::PAYMENT_REQUIRED
        );
        assert_eq!(uses_of(&pool, created.id).await, 0);

        // An existing seat-holder is exempt: they consume no new seat.
        let second_team = seed_team_with_roles(&pool, owner).await;
        let seat_holder = manager;
        let second_grant = mint(&pool, second_team, owner, "member", 5).await;
        assert!(
            redeem(&pool, second_grant.id, &second_grant.secret, seat_holder).await.is_ok(),
            "a user already holding one of this owner's seats may join another of their teams"
        );
    }

    // ─── Audit ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_revoke_and_redeem_each_land_an_audit_row() {
        let pool = test_pool_or_skip!();
        let (team, _owner, manager) = seed_team_with_manager(&pool).await;
        let joiner = seed_user(&pool).await;

        assert!(audit_actions(&pool, team).await.is_empty());

        let created = mint(&pool, team, manager, "editor", 5).await;
        let _ = redeem(&pool, created.id, &created.secret, joiner).await.unwrap();
        revoke_grant(
            State(pool.clone()),
            Extension(AuthUser(manager)),
            Extension(SyncNotifier::new()),
            Path((team, created.id)),
        )
        .await
        .unwrap();

        assert_eq!(
            audit_actions(&pool, team).await,
            vec!["join_grant.created", "member.joined", "join_grant.revoked"],
            "all three rows must actually reach the database"
        );

        let (target_id, metadata) = sqlx::query_as::<_, (Option<String>, Option<serde_json::Value>)>(
            "SELECT target_id, metadata FROM audit_logs WHERE team_id = $1 AND action = 'member.joined'",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(target_id.as_deref(), Some(joiner.to_string().as_str()));
        let metadata = metadata.unwrap();
        assert_eq!(metadata["via"], "join_grant");
        assert_eq!(metadata["role"], "editor");
        assert_eq!(metadata["grant_id"], created.id.to_string());
        assert!(metadata.get("account_id").is_none());
    }

    // ─── Clamps ──────────────────────────────────────────────────────────────

    #[test]
    fn ttl_and_use_counts_are_clamped_into_range() {
        assert_eq!(grants::clamp_max_uses(None), 1);
        assert_eq!(grants::clamp_max_uses(Some(0)), 1);
        assert_eq!(grants::clamp_max_uses(Some(-5)), 1);
        assert_eq!(grants::clamp_max_uses(Some(1_000_000)), grants::MAX_USES_CEILING);

        assert_eq!(grants::clamp_ttl(None).num_seconds(), grants::DEFAULT_TTL_SECS);
        assert_eq!(grants::clamp_ttl(Some(-1)).num_seconds(), 60);
        assert_eq!(
            grants::clamp_ttl(Some(i64::MAX)).num_seconds(),
            grants::MAX_TTL_SECS,
            "an unattended link always expires"
        );
    }

    #[test]
    fn generated_secrets_are_url_safe_and_high_entropy() {
        let secret = grants::generate_secret();
        assert_eq!(secret.len(), 43, "43 base64url characters is 256 bits");
        assert!(secret.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(secret, grants::generate_secret());
    }
}
