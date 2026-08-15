use axum::{extract::{Path, Query, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::models::team::{Team, TeamMember, TeamRole};
use crate::routes::audit::write_audit_event;
use crate::self_host;
use crate::sync_notifier::SyncNotifier;
use crate::PresenceMap;

async fn notify_team_members(
    pool: &PgPool,
    notifier: &SyncNotifier,
    team_id: Uuid,
    payload: String,
) {
    let member_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM team_members WHERE team_id = $1")
            .bind(team_id)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    for member_id in member_ids {
        notifier.notify(member_id, payload.clone());
    }
}

pub(crate) async fn notify_team_members_changed(pool: &PgPool, notifier: &SyncNotifier, team_id: Uuid) {
    notify_team_members(pool, notifier, team_id, format!("team_members:{team_id}")).await;
}

// ─── Plan tier helper ─────────────────────────────────────────────────────────

async fn require_business_tier(pool: &PgPool, team_id: Uuid) -> Result<(), StatusCode> {
    if self_host::is_self_hosted() {
        return Ok(());
    }
    let owner_id = sqlx::query_scalar::<_, Uuid>("SELECT owner_id FROM teams WHERE id = $1")
        .bind(team_id)
        .fetch_one(pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to fetch team owner"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let tier = sqlx::query_scalar::<_, String>("SELECT subscription_tier FROM users WHERE id = $1")
        .bind(owner_id)
        .fetch_one(pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to fetch owner tier"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if tier != "business" {
        return Err(StatusCode::PAYMENT_REQUIRED);
    }
    Ok(())
}

// ─── Create team ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
}

pub async fn create_team(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<CreateTeamRequest>,
) -> Result<(StatusCode, Json<Team>), StatusCode> {
    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let team = sqlx::query_as::<_, Team>(
        "INSERT INTO teams (name, owner_id) VALUES ($1, $2) RETURNING id, name, owner_id, created_at",
    )
    .bind(&body.name)
    .bind(auth.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to create team");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query("INSERT INTO team_members (team_id, user_id) VALUES ($1, $2)")
        .bind(team.id)
        .bind(auth.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to add owner as team member");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Seed builtin roles for the new team
    for (name, permissions, position) in crate::permissions::BUILTIN_ROLES {
        sqlx::query(
            "INSERT INTO team_roles (team_id, name, permissions, is_builtin, position) VALUES ($1, $2, $3, TRUE, $4)",
        )
        .bind(team.id)
        .bind(*name)
        .bind(*permissions)
        .bind(*position)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, name = %name, "Failed to seed builtin role");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Assign owner role to creator
    sqlx::query(
        r#"INSERT INTO team_member_roles (team_id, user_id, role_id)
           SELECT $1, $2, id FROM team_roles
           WHERE team_id = $1 AND name = 'owner' AND is_builtin = TRUE"#,
    )
    .bind(team.id)
    .bind(auth.0)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to assign owner role");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit team creation transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(team_id = %team.id, owner_id = %auth.0, "Team created");
    Ok((StatusCode::CREATED, Json(team)))
}

// ─── List my teams ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TeamWithRole {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub owner_tier: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub role_ids: Vec<Uuid>,
}

pub async fn list_teams(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<Vec<TeamWithRole>>, StatusCode> {
    // Returns one row per (team, role) — aggregated in Rust
    let rows = sqlx::query_as::<_, (Uuid, String, Uuid, String, chrono::DateTime<chrono::Utc>, Option<Uuid>)>(
        r#"
        SELECT t.id, t.name, t.owner_id, u.subscription_tier, t.created_at, tmr.role_id
        FROM teams t
        JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = $1
        JOIN users u ON u.id = t.owner_id
        LEFT JOIN team_member_roles tmr ON tmr.team_id = t.id AND tmr.user_id = $1
        ORDER BY t.created_at ASC, tmr.role_id ASC NULLS LAST
        "#,
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list teams");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut teams: Vec<TeamWithRole> = Vec::new();
    for (id, name, owner_id, owner_tier, created_at, role_id) in rows {
        match teams.last_mut() {
            Some(last) if last.id == id => {
                if let Some(rid) = role_id {
                    last.role_ids.push(rid);
                }
            }
            _ => {
                teams.push(TeamWithRole {
                    id,
                    name,
                    owner_id,
                    owner_tier,
                    created_at,
                    role_ids: role_id.into_iter().collect(),
                });
            }
        }
    }

    Ok(Json(teams))
}

// ─── Get team members ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct TeamMemberResponse {
    #[serde(flatten)]
    member: TeamMember,
    is_online: bool,
}

fn member_public_key_for_response(public_key: Option<String>) -> String {
    public_key.unwrap_or_default()
}

#[cfg(test)]
mod team_member_tests {
    use super::*;

    #[test]
    fn nullable_member_public_key_serializes_as_empty_string() {
        assert_eq!(member_public_key_for_response(None), "");
        assert_eq!(
            member_public_key_for_response(Some("public-key".to_string())),
            "public-key",
        );
    }
}

pub async fn list_members(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(presence): axum::Extension<PresenceMap>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
) -> Result<Json<Vec<TeamMemberResponse>>, StatusCode> {
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to check team membership");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        warn!(team_id = %team_id, user_id = %auth.0, "Non-member tried to list team members");
        return Err(StatusCode::FORBIDDEN);
    }

    // Returns one row per (member, role) — aggregated in Rust
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            Uuid,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
            String,
            String,
            Option<String>,
            Option<Uuid>,
        ),
    >(
        r#"
        SELECT tm.team_id, tm.user_id, inv.display_name AS invited_by_display_name, tm.joined_at,
               u.display_name, u.handle, u.public_key, tmr.role_id
        FROM team_members tm
        JOIN users u ON u.id = tm.user_id
        LEFT JOIN users inv ON inv.id = tm.invited_by
        LEFT JOIN team_member_roles tmr ON tmr.team_id = tm.team_id AND tmr.user_id = tm.user_id
        WHERE tm.team_id = $1
        ORDER BY tm.joined_at ASC, tmr.role_id ASC NULLS LAST
        "#,
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list team members");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut members: Vec<TeamMemberResponse> = Vec::new();
    for (t_id, user_id, invited_by_display_name, joined_at, display_name, handle, public_key, role_id) in rows
    {
        match members.last_mut() {
            Some(last) if last.member.user_id == user_id => {
                if let Some(rid) = role_id {
                    last.member.role_ids.push(rid);
                }
            }
            _ => {
                members.push(TeamMemberResponse {
                    is_online: presence.contains_key(&user_id),
                    member: TeamMember {
                        team_id: t_id,
                        user_id,
                        display_name,
                        handle,
                        public_key: member_public_key_for_response(public_key),
                        invited_by_display_name,
                        joined_at,
                        role_ids: role_id.into_iter().collect(),
                    },
                });
            }
        }
    }

    Ok(Json(members))
}

// ─── Add member (by email or user_id) ────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub email: Option<String>,
    pub user_id: Option<Uuid>,
    pub role: Option<String>,
}

pub async fn add_member(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
    Json(body): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<InviteMemberResponse>), StatusCode> {
    let can_invite = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_INVITE_MEMBERS,
    )
    .await?;
    if !can_invite {
        warn!(team_id = %team_id, user_id = %auth.0, "Insufficient permission to invite members");
        return Err(StatusCode::FORBIDDEN);
    }

    let invitee_id: Uuid = if let Some(uid) = body.user_id {
        let exists = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .map_err(|e| { error!(error = %e, "Failed to verify user"); StatusCode::INTERNAL_SERVER_ERROR })?;
        if !exists { return Err(StatusCode::NOT_FOUND); }
        uid
    } else if let Some(email) = &body.email {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE email = $1")
            .bind(crate::email::normalize(email))
            .fetch_optional(&pool)
            .await
            .map_err(|e| { error!(error = %e, "Failed to find user by email"); StatusCode::INTERNAL_SERVER_ERROR })?
            .ok_or_else(|| { warn!("Invite target not found"); StatusCode::NOT_FOUND })?
    } else {
        return Err(StatusCode::BAD_REQUEST);
    };

    if invitee_id == auth.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let owner_id = sqlx::query_scalar::<_, Uuid>("SELECT owner_id FROM teams WHERE id = $1")
        .bind(team_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to fetch team owner"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let (seat_count, trial_ends_at) = sqlx::query_as::<_, (Option<i32>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT seat_count, trial_ends_at FROM users WHERE id = $1",
    )
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to fetch seat count"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if let Some(seats) = seat_count {
        let effective_cap = if trial_ends_at.is_some() { seats.min(10) } else { seats };
        let used = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT tm.user_id)
             FROM team_members tm
             JOIN teams t ON tm.team_id = t.id
             WHERE t.owner_id = $1",
        )
        .bind(owner_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to count used seats"); StatusCode::INTERNAL_SERVER_ERROR })?;

        if used >= effective_cap as i64 {
            warn!(owner_id = %owner_id, effective_cap, used, "Seat limit reached");
            return Err(StatusCode::PAYMENT_REQUIRED);
        }
    }

    let role_name = body.role.as_deref().unwrap_or("member").to_string();
    const VALID_ROLES: &[&str] = &["owner", "manager", "editor", "member", "connect-only"];
    if !VALID_ROLES.contains(&role_name.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Already a member — no-op
    let already_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(invitee_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check existing membership"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if already_member {
        return Ok((StatusCode::OK, Json(InviteMemberResponse { status: "already_member".to_string() })));
    }

    let (invitee_email, invitee_display_name) = sqlx::query_as::<_, (String, String)>(
        "SELECT email, display_name FROM users WHERE id = $1",
    )
    .bind(invitee_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to fetch invitee"); StatusCode::INTERNAL_SERVER_ERROR })?;

    sqlx::query(
        "INSERT INTO pending_invitations (team_id, user_id, email, role, invited_by)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (team_id, email) DO UPDATE
           SET user_id = EXCLUDED.user_id,
               role = EXCLUDED.role,
               invited_by = EXCLUDED.invited_by,
               expires_at = now() + INTERVAL '7 days',
               accepted_at = NULL",
    )
    .bind(team_id)
    .bind(invitee_id)
    .bind(&invitee_email)
    .bind(&role_name)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to create pending invitation"); StatusCode::INTERNAL_SERVER_ERROR })?;

    info!(team_id = %team_id, invitee_id = %invitee_id, role = %role_name, "Pending invitation created for existing user");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.invited",
        Some("user"),
        Some(invitee_id.to_string()),
        Some(invitee_display_name),
        Some(json!({ "role": role_name, "status": "pending" })),
    ));
    // Notify the invitee so their client refreshes pending invitations
    notifier.notify_pending_invitations_changed(invitee_id);
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok((StatusCode::CREATED, Json(InviteMemberResponse { status: "pending".to_string() })))
}

// ─── Remove member ────────────────────────────────────────────────────────────

pub async fn remove_member(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::Extension(manager): axum::Extension<crate::terminal_manager::TerminalManager>,
    axum::extract::Path((team_id, user_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    if auth.0 != user_id {
        let can_manage = crate::permissions::has_team_permission(
            &pool, team_id, auth.0, crate::permissions::PERM_MANAGE_MEMBERS,
        )
        .await?;
        if !can_manage {
            warn!(team_id = %team_id, user_id = %auth.0, "Insufficient permission to remove members");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Cannot remove the team owner
    let is_owner = sqlx::query_scalar::<_, bool>(
        "SELECT owner_id = $2 FROM teams WHERE id = $1",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check team owner"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if is_owner {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin remove_member transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let result = sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
        .bind(team_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| { error!(error = %e, "Failed to remove team member"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    sqlx::query("DELETE FROM team_vault_keys WHERE team_id = $1 AND user_id = $2")
        .bind(team_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| { error!(error = %e, "Failed to remove team vault key"); StatusCode::INTERNAL_SERVER_ERROR })?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit remove_member transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Best effort, after commit: the membership row is already gone, so a
    // failure here must not fail the request.
    if let Err(e) =
        crate::routes::terminal::revoke_grants_for_departed_member(&pool, &manager, user_id).await
    {
        error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to revoke session invitee grants");
    }

    let removed_display_name = sqlx::query_scalar::<_, String>("SELECT display_name FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    info!(team_id = %team_id, removed_user_id = %user_id, "Member removed");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.removed",
        Some("user"),
        Some(user_id.to_string()),
        removed_display_name,
        None,
    ));
    notifier.notify_membership_changed(user_id);
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Delete team ──────────────────────────────────────────────────────────────

pub async fn delete_team(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let is_owner = sqlx::query_scalar::<_, bool>(
        "SELECT owner_id = $2 FROM teams WHERE id = $1",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check team ownership"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if !is_owner {
        warn!(team_id = %team_id, user_id = %auth.0, "Non-owner tried to delete team");
        return Err(StatusCode::FORBIDDEN);
    }

    let member_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM team_members WHERE team_id = $1")
            .bind(team_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!(error = %e, team_id = %team_id, "Failed to fetch team members before delete");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    sqlx::query("DELETE FROM teams WHERE id = $1")
        .bind(team_id)
        .execute(&pool)
        .await
        .map_err(|e| { error!(error = %e, team_id = %team_id, "Failed to delete team"); StatusCode::INTERNAL_SERVER_ERROR })?;

    info!(team_id = %team_id, deleted_by = %auth.0, "Team deleted by owner");
    for member_id in member_ids {
        notifier.notify_membership_changed(member_id);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ─── Search users ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SearchUsersQuery {
    pub q: String,
}

/// The teammate pair test. Four copies exist; if you change the predicate,
/// change all four:
///   - This constant, spliced via `format!` into `search_users_inner` (below,
///     in this file) and into `shares_a_team` (routes::terminal), which share
///     its `$2`/`u.id` parameter shape.
///   - The `NOT EXISTS` in `revoke_grants_for_departed_member`
///     (routes::terminal) — inlined because it binds only `$1` and needs
///     `tsi.invited_by`/`tsi.user_id`, not `$2`/`u.id`.
///   - The `connection_name` redaction `CASE` in `visible_sessions`
///     (routes::terminal) — inlined because that query already uses `$2` for
///     `PERM_VIEW_TERMINAL_SESSIONS` (an int, not a uuid), so splicing this
///     constant's hardcoded `$2` in would silently bind the wrong value.
pub(crate) const TEAMMATE_PAIR_SQL: &str = "EXISTS (SELECT 1 FROM team_members a \
     JOIN team_members b ON a.team_id = b.team_id \
     WHERE a.user_id = $2 AND b.user_id = u.id)";

#[derive(Serialize, sqlx::FromRow)]
pub struct UserSearchResult {
    pub user_id: Uuid,
    pub display_name: String,
    pub handle: String,
    pub is_teammate: bool,
}

/// Resolution rules (D2): teammates fuzzy on name and email; anyone with a
/// *custom* handle fuzzy on that handle; everyone else on a full email address
/// or an exact handle. Email substring matching is gone — it was an enumeration
/// oracle, and rate-limiting it would only have slowed the harvest down.
pub(crate) async fn search_users_inner(
    pool: &PgPool,
    me: Uuid,
    q: &str,
) -> Result<Vec<UserSearchResult>, StatusCode> {
    if q.trim().chars().count() < 2 {
        return Ok(vec![]);
    }
    let q = q.trim().to_lowercase();
    let fuzzy = format!("%{q}%");
    let prefix = format!("{q}%");
    let exact_email = if q.contains('@') && q.contains('.') { q.clone() } else { String::new() };
    let exact_handle = crate::handles::normalize_handle(&q);

    let sql = format!(
        r#"
        SELECT u.id AS user_id, u.display_name, u.handle, {pair} AS is_teammate
        FROM users u
        WHERE u.id <> $2
          AND u.deleted_at IS NULL
          AND (
               ({pair} AND (LOWER(u.display_name) LIKE $1 OR LOWER(u.email) LIKE $1))
            OR (u.handle_is_custom AND LOWER(u.handle) LIKE $1)
            OR LOWER(u.email) = $3
            OR LOWER(u.handle) = $4
          )
        ORDER BY is_teammate DESC,
                 CASE WHEN LOWER(u.display_name) LIKE $5 OR LOWER(u.handle) LIKE $5 THEN 0 ELSE 1 END,
                 u.display_name
        LIMIT 8
        "#,
        pair = TEAMMATE_PAIR_SQL,
    );

    sqlx::query_as::<_, UserSearchResult>(&sql)
        .bind(&fuzzy)
        .bind(me)
        .bind(&exact_email)
        .bind(&exact_handle)
        .bind(&prefix)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to search users");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

pub async fn search_users(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(limiter): axum::Extension<crate::rate_limit::SearchRateLimiter>,
    Query(params): Query<SearchUsersQuery>,
) -> Result<Json<Vec<UserSearchResult>>, StatusCode> {
    if !limiter.0.check(auth.0).await {
        warn!(user_id = %auth.0, "User search rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(Json(search_users_inner(&pool, auth.0, &params.q).await?))
}

// ─── Update public key ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdatePublicKeyRequest {
    pub public_key: String,
}

pub async fn update_public_key(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<UpdatePublicKeyRequest>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE users SET public_key = $1, updated_at = now() WHERE id = $2")
        .bind(&body.public_key)
        .bind(auth.0)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to update public key");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::NO_CONTENT)
}

// ─── List roles ───────────────────────────────────────────────────────────────

pub async fn list_roles(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
) -> Result<Json<Vec<TeamRole>>, StatusCode> {
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check team membership"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    let roles = sqlx::query_as::<_, TeamRole>(
        "SELECT id, team_id, name, color, permissions, is_builtin, position, created_at
         FROM team_roles WHERE team_id = $1
         ORDER BY position ASC, created_at ASC",
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to list roles"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(Json(roles))
}

// ─── Create role ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub color: Option<String>,
    pub permissions: i64,
}

pub async fn create_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
    Json(body): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<TeamRole>), StatusCode> {
    require_business_tier(&pool, team_id).await?;

    let can_manage = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_MANAGE_ROLES,
    )
    .await?;
    if !can_manage {
        return Err(StatusCode::FORBIDDEN);
    }

    if body.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let permissions = body.permissions & crate::permissions::ALL_PERMISSIONS;

    let role = sqlx::query_as::<_, TeamRole>(
        r#"INSERT INTO team_roles (team_id, name, color, permissions, is_builtin, position)
           VALUES ($1, $2, $3, $4, FALSE, 10)
           RETURNING id, team_id, name, color, permissions, is_builtin, position, created_at"#,
    )
    .bind(team_id)
    .bind(body.name.trim())
    .bind(&body.color)
    .bind(permissions)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to create role");
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.code().as_deref() == Some("23505") {
                return StatusCode::CONFLICT;
            }
        }
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(team_id = %team_id, role_id = %role.id, name = %role.name, "Custom role created");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "role.created",
        Some("role"),
        Some(role.id.to_string()),
        Some(role.name.clone()),
        Some(json!({ "permissions": role.permissions })),
    ));
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok((StatusCode::CREATED, Json(role)))
}

// ─── Update role ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateRoleBody {
    pub name: Option<String>,
    pub color: Option<String>,
    pub permissions: Option<i64>,
    pub position: Option<i32>,
}

pub async fn update_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path((team_id, role_id)): axum::extract::Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateRoleBody>,
) -> Result<StatusCode, StatusCode> {
    require_business_tier(&pool, team_id).await?;

    let can_manage = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_MANAGE_ROLES,
    )
    .await?;
    if !can_manage {
        return Err(StatusCode::FORBIDDEN);
    }

    let role_info = sqlx::query_as::<_, (bool,)>(
        "SELECT is_builtin FROM team_roles WHERE id = $1 AND team_id = $2",
    )
    .bind(role_id)
    .bind(team_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to fetch role info"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if role_info.0 {
        warn!(role_id = %role_id, "Cannot modify builtin role");
        return Err(StatusCode::FORBIDDEN);
    }

    if let Some(ref name) = body.name {
        if name.trim().is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let permissions = body.permissions.map(|p| p & crate::permissions::ALL_PERMISSIONS);

    sqlx::query(
        r#"UPDATE team_roles
           SET name        = COALESCE($1, name),
               color       = CASE WHEN $2::text IS NOT NULL THEN $2 ELSE color END,
               permissions = COALESCE($3, permissions),
               position    = COALESCE($4, position)
           WHERE id = $5 AND team_id = $6"#,
    )
    .bind(body.name.as_deref().map(str::trim))
    .bind(&body.color)
    .bind(permissions)
    .bind(body.position)
    .bind(role_id)
    .bind(team_id)
    .execute(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to update role"); StatusCode::INTERNAL_SERVER_ERROR })?;

    info!(team_id = %team_id, role_id = %role_id, "Role updated");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "role.updated",
        Some("role"),
        Some(role_id.to_string()),
        body.name.clone(),
        body.permissions.map(|p| json!({ "permissions": p })),
    ));
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Delete role ──────────────────────────────────────────────────────────────

pub async fn delete_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path((team_id, role_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    require_business_tier(&pool, team_id).await?;

    let can_manage = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_MANAGE_ROLES,
    )
    .await?;
    if !can_manage {
        return Err(StatusCode::FORBIDDEN);
    }

    let role_info = sqlx::query_as::<_, (bool,)>(
        "SELECT is_builtin FROM team_roles WHERE id = $1 AND team_id = $2",
    )
    .bind(role_id)
    .bind(team_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to fetch role info"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if role_info.0 {
        warn!(role_id = %role_id, "Cannot delete builtin role");
        return Err(StatusCode::FORBIDDEN);
    }

    // CASCADE on team_member_roles handles removal from members automatically
    let result = sqlx::query("DELETE FROM team_roles WHERE id = $1 AND team_id = $2")
        .bind(role_id)
        .bind(team_id)
        .execute(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to delete role"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    info!(team_id = %team_id, role_id = %role_id, "Custom role deleted");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "role.deleted",
        Some("role"),
        Some(role_id.to_string()),
        None,
        None,
    ));
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── List member roles ────────────────────────────────────────────────────────

pub async fn list_member_roles(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path((team_id, target_user_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<TeamRole>>, StatusCode> {
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check membership"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    let roles = sqlx::query_as::<_, TeamRole>(
        r#"SELECT tr.id, tr.team_id, tr.name, tr.color, tr.permissions, tr.is_builtin, tr.position, tr.created_at
           FROM team_member_roles tmr
           JOIN team_roles tr ON tr.id = tmr.role_id
           WHERE tmr.team_id = $1 AND tmr.user_id = $2
           ORDER BY tr.position ASC"#,
    )
    .bind(team_id)
    .bind(target_user_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to list member roles"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(Json(roles))
}

// ─── Assign role to member ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AssignRoleRequest {
    pub role_id: Uuid,
}

pub async fn assign_member_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path((team_id, target_user_id)): axum::extract::Path<(Uuid, Uuid)>,
    Json(body): Json<AssignRoleRequest>,
) -> Result<StatusCode, StatusCode> {
    let can_manage = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_MANAGE_MEMBERS,
    )
    .await?;
    if !can_manage {
        return Err(StatusCode::FORBIDDEN);
    }

    // Verify target is a member
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(target_user_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check target membership"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !is_member {
        return Err(StatusCode::NOT_FOUND);
    }

    // Verify role belongs to this team
    let role_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_roles WHERE id = $1 AND team_id = $2)",
    )
    .bind(body.role_id)
    .bind(team_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to verify role"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !role_exists {
        return Err(StatusCode::NOT_FOUND);
    }

    let target_display_name = sqlx::query_scalar::<_, String>("SELECT display_name FROM users WHERE id = $1")
        .bind(target_user_id)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    sqlx::query(
        "INSERT INTO team_member_roles (team_id, user_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(team_id)
    .bind(target_user_id)
    .bind(body.role_id)
    .execute(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to assign role"); StatusCode::INTERNAL_SERVER_ERROR })?;

    info!(team_id = %team_id, target_user_id = %target_user_id, role_id = %body.role_id, "Role assigned to member");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.role_changed",
        Some("user"),
        Some(target_user_id.to_string()),
        target_display_name,
        Some(json!({ "role_id": body.role_id, "change": "assigned" })),
    ));
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Remove role from member ──────────────────────────────────────────────────

pub async fn remove_member_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path((team_id, target_user_id, role_id)): axum::extract::Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    let can_manage = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_MANAGE_MEMBERS,
    )
    .await?;
    if !can_manage {
        return Err(StatusCode::FORBIDDEN);
    }

    // Cannot remove the owner role from the team owner
    let is_target_team_owner = sqlx::query_scalar::<_, bool>(
        "SELECT owner_id = $2 FROM teams WHERE id = $1",
    )
    .bind(team_id)
    .bind(target_user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check team owner"); StatusCode::INTERNAL_SERVER_ERROR })?
    .unwrap_or(false);

    if is_target_team_owner {
        let is_owner_role = sqlx::query_scalar::<_, bool>(
            "SELECT is_builtin AND name = 'owner' FROM team_roles WHERE id = $1 AND team_id = $2",
        )
        .bind(role_id)
        .bind(team_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to check role type"); StatusCode::INTERNAL_SERVER_ERROR })?
        .unwrap_or(false);

        if is_owner_role {
            warn!(team_id = %team_id, "Cannot remove owner role from team owner");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let result = sqlx::query(
        "DELETE FROM team_member_roles WHERE team_id = $1 AND user_id = $2 AND role_id = $3",
    )
    .bind(team_id)
    .bind(target_user_id)
    .bind(role_id)
    .execute(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to remove member role"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    let target_display_name = sqlx::query_scalar::<_, String>("SELECT display_name FROM users WHERE id = $1")
        .bind(target_user_id)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    info!(team_id = %team_id, target_user_id = %target_user_id, role_id = %role_id, "Role removed from member");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.role_changed",
        Some("user"),
        Some(target_user_id.to_string()),
        target_display_name,
        Some(json!({ "role_id": role_id, "change": "removed" })),
    ));
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Invite member (email-based) ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub role: Option<String>,
}

#[derive(Serialize)]
pub struct InviteMemberResponse {
    pub status: String,
}

pub async fn invite_member(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
    Json(body): Json<InviteMemberRequest>,
) -> Result<Json<InviteMemberResponse>, StatusCode> {
    let can_invite = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_INVITE_MEMBERS,
    )
    .await?;
    if !can_invite {
        warn!(team_id = %team_id, user_id = %auth.0, "Insufficient permission to invite members");
        return Err(StatusCode::FORBIDDEN);
    }

    let email = crate::email::normalize(&body.email);
    if email.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let role = body.role.as_deref().unwrap_or("member").to_string();

    let owner_id = sqlx::query_scalar::<_, Uuid>("SELECT owner_id FROM teams WHERE id = $1")
        .bind(team_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to fetch team owner"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let (seat_count, trial_ends_at) = sqlx::query_as::<_, (Option<i32>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT seat_count, trial_ends_at FROM users WHERE id = $1",
    )
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to fetch seat count"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if let Some(seats) = seat_count {
        let effective_cap = if trial_ends_at.is_some() { seats.min(10) } else { seats };
        let used = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT tm.user_id)
             FROM team_members tm
             JOIN teams t ON tm.team_id = t.id
             WHERE t.owner_id = $1",
        )
        .bind(owner_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to count used seats"); StatusCode::INTERNAL_SERVER_ERROR })?;

        if used >= effective_cap as i64 {
            warn!(owner_id = %owner_id, effective_cap, used, "Seat limit reached on invite");
            return Err(StatusCode::PAYMENT_REQUIRED);
        }
    }

    let existing_user = sqlx::query_as::<_, (Uuid,)>("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to look up user by email"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if let Some((user_id,)) = existing_user {
        if user_id == auth.0 {
            return Err(StatusCode::BAD_REQUEST);
        }

        let already_member = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
        )
        .bind(team_id)
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to check existing membership"); StatusCode::INTERNAL_SERVER_ERROR })?;

        if already_member {
            return Ok(Json(InviteMemberResponse { status: "already_member".to_string() }));
        }

        sqlx::query(
            "INSERT INTO pending_invitations (team_id, user_id, email, role, invited_by)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (team_id, email) DO UPDATE
               SET user_id = EXCLUDED.user_id,
                   role = EXCLUDED.role,
                   invited_by = EXCLUDED.invited_by,
                   expires_at = now() + INTERVAL '7 days',
                   accepted_at = NULL",
        )
        .bind(team_id)
        .bind(user_id)
        .bind(&email)
        .bind(&role)
        .bind(auth.0)
        .execute(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to create pending invitation for existing user"); StatusCode::INTERNAL_SERVER_ERROR })?;

        info!(team_id = %team_id, user_id = %user_id, role = %role, "Pending invitation created for existing user via invite endpoint");
        let invite_display_name = sqlx::query_scalar::<_, String>("SELECT display_name FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&pool)
            .await
            .unwrap_or(None);
        tokio::spawn(write_audit_event(
            pool.clone(),
            team_id,
            auth.0,
            "member.invited",
            Some("user"),
            Some(user_id.to_string()),
            invite_display_name,
            Some(json!({ "role": role, "status": "pending" })),
        ));
        notifier.notify_pending_invitations_changed(user_id);
        notify_team_members_changed(&pool, &notifier, team_id).await;
        return Ok(Json(InviteMemberResponse { status: "invited".to_string() }));
    }

    // User doesn't exist — create pending invitation and send email
    let inviter_email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to fetch inviter email"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let team_name = sqlx::query_scalar::<_, String>("SELECT name FROM teams WHERE id = $1")
        .bind(team_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to fetch team name"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let token: String = sqlx::query_scalar(
        "INSERT INTO pending_invitations (team_id, email, role, invited_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (team_id, email) DO UPDATE
           SET role = EXCLUDED.role,
               invited_by = EXCLUDED.invited_by,
               expires_at = now() + INTERVAL '7 days',
               accepted_at = NULL
         RETURNING token",
    )
    .bind(team_id)
    .bind(&email)
    .bind(&role)
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to create pending invitation"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let app_url = std::env::var("VOLTIUS_APP_URL")
        .unwrap_or_else(|_| "https://app.voltius.app".to_string());

    if let Err(e) = crate::email::send_team_invitation(&email, &team_name, &inviter_email, &token, &app_url).await {
        error!(error = %e, "Failed to send invitation email");
    }

    info!(team_id = %team_id, email = %email, "Pending invitation created");
    let invite_display_name = email.split('@').next().unwrap_or(&email).to_string();
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.invited",
        Some("user"),
        None,
        Some(invite_display_name),
        Some(json!({ "role": role, "status": "pending" })),
    ));
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(Json(InviteMemberResponse { status: "invited".to_string() }))
}

// ─── List pending invitations ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct PendingInvitation {
    pub id: Uuid,
    pub display_name: String,
    pub role: String,
    pub invited_by_display_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_pending_invitations(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
) -> Result<Json<Vec<PendingInvitation>>, StatusCode> {
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check membership"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    let rows = sqlx::query_as::<_, (Uuid, String, String, Option<String>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>(
        r#"SELECT pi.id, COALESCE(invitee.display_name, pi.email), pi.role, inv.display_name, pi.created_at, pi.expires_at
           FROM pending_invitations pi
           LEFT JOIN users inv ON inv.id = pi.invited_by
           LEFT JOIN users invitee ON invitee.id = pi.user_id
           WHERE pi.team_id = $1
             AND pi.accepted_at IS NULL
             AND pi.expires_at > now()
           ORDER BY pi.created_at DESC"#,
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to list pending invitations"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, display_name, role, invited_by_display_name, created_at, expires_at)| PendingInvitation {
                id, display_name, role, invited_by_display_name, created_at, expires_at,
            })
            .collect(),
    ))
}

// ─── Revoke pending invitation ────────────────────────────────────────────────

pub async fn revoke_pending_invitation(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path((team_id, invitation_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    let can_manage = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_MANAGE_MEMBERS,
    )
    .await?;
    if !can_manage {
        return Err(StatusCode::FORBIDDEN);
    }

    let result = sqlx::query(
        "DELETE FROM pending_invitations WHERE id = $1 AND team_id = $2",
    )
    .bind(invitation_id)
    .bind(team_id)
    .execute(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to revoke invitation"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    info!(team_id = %team_id, invitation_id = %invitation_id, "Pending invitation revoked");
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod authz_tests {
    //! Handler-level enforcement locks: each test seeds a member WITHOUT the
    //! required permission bit and asserts the handler rejects with FORBIDDEN,
    //! plus a positive case with the bit granted. Requires TEST_DATABASE_URL.
    use super::*;
    use crate::auth::AuthUser;
    use crate::permissions::{
        PERM_INVITE_MEMBERS, PERM_MANAGE_MEMBERS, PERM_MANAGE_ROLES, PERM_VIEW_SECRETS,
    };
    use crate::sync_notifier::SyncNotifier;
    use crate::terminal_manager::TerminalManager;
    use crate::test_pool_or_skip;
    use crate::test_support::{
        add_member as add_team_member, env_lock, member_with_role, seed_role, seed_team,
        seed_user, set_user_seats, set_user_tier, set_user_trial,
    };
    use axum::extract::{Path, State};
    use axum::{Extension, Json};

    /// Insert a bare `terminal_sessions` row — the invitee-revoke tests only
    /// need it to satisfy `terminal_session_invitees`'s FK, not a full session.
    async fn seed_direct_session(pool: &PgPool, host: Uuid) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO terminal_sessions (host_user_id, connection_name, visibility) \
             VALUES ($1, 'web-prod', 'direct') RETURNING id",
        )
        .bind(host)
        .fetch_one(pool)
        .await
        .expect("insert session")
    }

    async fn seed_invitee_grant(pool: &PgPool, session_id: Uuid, user_id: Uuid, invited_by: Uuid) {
        sqlx::query(
            "INSERT INTO terminal_session_invitees (session_id, user_id, invited_by) \
             VALUES ($1, $2, $3)",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(invited_by)
        .execute(pool)
        .await
        .expect("insert invitee grant");
    }

    /// WebSocket admission for the live session, computed the way the socket
    /// handler computes it — from the in-memory set, not the table.
    async fn admits_over_ws(
        pool: &PgPool,
        manager: &TerminalManager,
        session_id: Uuid,
        host: Uuid,
        user: Uuid,
    ) -> bool {
        let invitees = manager
            .sessions
            .lock()
            .await
            .get(&session_id)
            .expect("live session")
            .invitees
            .clone();
        crate::routes::terminal::is_authorized_participant(
            pool, user, host, "direct", &[], &[], None, None, &invitees,
        )
        .await
    }

    /// Seeds a live session plus a real grant through `grant_invitee`, so the
    /// in-memory admission set is populated exactly as a live session's is.
    async fn seed_live_session_with_grant(
        pool: &PgPool,
        host: Uuid,
        invitee: Uuid,
    ) -> (Uuid, TerminalManager) {
        let session_id = seed_direct_session(pool, host).await;
        let manager = TerminalManager::new();
        manager.insert_test_session(session_id, host).await;
        crate::routes::terminal::grant_invitee(
            pool,
            &SyncNotifier::new(),
            &manager,
            &crate::test_support::default_knock_limiter(),
            session_id,
            host,
            invitee,
            "wrapped",
        )
        .await
        .expect("grant");
        (session_id, manager)
    }

    async fn key_count(pool: &PgPool, session_id: Uuid, user_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_keys WHERE session_id = $1 AND user_id = $2",
        )
        .bind(session_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn grant_count(pool: &PgPool, session_id: Uuid, user_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2",
        )
        .bind(session_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn add_member_forbidden_without_invite_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Caller is a member but has only VIEW_SECRETS, not INVITE_MEMBERS.
        let caller = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;
        let invitee = seed_user(&pool).await;

        let res = add_member(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(AddMemberRequest {
                user_id: Some(invitee),
                email: None,
                role: None,
            }),
        )
        .await;

        // `InviteMemberResponse` (the Ok payload) has no `Debug` impl, so
        // `unwrap_err()` doesn't typecheck here — match instead.
        match res {
            Err(status) => assert_eq!(status, axum::http::StatusCode::FORBIDDEN),
            Ok(_) => panic!("expected FORBIDDEN, got Ok"),
        }
    }

    #[tokio::test]
    async fn add_member_allowed_with_invite_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_INVITE_MEMBERS).await;
        let invitee = seed_user(&pool).await;

        let res = add_member(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(AddMemberRequest {
                user_id: Some(invitee),
                email: None,
                role: None,
            }),
        )
        .await;

        assert!(res.is_ok(), "expected Ok, got {:?}", res.err());
    }

    #[tokio::test]
    async fn list_members_returns_each_members_own_handle() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = seed_user(&pool).await;
        let other = seed_user(&pool).await;
        add_team_member(&pool, team, caller).await;
        add_team_member(&pool, team, other).await;

        let caller_handle: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
            .bind(caller)
            .fetch_one(&pool)
            .await
            .unwrap();
        let other_handle: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
            .bind(other)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(caller_handle, other_handle);

        let presence: PresenceMap = std::sync::Arc::new(dashmap::DashMap::new());
        let members = list_members(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(presence),
            Path(team),
        )
        .await
        .expect("list members")
        .0;

        let handle_of = |id: Uuid| {
            members
                .iter()
                .find(|m| m.member.user_id == id)
                .expect("member present")
                .member
                .handle
                .clone()
        };
        assert_eq!(handle_of(caller), caller_handle);
        assert_eq!(handle_of(other), other_handle);
    }

    #[tokio::test]
    async fn remove_member_forbidden_without_manage_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;
        let victim = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;

        let res = remove_member(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(TerminalManager::new()),
            Path((team, victim)),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn remove_member_allows_self_removal_without_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Caller has NO management perm but removes themselves — allowed.
        let caller = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;

        let res = remove_member(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(TerminalManager::new()),
            Path((team, caller)),
        )
        .await;

        assert!(res.is_ok(), "self-removal should succeed, got {:?}", res.err());
    }

    #[tokio::test]
    async fn removing_a_member_revokes_grants_from_a_host_they_no_longer_share_a_team_with() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_team_member(&pool, team, host).await;
        add_team_member(&pool, team, mate).await;
        let session_id = seed_direct_session(&pool, host).await;
        seed_invitee_grant(&pool, session_id, mate, host).await;

        let res = remove_member(
            State(pool.clone()),
            Extension(AuthUser(mate)),
            Extension(SyncNotifier::new()),
            Extension(TerminalManager::new()),
            Path((team, mate)),
        )
        .await;

        assert!(res.is_ok(), "self-removal should succeed, got {:?}", res.err());
        assert_eq!(
            grant_count(&pool, session_id, mate).await,
            0,
            "leaving the only shared team must revoke the grant"
        );
    }

    #[tokio::test]
    async fn removing_a_member_from_one_of_two_shared_teams_leaves_the_grant_intact() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let team_a = seed_team(&pool, host).await;
        let team_b = seed_team(&pool, host).await;
        add_team_member(&pool, team_a, host).await;
        add_team_member(&pool, team_a, mate).await;
        add_team_member(&pool, team_b, host).await;
        add_team_member(&pool, team_b, mate).await;
        let session_id = seed_direct_session(&pool, host).await;
        seed_invitee_grant(&pool, session_id, mate, host).await;

        let res = remove_member(
            State(pool.clone()),
            Extension(AuthUser(mate)),
            Extension(SyncNotifier::new()),
            Extension(TerminalManager::new()),
            Path((team_a, mate)),
        )
        .await;

        assert!(res.is_ok(), "self-removal should succeed, got {:?}", res.err());
        assert_eq!(
            grant_count(&pool, session_id, mate).await,
            1,
            "host and invitee still share team_b, so the grant must survive"
        );
    }

    #[tokio::test]
    async fn removing_a_member_does_not_touch_an_unrelated_users_grant() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let stranger = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_team_member(&pool, team, host).await;
        add_team_member(&pool, team, mate).await;
        add_team_member(&pool, team, stranger).await;
        let session_id = seed_direct_session(&pool, host).await;
        seed_invitee_grant(&pool, session_id, mate, host).await;
        seed_invitee_grant(&pool, session_id, stranger, host).await;

        let res = remove_member(
            State(pool.clone()),
            Extension(AuthUser(mate)),
            Extension(SyncNotifier::new()),
            Extension(TerminalManager::new()),
            Path((team, mate)),
        )
        .await;

        assert!(res.is_ok(), "self-removal should succeed, got {:?}", res.err());
        assert_eq!(
            grant_count(&pool, session_id, stranger).await,
            1,
            "removing mate must not touch a grant belonging to a different invitee"
        );
    }

    #[tokio::test]
    async fn removing_a_member_closes_ws_admission_and_deletes_their_wrapped_key() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_team_member(&pool, team, host).await;
        add_team_member(&pool, team, mate).await;
        let (session_id, manager) = seed_live_session_with_grant(&pool, host, mate).await;
        assert!(admits_over_ws(&pool, &manager, session_id, host, mate).await);

        let res = remove_member(
            State(pool.clone()),
            Extension(AuthUser(mate)),
            Extension(SyncNotifier::new()),
            Extension(manager.clone()),
            Path((team, mate)),
        )
        .await;

        assert!(res.is_ok(), "self-removal should succeed, got {:?}", res.err());
        assert!(
            !admits_over_ws(&pool, &manager, session_id, host, mate).await,
            "a removed teammate must no longer be admitted to the still-live session"
        );
        assert_eq!(
            key_count(&pool, session_id, mate).await,
            0,
            "the wrapped key GET .../key serves must go with the grant"
        );
    }

    #[tokio::test]
    async fn removing_the_inviter_revokes_the_grants_they_issued() {
        let pool = test_pool_or_skip!();
        // Owned by a third party: the owner cannot be removed from their team.
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let host = seed_user(&pool).await;
        let guest = seed_user(&pool).await;
        add_team_member(&pool, team, host).await;
        add_team_member(&pool, team, guest).await;
        let (session_id, manager) = seed_live_session_with_grant(&pool, host, guest).await;

        // The *inviter* leaves the only team they share with their guest —
        // `grant_invitee` would now refuse the invite, so the grant must go too.
        let res = remove_member(
            State(pool.clone()),
            Extension(AuthUser(host)),
            Extension(SyncNotifier::new()),
            Extension(manager.clone()),
            Path((team, host)),
        )
        .await;

        assert!(res.is_ok(), "self-removal should succeed, got {:?}", res.err());
        assert_eq!(
            grant_count(&pool, session_id, guest).await,
            0,
            "a grant dies when its inviter stops being a teammate, not only its holder"
        );
        assert!(
            !admits_over_ws(&pool, &manager, session_id, host, guest).await,
            "the guest must lose admission to the session too"
        );
    }

    #[tokio::test]
    async fn assign_member_role_forbidden_without_manage_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;
        let target = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;
        let new_role = seed_role(&pool, team, "assignable", PERM_VIEW_SECRETS).await;

        let res = assign_member_role(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, target)),
            Json(AssignRoleRequest { role_id: new_role }),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    /// Wraps the env mutex guard so it isn't a bare `MutexGuard` binding —
    /// clippy's `await_holding_lock` only fires on the direct type, and this
    /// lock is process-global/test-only with no real contention risk.
    #[allow(dead_code)]
    struct EnvLockGuard(std::sync::MutexGuard<'static, ()>);

    #[tokio::test]
    async fn create_role_forbidden_without_manage_roles() {
        // No LEMONSQUEEZY_API_KEY in test env → business gate is bypassed, so the
        // PERM_MANAGE_ROLES check is what rejects here. Hold the env lock (without
        // mutating anything) so this can't race against a concurrently-running
        // BillingEnv-holding test that sets LEMONSQUEEZY_API_KEY out from under us.
        let _env = EnvLockGuard(env_lock());
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await; // has members, not roles

        let res = create_role(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(CreateRoleRequest {
                name: "custom".to_string(),
                color: None,
                permissions: PERM_VIEW_SECRETS,
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    /// RAII guard: set LEMONSQUEEZY_API_KEY so is_self_hosted()==false, restore on drop.
    /// Field 0 (the lock) is held only for its lifetime, never read.
    #[allow(dead_code)]
    struct BillingEnv(std::sync::MutexGuard<'static, ()>, Option<String>);
    impl BillingEnv {
        fn on() -> Self {
            let g = env_lock();
            let prev = std::env::var("LEMONSQUEEZY_API_KEY").ok();
            std::env::set_var("LEMONSQUEEZY_API_KEY", "test-key");
            BillingEnv(g, prev)
        }
    }
    impl Drop for BillingEnv {
        fn drop(&mut self) {
            match &self.1 {
                Some(v) => std::env::set_var("LEMONSQUEEZY_API_KEY", v),
                None => std::env::remove_var("LEMONSQUEEZY_API_KEY"),
            }
        }
    }

    #[tokio::test]
    async fn create_role_payment_required_when_owner_not_business() {
        let _env = BillingEnv::on();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await; // default tier 'free'
        let team = seed_team(&pool, owner).await;
        // Caller HAS manage-roles, so only the business gate can reject.
        let caller = member_with_role(&pool, team, PERM_MANAGE_ROLES).await;

        let res = create_role(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(CreateRoleRequest {
                name: "custom".to_string(),
                color: None,
                permissions: PERM_VIEW_SECRETS,
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn create_role_ok_when_business_and_manage_roles() {
        let _env = BillingEnv::on();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "business").await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_MANAGE_ROLES).await;

        let res = create_role(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(CreateRoleRequest {
                name: "custom".to_string(),
                color: None,
                permissions: PERM_VIEW_SECRETS,
            }),
        )
        .await;

        assert!(res.is_ok(), "expected Ok, got {:?}", res.err());
    }

    #[tokio::test]
    async fn update_role_forbidden_without_manage_roles() {
        // Same shape as create_role: no LEMONSQUEEZY_API_KEY → business gate
        // bypassed, so PERM_MANAGE_ROLES is what rejects. Both gates fire
        // before the role lookup, so a random role_id is fine. Hold the env
        // lock (without mutating anything) so this can't race a concurrently
        // running BillingEnv-holding test that sets LEMONSQUEEZY_API_KEY.
        let _env = EnvLockGuard(env_lock());
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;

        let res = update_role(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, Uuid::new_v4())),
            Json(UpdateRoleBody {
                name: Some("renamed".to_string()),
                color: None,
                permissions: None,
                position: None,
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn update_role_payment_required_when_owner_not_business() {
        let _env = BillingEnv::on();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await; // default tier 'free'
        let team = seed_team(&pool, owner).await;
        // Caller HAS manage-roles, so only the business gate can reject.
        let caller = member_with_role(&pool, team, PERM_MANAGE_ROLES).await;

        let res = update_role(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, Uuid::new_v4())),
            Json(UpdateRoleBody {
                name: Some("renamed".to_string()),
                color: None,
                permissions: None,
                position: None,
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn update_role_ok_when_business_and_manage_roles() {
        let _env = BillingEnv::on();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "business").await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_MANAGE_ROLES).await;
        let role = seed_role(&pool, team, "editable", PERM_VIEW_SECRETS).await; // non-builtin

        let res = update_role(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, role)),
            Json(UpdateRoleBody {
                name: Some("renamed".to_string()),
                color: None,
                permissions: None,
                position: None,
            }),
        )
        .await;

        assert!(res.is_ok(), "expected Ok, got {:?}", res.err());
    }

    #[tokio::test]
    async fn add_member_payment_required_when_seats_exhausted() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        // No trial_ends_at (default NULL) → effective cap == seat_count.
        set_user_seats(&pool, owner, 1).await;
        let team = seed_team(&pool, owner).await;

        // A caller that CAN invite, so only the seat cap can reject.
        let inviter = member_with_role(&pool, team, PERM_INVITE_MEMBERS).await;
        // `member_with_role` adds `inviter` to `team_members`; `seed_team` does
        // NOT add the owner, so `inviter` alone already fills the single seat.
        let invitee = seed_user(&pool).await;

        let res = add_member(
            State(pool.clone()),
            Extension(AuthUser(inviter)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(AddMemberRequest {
                user_id: Some(invitee),
                email: None,
                role: None,
            }),
        )
        .await;

        // `InviteMemberResponse` (the Ok payload) has no `Debug` impl, so
        // `unwrap_err()` doesn't typecheck here — match instead.
        match res {
            Err(status) => assert_eq!(status, axum::http::StatusCode::PAYMENT_REQUIRED),
            Ok(_) => panic!("expected PAYMENT_REQUIRED, got Ok"),
        }
    }

    #[tokio::test]
    async fn add_member_ok_when_seats_available() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_seats(&pool, owner, 50).await;
        let team = seed_team(&pool, owner).await;
        let inviter = member_with_role(&pool, team, PERM_INVITE_MEMBERS).await;
        let invitee = seed_user(&pool).await;

        let res = add_member(
            State(pool.clone()),
            Extension(AuthUser(inviter)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(AddMemberRequest {
                user_id: Some(invitee),
                email: None,
                role: None,
            }),
        )
        .await;

        assert!(res.is_ok(), "expected Ok, got {:?}", res.err());
    }

    /// Fill `team` with `n` distinct members (one holding INVITE_MEMBERS). Returns
    /// the inviter. Owner is not a member (seed_team doesn't add them), so the used
    /// seat count equals `n`.
    async fn fill_seats(pool: &sqlx::PgPool, team: Uuid, n: usize) -> Uuid {
        let inviter = member_with_role(pool, team, PERM_INVITE_MEMBERS).await;
        for _ in 1..n {
            member_with_role(pool, team, 0).await;
        }
        inviter
    }

    #[tokio::test]
    async fn add_member_trial_clamps_effective_seats_to_ten() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        // Big nominal cap, but an active trial clamps the effective cap to 10.
        set_user_seats(&pool, owner, 50).await;
        set_user_trial(&pool, owner, 7).await;
        let team = seed_team(&pool, owner).await;

        // 10 members already fill the clamped cap.
        let inviter = fill_seats(&pool, team, 10).await;
        let invitee = seed_user(&pool).await;

        let res = add_member(
            State(pool.clone()),
            Extension(AuthUser(inviter)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(AddMemberRequest {
                user_id: Some(invitee),
                email: None,
                role: None,
            }),
        )
        .await;

        match res {
            Err(status) => assert_eq!(status, axum::http::StatusCode::PAYMENT_REQUIRED),
            Ok(_) => panic!("expected PAYMENT_REQUIRED (trial clamp), got Ok"),
        }
    }

    #[tokio::test]
    async fn add_member_without_trial_uses_full_seat_count() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        // Same 50 seats and same 10 members, but no trial → cap stays 50, so the
        // 11th member is admitted. Isolates the trial-only clamp from the base cap.
        set_user_seats(&pool, owner, 50).await;
        let team = seed_team(&pool, owner).await;

        let inviter = fill_seats(&pool, team, 10).await;
        let invitee = seed_user(&pool).await;

        let res = add_member(
            State(pool.clone()),
            Extension(AuthUser(inviter)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(AddMemberRequest {
                user_id: Some(invitee),
                email: None,
                role: None,
            }),
        )
        .await;

        assert!(res.is_ok(), "expected Ok, got {:?}", res.err());
    }

    #[tokio::test]
    async fn invite_member_trial_clamps_effective_seats_to_ten() {
        // `invite_member` (email-based) carries its own copy of the seat clamp,
        // separate from `add_member`; lock in the trial branch here too.
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_seats(&pool, owner, 50).await;
        set_user_trial(&pool, owner, 7).await;
        let team = seed_team(&pool, owner).await;

        // 10 members fill the clamped cap; the inviter holds INVITE_MEMBERS.
        let inviter = fill_seats(&pool, team, 10).await;

        let res = invite_member(
            State(pool.clone()),
            Extension(AuthUser(inviter)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(InviteMemberRequest {
                email: "newcomer@test.local".to_string(),
                role: None,
            }),
        )
        .await;

        match res {
            Err(status) => assert_eq!(status, axum::http::StatusCode::PAYMENT_REQUIRED),
            Ok(_) => panic!("expected PAYMENT_REQUIRED (trial clamp), got Ok"),
        }
    }
}

#[cfg(test)]
mod search_tests {
    use super::*;
    use uuid::Uuid;

    async fn mk_user(pool: &PgPool, email: &str, name: &str, handle: &str, custom: bool) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO users (email, display_name, account_id, auth_hash, handle, handle_is_custom, public_key)
             VALUES ($1, $2, gen_random_uuid(), 'h', $3, $4, 'pk') RETURNING id",
        )
        .bind(email).bind(name).bind(handle).bind(custom)
        .fetch_one(pool).await.unwrap()
    }

    // Handles and emails are unique and the test DB is real and persistent, so a
    // literal like "kevin-p" collides with itself on the second test run. Mint a
    // fresh suffix per call, matching the pattern in routes::users's tests.
    fn unique_handle(base: &str) -> String {
        format!("{base}-{}", &Uuid::new_v4().simple().to_string()[..6])
    }

    #[tokio::test]
    async fn a_stranger_is_not_found_by_an_email_substring() {
        let pool = crate::test_pool_or_skip!();
        let me = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Me", &crate::handles::generate_unique_handle(&pool).await.unwrap(), false).await;
        let email = format!("kevin.parker.{}@corp.test", &Uuid::new_v4().simple().to_string()[..6]);
        let them = mk_user(&pool, &email, "Kevin Parker", &unique_handle("quiet-otter"), false).await;

        let hits = search_users_inner(&pool, me, "kevin").await.unwrap();
        assert!(!hits.iter().any(|r| r.user_id == them), "email substring must not resolve a stranger");

        let hits = search_users_inner(&pool, me, &email).await.unwrap();
        assert!(hits.iter().any(|r| r.user_id == them), "a full email address must resolve");
    }

    #[tokio::test]
    async fn a_generated_handle_matches_only_exactly() {
        let pool = crate::test_pool_or_skip!();
        let me = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Me", &crate::handles::generate_unique_handle(&pool).await.unwrap(), false).await;
        let handle = unique_handle("swift-otter");
        let them = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Gen", &handle, false).await;

        assert!(!search_users_inner(&pool, me, "swift-otter").await.unwrap().iter().any(|r| r.user_id == them));
        assert!(search_users_inner(&pool, me, &format!("@{handle}")).await.unwrap().iter().any(|r| r.user_id == them));
    }

    #[tokio::test]
    async fn a_custom_handle_matches_fuzzily() {
        let pool = crate::test_pool_or_skip!();
        let me = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Me", &crate::handles::generate_unique_handle(&pool).await.unwrap(), false).await;
        let handle = unique_handle("kevin-p");
        let them = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Kev", &handle, true).await;

        // Search on the unique suffix rather than the common "kev" prefix: the
        // test DB is persistent, and LIMIT 8 means a common substring can be
        // crowded out entirely by unrelated rows accumulated across runs.
        let hits = search_users_inner(&pool, me, &handle[..handle.len() - 1]).await.unwrap();
        assert!(hits.iter().any(|r| r.user_id == them));
        assert!(!hits.iter().any(|r| r.is_teammate));
    }

    #[tokio::test]
    async fn a_teammate_still_matches_a_name_substring_and_is_flagged() {
        let pool = crate::test_pool_or_skip!();
        let me = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Me", &crate::handles::generate_unique_handle(&pool).await.unwrap(), false).await;
        let mate = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Zoe Teammate", &crate::handles::generate_unique_handle(&pool).await.unwrap(), false).await;
        let team: Uuid = sqlx::query_scalar("INSERT INTO teams (name, owner_id) VALUES ('t', $1) RETURNING id")
            .bind(me).fetch_one(&pool).await.unwrap();
        for u in [me, mate] {
            sqlx::query("INSERT INTO team_members (team_id, user_id) VALUES ($1, $2)")
                .bind(team).bind(u).execute(&pool).await.unwrap();
        }

        let hits = search_users_inner(&pool, me, "zo").await.unwrap();
        let hit = hits.iter().find(|r| r.user_id == mate).expect("teammate must match a name substring");
        assert!(hit.is_teammate);
    }

    #[tokio::test]
    async fn the_response_carries_no_public_key() {
        let pool = crate::test_pool_or_skip!();
        let me = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Me", &crate::handles::generate_unique_handle(&pool).await.unwrap(), false).await;
        let handle = unique_handle("kevin-pk");
        let them = mk_user(&pool, &format!("{}@a.test", Uuid::new_v4()), "Kev", &handle, true).await;
        let hits = search_users_inner(&pool, me, &handle).await.unwrap();
        let json = serde_json::to_string(&hits).unwrap();
        assert!(!json.contains("public_key"), "search must never carry key material: {json}");
        assert!(hits.iter().any(|r| r.user_id == them));
    }
}
