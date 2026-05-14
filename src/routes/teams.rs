use axum::{extract::{Path, Query, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::models::team::{Team, TeamMember, TeamRole};
use crate::routes::audit::write_audit_event;
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

async fn notify_team_members_changed(pool: &PgPool, notifier: &SyncNotifier, team_id: Uuid) {
    notify_team_members(pool, notifier, team_id, format!("team_members:{team_id}")).await;
}

// ─── Plan tier helper ─────────────────────────────────────────────────────────

async fn require_business_tier(pool: &PgPool, team_id: Uuid) -> Result<(), StatusCode> {
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
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub role_ids: Vec<Uuid>,
}

pub async fn list_teams(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<Vec<TeamWithRole>>, StatusCode> {
    // Returns one row per (team, role) — aggregated in Rust
    let rows = sqlx::query_as::<_, (Uuid, String, Uuid, chrono::DateTime<chrono::Utc>, Option<Uuid>)>(
        r#"
        SELECT t.id, t.name, t.owner_id, t.created_at, tmr.role_id
        FROM teams t
        JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = $1
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
    for (id, name, owner_id, created_at, role_id) in rows {
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
            Option<String>,
            Option<Uuid>,
        ),
    >(
        r#"
        SELECT tm.team_id, tm.user_id, inv.email AS invited_by_email, tm.joined_at,
               u.email, u.public_key, tmr.role_id
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
    for (t_id, user_id, invited_by_email, joined_at, email, public_key, role_id) in rows {
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
                        email,
                        public_key: member_public_key_for_response(public_key),
                        invited_by_email,
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
) -> Result<StatusCode, StatusCode> {
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
            .bind(email)
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

    let role_name = body.role.as_deref().unwrap_or("member");
    const VALID_ROLES: &[&str] = &["owner", "manager", "editor", "member", "connect-only"];
    if !VALID_ROLES.contains(&role_name) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "INSERT INTO team_members (team_id, user_id, invited_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(team_id)
    .bind(invitee_id)
    .bind(auth.0)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to add team member");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        r#"INSERT INTO team_member_roles (team_id, user_id, role_id)
           SELECT $1, $2, id FROM team_roles
           WHERE team_id = $1 AND name = $3 AND is_builtin = TRUE
           ON CONFLICT DO NOTHING"#,
    )
    .bind(team_id)
    .bind(invitee_id)
    .bind(role_name)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to assign builtin role");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit add member transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(team_id = %team_id, invitee_id = %invitee_id, role = %role_name, "Member added");
    let invitee_email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
        .bind(invitee_id)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.joined",
        Some("user"),
        Some(invitee_id.to_string()),
        invitee_email,
        Some(json!({ "role": role_name })),
    ));
    notifier.notify_membership_changed(invitee_id);
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Remove member ────────────────────────────────────────────────────────────

pub async fn remove_member(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
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

    info!(team_id = %team_id, removed_user_id = %user_id, "Member removed");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.removed",
        Some("user"),
        Some(user_id.to_string()),
        None,
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

#[derive(Serialize)]
pub struct UserSearchResult {
    pub user_id: Uuid,
    pub email: String,
    pub public_key: String,
}

pub async fn search_users(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Query(params): Query<SearchUsersQuery>,
) -> Result<Json<Vec<UserSearchResult>>, StatusCode> {
    if params.q.len() < 2 {
        return Ok(Json(vec![]));
    }

    let pattern = format!("%{}%", params.q.to_lowercase());
    let results = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
        r#"
        SELECT id, email, public_key
        FROM users
        WHERE LOWER(email) LIKE $1
          AND id != $2
        ORDER BY
          CASE WHEN LOWER(email) LIKE $3 THEN 0 ELSE 1 END,
          email
        LIMIT 8
        "#,
    )
    .bind(&pattern)
    .bind(auth.0)
    .bind(format!("{}%", params.q.to_lowercase()))
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to search users");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        results
            .into_iter()
            .map(|(user_id, email, public_key)| UserSearchResult {
                user_id,
                email,
                public_key: member_public_key_for_response(public_key),
            })
            .collect(),
    ))
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

    let permissions = body.permissions & 0xFFFF;

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

    let permissions = body.permissions.map(|p| p & 0xFFFF);

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
        None,
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

    info!(team_id = %team_id, target_user_id = %target_user_id, role_id = %role_id, "Role removed from member");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.role_changed",
        Some("user"),
        Some(target_user_id.to_string()),
        None,
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

    let email = body.email.trim().to_lowercase();
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

        let mut tx = pool.begin().await.map_err(|e| {
            error!(error = %e, "Failed to begin transaction");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        sqlx::query(
            "INSERT INTO team_members (team_id, user_id, invited_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(team_id)
        .bind(user_id)
        .bind(auth.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| { error!(error = %e, "Failed to add team member directly"); StatusCode::INTERNAL_SERVER_ERROR })?;

        sqlx::query(
            r#"INSERT INTO team_member_roles (team_id, user_id, role_id)
               SELECT $1, $2, id FROM team_roles
               WHERE team_id = $1 AND name = $3 AND is_builtin = TRUE
               ON CONFLICT DO NOTHING"#,
        )
        .bind(team_id)
        .bind(user_id)
        .bind(&role)
        .execute(&mut *tx)
        .await
        .map_err(|e| { error!(error = %e, "Failed to assign role on direct invite"); StatusCode::INTERNAL_SERVER_ERROR })?;

        tx.commit().await.map_err(|e| {
            error!(error = %e, "Failed to commit direct invite transaction");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        info!(team_id = %team_id, user_id = %user_id, role = %role, "Member directly added via invite endpoint");
        tokio::spawn(write_audit_event(
            pool.clone(),
            team_id,
            auth.0,
            "member.invited",
            Some("user"),
            Some(user_id.to_string()),
            Some(email.clone()),
            Some(json!({ "role": role })),
        ));
        notifier.notify_membership_changed(user_id);
        notify_team_members_changed(&pool, &notifier, team_id).await;
        return Ok(Json(InviteMemberResponse { status: "added".to_string() }));
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
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.invited",
        Some("user"),
        None,
        Some(email.clone()),
        Some(json!({ "role": role, "status": "pending" })),
    ));
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(Json(InviteMemberResponse { status: "invited".to_string() }))
}

// ─── List pending invitations ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct PendingInvitation {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub invited_by_email: Option<String>,
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
        r#"SELECT pi.id, pi.email, pi.role, u.email, pi.created_at, pi.expires_at
           FROM pending_invitations pi
           LEFT JOIN users u ON u.id = pi.invited_by
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
            .map(|(id, email, role, invited_by_email, created_at, expires_at)| PendingInvitation {
                id, email, role, invited_by_email, created_at, expires_at,
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
