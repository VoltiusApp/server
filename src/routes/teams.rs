use axum::{extract::{Query, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::models::team::{CustomRole, Team, TeamMember};
use crate::sync_notifier::SyncNotifier;

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
    let team = sqlx::query_as::<_, Team>(
        "INSERT INTO teams (name, owner_id) VALUES ($1, $2) RETURNING id, name, owner_id, created_at",
    )
    .bind(&body.name)
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to create team");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Owner is automatically a member
    sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'owner')",
    )
    .bind(team.id)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to add owner as team member");
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
    pub role: String,
}

pub async fn list_teams(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<Vec<TeamWithRole>>, StatusCode> {
    let rows = sqlx::query_as::<_, (Uuid, String, Uuid, chrono::DateTime<chrono::Utc>, String)>(
        r#"
        SELECT t.id, t.name, t.owner_id, t.created_at, tm.role
        FROM teams t
        JOIN team_members tm ON tm.team_id = t.id
        WHERE tm.user_id = $1
        ORDER BY t.created_at ASC
        "#,
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list teams");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, name, owner_id, created_at, role)| TeamWithRole {
                id,
                name,
                owner_id,
                created_at,
                role,
            })
            .collect(),
    ))
}

// ─── Get team members ─────────────────────────────────────────────────────────

pub async fn list_members(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
) -> Result<Json<Vec<TeamMember>>, StatusCode> {
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

    let members = sqlx::query_as::<_, TeamMember>(
        r#"
        SELECT tm.team_id, tm.user_id, tm.role, tm.invited_by, tm.joined_at,
               u.email, u.public_key,
               tm.custom_role_id, cr.name AS custom_role_name, cr.permissions AS custom_role_permissions
        FROM team_members tm
        JOIN users u ON u.id = tm.user_id
        LEFT JOIN custom_roles cr ON cr.id = tm.custom_role_id
        WHERE tm.team_id = $1
        ORDER BY tm.joined_at ASC
        "#,
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list team members");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(members))
}

// ─── Add member (by email or user_id) ────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddMemberRequest {
    /// Invite by email address
    pub email: Option<String>,
    /// Invite directly by user_id (from search results)
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
    // Verify requester has INVITE_MEMBERS permission (built-in owner/manager or custom role with bit)
    let can_invite = crate::permissions::has_team_permission(
        &pool, team_id, auth.0, crate::permissions::PERM_INVITE_MEMBERS,
    )
    .await?;
    if !can_invite {
        warn!(team_id = %team_id, user_id = %auth.0, "Insufficient permission to invite members");
        return Err(StatusCode::FORBIDDEN);
    }

    // Resolve invitee: prefer user_id if provided, else find by email
    let invitee_id: Uuid = if let Some(uid) = body.user_id {
        // Verify user exists
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

    // Don't add yourself
    if invitee_id == auth.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Enforce seat limit: owner's seat_count caps how many members the team can have
    let owner_id = sqlx::query_scalar::<_, Uuid>("SELECT owner_id FROM teams WHERE id = $1")
        .bind(team_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to fetch team owner"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let seat_count = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT seat_count FROM users WHERE id = $1",
    )
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to fetch seat count"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if let Some(seats) = seat_count {
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM team_members WHERE team_id = $1",
        )
        .bind(team_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to count team members"); StatusCode::INTERNAL_SERVER_ERROR })?;

        if current >= seats as i64 {
            warn!(team_id = %team_id, seats, current, "Seat limit reached");
            return Err(StatusCode::PAYMENT_REQUIRED);
        }
    }

    let member_role = body.role.as_deref().unwrap_or("member");
    sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, invited_by) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(team_id)
    .bind(invitee_id)
    .bind(member_role)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to add team member");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(team_id = %team_id, invitee_id = %invitee_id, role = %member_role, "Member added");
    notifier.notify_membership_changed(invitee_id);
    Ok(StatusCode::NO_CONTENT)
}

// ─── Update member role ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    /// Built-in role name ("manager" | "editor" | "member")
    pub role: Option<String>,
    /// Custom role UUID (mutually exclusive with role)
    pub custom_role_id: Option<Uuid>,
}

pub async fn update_member_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path((team_id, target_user_id)): axum::extract::Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateRoleRequest>,
) -> Result<StatusCode, StatusCode> {
    // Requester must be owner
    let requester_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to get requester role"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::FORBIDDEN)?;

    if requester_role != "owner" {
        warn!(team_id = %team_id, user_id = %auth.0, "Non-owner tried to change role");
        return Err(StatusCode::FORBIDDEN);
    }

    // Can't change owner's own role
    if target_user_id == auth.0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get target's current role
    let target_current_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(target_user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to get target role"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::NOT_FOUND)?;

    // Can't change an owner's role
    if target_current_role == "owner" {
        return Err(StatusCode::FORBIDDEN);
    }

    if let Some(custom_role_id) = body.custom_role_id {
        // Validate custom role belongs to this team
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM custom_roles WHERE id = $1 AND team_id = $2)",
        )
        .bind(custom_role_id)
        .bind(team_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to verify custom role"); StatusCode::INTERNAL_SERVER_ERROR })?;

        if !exists {
            return Err(StatusCode::NOT_FOUND);
        }

        let updated = sqlx::query_scalar::<_, i64>(
            r#"WITH upd AS (
                UPDATE team_members
                SET role = 'member', custom_role_id = $1
                WHERE team_id = $2 AND user_id = $3
                RETURNING 1
            ) SELECT COUNT(*) FROM upd"#,
        )
        .bind(custom_role_id)
        .bind(team_id)
        .bind(target_user_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to assign custom role"); StatusCode::INTERNAL_SERVER_ERROR })?;

        if updated == 0 { return Err(StatusCode::NOT_FOUND); }
        info!(team_id = %team_id, target_user_id = %target_user_id, custom_role_id = %custom_role_id, "Custom role assigned");

    } else if let Some(ref new_role) = body.role {
        const VALID_ROLES: &[&str] = &["owner", "manager", "editor", "member"];
        if !VALID_ROLES.contains(&new_role.as_str()) {
            return Err(StatusCode::BAD_REQUEST);
        }

        let updated = sqlx::query_scalar::<_, i64>(
            r#"WITH upd AS (
                UPDATE team_members
                SET role = $1, custom_role_id = NULL
                WHERE team_id = $2 AND user_id = $3
                RETURNING 1
            ) SELECT COUNT(*) FROM upd"#,
        )
        .bind(new_role)
        .bind(team_id)
        .bind(target_user_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to update role"); StatusCode::INTERNAL_SERVER_ERROR })?;

        if updated == 0 { return Err(StatusCode::NOT_FOUND); }
        info!(team_id = %team_id, target_user_id = %target_user_id, new_role = %new_role, "Member role updated");

    } else {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ─── Remove member ────────────────────────────────────────────────────────────

pub async fn remove_member(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path((team_id, user_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    // Members can remove themselves; MANAGE_MEMBERS permission required to remove others
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

    // Can't remove the owner
    let target_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to get target member role"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if target_role == "owner" {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
        .bind(team_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .map_err(|e| { error!(error = %e, "Failed to remove team member"); StatusCode::INTERNAL_SERVER_ERROR })?;

    info!(team_id = %team_id, removed_user_id = %user_id, "Member removed");
    notifier.notify_membership_changed(user_id);
    Ok(StatusCode::NO_CONTENT)
}

// ─── Search users (instance-wide, for invite autocomplete) ───────────────────

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
    let results = sqlx::query_as::<_, (Uuid, String, String)>(
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
            .map(|(user_id, email, public_key)| UserSearchResult { user_id, email, public_key })
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

// ─── List custom roles ────────────────────────────────────────────────────────

pub async fn list_roles(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
) -> Result<Json<Vec<CustomRole>>, StatusCode> {
    // Any team member can see the roles
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

    let roles = sqlx::query_as::<_, CustomRole>(
        "SELECT id, team_id, name, permissions, created_at FROM custom_roles WHERE team_id = $1 ORDER BY created_at ASC",
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to list custom roles"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(Json(roles))
}

// ─── Create custom role ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub permissions: i64,
}

pub async fn create_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path(team_id): axum::extract::Path<Uuid>,
    Json(body): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<CustomRole>), StatusCode> {
    // Owner only
    let requester_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to get requester role"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::FORBIDDEN)?;

    if requester_role != "owner" {
        return Err(StatusCode::FORBIDDEN);
    }

    if body.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Clamp permissions to valid 15-bit range
    let permissions = body.permissions & 0x7FFF;

    let role = sqlx::query_as::<_, CustomRole>(
        "INSERT INTO custom_roles (team_id, name, permissions) VALUES ($1, $2, $3) RETURNING id, team_id, name, permissions, created_at",
    )
    .bind(team_id)
    .bind(body.name.trim())
    .bind(permissions)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to create custom role");
        // 23505 = unique violation
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.code().as_deref() == Some("23505") {
                return StatusCode::CONFLICT;
            }
        }
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(team_id = %team_id, role_id = %role.id, name = %role.name, "Custom role created");
    Ok((StatusCode::CREATED, Json(role)))
}

// ─── Update custom role ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateRoleBody {
    pub name: Option<String>,
    pub permissions: Option<i64>,
}

pub async fn update_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path((team_id, role_id)): axum::extract::Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateRoleBody>,
) -> Result<StatusCode, StatusCode> {
    // Owner only
    let requester_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to get requester role"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::FORBIDDEN)?;

    if requester_role != "owner" {
        return Err(StatusCode::FORBIDDEN);
    }

    // Verify role belongs to this team
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM custom_roles WHERE id = $1 AND team_id = $2)",
    )
    .bind(role_id)
    .bind(team_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to verify role"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !exists {
        return Err(StatusCode::NOT_FOUND);
    }

    if let Some(ref name) = body.name {
        if name.trim().is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let permissions = body.permissions.map(|p| p & 0x7FFF);

    sqlx::query(
        r#"UPDATE custom_roles
           SET name        = COALESCE($1, name),
               permissions = COALESCE($2, permissions)
           WHERE id = $3 AND team_id = $4"#,
    )
    .bind(body.name.as_deref().map(str::trim))
    .bind(permissions)
    .bind(role_id)
    .bind(team_id)
    .execute(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to update custom role"); StatusCode::INTERNAL_SERVER_ERROR })?;

    info!(team_id = %team_id, role_id = %role_id, "Custom role updated");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Delete custom role ───────────────────────────────────────────────────────

pub async fn delete_role(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path((team_id, role_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    // Owner only
    let requester_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to get requester role"); StatusCode::INTERNAL_SERVER_ERROR })?
    .ok_or(StatusCode::FORBIDDEN)?;

    if requester_role != "owner" {
        return Err(StatusCode::FORBIDDEN);
    }

    // Fail if any member has this role assigned
    let in_use = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE custom_role_id = $1)",
    )
    .bind(role_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to check role usage"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if in_use {
        warn!(role_id = %role_id, "Cannot delete role still assigned to members");
        return Err(StatusCode::CONFLICT);
    }

    let result = sqlx::query(
        "DELETE FROM custom_roles WHERE id = $1 AND team_id = $2",
    )
    .bind(role_id)
    .bind(team_id)
    .execute(&pool)
    .await
    .map_err(|e| { error!(error = %e, "Failed to delete custom role"); StatusCode::INTERNAL_SERVER_ERROR })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    info!(team_id = %team_id, role_id = %role_id, "Custom role deleted");
    Ok(StatusCode::NO_CONTENT)
}
