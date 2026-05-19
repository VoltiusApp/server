use axum::http::StatusCode;
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

// Permission bits — must stay in sync with frontend usePermission.ts
pub const PERM_VIEW_SECRETS: i64           = 1 << 0;  // 1
pub const PERM_COPY_SECRETS: i64           = 1 << 1;  // 2
pub const PERM_CONNECT: i64                = 1 << 2;  // 4
pub const PERM_EDIT_CONNECTIONS: i64       = 1 << 3;  // 8
pub const PERM_EDIT_IDENTITIES: i64        = 1 << 4;  // 16
pub const PERM_EDIT_KEYS: i64              = 1 << 5;  // 32
pub const PERM_EDIT_FOLDERS: i64           = 1 << 6;  // 64
pub const PERM_VIEW_AUDIT_LOG: i64         = 1 << 7;  // 128
pub const PERM_INVITE_MEMBERS: i64         = 1 << 8;  // 256
pub const PERM_MANAGE_MEMBERS: i64         = 1 << 9;  // 512
pub const PERM_CREATE_CUSTOM_ROLES: i64 = 1 << 10; // 1024 — retired, kept for compat
pub const PERM_MANAGE_VAULT: i64 = 1 << 11; // 2048
pub const PERM_START_TERMINAL_SESSION: i64 = 1 << 12; // 4096
pub const PERM_JOIN_TERMINAL_SESSION: i64  = 1 << 13; // 8192
pub const PERM_VIEW_TERMINAL_SESSIONS: i64 = 1 << 14; // 16384
pub const PERM_MANAGE_ROLES: i64           = 1 << 15; // 32768
pub const PERM_EDIT_SNIPPETS: i64          = 1 << 16; // 65536

pub const ALL_PERMISSIONS: i64 = PERM_VIEW_SECRETS
    | PERM_COPY_SECRETS
    | PERM_CONNECT
    | PERM_EDIT_CONNECTIONS
    | PERM_EDIT_IDENTITIES
    | PERM_EDIT_KEYS
    | PERM_EDIT_FOLDERS
    | PERM_VIEW_AUDIT_LOG
    | PERM_INVITE_MEMBERS
    | PERM_MANAGE_MEMBERS
    | PERM_CREATE_CUSTOM_ROLES
    | PERM_MANAGE_VAULT
    | PERM_START_TERMINAL_SESSION
    | PERM_JOIN_TERMINAL_SESSION
    | PERM_VIEW_TERMINAL_SESSIONS
    | PERM_MANAGE_ROLES
    | PERM_EDIT_SNIPPETS;

// Builtin role definitions: (name, permissions, position)
// Every role that today grants PERM_EDIT_CONNECTIONS (bit 3 = 8) also grants
// PERM_EDIT_SNIPPETS — Phase 2 is a zero-loss refactor.
pub const BUILTIN_ROLES: &[(&str, i64, i32)] = &[
    ("owner",        ALL_PERMISSIONS,             0), // all 17 bits
    ("manager",      63487 | PERM_EDIT_SNIPPETS,  1),
    ("editor",       28799 | PERM_EDIT_SNIPPETS,  2),
    ("member",       28679 | PERM_EDIT_SNIPPETS,  3),
    ("connect-only", 28676,                       4), // no edit perms today
];

/// Returns the union of all role permission bits for (team_id, user_id).
/// Returns false if user has no roles in the team (or is not a member).
pub async fn has_team_permission(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
    permission: i64,
) -> Result<bool, StatusCode> {
    let effective = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COALESCE(bit_or(tr.permissions), 0)
        FROM team_member_roles tmr
        JOIN team_roles tr ON tr.id = tmr.role_id
        WHERE tmr.team_id = $1 AND tmr.user_id = $2
        "#,
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to check team permission");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((effective & permission) != 0)
}

pub async fn require_all_team_permissions(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
    permissions: &[i64],
) -> Result<(), StatusCode> {
    let effective = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COALESCE(bit_or(tr.permissions), 0)
        FROM team_member_roles tmr
        JOIN team_roles tr ON tr.id = tmr.role_id
        WHERE tmr.team_id = $1 AND tmr.user_id = $2
        "#,
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to check team permissions");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if permissions.iter().all(|p| (effective & *p) != 0) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub async fn require_team_member(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<(), StatusCode> {
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to check team membership");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_member {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Check permission across any team in `team_ids`. Returns true if at least one grants the bit.
pub async fn has_any_team_permission(
    pool: &PgPool,
    team_ids: &[Uuid],
    user_id: Uuid,
    permission: i64,
) -> Result<bool, StatusCode> {
    if team_ids.is_empty() {
        return Ok(false);
    }
    let effective = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COALESCE(bit_or(tr.permissions), 0)
        FROM team_member_roles tmr
        JOIN team_roles tr ON tr.id = tmr.role_id
        WHERE tmr.team_id = ANY($1) AND tmr.user_id = $2
        "#,
    )
    .bind(team_ids)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to check any-team permission");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((effective & permission) != 0)
}
