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
pub const PERM_CREATE_CUSTOM_ROLES: i64    = 1 << 10; // 1024
pub const PERM_MANAGE_VAULT: i64           = 1 << 11; // 2048
pub const PERM_START_TERMINAL_SESSION: i64 = 1 << 12; // 4096
pub const PERM_JOIN_TERMINAL_SESSION: i64  = 1 << 13; // 8192
pub const PERM_VIEW_TERMINAL_SESSIONS: i64 = 1 << 14; // 16384

fn builtin_permissions(role: &str) -> i64 {
    match role {
        "owner" => 0x7FFF,
        "manager" => 0x7FFF & !(PERM_CREATE_CUSTOM_ROLES | PERM_MANAGE_VAULT),
        "editor" => PERM_VIEW_SECRETS | PERM_COPY_SECRETS | PERM_CONNECT
            | PERM_EDIT_CONNECTIONS | PERM_EDIT_IDENTITIES | PERM_EDIT_KEYS | PERM_EDIT_FOLDERS
            | PERM_START_TERMINAL_SESSION | PERM_JOIN_TERMINAL_SESSION | PERM_VIEW_TERMINAL_SESSIONS,
        "member" => PERM_VIEW_SECRETS | PERM_COPY_SECRETS | PERM_CONNECT
            | PERM_START_TERMINAL_SESSION | PERM_JOIN_TERMINAL_SESSION | PERM_VIEW_TERMINAL_SESSIONS,
        "connect-only" => PERM_CONNECT
            | PERM_START_TERMINAL_SESSION | PERM_JOIN_TERMINAL_SESSION | PERM_VIEW_TERMINAL_SESSIONS,
        _ => 0,
    }
}

/// Returns true if `user_id` has `permission` in `team_id`.
/// Returns false if user is not a member. Returns Err on DB failure.
pub async fn has_team_permission(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
    permission: i64,
) -> Result<bool, StatusCode> {
    let row = sqlx::query_as::<_, (String, Option<i64>)>(
        r#"
        SELECT tm.role, cr.permissions
        FROM team_members tm
        LEFT JOIN custom_roles cr ON cr.id = tm.custom_role_id
        WHERE tm.team_id = $1 AND tm.user_id = $2
        "#,
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to check team permission");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(match row {
        None => false,
        Some((_, Some(custom_perms))) => (custom_perms & permission) != 0,
        Some((role, None)) => (builtin_permissions(&role) & permission) != 0,
    })
}

/// Check permission across any team in `team_ids`. Returns true if at least one passes.
pub async fn has_any_team_permission(
    pool: &PgPool,
    team_ids: &[Uuid],
    user_id: Uuid,
    permission: i64,
) -> Result<bool, StatusCode> {
    if team_ids.is_empty() {
        return Ok(false);
    }
    let rows = sqlx::query_as::<_, (String, Option<i64>)>(
        r#"
        SELECT tm.role, cr.permissions
        FROM team_members tm
        LEFT JOIN custom_roles cr ON cr.id = tm.custom_role_id
        WHERE tm.team_id = ANY($1) AND tm.user_id = $2
        "#,
    )
    .bind(team_ids)
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to check any-team permission");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(rows.iter().any(|(role, custom_perms)| match custom_perms {
        Some(p) => (p & permission) != 0,
        None => (builtin_permissions(role) & permission) != 0,
    }))
}
