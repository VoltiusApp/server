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

const PERMISSION_JOINS: &str = r#"
    FROM team_members tm
    LEFT JOIN team_member_roles tmr ON tmr.team_id = tm.team_id AND tmr.user_id = tm.user_id
    LEFT JOIN team_roles tr ON tr.id = tmr.role_id
    LEFT JOIN team_member_permission_overrides o
           ON o.team_id = tm.team_id AND o.user_id = tm.user_id
"#;

// MAX pulls the single override row (join is one-to-at-most-one) into the aggregate.
const EFFECTIVE_EXPR: &str = "(COALESCE(bit_or(tr.permissions), 0) | COALESCE(MAX(o.allow_mask), 0)) \
                              & ~COALESCE(MAX(o.deny_mask), 0)";

/// `(roleUnion | allow) & ~deny`. Returns 0 if the user is not a member.
pub async fn effective_permissions(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<i64, StatusCode> {
    let sql = format!(
        "SELECT {EFFECTIVE_EXPR} {PERMISSION_JOINS} \
         WHERE tm.team_id = $1 AND tm.user_id = $2"
    );
    sqlx::query_scalar::<_, i64>(&sql)
        .bind(team_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map(|v| v.unwrap_or(0))
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to check team permission");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// Returns true if any of (team_id, user_id)'s roles grant `permission`.
pub async fn has_team_permission(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
    permission: i64,
) -> Result<bool, StatusCode> {
    Ok((effective_permissions(pool, team_id, user_id).await? & permission) != 0)
}

/// How a set of permission bits is matched against a member's effective bits.
///
/// Most routes name one capability and want `All`. A route several distinct
/// roles legitimately reach — the team vault key, which a connect-only member
/// needs to *use* a stored credential and a secrets viewer to *read* it — wants
/// `Any` (issue #190).
#[derive(Clone, Copy)]
pub enum PermCheck<'a> {
    All(&'a [i64]),
    Any(&'a [i64]),
}

impl PermCheck<'_> {
    fn satisfied_by(self, effective: i64) -> bool {
        match self {
            PermCheck::All(bits) => bits.iter().all(|p| (effective & *p) != 0),
            PermCheck::Any(bits) => bits.iter().any(|p| (effective & *p) != 0),
        }
    }
}

pub async fn require_team_permissions(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
    check: PermCheck<'_>,
) -> Result<(), StatusCode> {
    let effective = effective_permissions(pool, team_id, user_id).await?;
    if check.satisfied_by(effective) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub async fn require_all_team_permissions(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
    permissions: &[i64],
) -> Result<(), StatusCode> {
    require_team_permissions(pool, team_id, user_id, PermCheck::All(permissions)).await
}

/// Returns true if the user is a member of the team.
pub async fn is_team_member(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<bool, StatusCode> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to check team membership");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

pub async fn require_team_member(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<(), StatusCode> {
    if is_team_member(pool, team_id, user_id).await? {
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
    let sql = format!(
        "SELECT COALESCE(bool_or(granted), false) FROM ( \
             SELECT (({EFFECTIVE_EXPR}) & $3) <> 0 AS granted \
             {PERMISSION_JOINS} \
             WHERE tm.team_id = ANY($1) AND tm.user_id = $2 \
             GROUP BY tm.team_id \
         ) per_team"
    );
    let granted = sqlx::query_scalar::<_, bool>(&sql)
        .bind(team_ids)
        .bind(user_id)
        .bind(permission)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Failed to check any-team permission");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(granted)
}

#[cfg(test)]
mod db_tests {
    //! Behavioral lock-in for the team authz helpers. These pin the exact
    //! semantics (bit-or union across roles, member checks, multi-team checks)
    //! so the planned dedup of the repeated `bit_or` query is provably safe.
    //!
    //! Requires `TEST_DATABASE_URL`; otherwise each test skips.
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, assign_role, seed_role, seed_team, seed_user, set_member_overrides};

    #[tokio::test]
    async fn has_team_permission_reflects_granted_bit() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team = seed_team(&pool, user).await;
        let role = seed_role(&pool, team, "r", PERM_VIEW_SECRETS | PERM_CONNECT).await;
        add_member(&pool, team, user).await;
        assign_role(&pool, team, user, role).await;

        assert!(has_team_permission(&pool, team, user, PERM_VIEW_SECRETS)
            .await
            .unwrap());
        assert!(!has_team_permission(&pool, team, user, PERM_MANAGE_ROLES)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn has_team_permission_unions_multiple_roles() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team = seed_team(&pool, user).await;
        let role_a = seed_role(&pool, team, "a", PERM_VIEW_SECRETS).await;
        let role_b = seed_role(&pool, team, "b", PERM_MANAGE_ROLES).await;
        add_member(&pool, team, user).await;
        assign_role(&pool, team, user, role_a).await;
        assign_role(&pool, team, user, role_b).await;

        // Bits from either role are effective (bit_or).
        assert!(has_team_permission(&pool, team, user, PERM_VIEW_SECRETS)
            .await
            .unwrap());
        assert!(has_team_permission(&pool, team, user, PERM_MANAGE_ROLES)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn has_team_permission_false_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let outsider = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;

        assert!(!has_team_permission(&pool, team, outsider, PERM_VIEW_SECRETS)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn require_all_team_permissions_needs_every_bit() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team = seed_team(&pool, user).await;
        let role = seed_role(&pool, team, "r", PERM_VIEW_SECRETS | PERM_CONNECT).await;
        add_member(&pool, team, user).await;
        assign_role(&pool, team, user, role).await;

        assert!(
            require_all_team_permissions(&pool, team, user, &[PERM_VIEW_SECRETS, PERM_CONNECT])
                .await
                .is_ok()
        );
        // Missing one of the required bits → FORBIDDEN.
        assert_eq!(
            require_all_team_permissions(
                &pool,
                team,
                user,
                &[PERM_VIEW_SECRETS, PERM_MANAGE_ROLES]
            )
            .await
            .unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn require_team_member_distinguishes_members() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let member = seed_user(&pool).await;
        let outsider = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, member).await;

        assert!(require_team_member(&pool, team, member).await.is_ok());
        assert_eq!(
            require_team_member(&pool, team, outsider).await.unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn has_any_team_permission_checks_across_teams() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team_a = seed_team(&pool, user).await;
        let team_b = seed_team(&pool, user).await;
        let role = seed_role(&pool, team_b, "r", PERM_VIEW_AUDIT_LOG).await;
        add_member(&pool, team_b, user).await;
        assign_role(&pool, team_b, user, role).await;

        // Empty slice short-circuits to false.
        assert!(!has_any_team_permission(&pool, &[], user, PERM_VIEW_AUDIT_LOG)
            .await
            .unwrap());
        // Granted in team_b even though team_a grants nothing.
        assert!(
            has_any_team_permission(&pool, &[team_a, team_b], user, PERM_VIEW_AUDIT_LOG)
                .await
                .unwrap()
        );
        assert!(
            !has_any_team_permission(&pool, &[team_a, team_b], user, PERM_MANAGE_VAULT)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn overrides_cascade_when_member_is_removed() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let member = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, member).await;
        set_member_overrides(&pool, team, member, PERM_VIEW_SECRETS, 0).await;

        sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team)
            .bind(member)
            .execute(&pool)
            .await
            .unwrap();

        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_member_permission_overrides WHERE team_id = $1 AND user_id = $2",
        )
        .bind(team)
        .bind(member)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn allow_override_grants_a_bit_no_role_provides() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team = seed_team(&pool, user).await;
        let role = seed_role(&pool, team, "r", PERM_CONNECT).await;
        add_member(&pool, team, user).await;
        assign_role(&pool, team, user, role).await;
        crate::test_support::set_member_overrides(&pool, team, user, PERM_VIEW_SECRETS, 0).await;

        assert!(has_team_permission(&pool, team, user, PERM_VIEW_SECRETS).await.unwrap());
        assert!(has_team_permission(&pool, team, user, PERM_CONNECT).await.unwrap());
    }

    #[tokio::test]
    async fn allow_override_works_for_a_member_with_no_roles() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let member = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, member).await;
        crate::test_support::set_member_overrides(&pool, team, member, PERM_CONNECT, 0).await;

        assert!(has_team_permission(&pool, team, member, PERM_CONNECT).await.unwrap());
    }

    #[tokio::test]
    async fn deny_override_beats_a_granting_role() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team = seed_team(&pool, user).await;
        let role = seed_role(&pool, team, "r", PERM_VIEW_SECRETS | PERM_CONNECT).await;
        add_member(&pool, team, user).await;
        assign_role(&pool, team, user, role).await;
        crate::test_support::set_member_overrides(&pool, team, user, 0, PERM_VIEW_SECRETS).await;

        assert!(!has_team_permission(&pool, team, user, PERM_VIEW_SECRETS).await.unwrap());
        assert!(has_team_permission(&pool, team, user, PERM_CONNECT).await.unwrap());
    }

    #[tokio::test]
    async fn deny_survives_a_newly_assigned_role_granting_the_same_bit() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team = seed_team(&pool, user).await;
        let role_a = seed_role(&pool, team, "a", PERM_CONNECT).await;
        add_member(&pool, team, user).await;
        assign_role(&pool, team, user, role_a).await;
        crate::test_support::set_member_overrides(&pool, team, user, 0, PERM_VIEW_SECRETS).await;

        let role_b = seed_role(&pool, team, "b", PERM_VIEW_SECRETS).await;
        assign_role(&pool, team, user, role_b).await;

        assert!(!has_team_permission(&pool, team, user, PERM_VIEW_SECRETS).await.unwrap());
    }

    #[tokio::test]
    async fn deny_wins_when_a_bit_is_in_both_masks() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team = seed_team(&pool, user).await;
        add_member(&pool, team, user).await;
        crate::test_support::set_member_overrides(
            &pool, team, user, PERM_VIEW_SECRETS, PERM_VIEW_SECRETS,
        )
        .await;

        assert!(!has_team_permission(&pool, team, user, PERM_VIEW_SECRETS).await.unwrap());
    }

    #[tokio::test]
    async fn deny_in_one_team_does_not_suppress_a_grant_in_another() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team_a = seed_team(&pool, user).await;
        let team_b = seed_team(&pool, user).await;

        let role_a = seed_role(&pool, team_a, "a", PERM_VIEW_AUDIT_LOG).await;
        add_member(&pool, team_a, user).await;
        assign_role(&pool, team_a, user, role_a).await;
        crate::test_support::set_member_overrides(&pool, team_a, user, 0, PERM_VIEW_AUDIT_LOG).await;

        let role_b = seed_role(&pool, team_b, "b", PERM_VIEW_AUDIT_LOG).await;
        add_member(&pool, team_b, user).await;
        assign_role(&pool, team_b, user, role_b).await;

        assert!(
            has_any_team_permission(&pool, &[team_a, team_b], user, PERM_VIEW_AUDIT_LOG)
                .await
                .unwrap(),
            "team_b still grants the bit; team_a's deny must not reach across teams"
        );
        assert!(
            !has_team_permission(&pool, team_a, user, PERM_VIEW_AUDIT_LOG).await.unwrap(),
            "team_a's own deny still applies inside team_a"
        );
    }

    #[tokio::test]
    async fn deny_override_applies_to_multi_team_checks() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        let team = seed_team(&pool, user).await;
        let role = seed_role(&pool, team, "r", PERM_VIEW_AUDIT_LOG).await;
        add_member(&pool, team, user).await;
        assign_role(&pool, team, user, role).await;
        crate::test_support::set_member_overrides(&pool, team, user, 0, PERM_VIEW_AUDIT_LOG).await;

        assert!(
            !has_any_team_permission(&pool, &[team], user, PERM_VIEW_AUDIT_LOG)
                .await
                .unwrap(),
            "a deny override must be honoured on the multi-team path, not only the single-team one"
        );
    }

    #[tokio::test]
    async fn allow_override_applies_to_multi_team_checks() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let member = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, member).await;
        crate::test_support::set_member_overrides(&pool, team, member, PERM_VIEW_AUDIT_LOG, 0).await;

        assert!(
            has_any_team_permission(&pool, &[team], member, PERM_VIEW_AUDIT_LOG)
                .await
                .unwrap(),
            "an allow override must grant on the multi-team path"
        );
    }
}
