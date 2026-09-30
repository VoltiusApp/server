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
pub const PERM_VIEW: i64                   = 1 << 17; // 131072
pub const PERM_ADMINISTRATOR: i64          = 1 << 18; // 262144

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
    | PERM_EDIT_SNIPPETS
    | PERM_VIEW
    | PERM_ADMINISTRATOR;

pub const OBJECT_RULE_BITS: i64 = PERM_VIEW
    | PERM_CONNECT
    | PERM_VIEW_SECRETS
    | PERM_COPY_SECRETS
    | PERM_EDIT_CONNECTIONS
    | PERM_EDIT_IDENTITIES
    | PERM_EDIT_KEYS
    | PERM_EDIT_FOLDERS
    | PERM_EDIT_SNIPPETS
    | PERM_MANAGE_ROLES;

pub const RULE_SET_ERA_BITS: i64 = PERM_VIEW | PERM_ADMINISTRATOR;

/// A client unaware of `RULE_SET_ERA_BITS` cannot set or clear them: keep
/// whatever was already stored for those bits, take everything else from `sent`.
pub fn keep_era_bits(sent: i64, stored: i64) -> i64 {
    (sent & !RULE_SET_ERA_BITS) | (stored & RULE_SET_ERA_BITS)
}

// Builtin role definitions: (name, permissions, position)
// Every role that today grants PERM_EDIT_CONNECTIONS (bit 3 = 8) also grants
// PERM_EDIT_SNIPPETS — Phase 2 is a zero-loss refactor.
pub const BUILTIN_ROLES: &[(&str, i64, i32)] = &[
    ("owner",        ALL_PERMISSIONS,                          0),
    ("manager",      63487 | PERM_EDIT_SNIPPETS | PERM_VIEW,   1),
    ("editor",       28799 | PERM_EDIT_SNIPPETS | PERM_VIEW,   2),
    ("member",       28679 | PERM_EDIT_SNIPPETS | PERM_VIEW,   3),
    ("connect-only", 28676 | PERM_VIEW,                        4),
];

pub(crate) const PERMISSION_JOINS: &str = r#"
    FROM team_members tm
    LEFT JOIN team_member_roles tmr ON tmr.team_id = tm.team_id AND tmr.user_id = tm.user_id
    LEFT JOIN team_roles tr ON tr.id = tmr.role_id
    LEFT JOIN team_member_permission_overrides o
           ON o.team_id = tm.team_id AND o.user_id = tm.user_id
"#;

/// Business: `(roles | allow) & !deny`; locked: `builtin & !deny`. 0 for a non-member.
pub async fn effective_permissions(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<i64, StatusCode> {
    Ok(crate::object_authz::member_contexts(pool, team_id, Some(user_id))
        .await?
        .pop()
        .map_or(0, |m| with_dependencies(m.base)))
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
#[derive(Clone, Copy)]
pub enum PermCheck<'a> {
    All(&'a [i64]),
}

impl PermCheck<'_> {
    fn satisfied_by(self, effective: i64) -> bool {
        match self {
            PermCheck::All(bits) => bits.iter().all(|p| (effective & *p) != 0),
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
    for &team_id in team_ids {
        if effective_permissions(pool, team_id, user_id).await? & permission != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleLayers {
    pub everyone_allow: i64,
    pub everyone_deny: i64,
    pub roles_allow: i64,
    pub roles_deny: i64,
    pub member_allow: i64,
    pub member_deny: i64,
}

/// Keep in sync with `resolveObjectPermissions` in the client's `src/services/permissions.ts`.
pub fn object_permissions(base: i64, team_deny: i64, rules: Option<&RuleLayers>, locked: bool) -> i64 {
    if base & PERM_ADMINISTRATOR != 0 {
        return with_dependencies(ALL_PERMISSIONS & !team_deny);
    }
    let Some(r) = rules else { return with_dependencies(base) };
    let mut p = if locked {
        base & !(r.everyone_deny | r.roles_deny | r.member_deny)
    } else {
        let p = (base & !r.everyone_deny) | r.everyone_allow;
        let p = (p & !r.roles_deny) | r.roles_allow;
        (p & !r.member_deny) | r.member_allow
    };
    p &= !team_deny;
    if p & PERM_VIEW == 0 { 0 } else { with_dependencies(p) }
}

/// A secret that can be read can be used, so reading one requires `CONNECT` (or Administrator).
pub fn with_dependencies(p: i64) -> i64 {
    if p & (PERM_CONNECT | PERM_ADMINISTRATOR) == 0 { p & !(PERM_VIEW_SECRETS | PERM_COPY_SECRETS) } else { p }
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
        let role_a = seed_role(&pool, team, "a", PERM_CONNECT).await;
        let role_b = seed_role(&pool, team, "b", PERM_MANAGE_ROLES).await;
        add_member(&pool, team, user).await;
        assign_role(&pool, team, user, role_a).await;
        assign_role(&pool, team, user, role_b).await;

        // Bits from either role are effective (bit_or).
        assert!(has_team_permission(&pool, team, user, PERM_CONNECT)
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

    #[tokio::test]
    async fn migration_045_backfills_view_and_owner_administrator_and_creates_no_rule_sets() {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        };
        let admin = PgPool::connect(&url).await.expect("connect admin");
        let db = format!("mig045_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {db}")).execute(&admin).await.unwrap();
        let db_url = format!("{}/{db}", url.rsplit_once('/').unwrap().0);
        let pool = PgPool::connect(&db_url).await.expect("connect scratch db");

        let full = sqlx::migrate!("./migrations");
        let before_045 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                full.migrations.iter().filter(|m| m.version < 45).cloned().collect(),
            ),
            ..sqlx::migrate!("./migrations")
        };
        before_045.run(&pool).await.expect("migrate to 044");

        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let legacy_all: i64 = (1 << 17) - 1;
        let owner_role: Uuid = sqlx::query_scalar(
            "INSERT INTO team_roles (team_id, name, permissions, is_builtin, position)
             VALUES ($1, 'owner', $2, TRUE, 0) RETURNING id",
        )
        .bind(team)
        .bind(legacy_all)
        .fetch_one(&pool)
        .await
        .unwrap();
        let custom = seed_role(&pool, team, "legacy", PERM_CONNECT).await;

        full.run(&pool).await.expect("migrate to head");

        let perms = |id: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>("SELECT permissions FROM team_roles WHERE id = $1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(perms(owner_role).await, legacy_all | PERM_VIEW | PERM_ADMINISTRATOR);
        assert_eq!(perms(custom).await, PERM_CONNECT | PERM_VIEW);
        let sets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_rule_sets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sets, 0);

        pool.close().await;
        sqlx::query(&format!("DROP DATABASE {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    }

    #[tokio::test]
    async fn migration_046_regrants_view_only_on_teams_without_rule_sets() {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        };
        let admin = PgPool::connect(&url).await.expect("connect admin");
        let db = format!("mig046_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {db}")).execute(&admin).await.unwrap();
        let db_url = format!("{}/{db}", url.rsplit_once('/').unwrap().0);
        let pool = PgPool::connect(&db_url).await.expect("connect scratch db");

        let full = sqlx::migrate!("./migrations");
        let before_046 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                full.migrations.iter().filter(|m| m.version < 46).cloned().collect(),
            ),
            ..sqlx::migrate!("./migrations")
        };
        before_046.run(&pool).await.expect("migrate to 045");

        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let saved_by_old_app = seed_role(&pool, team, "legacy-edit", PERM_CONNECT).await;
        let ruled_team = seed_team(&pool, owner).await;
        crate::test_support::seed_rule_set(&pool, ruled_team, owner, &[]).await;
        let deliberately_viewless = seed_role(&pool, ruled_team, "no-view", PERM_CONNECT).await;

        full.run(&pool).await.expect("migrate to head");

        let perms = |id: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>("SELECT permissions FROM team_roles WHERE id = $1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(perms(saved_by_old_app).await, PERM_CONNECT | PERM_VIEW);
        assert_eq!(perms(deliberately_viewless).await, PERM_CONNECT);

        pool.close().await;
        sqlx::query(&format!("DROP DATABASE {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    }

    #[tokio::test]
    async fn an_object_cannot_point_at_another_teams_rule_set() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team_a = seed_team(&pool, owner).await;
        let team_b = seed_team(&pool, owner).await;
        crate::test_support::seed_team_object(&pool, team_a, owner, "o-1", "connection").await;
        let foreign = crate::test_support::seed_rule_set(&pool, team_b, owner, &[]).await;

        let res = sqlx::query(
            "UPDATE team_vault_objects SET rule_set_id = $3 WHERE team_id = $1 AND object_id = $2",
        )
        .bind(team_a)
        .bind("o-1")
        .bind(foreign)
        .execute(&pool)
        .await;

        assert!(res.is_err(), "the composite FK must refuse a cross-team pointer");
    }

    #[tokio::test]
    async fn locked_team_custom_role_grants_nothing() {
        let _mode = crate::test_support::BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        crate::test_support::set_user_tier(&pool, owner, "teams").await;
        let team = crate::test_support::seed_team_with_roles(&pool, owner).await;
        let member = crate::test_support::member_with_role(&pool, team, PERM_VIEW_AUDIT_LOG).await;
        assert_eq!(effective_permissions(&pool, team, member).await.unwrap(), 0);
        crate::test_support::set_user_tier(&pool, owner, "business").await;
        assert_ne!(effective_permissions(&pool, team, member).await.unwrap() & PERM_VIEW_AUDIT_LOG, 0);
    }

    #[tokio::test]
    async fn locked_team_drops_allowed_bits_and_keeps_denies() {
        let _mode = crate::test_support::BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        crate::test_support::set_user_tier(&pool, owner, "teams").await;
        let team = crate::test_support::seed_team_with_roles(&pool, owner).await;
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;
        crate::test_support::grant_builtin_role(&pool, team, member, "member").await;
        set_member_overrides(&pool, team, member, PERM_VIEW_AUDIT_LOG | PERM_CONNECT, PERM_VIEW_SECRETS).await;
        let p = effective_permissions(&pool, team, member).await.unwrap();
        assert_eq!(p & (PERM_VIEW_AUDIT_LOG | PERM_VIEW_SECRETS), 0);
        assert_ne!(p & PERM_CONNECT, 0);
    }

    #[tokio::test]
    async fn has_any_team_permission_is_plan_aware_per_team() {
        let _mode = crate::test_support::BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let locked_owner = seed_user(&pool).await;
        let paid_owner = seed_user(&pool).await;
        crate::test_support::set_user_tier(&pool, locked_owner, "teams").await;
        crate::test_support::set_user_tier(&pool, paid_owner, "business").await;
        let locked_team = crate::test_support::seed_team_with_roles(&pool, locked_owner).await;
        let paid_team = crate::test_support::seed_team_with_roles(&pool, paid_owner).await;
        let user = crate::test_support::member_with_role(&pool, locked_team, PERM_VIEW_AUDIT_LOG).await;
        assert!(!has_any_team_permission(&pool, &[locked_team], user, PERM_VIEW_AUDIT_LOG).await.unwrap());
        let role = seed_role(&pool, paid_team, "auditor", PERM_VIEW_AUDIT_LOG).await;
        add_member(&pool, paid_team, user).await;
        assign_role(&pool, paid_team, user, role).await;
        assert!(has_any_team_permission(&pool, &[locked_team, paid_team], user, PERM_VIEW_AUDIT_LOG).await.unwrap());
    }
}

#[cfg(test)]
mod object_permission_tests {
    use super::*;

    const MEMBER: i64 = PERM_VIEW | PERM_CONNECT | PERM_VIEW_SECRETS;

    fn layers() -> RuleLayers {
        RuleLayers::default()
    }

    #[test]
    fn no_rule_set_returns_the_team_mask() {
        assert_eq!(object_permissions(MEMBER, 0, None, false), MEMBER);
    }

    #[test]
    fn a_rule_set_with_no_relevant_entries_keeps_the_team_mask() {
        assert_eq!(object_permissions(MEMBER, 0, Some(&layers()), false), MEMBER);
    }

    #[test]
    fn everyone_deny_removes_and_everyone_allow_adds() {
        let r = RuleLayers { everyone_deny: PERM_VIEW_SECRETS, everyone_allow: PERM_COPY_SECRETS, ..layers() };
        assert_eq!(
            object_permissions(MEMBER, 0, Some(&r), false),
            PERM_VIEW | PERM_CONNECT | PERM_COPY_SECRETS
        );
    }

    #[test]
    fn role_layer_overrides_everyone() {
        let r = RuleLayers { everyone_deny: PERM_CONNECT, roles_allow: PERM_CONNECT, ..layers() };
        assert_eq!(object_permissions(MEMBER, 0, Some(&r), false), MEMBER);
    }

    #[test]
    fn within_the_role_layer_allow_beats_deny() {
        let r = RuleLayers { roles_deny: PERM_CONNECT, roles_allow: PERM_CONNECT, ..layers() };
        assert_eq!(object_permissions(MEMBER, 0, Some(&r), false), MEMBER);
    }

    #[test]
    fn member_layer_overrides_roles() {
        let r = RuleLayers { roles_allow: PERM_EDIT_CONNECTIONS, member_deny: PERM_EDIT_CONNECTIONS, ..layers() };
        assert_eq!(object_permissions(MEMBER, 0, Some(&r), false), MEMBER);
    }

    #[test]
    fn team_deny_stays_absolute_over_a_member_allow() {
        let base = MEMBER & !PERM_VIEW_SECRETS;
        let r = RuleLayers { member_allow: PERM_VIEW_SECRETS, ..layers() };
        assert_eq!(object_permissions(base, PERM_VIEW_SECRETS, Some(&r), false), base);
    }

    #[test]
    fn losing_view_zeroes_every_bit() {
        let r = RuleLayers { everyone_deny: PERM_VIEW, ..layers() };
        assert_eq!(object_permissions(MEMBER, 0, Some(&r), false), 0);
    }

    #[test]
    fn a_rule_can_grant_view_the_team_mask_lacks() {
        let r = RuleLayers { member_allow: PERM_VIEW, ..layers() };
        assert_eq!(object_permissions(PERM_CONNECT, 0, Some(&r), false), PERM_VIEW | PERM_CONNECT);
    }

    #[test]
    fn denying_connect_on_an_object_also_removes_its_secrets() {
        let r = RuleLayers { everyone_deny: PERM_CONNECT, ..layers() };
        let base = MEMBER | PERM_COPY_SECRETS;
        assert_eq!(object_permissions(base, 0, Some(&r), false), PERM_VIEW);
    }

    #[test]
    fn secrets_without_connect_grant_nothing_on_the_team_mask() {
        let base = PERM_VIEW | PERM_VIEW_SECRETS | PERM_COPY_SECRETS;
        assert_eq!(object_permissions(base, 0, None, false), PERM_VIEW);
    }

    #[test]
    fn a_member_allow_of_secrets_needs_connect_too() {
        let r = RuleLayers { member_deny: PERM_CONNECT, member_allow: PERM_VIEW_SECRETS, ..layers() };
        assert_eq!(object_permissions(MEMBER, 0, Some(&r), false), PERM_VIEW);
    }

    #[test]
    fn administrator_satisfies_the_connect_dependency() {
        let p = PERM_ADMINISTRATOR | PERM_VIEW_SECRETS | PERM_COPY_SECRETS;
        assert_eq!(with_dependencies(p), p);
    }

    #[test]
    fn administrator_ignores_every_rule() {
        let r = RuleLayers { everyone_deny: ALL_PERMISSIONS, member_deny: ALL_PERMISSIONS, ..layers() };
        assert_eq!(object_permissions(PERM_ADMINISTRATOR, 0, Some(&r), false), ALL_PERMISSIONS);
        assert_eq!(object_permissions(PERM_ADMINISTRATOR, 0, None, false), ALL_PERMISSIONS);
    }

    #[test]
    fn administrator_still_loses_a_team_denied_bit() {
        assert_eq!(
            object_permissions(PERM_ADMINISTRATOR, PERM_COPY_SECRETS, None, false),
            ALL_PERMISSIONS & !PERM_COPY_SECRETS
        );
    }

    #[test]
    fn locked_ignores_allow_layers() {
        let r = RuleLayers { everyone_deny: PERM_VIEW, member_allow: PERM_VIEW, ..layers() };
        assert_eq!(object_permissions(MEMBER, 0, Some(&r), true), 0);
    }

    #[test]
    fn locked_keeps_deny_only_rules_for_everyone_else() {
        let r = RuleLayers { member_deny: PERM_VIEW_SECRETS, ..layers() };
        assert_eq!(object_permissions(MEMBER, 0, Some(&r), true), MEMBER & !PERM_VIEW_SECRETS);
    }

    #[test]
    fn locked_applies_a_role_deny() {
        let r = RuleLayers { roles_deny: PERM_VIEW, ..layers() };
        assert_eq!(object_permissions(MEMBER, 0, Some(&r), true), 0);
    }

    #[test]
    fn locked_without_rules_is_the_team_mask() {
        assert_eq!(object_permissions(MEMBER, 0, None, true), MEMBER);
    }

    #[test]
    fn locked_builtin_administrator_keeps_the_bypass() {
        let r = RuleLayers { everyone_deny: PERM_VIEW, ..layers() };
        assert_eq!(object_permissions(PERM_ADMINISTRATOR, 0, Some(&r), true), ALL_PERMISSIONS);
    }

    fn subsets(bits: &[i64]) -> Vec<i64> {
        (0..1usize << bits.len())
            .map(|i| bits.iter().enumerate().filter(|(b, _)| i & (1 << b) != 0).fold(0, |a, (_, v)| a | v))
            .collect()
    }

    #[test]
    fn locked_is_never_wider_than_business() {
        let masks = subsets(&[PERM_VIEW, PERM_CONNECT, PERM_VIEW_SECRETS, PERM_COPY_SECRETS, PERM_EDIT_CONNECTIONS]);
        for &base in &masks {
            for &allow in &masks {
                for &deny in &masks {
                    let r = RuleLayers {
                        everyone_allow: allow,
                        everyone_deny: deny,
                        roles_allow: deny,
                        roles_deny: allow,
                        member_allow: allow,
                        member_deny: deny,
                    };
                    let locked = object_permissions(base, 0, Some(&r), true);
                    let business = object_permissions(base, 0, Some(&r), false);
                    assert_eq!(locked & !business, 0, "base={base} allow={allow} deny={deny}");
                }
            }
        }
    }

    #[test]
    fn object_rule_bits_exclude_administrator_and_team_only_bits() {
        assert_eq!(OBJECT_RULE_BITS & PERM_ADMINISTRATOR, 0);
        assert_eq!(OBJECT_RULE_BITS & PERM_INVITE_MEMBERS, 0);
        assert_eq!(OBJECT_RULE_BITS & PERM_VIEW_AUDIT_LOG, 0);
        assert_ne!(OBJECT_RULE_BITS & PERM_MANAGE_ROLES, 0);
    }

    #[test]
    fn every_builtin_role_has_view_and_only_owner_is_administrator() {
        for (name, perms, _) in BUILTIN_ROLES {
            assert_ne!(perms & PERM_VIEW, 0, "{name} lacks VIEW");
            assert_eq!(perms & PERM_ADMINISTRATOR != 0, *name == "owner", "{name}");
        }
    }
}

#[cfg(test)]
mod keep_era_bits_tests {
    use super::*;

    #[test]
    fn a_sent_era_bit_is_dropped_in_favor_of_the_stored_one() {
        assert_eq!(keep_era_bits(PERM_CONNECT | PERM_VIEW, 0), PERM_CONNECT);
        assert_eq!(keep_era_bits(PERM_CONNECT, PERM_VIEW | PERM_ADMINISTRATOR), PERM_CONNECT | PERM_VIEW | PERM_ADMINISTRATOR);
    }

    #[test]
    fn non_era_bits_pass_through_unchanged() {
        assert_eq!(keep_era_bits(PERM_CONNECT | PERM_COPY_SECRETS, 0), PERM_CONNECT | PERM_COPY_SECRETS);
    }
}
