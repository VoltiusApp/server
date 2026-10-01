use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::object_authz::{live_rule_set_ids, rule_set_in_team, ObjectAuthz};
use crate::permissions::{OBJECT_RULE_BITS, PERM_MANAGE_ROLES, PERM_VIEW};
use crate::routes::client_version::require_rule_set_feature;
use crate::sync_notifier::{notify_team_vault_changed, SyncNotifier};

pub const MAX_RULE_SET_ENTRIES: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RuleEntryBody {
    pub subject_type: String,
    pub subject_id: Option<Uuid>,
    pub allow: i64,
    pub deny: i64,
}

#[derive(Debug, Deserialize)]
pub struct RuleSetBody {
    pub entries: Vec<RuleEntryBody>,
}

#[derive(Debug, Deserialize)]
pub struct PutRuleSetBody {
    pub entries: Vec<RuleEntryBody>,
    #[serde(default)]
    pub expected_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct RuleSetResponse {
    pub id: Uuid,
    pub entries: Vec<RuleEntryBody>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Uuid,
}

#[derive(Debug, Serialize)]
pub struct CreatedRuleSet {
    pub id: Uuid,
}

fn internal(e: sqlx::Error, what: &'static str) -> StatusCode {
    error!(error = %e, what, "Rule set query failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn validate_entries(pool: &PgPool, team_id: Uuid, entries: Vec<RuleEntryBody>) -> Result<Vec<RuleEntryBody>, StatusCode> {
    if entries.len() > MAX_RULE_SET_ENTRIES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let mut seen = std::collections::HashSet::new();
    let (mut roles, mut members) = (Vec::new(), Vec::new());
    for e in &entries {
        let masks_ok = e.allow >= 0 && e.deny >= 0 && (e.allow | e.deny) & !OBJECT_RULE_BITS == 0 && e.allow & e.deny == 0;
        let subject_ok = match (e.subject_type.as_str(), e.subject_id) {
            ("everyone", None) => true,
            ("role", Some(id)) => { roles.push(id); true }
            ("member", Some(id)) => { members.push(id); true }
            _ => false,
        };
        if !masks_ok || !subject_ok || !seen.insert((e.subject_type.clone(), e.subject_id)) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let roles_found: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_roles WHERE team_id = $1 AND id = ANY($2)")
        .bind(team_id).bind(&roles).fetch_one(pool).await.map_err(|e| internal(e, "validate roles"))?;
    let members_found: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_members WHERE team_id = $1 AND user_id = ANY($2)")
        .bind(team_id).bind(&members).fetch_one(pool).await.map_err(|e| internal(e, "validate members"))?;
    if roles_found != roles.len() as i64 || members_found != members.len() as i64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(entries.into_iter().filter(|e| e.allow != 0 || e.deny != 0).collect())
}

async fn insert_entries(conn: &mut sqlx::PgConnection, set_id: Uuid, entries: &[RuleEntryBody]) -> Result<(), StatusCode> {
    for e in entries {
        sqlx::query(
            "INSERT INTO team_rule_set_entries (rule_set_id, subject_type, subject_id, allow_mask, deny_mask) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(set_id).bind(&e.subject_type).bind(e.subject_id).bind(e.allow).bind(e.deny)
        .execute(&mut *conn)
        .await
        .map_err(|e| internal(e, "insert rule entry"))?;
    }
    Ok(())
}

async fn load_member(pool: &PgPool, team_id: Uuid, user_id: Uuid) -> Result<ObjectAuthz, StatusCode> {
    ObjectAuthz::load(pool, team_id, user_id).await?.ok_or(StatusCode::FORBIDDEN)
}

/// Admin (set in team), or `bit` through a set a live object uses. View only → 403, nothing → 404.
/// Administrator only replaces the "reachable" half of this check — team-level Deny still applies.
async fn require_on_set(pool: &PgPool, authz: &ObjectAuthz, team_id: Uuid, set_id: Uuid, bit: i64) -> Result<(), StatusCode> {
    let reachable = if authz.is_admin() {
        rule_set_in_team(pool, team_id, set_id).await?
    } else {
        live_rule_set_ids(pool, team_id).await?.contains(&set_id)
    };
    if !reachable || !authz.can(Some(set_id), PERM_VIEW) {
        return Err(StatusCode::NOT_FOUND);
    }
    if authz.can(Some(set_id), bit) { Ok(()) } else { Err(StatusCode::FORBIDDEN) }
}

async fn load_entries<'e, E: sqlx::PgExecutor<'e>>(executor: E, set_id: Uuid) -> Result<Vec<RuleEntryBody>, StatusCode> {
    Ok(sqlx::query_as::<_, (String, Option<Uuid>, i64, i64)>(
        "SELECT subject_type, subject_id, allow_mask, deny_mask FROM team_rule_set_entries \
         WHERE rule_set_id = $1 ORDER BY subject_type, subject_id",
    )
    .bind(set_id)
    .fetch_all(executor)
    .await
    .map_err(|e| internal(e, "read entries"))?
    .into_iter()
    .map(|(subject_type, subject_id, allow, deny)| RuleEntryBody { subject_type, subject_id, allow, deny })
    .collect())
}

fn narrows_entries(current: &[RuleEntryBody], next: &[RuleEntryBody]) -> bool {
    next.iter().all(|e| {
        current.iter().any(|c| {
            c.subject_type == e.subject_type
                && c.subject_id == e.subject_id
                && crate::team_plan::narrows_masks((c.allow, c.deny), (e.allow, e.deny))
        })
    })
}

async fn new_set(conn: &mut sqlx::PgConnection, team_id: Uuid, author: Uuid) -> Result<Uuid, StatusCode> {
    sqlx::query_scalar("INSERT INTO team_rule_sets (team_id, updated_by) VALUES ($1, $2) RETURNING id")
        .bind(team_id).bind(author).fetch_one(&mut *conn).await.map_err(|e| internal(e, "insert rule set"))
}

pub async fn create_rule_set(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    headers: HeaderMap,
    Path(team_id): Path<Uuid>,
    Json(body): Json<RuleSetBody>,
) -> Result<(StatusCode, Json<CreatedRuleSet>), StatusCode> {
    require_rule_set_feature(&headers)?;
    let authz = load_member(&pool, team_id, auth.0).await?;
    if !authz.grants_anywhere(&live_rule_set_ids(&pool, team_id).await?, PERM_MANAGE_ROLES) {
        return Err(StatusCode::FORBIDDEN);
    }
    let entries = validate_entries(&pool, team_id, body.entries).await?;
    crate::team_plan::require_granular(&pool, team_id, entries.is_empty()).await?;
    let mut tx = pool.begin().await.map_err(|e| internal(e, "begin create"))?;
    let id = new_set(&mut tx, team_id, auth.0).await?;
    insert_entries(&mut tx, id, &entries).await?;
    tx.commit().await.map_err(|e| internal(e, "commit create"))?;
    Ok((StatusCode::CREATED, Json(CreatedRuleSet { id })))
}

pub async fn copy_rule_set(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    headers: HeaderMap,
    Path((team_id, set_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<CreatedRuleSet>), StatusCode> {
    require_rule_set_feature(&headers)?;
    let authz = load_member(&pool, team_id, auth.0).await?;
    require_on_set(&pool, &authz, team_id, set_id, PERM_VIEW).await?;
    let mut tx = pool.begin().await.map_err(|e| internal(e, "begin copy"))?;
    let id = new_set(&mut tx, team_id, auth.0).await?;
    sqlx::query(
        "INSERT INTO team_rule_set_entries (rule_set_id, subject_type, subject_id, allow_mask, deny_mask) \
         SELECT $1, subject_type, subject_id, allow_mask, deny_mask FROM team_rule_set_entries WHERE rule_set_id = $2",
    )
    .bind(id).bind(set_id).execute(&mut *tx).await.map_err(|e| internal(e, "copy entries"))?;
    tx.commit().await.map_err(|e| internal(e, "commit copy"))?;
    Ok((StatusCode::CREATED, Json(CreatedRuleSet { id })))
}

pub async fn get_rule_set(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path((team_id, set_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RuleSetResponse>, StatusCode> {
    let authz = load_member(&pool, team_id, auth.0).await?;
    require_on_set(&pool, &authz, team_id, set_id, PERM_MANAGE_ROLES).await?;
    let (updated_at, updated_by): (DateTime<Utc>, Uuid) =
        sqlx::query_as("SELECT updated_at, updated_by FROM team_rule_sets WHERE id = $1")
            .bind(set_id).fetch_one(&pool).await.map_err(|e| internal(e, "read set"))?;
    let entries = load_entries(&pool, set_id).await?;
    Ok(Json(RuleSetResponse { id: set_id, entries, updated_at, updated_by }))
}

pub async fn put_rule_set(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(sync_notifier): Extension<SyncNotifier>,
    headers: HeaderMap,
    Path((team_id, set_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<PutRuleSetBody>,
) -> Result<StatusCode, StatusCode> {
    require_rule_set_feature(&headers)?;
    let authz = load_member(&pool, team_id, auth.0).await?;
    require_on_set(&pool, &authz, team_id, set_id, PERM_MANAGE_ROLES).await?;
    let entries = validate_entries(&pool, team_id, body.entries).await?;
    let mut tx = pool.begin().await.map_err(|e| internal(e, "begin put"))?;
    // Stamp first: the row lock this UPDATE takes serializes concurrent PUTs on
    // the same set until commit, and the stamp check re-runs on the locked row.
    let stamped = sqlx::query(
        "UPDATE team_rule_sets SET updated_at = now(), updated_by = $2 \
         WHERE id = $1 AND ($3::timestamptz IS NULL OR updated_at = $3)",
    )
    .bind(set_id).bind(auth.0).bind(body.expected_updated_at)
    .execute(&mut *tx).await.map_err(|e| internal(e, "stamp set"))?;
    if stamped.rows_affected() == 0 {
        return Err(StatusCode::CONFLICT);
    }
    let current = load_entries(&mut *tx, set_id).await?;
    crate::team_plan::require_granular(&pool, team_id, narrows_entries(&current, &entries)).await?;
    sqlx::query("DELETE FROM team_rule_set_entries WHERE rule_set_id = $1")
        .bind(set_id).execute(&mut *tx).await.map_err(|e| internal(e, "clear entries"))?;
    insert_entries(&mut tx, set_id, &entries).await?;
    tx.commit().await.map_err(|e| internal(e, "commit put"))?;
    notify_team_vault_changed(&pool, &sync_notifier, team_id, auth.0).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::*;
    use crate::test_pool_or_skip;
    use crate::test_support::*;
    use axum::extract::{Path, State};
    use axum::{Extension, Json};

    fn entry(subject_type: &str, subject_id: Option<Uuid>, allow: i64, deny: i64) -> RuleEntryBody {
        RuleEntryBody { subject_type: subject_type.into(), subject_id, allow, deny }
    }

    async fn create(pool: &PgPool, team: Uuid, user: Uuid, entries: Vec<RuleEntryBody>) -> Result<Uuid, StatusCode> {
        create_rule_set(State(pool.clone()), Extension(AuthUser(user)), rule_set_client_headers(), Path(team), Json(RuleSetBody { entries }))
            .await
            .map(|(_, Json(c))| c.id)
    }

    async fn put_expecting(
        pool: &PgPool,
        team: Uuid,
        user: Uuid,
        set: Uuid,
        entries: Vec<RuleEntryBody>,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<StatusCode, StatusCode> {
        put_rule_set(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(crate::sync_notifier::SyncNotifier::new()),
            rule_set_client_headers(),
            Path((team, set)),
            Json(PutRuleSetBody { entries, expected_updated_at }),
        )
        .await
    }

    async fn put(pool: &PgPool, team: Uuid, user: Uuid, set: Uuid, entries: Vec<RuleEntryBody>) -> Result<StatusCode, StatusCode> {
        put_expecting(pool, team, user, set, entries, None).await
    }

    async fn stamp_of(pool: &PgPool, set: Uuid) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT updated_at FROM team_rule_sets WHERE id = $1").bind(set).fetch_one(pool).await.unwrap()
    }

    #[test]
    fn narrowing_entries_only_drop_or_shrink() {
        let both = entry("everyone", None, 0, PERM_VIEW | PERM_CONNECT);
        let view = entry("everyone", None, 0, PERM_VIEW);
        let other = entry("role", Some(Uuid::nil()), PERM_CONNECT, 0);
        assert!(narrows_entries(&[both.clone(), other.clone()], std::slice::from_ref(&both)));
        assert!(narrows_entries(std::slice::from_ref(&both), &[]));
        assert!(narrows_entries(std::slice::from_ref(&both), std::slice::from_ref(&view)));
        assert!(!narrows_entries(std::slice::from_ref(&view), std::slice::from_ref(&both)));
        assert!(!narrows_entries(std::slice::from_ref(&view), &[view.clone(), other]));
        assert!(!narrows_entries(&[view], &[entry("everyone", None, PERM_VIEW, 0)]));
    }

    #[tokio::test]
    async fn a_teams_team_can_drop_a_single_bit_of_a_rule() {
        let _env = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        set_user_tier(&pool, f.owner, "teams").await;
        grant_builtin_role(&pool, f.team, f.admin, "owner").await;
        let set = seed_rule_set(&pool, f.team, f.owner, &[("everyone", None, 0, PERM_VIEW | PERM_CONNECT)]).await;
        point_object(&pool, f.team, &f.object_id, Some(set)).await;

        assert_eq!(put(&pool, f.team, f.admin, set, vec![entry("everyone", None, 0, PERM_VIEW)]).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(
            put(&pool, f.team, f.admin, set, vec![entry("everyone", None, 0, PERM_VIEW | PERM_CONNECT)]).await.unwrap_err(),
            StatusCode::PAYMENT_REQUIRED,
        );
    }

    #[tokio::test]
    async fn a_teams_team_can_only_remove_rules() {
        let _env = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        set_user_tier(&pool, f.owner, "teams").await;
        grant_builtin_role(&pool, f.team, f.admin, "owner").await;

        assert_eq!(create(&pool, f.team, f.admin, vec![entry("everyone", None, 0, PERM_VIEW)]).await.unwrap_err(), StatusCode::PAYMENT_REQUIRED);
        assert!(create(&pool, f.team, f.admin, vec![entry("everyone", None, 0, 0)]).await.is_ok());
        assert_eq!(
            put(&pool, f.team, f.admin, f.rule_set, vec![entry("member", Some(f.blocked), PERM_VIEW, 0)]).await.unwrap_err(),
            StatusCode::PAYMENT_REQUIRED,
        );
        assert_eq!(put(&pool, f.team, f.admin, f.rule_set, vec![entry("everyone", None, 0, PERM_VIEW)]).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(put(&pool, f.team, f.admin, f.rule_set, vec![]).await, Ok(StatusCode::NO_CONTENT));
    }

    #[tokio::test]
    async fn a_business_team_can_add_rules() {
        let _env = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        set_user_tier(&pool, f.owner, "business").await;

        assert_eq!(
            put(&pool, f.team, f.admin, f.rule_set, vec![entry("member", Some(f.blocked), PERM_VIEW, 0)]).await,
            Ok(StatusCode::NO_CONTENT),
        );
    }

    #[tokio::test]
    async fn put_with_a_stale_stamp_is_409_and_leaves_the_entries() {
        let _env = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        let seen = stamp_of(&pool, f.rule_set).await;
        let theirs = vec![entry("member", Some(f.blocked), PERM_VIEW, 0)];
        assert_eq!(put_expecting(&pool, f.team, f.admin, f.rule_set, theirs.clone(), Some(seen)).await, Ok(StatusCode::NO_CONTENT));
        let after_theirs = stamp_of(&pool, f.rule_set).await;
        assert_ne!(after_theirs, seen);

        let stale = put_expecting(&pool, f.team, f.admin, f.rule_set, vec![], Some(seen)).await;
        assert_eq!(stale.unwrap_err(), StatusCode::CONFLICT);
        assert_eq!(load_entries(&pool, f.rule_set).await.unwrap(), theirs);
        assert_eq!(put_expecting(&pool, f.team, f.admin, f.rule_set, vec![], Some(after_theirs)).await, Ok(StatusCode::NO_CONTENT));
    }

    #[tokio::test]
    async fn a_manager_creates_a_set_and_reads_it_back_once_an_object_uses_it() {
        let _env = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let manager = member_with_role(&pool, team, PERM_MANAGE_ROLES).await;
        let set = create(&pool, team, manager, vec![entry("everyone", None, 0, PERM_VIEW), entry("member", Some(manager), PERM_VIEW, 0)]).await.unwrap();
        seed_team_object(&pool, team, owner, "f-1", "folder").await;
        point_object(&pool, team, "f-1", Some(set)).await;

        let got = get_rule_set(State(pool.clone()), Extension(AuthUser(manager)), Path((team, set))).await.unwrap().0;
        assert_eq!(got.entries.len(), 2);
    }

    #[tokio::test]
    async fn creating_needs_manage_somewhere() {
        let _env = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT).await;
        assert_eq!(create(&pool, team, member, vec![]).await.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn creating_without_the_capability_header_is_426() {
        let _env = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let manager = member_with_role(&pool, team, PERM_MANAGE_ROLES).await;
        let res = create_rule_set(State(pool.clone()), Extension(AuthUser(manager)), axum::http::HeaderMap::new(), Path(team), Json(RuleSetBody { entries: vec![] })).await;
        assert_eq!(res.err(), Some(StatusCode::UPGRADE_REQUIRED));
    }

    #[tokio::test]
    async fn entries_are_validated() {
        let _env = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let other_team = seed_team(&pool, owner).await;
        let manager = member_with_role(&pool, team, PERM_MANAGE_ROLES).await;
        let foreign_role = seed_role(&pool, other_team, "foreign", PERM_VIEW).await;
        let bad = [
            vec![entry("everyone", None, PERM_ADMINISTRATOR, 0)],
            vec![entry("everyone", None, PERM_INVITE_MEMBERS, 0)],
            vec![entry("everyone", None, PERM_VIEW, PERM_VIEW)],
            vec![entry("everyone", None, -1, 0)],
            vec![entry("everyone", Some(manager), PERM_VIEW, 0)],
            vec![entry("member", None, PERM_VIEW, 0)],
            vec![entry("role", Some(foreign_role), PERM_VIEW, 0)],
            vec![entry("member", Some(seed_user(&pool).await), PERM_VIEW, 0)],
            vec![entry("everyone", None, PERM_VIEW, 0), entry("everyone", None, 0, PERM_CONNECT)],
            vec![entry("group", Some(manager), PERM_VIEW, 0)],
        ];
        for entries in bad {
            assert_eq!(create(&pool, team, manager, entries.clone()).await.unwrap_err(), StatusCode::BAD_REQUEST, "{entries:?}");
        }
        let too_many: Vec<_> = (0..=MAX_RULE_SET_ENTRIES).map(|_| entry("member", Some(Uuid::new_v4()), PERM_VIEW, 0)).collect();
        assert_eq!(create(&pool, team, manager, too_many).await.unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_member_who_cannot_view_the_set_gets_404_and_a_viewer_without_manage_403() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        let blocked = get_rule_set(State(pool.clone()), Extension(AuthUser(f.blocked)), Path((f.team, f.rule_set))).await;
        assert_eq!(blocked.err(), Some(StatusCode::NOT_FOUND));
        let viewer = get_rule_set(State(pool.clone()), Extension(AuthUser(f.viewer)), Path((f.team, f.rule_set))).await;
        assert_eq!(viewer.err(), Some(StatusCode::FORBIDDEN));
        assert!(get_rule_set(State(pool.clone()), Extension(AuthUser(f.admin)), Path((f.team, f.rule_set))).await.is_ok());
    }

    #[tokio::test]
    async fn an_admin_whose_team_deny_removes_view_gets_404_not_a_free_pass() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        set_member_overrides(&pool, f.team, f.admin, 0, PERM_VIEW).await;
        let res = get_rule_set(State(pool.clone()), Extension(AuthUser(f.admin)), Path((f.team, f.rule_set))).await;
        assert_eq!(res.err(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn put_replaces_entries_and_changes_what_members_see() {
        let _env = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        put(&pool, f.team, f.admin, f.rule_set, vec![entry("member", Some(f.blocked), PERM_VIEW, 0)]).await.unwrap();
        let blocked = crate::object_authz::ObjectAuthz::load(&pool, f.team, f.blocked).await.unwrap().unwrap();
        assert!(blocked.can(Some(f.rule_set), PERM_VIEW));
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_rule_set_entries WHERE rule_set_id = $1")
            .bind(f.rule_set).fetch_one(&pool).await.unwrap();
        assert_eq!(n, 1, "PUT must replace, not accumulate, the set's entries");
    }

    #[tokio::test]
    async fn copy_clones_entries_for_anyone_who_can_view_the_set() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        let copy = copy_rule_set(State(pool.clone()), Extension(AuthUser(f.viewer)), rule_set_client_headers(), Path((f.team, f.rule_set)))
            .await
            .unwrap()
            .1
            .0
            .id;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_rule_set_entries WHERE rule_set_id = $1")
            .bind(copy).fetch_one(&pool).await.unwrap();
        assert_eq!(n, 2);
        let blocked = copy_rule_set(State(pool.clone()), Extension(AuthUser(f.blocked)), rule_set_client_headers(), Path((f.team, f.rule_set))).await;
        assert_eq!(blocked.err(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn the_sweep_removes_only_old_unattached_sets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        seed_team_object(&pool, team, owner, "o-1", "connection").await;
        let attached = seed_rule_set(&pool, team, owner, &[]).await;
        point_object(&pool, team, "o-1", Some(attached)).await;
        let old_orphan = seed_rule_set(&pool, team, owner, &[]).await;
        let fresh_orphan = seed_rule_set(&pool, team, owner, &[]).await;
        sqlx::query("UPDATE team_rule_sets SET updated_at = now() - interval '2 days' WHERE id = ANY($1)")
            .bind(vec![attached, old_orphan]).execute(&pool).await.unwrap();

        crate::object_authz::sweep_unattached_rule_sets(&pool).await.unwrap();

        let left: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM team_rule_sets WHERE team_id = $1")
            .bind(team).fetch_all(&pool).await.unwrap();
        assert!(left.contains(&attached) && left.contains(&fresh_orphan) && !left.contains(&old_orphan));
    }
}
