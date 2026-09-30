use std::collections::HashMap;

use axum::http::{HeaderMap, StatusCode};
use sqlx::PgPool;
use tracing::{error, warn};
use uuid::Uuid;

use crate::permissions::{
    object_permissions, RuleLayers, PERMISSION_JOINS, PERM_ADMINISTRATOR, PERM_CONNECT, PERM_VIEW,
};
use crate::routes::client_version::client_supports_rule_sets;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    Everyone,
    Role(Uuid),
    Member(Uuid),
}

#[derive(Clone, Copy, Debug)]
pub struct RuleEntry {
    pub subject: Subject,
    pub allow: i64,
    pub deny: i64,
}

pub fn layers_for(entries: &[RuleEntry], role_ids: &[Uuid], user_id: Uuid) -> RuleLayers {
    let mut l = RuleLayers::default();
    for e in entries {
        match e.subject {
            Subject::Everyone => {
                l.everyone_allow |= e.allow;
                l.everyone_deny |= e.deny;
            }
            Subject::Role(id) if role_ids.contains(&id) => {
                l.roles_allow |= e.allow;
                l.roles_deny |= e.deny;
            }
            Subject::Member(id) if id == user_id => {
                l.member_allow |= e.allow;
                l.member_deny |= e.deny;
            }
            _ => {}
        }
    }
    l
}

#[derive(Clone, Debug)]
pub struct MemberContext {
    pub user_id: Uuid,
    pub base: i64,
    pub team_deny: i64,
    pub role_ids: Vec<Uuid>,
}

fn db_error(e: sqlx::Error, what: &'static str) -> StatusCode {
    error!(error = %e, what, "Object authorization query failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

pub async fn member_contexts(
    pool: &PgPool,
    team_id: Uuid,
    only: Option<Uuid>,
) -> Result<Vec<MemberContext>, StatusCode> {
    let sql = format!(
        "SELECT tm.user_id, COALESCE(bit_or(tr.permissions), 0), COALESCE(MAX(o.allow_mask), 0), \
                COALESCE(MAX(o.deny_mask), 0), \
                COALESCE(array_agg(tmr.role_id) FILTER (WHERE tmr.role_id IS NOT NULL), '{{}}'::uuid[]) \
         {PERMISSION_JOINS} \
         WHERE tm.team_id = $1 AND ($2::uuid IS NULL OR tm.user_id = $2) \
         GROUP BY tm.user_id"
    );
    let rows = sqlx::query_as::<_, (Uuid, i64, i64, i64, Vec<Uuid>)>(&sql)
        .bind(team_id)
        .bind(only)
        .fetch_all(pool)
        .await
        .map_err(|e| db_error(e, "member_contexts"))?;
    Ok(rows
        .into_iter()
        .map(|(user_id, roles, allow, deny, role_ids)| MemberContext {
            user_id,
            base: (roles | allow) & !deny,
            team_deny: deny,
            role_ids,
        })
        .collect())
}

pub async fn rule_entries(
    pool: &PgPool,
    team_id: Uuid,
    set_ids: Option<&[Uuid]>,
) -> Result<HashMap<Uuid, Vec<RuleEntry>>, StatusCode> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<Uuid>, i64, i64)>(
        "SELECT e.rule_set_id, e.subject_type, e.subject_id, e.allow_mask, e.deny_mask \
         FROM team_rule_set_entries e JOIN team_rule_sets s ON s.id = e.rule_set_id \
         WHERE s.team_id = $1 AND ($2::uuid[] IS NULL OR e.rule_set_id = ANY($2))",
    )
    .bind(team_id)
    .bind(set_ids.map(<[Uuid]>::to_vec))
    .fetch_all(pool)
    .await
    .map_err(|e| db_error(e, "rule_entries"))?;
    let mut by_set: HashMap<Uuid, Vec<RuleEntry>> = HashMap::new();
    for (set, subject_type, subject_id, allow, deny) in rows {
        let subject = match (subject_type.as_str(), subject_id) {
            ("everyone", _) => Subject::Everyone,
            ("role", Some(id)) => Subject::Role(id),
            ("member", Some(id)) => Subject::Member(id),
            _ => continue,
        };
        by_set.entry(set).or_default().push(RuleEntry { subject, allow, deny });
    }
    Ok(by_set)
}

pub struct ObjectAuthz {
    member: MemberContext,
    entries: HashMap<Uuid, Vec<RuleEntry>>,
}

impl ObjectAuthz {
    pub async fn load(pool: &PgPool, team_id: Uuid, user_id: Uuid) -> Result<Option<Self>, StatusCode> {
        let Some(member) = member_contexts(pool, team_id, Some(user_id)).await?.pop() else {
            return Ok(None);
        };
        let entries = rule_entries(pool, team_id, None).await?;
        Ok(Some(Self::for_member(member, entries)))
    }

    pub fn for_member(member: MemberContext, entries: HashMap<Uuid, Vec<RuleEntry>>) -> Self {
        Self { member, entries }
    }

    pub fn is_admin(&self) -> bool {
        self.member.base & PERM_ADMINISTRATOR != 0
    }

    pub fn mask(&self, set: Option<Uuid>) -> i64 {
        let layers = set.map(|id| {
            self.entries
                .get(&id)
                .map(|es| layers_for(es, &self.member.role_ids, self.member.user_id))
                .unwrap_or_default()
        });
        object_permissions(self.member.base, self.member.team_deny, layers.as_ref())
    }

    pub fn can(&self, set: Option<Uuid>, bits: i64) -> bool {
        let m = self.mask(set);
        m & PERM_VIEW != 0 && m & bits == bits
    }

    pub fn can_any(&self, set: Option<Uuid>, bits: i64) -> bool {
        let m = self.mask(set);
        m & PERM_VIEW != 0 && m & bits != 0
    }

    pub fn grants_anywhere(&self, live_sets: &[Uuid], bits: i64) -> bool {
        self.can_any(None, bits) || live_sets.iter().any(|s| self.can_any(Some(*s), bits))
    }

    pub fn holds_vault_key_gate(&self, live: &[Uuid]) -> bool {
        holds_vault_key_gate(self.member.clone(), self.entries.clone(), live)
    }
}

/// Team-level `CONNECT`, or `CONNECT` on any live object.
pub fn holds_vault_key_gate(member: MemberContext, entries: HashMap<Uuid, Vec<RuleEntry>>, live: &[Uuid]) -> bool {
    ObjectAuthz::for_member(member, entries).grants_anywhere(live, PERM_CONNECT)
}

pub struct ObjectRow {
    pub object_type: String,
    pub rule_set_id: Option<Uuid>,
}

pub async fn object_row(pool: &PgPool, team_id: Uuid, object_id: &str) -> Result<Option<ObjectRow>, StatusCode> {
    sqlx::query_as::<_, (String, Option<Uuid>)>(
        "SELECT object_type, rule_set_id FROM team_vault_objects WHERE team_id = $1 AND object_id = $2",
    )
    .bind(team_id)
    .bind(object_id)
    .fetch_optional(pool)
    .await
    .map(|r| r.map(|(object_type, rule_set_id)| ObjectRow { object_type, rule_set_id }))
    .map_err(|e| db_error(e, "object_row"))
}

pub async fn connection_viewers(pool: &PgPool, connection_id: &str, exclude: Uuid) -> Result<Vec<Uuid>, StatusCode> {
    let owners = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
        "SELECT team_id, rule_set_id FROM team_vault_objects \
         WHERE object_id = $1 AND object_type = 'connection' AND deleted_at IS NULL",
    )
    .bind(connection_id)
    .fetch_all(pool)
    .await
    .map_err(|e| db_error(e, "connection owners"))?;
    let mut viewers = Vec::new();
    for (team_id, set) in owners {
        let entries = rule_entries(pool, team_id, set.as_ref().map(std::slice::from_ref)).await?;
        for member in member_contexts(pool, team_id, None).await? {
            let user_id = member.user_id;
            if user_id != exclude && ObjectAuthz::for_member(member, entries.clone()).can(set, PERM_VIEW) {
                viewers.push(user_id);
            }
        }
    }
    viewers.sort();
    viewers.dedup();
    Ok(viewers)
}

pub async fn visible_connection_ids(pool: &PgPool, user_id: Uuid) -> Result<Vec<String>, StatusCode> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(
        "SELECT tvo.team_id, tvo.object_id, tvo.rule_set_id FROM team_vault_objects tvo \
         JOIN team_members tm ON tm.team_id = tvo.team_id \
         WHERE tm.user_id = $1 AND tvo.object_type = 'connection' AND tvo.deleted_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| db_error(e, "visible connections"))?;
    let mut authz: HashMap<Uuid, Option<ObjectAuthz>> = HashMap::new();
    let mut visible = Vec::new();
    for (team_id, object_id, set) in rows {
        let entry = match authz.entry(team_id) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(ObjectAuthz::load(pool, team_id, user_id).await?)
            }
        };
        if entry.as_ref().is_some_and(|a| a.can(set, PERM_VIEW)) {
            visible.push(object_id);
        }
    }
    visible.sort();
    visible.dedup();
    Ok(visible)
}

pub async fn hidden_object_ids(pool: &PgPool, team_id: Uuid, user_id: Uuid) -> Result<Vec<String>, StatusCode> {
    let authz = ObjectAuthz::load(pool, team_id, user_id).await?.ok_or(StatusCode::FORBIDDEN)?;
    let rows = sqlx::query_as::<_, (String, Option<Uuid>)>(
        "SELECT object_id, rule_set_id FROM team_vault_objects WHERE team_id = $1",
    )
    .bind(team_id)
    .fetch_all(pool)
    .await
    .map_err(|e| db_error(e, "hidden_object_ids"))?;
    Ok(rows.into_iter().filter(|(_, set)| !authz.can(*set, PERM_VIEW)).map(|(id, _)| id).collect())
}

pub async fn live_rule_set_ids(pool: &PgPool, team_id: Uuid) -> Result<Vec<Uuid>, StatusCode> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT rule_set_id FROM team_vault_objects \
         WHERE team_id = $1 AND rule_set_id IS NOT NULL AND deleted_at IS NULL",
    )
    .bind(team_id)
    .fetch_all(pool)
    .await
    .map_err(|e| db_error(e, "live_rule_set_ids"))
}

pub async fn rule_set_in_team(pool: &PgPool, team_id: Uuid, set_id: Uuid) -> Result<bool, StatusCode> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM team_rule_sets WHERE team_id = $1 AND id = $2)")
        .bind(team_id)
        .bind(set_id)
        .fetch_one(pool)
        .await
        .map_err(|e| db_error(e, "rule_set_in_team"))
}

pub async fn gc_rule_sets(conn: &mut sqlx::PgConnection, team_id: Uuid, candidates: &[Uuid]) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM team_rule_sets s WHERE s.team_id = $1 AND s.id = ANY($2) \
         AND NOT EXISTS (SELECT 1 FROM team_vault_objects o WHERE o.team_id = s.team_id AND o.rule_set_id = s.id)",
    )
    .bind(team_id)
    .bind(candidates)
    .execute(conn)
    .await
    .map(|_| ())
}

pub async fn sweep_unattached_rule_sets(pool: &PgPool) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM team_rule_sets s WHERE s.updated_at < now() - interval '1 day' \
         AND NOT EXISTS (SELECT 1 FROM team_vault_objects o WHERE o.team_id = s.team_id AND o.rule_set_id = s.id)",
    )
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub async fn record_member_client(pool: &PgPool, team_id: Uuid, user_id: Uuid, headers: &HeaderMap) {
    let version = headers
        .get("x-client-version")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().chars().take(32).collect::<String>());
    let rule_sets = client_supports_rule_sets(headers);
    let res = sqlx::query(
        "UPDATE team_members SET last_client_version = $3, last_client_rule_sets = $4 \
         WHERE team_id = $1 AND user_id = $2 \
           AND (last_client_version IS DISTINCT FROM $3 OR last_client_rule_sets IS DISTINCT FROM $4)",
    )
    .bind(team_id)
    .bind(user_id)
    .bind(version)
    .bind(rule_sets)
    .execute(pool)
    .await;
    if let Err(e) = res {
        warn!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to record member client");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::*;
    use crate::test_pool_or_skip;
    use crate::test_support::*;

    #[test]
    fn layers_for_picks_only_the_callers_role_and_member_entries() {
        let me = Uuid::new_v4();
        let other = Uuid::new_v4();
        let my_role = Uuid::new_v4();
        let other_role = Uuid::new_v4();
        let entries = [
            RuleEntry { subject: Subject::Everyone, allow: PERM_CONNECT, deny: 0 },
            RuleEntry { subject: Subject::Role(my_role), allow: PERM_VIEW_SECRETS, deny: 0 },
            RuleEntry { subject: Subject::Role(other_role), allow: PERM_COPY_SECRETS, deny: 0 },
            RuleEntry { subject: Subject::Member(me), allow: 0, deny: PERM_EDIT_KEYS },
            RuleEntry { subject: Subject::Member(other), allow: PERM_MANAGE_ROLES, deny: 0 },
        ];
        assert_eq!(
            layers_for(&entries, &[my_role], me),
            RuleLayers {
                everyone_allow: PERM_CONNECT,
                roles_allow: PERM_VIEW_SECRETS,
                member_deny: PERM_EDIT_KEYS,
                ..RuleLayers::default()
            }
        );
    }

    #[tokio::test]
    async fn load_returns_none_for_a_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        assert!(ObjectAuthz::load(&pool, team, seed_user(&pool).await).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fixture_resolves_viewer_blocked_and_admin() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        let set = Some(f.rule_set);

        let viewer = ObjectAuthz::load(&pool, f.team, f.viewer).await.unwrap().unwrap();
        let blocked = ObjectAuthz::load(&pool, f.team, f.blocked).await.unwrap().unwrap();
        let admin = ObjectAuthz::load(&pool, f.team, f.admin).await.unwrap().unwrap();

        assert!(viewer.can(set, PERM_VIEW | PERM_CONNECT));
        assert_eq!(blocked.mask(set), 0);
        assert!(!blocked.can(set, PERM_VIEW));
        assert!(admin.is_admin());
        assert!(admin.can(set, PERM_VIEW_SECRETS | PERM_EDIT_KEYS));
        assert!(blocked.can(None, PERM_VIEW | PERM_CONNECT), "unpointed objects keep team-wide rules");
    }

    #[tokio::test]
    async fn a_role_without_view_sees_nothing_on_a_team_without_rule_sets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let role = seed_role(&pool, team, "no-view", PERM_CONNECT).await;
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;
        assign_role(&pool, team, member, role).await;

        let authz = ObjectAuthz::load(&pool, team, member).await.unwrap().unwrap();

        assert!(!authz.can(None, PERM_VIEW));
        assert_eq!(authz.mask(None), PERM_CONNECT);
    }

    #[tokio::test]
    async fn role_entries_apply_through_role_membership() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let role = seed_role(&pool, team, "ops", PERM_VIEW).await;
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;
        assign_role(&pool, team, member, role).await;
        let set = seed_rule_set(&pool, team, owner, &[("role", Some(role), PERM_CONNECT, 0)]).await;

        let authz = ObjectAuthz::load(&pool, team, member).await.unwrap().unwrap();

        assert_eq!(authz.mask(Some(set)), PERM_VIEW | PERM_CONNECT);
    }

    #[tokio::test]
    async fn team_deny_beats_a_member_rule() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT).await;
        set_member_overrides(&pool, team, member, 0, PERM_VIEW_SECRETS).await;
        let set = seed_rule_set(&pool, team, owner, &[("member", Some(member), PERM_VIEW_SECRETS, 0)]).await;

        let authz = ObjectAuthz::load(&pool, team, member).await.unwrap().unwrap();

        assert_eq!(authz.mask(Some(set)) & PERM_VIEW_SECRETS, 0);
    }

    #[tokio::test]
    async fn grants_anywhere_sees_a_single_object_grant() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let junior = member_with_role(&pool, team, 0).await;
        seed_team_object(&pool, team, owner, "h-1", "connection").await;
        let set = seed_rule_set(&pool, team, owner, &[("member", Some(junior), PERM_CONNECT, 0)]).await;

        let authz = ObjectAuthz::load(&pool, team, junior).await.unwrap().unwrap();
        assert!(!authz.grants_anywhere(&live_rule_set_ids(&pool, team).await.unwrap(), PERM_CONNECT));

        point_object(&pool, team, "h-1", Some(set)).await;
        assert!(authz.grants_anywhere(&live_rule_set_ids(&pool, team).await.unwrap(), PERM_CONNECT));
    }

    #[tokio::test]
    async fn grants_anywhere_sees_a_team_wide_grant_without_a_pointed_object() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT).await;

        let authz = ObjectAuthz::load(&pool, team, member).await.unwrap().unwrap();
        assert!(authz.grants_anywhere(&[], PERM_CONNECT));
    }

    #[tokio::test]
    async fn grants_anywhere_requires_view_on_the_team_wide_path() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let role = seed_role(&pool, team, "connect-no-view", PERM_CONNECT).await;
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;
        assign_role(&pool, team, member, role).await;
        seed_rule_set(&pool, team, owner, &[]).await;

        let authz = ObjectAuthz::load(&pool, team, member).await.unwrap().unwrap();
        let live = live_rule_set_ids(&pool, team).await.unwrap();
        assert!(!authz.grants_anywhere(&live, PERM_CONNECT));
    }

    #[tokio::test]
    async fn connection_viewers_excludes_blocked_members_and_the_excluded_user() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        let viewers = connection_viewers(&pool, &f.object_id, f.viewer).await.unwrap();
        assert!(viewers.contains(&f.admin));
        assert!(!viewers.contains(&f.blocked));
        assert!(!viewers.contains(&f.viewer));
    }

    #[tokio::test]
    async fn record_member_client_stamps_version_and_feature() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT).await;

        record_member_client(&pool, team, member, &rule_set_client_headers()).await;

        let (version, rule_sets): (Option<String>, bool) = sqlx::query_as(
            "SELECT last_client_version, last_client_rule_sets FROM team_members WHERE team_id = $1 AND user_id = $2",
        )
        .bind(team)
        .bind(member)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(version.as_deref(), Some("0.99.0"));
        assert!(rule_sets);
    }
}
