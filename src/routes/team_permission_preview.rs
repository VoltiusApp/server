use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::object_authz::{
    compose_member_row, live_rule_set_ids, member_rows, object_refs, preview_for, rule_entries,
    team_role_bits, MemberContext, MemberRow, ObjectAuthz, ObjectRef, Preview, RoleBits, RuleEntry,
};
use crate::permissions::{
    has_team_permission, ALL_PERMISSIONS, PERM_MANAGE_MEMBERS, PERM_MANAGE_ROLES, PERM_VIEW,
};
use crate::team_plan::{require_granular, team_locked};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PreviewSubject {
    Member { user_id: Uuid },
    Role { role_id: Uuid },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberDraft {
    pub role_ids: Vec<Uuid>,
    pub allow: i64,
    pub deny: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDraft {
    pub permissions: i64,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum PreviewDraft {
    Member(MemberDraft),
    Role(RoleDraft),
}

#[derive(Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PreviewScope {
    #[default]
    Full,
    VaultKeyGate,
}

#[derive(Deserialize)]
pub struct PreviewRequest {
    pub subject: PreviewSubject,
    #[serde(default)]
    pub draft: Option<PreviewDraft>,
    #[serde(default)]
    pub scope: PreviewScope,
}

#[derive(Serialize)]
pub struct Affected {
    pub changed: Vec<Uuid>,
    pub lose_vault_key: Vec<Uuid>,
}

#[derive(Serialize)]
pub struct PreviewResponse {
    pub locked: bool,
    pub current: Preview,
    pub draft: Option<Preview>,
    pub affected: Option<Affected>,
}

pub async fn preview_permissions(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, StatusCode> {
    let caller = ObjectAuthz::load(&pool, team_id, auth.0)
        .await?
        .ok_or(StatusCode::FORBIDDEN)?;
    let needed = match body.subject {
        PreviewSubject::Member { .. } => PERM_MANAGE_MEMBERS,
        PreviewSubject::Role { .. } => PERM_MANAGE_ROLES,
    };
    if !has_team_permission(&pool, team_id, auth.0, needed).await? {
        return Err(StatusCode::FORBIDDEN);
    }
    let gate_only = body.scope == PreviewScope::VaultKeyGate;
    if !gate_only {
        require_granular(&pool, team_id, false).await?;
    }
    let locked = team_locked(&pool, team_id).await?;
    let roles = team_role_bits(&pool, team_id).await?;
    let objects = visible_objects(&pool, team_id, &caller).await?;
    let entries = rule_entries(&pool, team_id, None).await?;
    let live = live_rule_set_ids(&pool, team_id).await?;
    let build = |ctx: MemberContext| shape(preview_for(ctx, &entries, &objects, &live), gate_only);

    let (current, draft, affected) = match (body.subject, body.draft) {
        (PreviewSubject::Member { user_id }, draft) => {
            let row = member_rows(&pool, team_id, Some(user_id))
                .await?
                .pop()
                .ok_or(StatusCode::NOT_FOUND)?;
            let draft_row = match draft {
                None => None,
                Some(PreviewDraft::Member(MemberDraft {
                    role_ids,
                    allow,
                    deny,
                })) => {
                    if !role_ids.iter().all(|id| roles.iter().any(|r| r.id == *id)) {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    Some(compose_member_row(
                        user_id,
                        &role_ids,
                        allow & ALL_PERMISSIONS,
                        deny & ALL_PERMISSIONS,
                        &roles,
                    ))
                }
                Some(PreviewDraft::Role(_)) => return Err(StatusCode::BAD_REQUEST),
            };
            (
                build(row.context(locked)),
                draft_row.map(|r| build(r.context(locked))),
                None,
            )
        }
        (PreviewSubject::Role { role_id }, draft) => {
            let role = roles
                .iter()
                .find(|r| r.id == role_id)
                .ok_or(StatusCode::NOT_FOUND)?;
            let role_ctx = |roles: &[RoleBits]| {
                compose_member_row(Uuid::nil(), &[role_id], 0, 0, roles).context(locked)
            };
            match draft {
                None => (build(role_ctx(&roles)), None, None),
                Some(PreviewDraft::Role(RoleDraft { permissions })) if !role.builtin => {
                    let drafted = with_role_bits(&roles, role_id, permissions);
                    let rows = member_rows(&pool, team_id, None).await?;
                    let affected = affected_by_role_draft(
                        &rows,
                        &roles,
                        role_id,
                        permissions,
                        locked,
                        &entries,
                        &objects,
                        &live,
                    );
                    (
                        build(role_ctx(&roles)),
                        Some(build(role_ctx(&drafted))),
                        Some(affected),
                    )
                }
                Some(_) => return Err(StatusCode::BAD_REQUEST),
            }
        }
    };

    Ok(Json(PreviewResponse {
        locked,
        current,
        draft,
        affected,
    }))
}

fn with_role_bits(roles: &[RoleBits], role_id: Uuid, draft_bits: i64) -> Vec<RoleBits> {
    roles
        .iter()
        .map(|r| RoleBits {
            permissions: if r.id == role_id {
                draft_bits & ALL_PERMISSIONS
            } else {
                r.permissions
            },
            ..*r
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn affected_by_role_draft(
    rows: &[MemberRow],
    roles: &[RoleBits],
    role_id: Uuid,
    draft_bits: i64,
    locked: bool,
    entries: &HashMap<Uuid, Vec<RuleEntry>>,
    objects: &[ObjectRef],
    live: &[Uuid],
) -> Affected {
    let drafted = with_role_bits(roles, role_id, draft_bits);
    let preview = |row: &MemberRow, roles: &[RoleBits]| {
        let ctx = compose_member_row(row.user_id, &row.role_ids, row.allow, row.deny, roles)
            .context(locked);
        preview_for(ctx, entries, objects, live)
    };
    let mut holders: Vec<&MemberRow> = rows
        .iter()
        .filter(|r| r.role_ids.contains(&role_id))
        .collect();
    holders.sort_by_key(|r| r.user_id);
    let mut affected = Affected {
        changed: vec![],
        lose_vault_key: vec![],
    };
    for row in holders {
        let (before, after) = (preview(row, roles), preview(row, &drafted));
        let same_objects = before.objects.len() == after.objects.len()
            && before
                .objects
                .iter()
                .zip(&after.objects)
                .all(|(a, b)| a.0 == b.0 && a.1.mask == b.1.mask);
        if before.team_bits != after.team_bits || !same_objects {
            affected.changed.push(row.user_id);
        }
        if before.holds_vault_key_gate && !after.holds_vault_key_gate {
            affected.lose_vault_key.push(row.user_id);
        }
    }
    affected
}

fn shape(mut preview: Preview, gate_only: bool) -> Preview {
    if gate_only {
        preview.objects.clear();
        preview.rule_sets.clear();
    }
    preview
}

async fn visible_objects(
    pool: &PgPool,
    team_id: Uuid,
    caller: &ObjectAuthz,
) -> Result<Vec<ObjectRef>, StatusCode> {
    let objects = object_refs(pool, team_id, false).await?;
    Ok(objects
        .into_iter()
        .filter(|o| caller.can(o.rule_set_id, PERM_VIEW))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_authz::{RuleEntry, Subject};
    use crate::permissions::{PERM_ADMINISTRATOR, PERM_CONNECT};
    use crate::routes::team_objects::list_objects;
    use crate::test_pool_or_skip;
    use crate::test_support::*;
    use std::collections::HashMap;

    struct Fx {
        team: Uuid,
        owner: Uuid,
        manager: Uuid,
        target: Uuid,
    }

    async fn fx(pool: &PgPool) -> Fx {
        let owner = seed_user(pool).await;
        let team = seed_team_with_roles(pool, owner).await;
        let manager = member_with_role(pool, team, PERM_MANAGE_MEMBERS | PERM_CONNECT).await;
        let target = member_with_role(pool, team, PERM_CONNECT).await;
        Fx {
            team,
            owner,
            manager,
            target,
        }
    }

    fn member_req(
        user: Uuid,
        draft: Option<PreviewDraft>,
        scope: PreviewScope,
    ) -> Json<PreviewRequest> {
        Json(PreviewRequest {
            subject: PreviewSubject::Member { user_id: user },
            draft,
            scope,
        })
    }

    async fn call(
        pool: &PgPool,
        team: Uuid,
        caller: Uuid,
        req: Json<PreviewRequest>,
    ) -> Result<PreviewResponse, StatusCode> {
        preview_permissions(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Path(team),
            req,
        )
        .await
        .map(|j| j.0)
    }

    async fn full(pool: &PgPool, f: &Fx, caller: Uuid, user: Uuid) -> PreviewResponse {
        call(
            pool,
            f.team,
            caller,
            member_req(user, None, PreviewScope::Full),
        )
        .await
        .expect("preview")
    }

    async fn soft_delete(pool: &PgPool, team: Uuid, id: &str) {
        sqlx::query("UPDATE team_vault_objects SET deleted_at = now() WHERE team_id = $1 AND object_id = $2")
            .bind(team)
            .bind(id)
            .execute(pool)
            .await
            .expect("soft delete");
    }

    #[tokio::test]
    async fn preview_requires_manage_members() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let plain = member_with_role(&pool, f.team, PERM_CONNECT).await;
        let res = call(
            &pool,
            f.team,
            plain,
            member_req(f.target, None, PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn preview_is_402_below_business() {
        let _b = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        set_user_tier(&pool, f.owner, "teams").await;
        let res = call(
            &pool,
            f.team,
            f.owner,
            member_req(f.target, None, PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::PAYMENT_REQUIRED));
    }

    #[tokio::test]
    async fn key_gate_scope_works_below_business() {
        let _b = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        set_user_tier(&pool, owner, "teams").await;
        let target = seed_user(&pool).await;
        add_member(&pool, team, target).await;
        grant_builtin_role(&pool, team, target, "member").await;
        seed_team_object(&pool, team, owner, "o1", "connection").await;
        let member_role: Uuid = sqlx::query_scalar(
            "SELECT id FROM team_roles WHERE team_id = $1 AND is_builtin AND name = 'member'",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .unwrap();
        let draft = PreviewDraft::Member(MemberDraft {
            role_ids: vec![member_role],
            allow: 0,
            deny: PERM_CONNECT,
        });
        let res = call(
            &pool,
            team,
            owner,
            member_req(target, Some(draft), PreviewScope::VaultKeyGate),
        )
        .await
        .expect("gate scope");
        assert!(res.current.holds_vault_key_gate);
        assert!(!res.draft.expect("draft").holds_vault_key_gate);
        assert!(res.current.objects.is_empty() && res.current.rule_sets.is_empty());
    }

    #[tokio::test]
    async fn preview_returns_404_for_a_non_member() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let res = call(
            &pool,
            f.team,
            f.owner,
            member_req(Uuid::new_v4(), None, PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn preview_matches_list_objects_for_the_target() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        grant_builtin_role(&pool, f.team, f.admin, "owner").await;
        seed_team_object(&pool, f.team, f.owner, "plain", "connection").await;
        let fx = Fx {
            team: f.team,
            owner: f.owner,
            manager: f.admin,
            target: f.viewer,
        };
        for target in [f.viewer, f.blocked] {
            let preview = full(&pool, &fx, f.admin, target).await;
            let listed: HashMap<String, i64> = list_objects(
                State(pool.clone()),
                Extension(AuthUser(target)),
                rule_set_client_headers(),
                Path(f.team),
            )
            .await
            .expect("list")
            .0
            .into_iter()
            .map(|o| (o.object_id, o.my_permissions))
            .collect();
            assert_eq!(preview.current.objects.len(), 2);
            for (id, o) in &preview.current.objects {
                assert_eq!(o.mask, listed.get(id).copied().unwrap_or(0), "object {id}");
            }
        }
        let blocked = full(&pool, &fx, f.admin, f.blocked).await;
        assert_eq!(blocked.current.objects[&f.object_id].mask, 0);
    }

    #[tokio::test]
    async fn preview_omits_objects_the_caller_cannot_view() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        seed_team_object(&pool, f.team, f.owner, "h", "connection").await;
        seed_team_object(&pool, f.team, f.owner, "v", "connection").await;
        let set = seed_rule_set(
            &pool,
            f.team,
            f.owner,
            &[
                ("member", Some(f.manager), 0, PERM_VIEW),
                ("member", Some(f.target), PERM_VIEW, 0),
            ],
        )
        .await;
        point_object(&pool, f.team, "h", Some(set)).await;
        let res = full(&pool, &f, f.manager, f.target).await;
        assert!(!res.current.objects.contains_key("h"));
        assert!(res.current.objects.contains_key("v"));
    }

    #[tokio::test]
    async fn preview_skips_deleted_objects() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let target = member_with_role(&pool, f.team, 0).await;
        seed_team_object(&pool, f.team, f.owner, "gone", "connection").await;
        seed_team_object(&pool, f.team, f.owner, "kept", "connection").await;
        let set = seed_rule_set(
            &pool,
            f.team,
            f.owner,
            &[("member", Some(target), PERM_CONNECT, 0)],
        )
        .await;
        point_object(&pool, f.team, "gone", Some(set)).await;
        let before = full(&pool, &f, f.owner, target).await;
        assert!(before.current.objects.contains_key("gone"));
        assert!(before.current.holds_vault_key_gate);
        soft_delete(&pool, f.team, "gone").await;
        let res = full(&pool, &f, f.owner, target).await;
        assert!(!res.current.objects.contains_key("gone"));
        assert!(res.current.objects.contains_key("kept"));
        assert!(res.current.rule_sets.is_empty());
        assert!(!res.current.holds_vault_key_gate);
    }

    #[tokio::test]
    async fn preview_of_an_administrator_sees_everything_the_caller_sees() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let admin = seed_user(&pool).await;
        add_member(&pool, f.team, admin).await;
        grant_builtin_role(&pool, f.team, admin, "owner").await;
        seed_team_object(&pool, f.team, f.owner, "a", "connection").await;
        seed_team_object(&pool, f.team, f.owner, "b", "folder").await;
        let set = seed_rule_set(
            &pool,
            f.team,
            f.owner,
            &[("everyone", None, 0, PERM_VIEW | PERM_CONNECT)],
        )
        .await;
        point_object(&pool, f.team, "b", Some(set)).await;
        let res = full(&pool, &f, f.owner, admin).await;
        assert_eq!(res.current.objects.len(), 2);
        for o in res.current.objects.values() {
            assert_eq!(
                o.mask & (PERM_VIEW | PERM_CONNECT),
                PERM_VIEW | PERM_CONNECT
            );
        }
        assert!(res.current.holds_vault_key_gate);
        assert!(res.current.team_bits & PERM_ADMINISTRATOR != 0);
    }

    #[tokio::test]
    async fn member_draft_overrides_change_the_draft_only() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        seed_team_object(&pool, f.team, f.owner, "o", "connection").await;
        let role_ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT role_id FROM team_member_roles WHERE user_id = $1")
                .bind(f.target)
                .fetch_all(&pool)
                .await
                .unwrap();
        let draft = PreviewDraft::Member(MemberDraft {
            role_ids,
            allow: 0,
            deny: PERM_CONNECT,
        });
        let res = call(
            &pool,
            f.team,
            f.owner,
            member_req(f.target, Some(draft), PreviewScope::Full),
        )
        .await
        .expect("preview");
        let d = res.draft.expect("draft");
        assert!(res.current.team_bits & PERM_CONNECT != 0);
        assert!(d.team_bits & PERM_CONNECT == 0);
        assert!(!d.holds_vault_key_gate);
        assert!(res.current.holds_vault_key_gate);
    }

    #[tokio::test]
    async fn member_draft_with_a_foreign_role_id_is_400() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let other_owner = seed_user(&pool).await;
        let other_team = seed_team_with_roles(&pool, other_owner).await;
        let foreign = seed_role(&pool, other_team, "foreign", PERM_CONNECT).await;
        let draft = PreviewDraft::Member(MemberDraft {
            role_ids: vec![foreign],
            allow: 0,
            deny: 0,
        });
        let res = call(
            &pool,
            f.team,
            f.owner,
            member_req(f.target, Some(draft), PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn member_draft_on_role_shape_is_400() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let draft = PreviewDraft::Role(RoleDraft {
            permissions: PERM_CONNECT,
        });
        let res = call(
            &pool,
            f.team,
            f.owner,
            member_req(f.target, Some(draft), PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn draft_shapes_deserialize_to_their_variants() {
        let m: PreviewDraft =
            serde_json::from_str(r#"{"role_ids":[],"allow":1,"deny":2}"#).unwrap();
        assert!(matches!(
            m,
            PreviewDraft::Member(MemberDraft {
                allow: 1,
                deny: 2,
                ..
            })
        ));
        let r: PreviewDraft = serde_json::from_str(r#"{"permissions":5}"#).unwrap();
        assert!(matches!(
            r,
            PreviewDraft::Role(RoleDraft { permissions: 5 })
        ));
    }

    #[test]
    fn mixed_draft_shapes_match_neither_variant() {
        for body in [
            r#"{"role_ids":[],"allow":0,"deny":0,"permissions":5}"#,
            r#"{"permissions":5,"allow":0}"#,
        ] {
            assert!(
                serde_json::from_str::<PreviewDraft>(body).is_err(),
                "{body}"
            );
        }
    }

    fn role(id: Uuid, builtin: bool, permissions: i64) -> RoleBits {
        RoleBits {
            id,
            builtin,
            permissions,
        }
    }

    fn holder(user: Uuid, role_ids: &[Uuid]) -> MemberRow {
        compose_member_row(user, role_ids, 0, 0, &[])
    }

    #[test]
    fn role_draft_lists_only_members_who_lose_the_gate() {
        let (r, member_role) = (Uuid::new_v4(), Uuid::new_v4());
        let (alice, bob, carol) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let roles = [
            role(r, false, PERM_VIEW | PERM_CONNECT),
            role(member_role, true, PERM_VIEW | PERM_CONNECT),
        ];
        let rows = [
            holder(alice, &[r]),
            holder(bob, &[r, member_role]),
            holder(carol, &[r]),
        ];
        let set = Uuid::new_v4();
        let entries = HashMap::from([(
            set,
            vec![RuleEntry {
                subject: Subject::Member(carol),
                allow: PERM_VIEW | PERM_CONNECT,
                deny: 0,
            }],
        )]);
        let objects = [ObjectRef {
            object_id: "o".into(),
            rule_set_id: Some(set),
        }];
        let a = affected_by_role_draft(
            &rows,
            &roles,
            r,
            PERM_VIEW,
            false,
            &entries,
            &objects,
            &[set],
        );
        assert_eq!(a.lose_vault_key, vec![alice]);
        assert!(a.changed.contains(&alice));
        assert!(!a.changed.contains(&bob));
    }

    #[test]
    fn role_draft_ignores_non_holders() {
        let (r, other) = (Uuid::new_v4(), Uuid::new_v4());
        let dave = Uuid::new_v4();
        let roles = [
            role(r, false, PERM_VIEW | PERM_CONNECT),
            role(other, false, PERM_CONNECT),
        ];
        let rows = [holder(dave, &[other])];
        let a = affected_by_role_draft(&rows, &roles, r, 0, false, &HashMap::new(), &[], &[]);
        assert!(a.changed.is_empty() && a.lose_vault_key.is_empty());
    }

    fn role_req(
        role_id: Uuid,
        draft: Option<PreviewDraft>,
        scope: PreviewScope,
    ) -> Json<PreviewRequest> {
        Json(PreviewRequest {
            subject: PreviewSubject::Role { role_id },
            draft,
            scope,
        })
    }

    async fn builtin_role_id(pool: &PgPool, team: Uuid, name: &str) -> Uuid {
        sqlx::query_scalar(
            "SELECT id FROM team_roles WHERE team_id = $1 AND is_builtin AND name = $2",
        )
        .bind(team)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn role_preview_requires_manage_roles() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let r = seed_role(&pool, f.team, "r", PERM_CONNECT).await;
        let res = call(
            &pool,
            f.team,
            f.manager,
            role_req(r, None, PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
        let outsider = seed_user(&pool).await;
        let res = call(
            &pool,
            f.team,
            outsider,
            role_req(r, None, PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn role_preview_of_a_builtin_role_works_without_draft() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        seed_team_object(&pool, f.team, f.owner, "o", "connection").await;
        let member = builtin_role_id(&pool, f.team, "member").await;
        let res = call(
            &pool,
            f.team,
            f.owner,
            role_req(member, None, PreviewScope::Full),
        )
        .await
        .expect("preview");
        assert!(res.draft.is_none() && res.affected.is_none());
        assert!(res.current.team_bits & PERM_CONNECT != 0);
        assert!(res.current.objects.contains_key("o"));
    }

    #[tokio::test]
    async fn role_draft_on_a_builtin_role_is_400() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let member = builtin_role_id(&pool, f.team, "member").await;
        let draft = PreviewDraft::Role(RoleDraft { permissions: 0 });
        let res = call(
            &pool,
            f.team,
            f.owner,
            role_req(member, Some(draft), PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn role_draft_of_the_member_shape_is_400() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let r = seed_role(&pool, f.team, "r", PERM_CONNECT).await;
        let draft = PreviewDraft::Member(MemberDraft {
            role_ids: vec![],
            allow: 0,
            deny: 0,
        });
        let res = call(
            &pool,
            f.team,
            f.owner,
            role_req(r, Some(draft), PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn role_preview_of_a_foreign_role_is_404() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let other_owner = seed_user(&pool).await;
        let other_team = seed_team_with_roles(&pool, other_owner).await;
        let foreign = seed_role(&pool, other_team, "foreign", PERM_CONNECT).await;
        let res = call(
            &pool,
            f.team,
            f.owner,
            role_req(foreign, None, PreviewScope::Full),
        )
        .await;
        assert_eq!(res.err(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn role_preview_uses_no_member_layer() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        seed_team_object(&pool, f.team, f.owner, "o", "connection").await;
        let r = seed_role(&pool, f.team, "r", PERM_VIEW).await;
        let set = seed_rule_set(
            &pool,
            f.team,
            f.owner,
            &[("member", Some(f.target), PERM_CONNECT, 0)],
        )
        .await;
        point_object(&pool, f.team, "o", Some(set)).await;
        let res = call(
            &pool,
            f.team,
            f.owner,
            role_req(r, None, PreviewScope::Full),
        )
        .await
        .expect("preview");
        assert_eq!(res.current.objects["o"].mask & PERM_CONNECT, 0);
        assert!(!res.current.holds_vault_key_gate);
    }

    #[tokio::test]
    async fn role_draft_reports_affected_holders() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let r = seed_role(&pool, f.team, "r", PERM_VIEW | PERM_CONNECT).await;
        let holder = seed_user(&pool).await;
        add_member(&pool, f.team, holder).await;
        assign_role(&pool, f.team, holder, r).await;
        let draft = PreviewDraft::Role(RoleDraft {
            permissions: PERM_VIEW,
        });
        let res = call(
            &pool,
            f.team,
            f.owner,
            role_req(r, Some(draft), PreviewScope::Full),
        )
        .await
        .expect("preview");
        let a = res.affected.expect("affected");
        assert_eq!(a.changed, vec![holder]);
        assert_eq!(a.lose_vault_key, vec![holder]);
        assert!(res.current.holds_vault_key_gate);
        assert!(!res.draft.expect("draft").holds_vault_key_gate);
    }

    #[tokio::test]
    async fn role_draft_with_gate_scope_still_returns_affected() {
        let _b = BillingMode::self_hosted();
        let pool = test_pool_or_skip!();
        let f = fx(&pool).await;
        let r = seed_role(&pool, f.team, "r", PERM_VIEW | PERM_CONNECT).await;
        let holder = seed_user(&pool).await;
        add_member(&pool, f.team, holder).await;
        assign_role(&pool, f.team, holder, r).await;
        seed_team_object(&pool, f.team, f.owner, "o", "connection").await;
        let draft = PreviewDraft::Role(RoleDraft { permissions: 0 });
        let res = call(
            &pool,
            f.team,
            f.owner,
            role_req(r, Some(draft), PreviewScope::VaultKeyGate),
        )
        .await
        .expect("preview");
        assert_eq!(res.affected.expect("affected").lose_vault_key, vec![holder]);
        assert!(res.current.objects.is_empty() && res.current.rule_sets.is_empty());
    }
}
