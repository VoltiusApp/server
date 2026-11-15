use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::object_authz::{
    compose_member_row, live_rule_set_ids, member_rows, object_refs, preview_for, rule_entries,
    team_role_bits, MemberContext, ObjectAuthz, ObjectRef, Preview,
};
use crate::permissions::{has_team_permission, ALL_PERMISSIONS, PERM_MANAGE_MEMBERS, PERM_VIEW};
use crate::team_plan::{require_granular, team_locked};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PreviewSubject {
    Member {
        user_id: Uuid,
    },
    Role {
        #[allow(dead_code)]
        role_id: Uuid,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum PreviewDraft {
    Member {
        role_ids: Vec<Uuid>,
        allow: i64,
        deny: i64,
    },
    Role {
        #[allow(dead_code)]
        permissions: i64,
    },
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
    let PreviewSubject::Member { user_id } = body.subject else {
        return Err(StatusCode::NOT_IMPLEMENTED);
    };
    let caller = ObjectAuthz::load(&pool, team_id, auth.0)
        .await?
        .ok_or(StatusCode::FORBIDDEN)?;
    if !has_team_permission(&pool, team_id, auth.0, PERM_MANAGE_MEMBERS).await? {
        return Err(StatusCode::FORBIDDEN);
    }
    let gate_only = body.scope == PreviewScope::VaultKeyGate;
    if !gate_only {
        require_granular(&pool, team_id, false).await?;
    }
    let row = member_rows(&pool, team_id, Some(user_id))
        .await?
        .pop()
        .ok_or(StatusCode::NOT_FOUND)?;
    let locked = team_locked(&pool, team_id).await?;

    let draft_row = match body.draft {
        None => None,
        Some(PreviewDraft::Member {
            role_ids,
            allow,
            deny,
        }) => {
            let roles = team_role_bits(&pool, team_id).await?;
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
        Some(PreviewDraft::Role { .. }) => return Err(StatusCode::BAD_REQUEST),
    };

    let objects = visible_objects(&pool, team_id, &caller).await?;
    let entries = rule_entries(&pool, team_id, None).await?;
    let live = live_rule_set_ids(&pool, team_id).await?;
    let build = |ctx: MemberContext| shape(preview_for(ctx, &entries, &objects, &live), gate_only);

    Ok(Json(PreviewResponse {
        locked,
        current: build(row.context(locked)),
        draft: draft_row.map(|r| build(r.context(locked))),
        affected: None,
    }))
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
        let draft = PreviewDraft::Member {
            role_ids: vec![member_role],
            allow: 0,
            deny: PERM_CONNECT,
        };
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
        let draft = PreviewDraft::Member {
            role_ids,
            allow: 0,
            deny: PERM_CONNECT,
        };
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
        let draft = PreviewDraft::Member {
            role_ids: vec![foreign],
            allow: 0,
            deny: 0,
        };
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
        let draft = PreviewDraft::Role {
            permissions: PERM_CONNECT,
        };
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
            PreviewDraft::Member {
                allow: 1,
                deny: 2,
                ..
            }
        ));
        let r: PreviewDraft = serde_json::from_str(r#"{"permissions":5}"#).unwrap();
        assert!(matches!(r, PreviewDraft::Role { permissions: 5 }));
    }
}
