use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::object_authz::{db_error, ObjectAuthz};
use crate::permissions::{is_team_member, PERM_CONNECT};

#[derive(Debug, Serialize)]
pub struct ObjectPick {
    pub object_id: String,
    pub identity_id: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct DefaultPick {
    pub team_id: Uuid,
    pub identity_id: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct IdentityPicks {
    pub objects: Vec<ObjectPick>,
    pub defaults: Vec<DefaultPick>,
}

#[derive(Debug, Deserialize)]
pub struct PickRequest {
    pub identity_id: String,
}

fn validate(identity_id: &str) -> Result<(), StatusCode> {
    if identity_id.is_empty() || identity_id.len() > 128 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

async fn can_pick_object(pool: &PgPool, user: Uuid, object_id: &str) -> Result<bool, StatusCode> {
    let rows = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
        "SELECT o.team_id, o.rule_set_id FROM team_vault_objects o
           JOIN team_members m ON m.team_id = o.team_id AND m.user_id = $1
          WHERE o.object_id = $2 AND o.object_type = 'connection' AND o.deleted_at IS NULL",
    )
    .bind(user)
    .bind(object_id)
    .fetch_all(pool)
    .await
    .map_err(|e| db_error(e, "pickable objects"))?;
    for (team_id, rule_set_id) in rows {
        if let Some(authz) = ObjectAuthz::load(pool, team_id, user).await? {
            if authz.can(rule_set_id, PERM_CONNECT) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub async fn list_picks(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<IdentityPicks>, StatusCode> {
    let objects = sqlx::query_as::<_, (String, String, DateTime<Utc>)>(
        "SELECT object_id, identity_id, updated_at FROM member_identity_picks
          WHERE user_id = $1 AND object_id IS NOT NULL ORDER BY object_id",
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| db_error(e, "list object picks"))?;
    let defaults = sqlx::query_as::<_, (Uuid, String, DateTime<Utc>)>(
        "SELECT team_id, identity_id, updated_at FROM member_identity_picks
          WHERE user_id = $1 AND team_id IS NOT NULL ORDER BY team_id",
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| db_error(e, "list team defaults"))?;
    Ok(Json(IdentityPicks {
        objects: objects
            .into_iter()
            .map(|(object_id, identity_id, updated_at)| ObjectPick {
                object_id,
                identity_id,
                updated_at,
            })
            .collect(),
        defaults: defaults
            .into_iter()
            .map(|(team_id, identity_id, updated_at)| DefaultPick {
                team_id,
                identity_id,
                updated_at,
            })
            .collect(),
    }))
}

pub async fn put_object_pick(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(object_id): Path<String>,
    Json(body): Json<PickRequest>,
) -> Result<StatusCode, StatusCode> {
    validate(&body.identity_id)?;
    if !can_pick_object(&pool, auth.0, &object_id).await? {
        return Err(StatusCode::NOT_FOUND);
    }
    sqlx::query(
        "INSERT INTO member_identity_picks (user_id, object_id, identity_id) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, object_id) WHERE object_id IS NOT NULL
         DO UPDATE SET identity_id = EXCLUDED.identity_id, updated_at = now()",
    )
    .bind(auth.0)
    .bind(&object_id)
    .bind(&body.identity_id)
    .execute(&pool)
    .await
    .map_err(|e| db_error(e, "upsert object pick"))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_object_pick(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(object_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("DELETE FROM member_identity_picks WHERE user_id = $1 AND object_id = $2")
        .bind(auth.0)
        .bind(&object_id)
        .execute(&pool)
        .await
        .map_err(|e| db_error(e, "delete object pick"))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn put_team_default(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<PickRequest>,
) -> Result<StatusCode, StatusCode> {
    validate(&body.identity_id)?;
    if !is_team_member(&pool, team_id, auth.0).await? {
        return Err(StatusCode::NOT_FOUND);
    }
    sqlx::query(
        "INSERT INTO member_identity_picks (user_id, team_id, identity_id) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, team_id) WHERE team_id IS NOT NULL
         DO UPDATE SET identity_id = EXCLUDED.identity_id, updated_at = now()",
    )
    .bind(auth.0)
    .bind(team_id)
    .bind(&body.identity_id)
    .execute(&pool)
    .await
    .map_err(|e| db_error(e, "upsert team default"))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_team_default(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("DELETE FROM member_identity_picks WHERE user_id = $1 AND team_id = $2")
        .bind(auth.0)
        .bind(team_id)
        .execute(&pool)
        .await
        .map_err(|e| db_error(e, "delete team default"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthUser;
    use crate::permissions::{PERM_CONNECT, PERM_VIEW};
    use crate::test_pool_or_skip;
    use crate::test_support::{
        hidden_object_fixture, member_with_role, seed_team, seed_team_object, seed_user,
    };
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::{Extension, Json};

    fn body(id: &str) -> Json<PickRequest> {
        Json(PickRequest {
            identity_id: id.to_string(),
        })
    }

    async fn picks(pool: &sqlx::PgPool, user: uuid::Uuid) -> IdentityPicks {
        list_picks(State(pool.clone()), Extension(AuthUser(user)))
            .await
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn object_pick_requires_view_and_connect() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        let put = |user: uuid::Uuid| {
            put_object_pick(
                State(pool.clone()),
                Extension(AuthUser(user)),
                Path(f.object_id.clone()),
                body("ident-a"),
            )
        };

        assert_eq!(put(f.blocked).await.unwrap_err(), StatusCode::NOT_FOUND);
        assert_eq!(put(f.viewer).await.unwrap(), StatusCode::NO_CONTENT);

        let view_only = member_with_role(&pool, f.team, PERM_VIEW).await;
        let plain = format!("obj-{}", uuid::Uuid::new_v4());
        seed_team_object(&pool, f.team, f.owner, &plain, "connection").await;
        let res = put_object_pick(
            State(pool.clone()),
            Extension(AuthUser(view_only)),
            Path(plain),
            body("ident-a"),
        )
        .await;
        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn object_pick_404_for_outsider_missing_object_and_non_host() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_VIEW | PERM_CONNECT).await;
        let outsider = seed_user(&pool).await;
        seed_team_object(&pool, team, owner, "host-1", "connection").await;
        seed_team_object(&pool, team, owner, "key-1", "key").await;

        let put = |user: uuid::Uuid, object: &str| {
            put_object_pick(
                State(pool.clone()),
                Extension(AuthUser(user)),
                Path(object.to_string()),
                body("ident-a"),
            )
        };
        assert_eq!(
            put(outsider, "host-1").await.unwrap_err(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            put(member, "ghost").await.unwrap_err(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            put(member, "key-1").await.unwrap_err(),
            StatusCode::NOT_FOUND
        );

        sqlx::query("UPDATE team_vault_objects SET deleted_at = now() WHERE team_id = $1 AND object_id = 'host-1'")
            .bind(team).execute(&pool).await.unwrap();
        assert_eq!(
            put(member, "host-1").await.unwrap_err(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn picks_are_per_user_and_admins_get_no_bypass() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        put_object_pick(
            State(pool.clone()),
            Extension(AuthUser(f.viewer)),
            Path(f.object_id.clone()),
            body("viewer-own"),
        )
        .await
        .unwrap();

        assert_eq!(picks(&pool, f.viewer).await.objects.len(), 1);
        assert!(picks(&pool, f.admin).await.objects.is_empty());
        assert!(picks(&pool, f.blocked).await.objects.is_empty());
    }

    #[tokio::test]
    async fn object_pick_upserts_and_delete_is_idempotent() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_VIEW | PERM_CONNECT).await;
        seed_team_object(&pool, team, owner, "host-1", "connection").await;

        let put = |id: &'static str| {
            put_object_pick(
                State(pool.clone()),
                Extension(AuthUser(member)),
                Path("host-1".to_string()),
                body(id),
            )
        };
        put("ident-a").await.unwrap();
        put("ident-b").await.unwrap();
        let listed = picks(&pool, member).await;
        assert_eq!(listed.objects.len(), 1);
        assert_eq!(listed.objects[0].identity_id, "ident-b");

        let del = || {
            delete_object_pick(
                State(pool.clone()),
                Extension(AuthUser(member)),
                Path("host-1".to_string()),
            )
        };
        assert_eq!(del().await.unwrap(), StatusCode::NO_CONTENT);
        assert_eq!(del().await.unwrap(), StatusCode::NO_CONTENT);
        assert!(picks(&pool, member).await.objects.is_empty());
    }

    #[tokio::test]
    async fn identity_id_is_validated() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_VIEW | PERM_CONNECT).await;
        seed_team_object(&pool, team, owner, "host-1", "connection").await;

        for bad in [String::new(), "x".repeat(129)] {
            let res = put_object_pick(
                State(pool.clone()),
                Extension(AuthUser(member)),
                Path("host-1".to_string()),
                body(&bad),
            )
            .await;
            assert_eq!(res.unwrap_err(), StatusCode::BAD_REQUEST);
            let res = put_team_default(
                State(pool.clone()),
                Extension(AuthUser(member)),
                Path(team),
                body(&bad),
            )
            .await;
            assert_eq!(res.unwrap_err(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn team_default_requires_membership_and_upserts() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, 0).await;
        let outsider = seed_user(&pool).await;

        let res = put_team_default(
            State(pool.clone()),
            Extension(AuthUser(outsider)),
            Path(team),
            body("x"),
        )
        .await;
        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);

        put_team_default(
            State(pool.clone()),
            Extension(AuthUser(member)),
            Path(team),
            body("a"),
        )
        .await
        .unwrap();
        put_team_default(
            State(pool.clone()),
            Extension(AuthUser(member)),
            Path(team),
            body("b"),
        )
        .await
        .unwrap();
        let listed = picks(&pool, member).await;
        assert_eq!(listed.defaults.len(), 1);
        assert_eq!(listed.defaults[0].identity_id, "b");

        delete_team_default(State(pool.clone()), Extension(AuthUser(member)), Path(team))
            .await
            .unwrap();
        assert!(picks(&pool, member).await.defaults.is_empty());
    }

    #[tokio::test]
    async fn leaving_a_team_drops_its_default_but_keeps_host_picks() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_VIEW | PERM_CONNECT).await;
        seed_team_object(&pool, team, owner, "host-1", "connection").await;
        put_object_pick(
            State(pool.clone()),
            Extension(AuthUser(member)),
            Path("host-1".to_string()),
            body("own"),
        )
        .await
        .unwrap();
        put_team_default(
            State(pool.clone()),
            Extension(AuthUser(member)),
            Path(team),
            body("own"),
        )
        .await
        .unwrap();

        sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team)
            .bind(member)
            .execute(&pool)
            .await
            .unwrap();

        let listed = picks(&pool, member).await;
        assert!(listed.defaults.is_empty());
        assert_eq!(listed.objects.len(), 1);
    }

    #[tokio::test]
    async fn deleting_an_object_keeps_picks_so_moves_survive() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_VIEW | PERM_CONNECT).await;
        seed_team_object(&pool, team, owner, "host-1", "connection").await;
        put_object_pick(
            State(pool.clone()),
            Extension(AuthUser(member)),
            Path("host-1".to_string()),
            body("own"),
        )
        .await
        .unwrap();

        sqlx::query("DELETE FROM team_vault_objects WHERE team_id = $1 AND object_id = 'host-1'")
            .bind(team)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(picks(&pool, member).await.objects.len(), 1);
    }
}
