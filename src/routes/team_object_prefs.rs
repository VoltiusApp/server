use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::permissions::require_team_member;

#[derive(Debug, Serialize)]
pub struct TeamObjectPrefResponse {
    pub object_id: String,
    pub pinned: Option<bool>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertPrefRequest {
    pub pinned: Option<bool>,
}

pub async fn list_object_prefs(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<Vec<TeamObjectPrefResponse>>, StatusCode> {
    require_team_member(&pool, team_id, auth.0).await?;

    let rows = sqlx::query_as::<_, (String, Option<bool>, DateTime<Utc>)>(
        r#"SELECT object_id, pinned, updated_at
           FROM team_user_object_prefs
           WHERE team_id = $1 AND user_id = $2"#,
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %auth.0, "Failed to list team user object prefs");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        rows.into_iter()
            .map(|(object_id, pinned, updated_at)| TeamObjectPrefResponse {
                object_id,
                pinned,
                updated_at,
            })
            .collect(),
    ))
}

pub async fn upsert_object_pref(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path((team_id, object_id)): Path<(Uuid, String)>,
    Json(body): Json<UpsertPrefRequest>,
) -> Result<StatusCode, StatusCode> {
    require_team_member(&pool, team_id, auth.0).await?;

    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_vault_objects WHERE team_id = $1 AND object_id = $2)",
    )
    .bind(team_id)
    .bind(&object_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, object_id = %object_id, "Failed to check team vault object existence");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !exists {
        return Err(StatusCode::NOT_FOUND);
    }

    if body.pinned.is_none() {
        sqlx::query(
            r#"DELETE FROM team_user_object_prefs
               WHERE team_id = $1 AND user_id = $2 AND object_id = $3"#,
        )
        .bind(team_id)
        .bind(auth.0)
        .bind(&object_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, object_id = %object_id, "Failed to clear team user object pref");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    } else {
        sqlx::query(
            r#"INSERT INTO team_user_object_prefs (team_id, user_id, object_id, pinned)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (team_id, user_id, object_id)
               DO UPDATE SET pinned = EXCLUDED.pinned, updated_at = now()"#,
        )
        .bind(team_id)
        .bind(auth.0)
        .bind(&object_id)
        .bind(body.pinned)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, object_id = %object_id, "Failed to upsert team user object pref");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_object_pref(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path((team_id, object_id)): Path<(Uuid, String)>,
) -> Result<StatusCode, StatusCode> {
    require_team_member(&pool, team_id, auth.0).await?;

    sqlx::query(
        r#"DELETE FROM team_user_object_prefs
           WHERE team_id = $1 AND user_id = $2 AND object_id = $3"#,
    )
    .bind(team_id)
    .bind(auth.0)
    .bind(&object_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, object_id = %object_id, "Failed to delete team user object pref");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod authz_tests {
    use super::*;
    use crate::auth::AuthUser;
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, seed_team, seed_team_object, seed_user};
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::{Extension, Json};

    #[tokio::test]
    async fn list_prefs_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await;

        let res = list_object_prefs(State(pool.clone()), Extension(AuthUser(outsider)), Path(team)).await;

        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_prefs_is_user_scoped() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let alice = seed_user(&pool).await;
        let bob = seed_user(&pool).await;
        add_member(&pool, team, alice).await;
        add_member(&pool, team, bob).await;
        seed_team_object(&pool, team, owner, "obj-a", "connection").await;
        seed_team_object(&pool, team, owner, "obj-b", "connection").await;

        // Alice pins obj-a; Bob pins obj-b.
        upsert_object_pref(
            State(pool.clone()), Extension(AuthUser(alice)),
            Path((team, "obj-a".to_string())), Json(UpsertPrefRequest { pinned: Some(true) }),
        ).await.unwrap();
        upsert_object_pref(
            State(pool.clone()), Extension(AuthUser(bob)),
            Path((team, "obj-b".to_string())), Json(UpsertPrefRequest { pinned: Some(true) }),
        ).await.unwrap();

        let alice_prefs = list_object_prefs(State(pool.clone()), Extension(AuthUser(alice)), Path(team)).await.unwrap().0;
        assert_eq!(alice_prefs.len(), 1);
        assert_eq!(alice_prefs[0].object_id, "obj-a");
    }

    #[tokio::test]
    async fn upsert_pref_forbidden_for_non_member_even_if_object_missing() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await;

        // 403 (membership) must win over 404 (object existence): outsider + no object.
        let res = upsert_object_pref(
            State(pool.clone()), Extension(AuthUser(outsider)),
            Path((team, "nope".to_string())), Json(UpsertPrefRequest { pinned: Some(true) }),
        ).await;

        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn upsert_pref_not_found_for_missing_object() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;

        let res = upsert_object_pref(
            State(pool.clone()), Extension(AuthUser(member)),
            Path((team, "ghost".to_string())), Json(UpsertPrefRequest { pinned: Some(true) }),
        ).await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn upsert_pref_sets_and_clears() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;
        seed_team_object(&pool, team, owner, "obj-1", "connection").await;

        // Set pinned=true → NO_CONTENT, and it shows up in the list read-back.
        let set = upsert_object_pref(
            State(pool.clone()), Extension(AuthUser(member)),
            Path((team, "obj-1".to_string())), Json(UpsertPrefRequest { pinned: Some(true) }),
        ).await.unwrap();
        assert_eq!(set, StatusCode::NO_CONTENT);
        let prefs = list_object_prefs(State(pool.clone()), Extension(AuthUser(member)), Path(team)).await.unwrap().0;
        assert_eq!(prefs.len(), 1);
        assert_eq!(prefs[0].pinned, Some(true));

        // pinned=None clears the row.
        upsert_object_pref(
            State(pool.clone()), Extension(AuthUser(member)),
            Path((team, "obj-1".to_string())), Json(UpsertPrefRequest { pinned: None }),
        ).await.unwrap();
        let after = list_object_prefs(State(pool.clone()), Extension(AuthUser(member)), Path(team)).await.unwrap().0;
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn delete_pref_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await;

        let res = delete_object_pref(
            State(pool.clone()), Extension(AuthUser(outsider)),
            Path((team, "whatever".to_string())),
        ).await;

        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_pref_removes_row() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;
        seed_team_object(&pool, team, owner, "obj-2", "connection").await;
        upsert_object_pref(
            State(pool.clone()), Extension(AuthUser(member)),
            Path((team, "obj-2".to_string())), Json(UpsertPrefRequest { pinned: Some(true) }),
        ).await.unwrap();

        let del = delete_object_pref(
            State(pool.clone()), Extension(AuthUser(member)),
            Path((team, "obj-2".to_string())),
        ).await.unwrap();
        assert_eq!(del, StatusCode::NO_CONTENT);

        let prefs = list_object_prefs(State(pool.clone()), Extension(AuthUser(member)), Path(team)).await.unwrap().0;
        assert!(prefs.is_empty());
    }
}
