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
