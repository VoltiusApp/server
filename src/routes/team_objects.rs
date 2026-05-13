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
use crate::permissions::{
    require_all_team_permissions, require_team_member, PERM_EDIT_CONNECTIONS, PERM_EDIT_FOLDERS,
    PERM_EDIT_IDENTITIES, PERM_EDIT_KEYS, PERM_VIEW_SECRETS,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TeamObjectType {
    Connection,
    Identity,
    Key,
    Folder,
    Snippet,
    SnippetFolder,
    PortForwardingRule,
}

impl TeamObjectType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Identity => "identity",
            Self::Key => "key",
            Self::Folder => "folder",
            Self::Snippet => "snippet",
            Self::SnippetFolder => "snippet_folder",
            Self::PortForwardingRule => "port_forwarding_rule",
        }
    }

    fn edit_permission(&self) -> i64 {
        match self {
            Self::Connection | Self::Snippet | Self::PortForwardingRule => PERM_EDIT_CONNECTIONS,
            Self::Identity => PERM_EDIT_IDENTITIES,
            Self::Key => PERM_EDIT_KEYS,
            Self::Folder | Self::SnippetFolder => PERM_EDIT_FOLDERS,
        }
    }
}

fn edit_permission_for_str(object_type: &str) -> Option<i64> {
    match object_type {
        "connection" | "snippet" | "port_forwarding_rule" => Some(PERM_EDIT_CONNECTIONS),
        "identity" => Some(PERM_EDIT_IDENTITIES),
        "key" => Some(PERM_EDIT_KEYS),
        "folder" | "snippet_folder" => Some(PERM_EDIT_FOLDERS),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub struct UpsertTeamObjectRequest {
    pub object_id: String,
    pub object_type: TeamObjectType,
    pub name: Option<String>,
    pub folder_id: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TeamObjectResponse {
    pub object_id: String,
    pub object_type: String,
    pub name: Option<String>,
    pub folder_id: Option<String>,
    pub metadata: serde_json::Value,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertSecretRequest {
    pub secret_id: String,
    pub object_id: String,
    pub secret_type: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize)]
pub struct TeamSecretResponse {
    pub secret_id: String,
    pub object_id: String,
    pub secret_type: String,
    pub ciphertext: String,
    pub updated_at: DateTime<Utc>,
}

pub async fn list_objects(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<Vec<TeamObjectResponse>>, StatusCode> {
    require_team_member(&pool, team_id, auth.0).await?;

    let rows = sqlx::query_as::<_, (
        String,
        String,
        Option<String>,
        Option<String>,
        serde_json::Value,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    )>(
        r#"SELECT object_id, object_type, name, folder_id, metadata, updated_at, deleted_at
           FROM team_vault_objects
           WHERE team_id = $1
           ORDER BY updated_at ASC"#,
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to list team vault objects");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        rows.into_iter()
            .map(|row| TeamObjectResponse {
                object_id: row.0,
                object_type: row.1,
                name: row.2,
                folder_id: row.3,
                metadata: row.4,
                updated_at: row.5,
                deleted_at: row.6,
            })
            .collect(),
    ))
}

pub async fn upsert_object(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<UpsertTeamObjectRequest>,
) -> Result<StatusCode, StatusCode> {
    require_all_team_permissions(&pool, team_id, auth.0, &[body.object_type.edit_permission()]).await?;

    sqlx::query(
        r#"INSERT INTO team_vault_objects
           (team_id, object_id, object_type, name, vault_id, folder_id, metadata, updated_by)
           VALUES ($1, $2, $3, $4, $1, $5, $6, $7)
           ON CONFLICT (team_id, object_id)
           DO UPDATE SET object_type = EXCLUDED.object_type,
                         name = EXCLUDED.name,
                         folder_id = EXCLUDED.folder_id,
                         metadata = EXCLUDED.metadata,
                         deleted_at = NULL,
                         updated_at = now(),
                         updated_by = EXCLUDED.updated_by"#,
    )
    .bind(team_id)
    .bind(&body.object_id)
    .bind(body.object_type.as_str())
    .bind(&body.name)
    .bind(&body.folder_id)
    .bind(&body.metadata)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, object_id = %body.object_id, "Failed to upsert team vault object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_object(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path((team_id, object_id)): Path<(Uuid, String)>,
) -> Result<StatusCode, StatusCode> {
    let object_type = sqlx::query_scalar::<_, String>(
        "SELECT object_type FROM team_vault_objects WHERE team_id = $1 AND object_id = $2",
    )
    .bind(team_id)
    .bind(&object_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, object_id = %object_id, "Failed to fetch team vault object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    let permission = edit_permission_for_str(&object_type).ok_or(StatusCode::BAD_REQUEST)?;
    require_all_team_permissions(&pool, team_id, auth.0, &[permission]).await?;

    sqlx::query(
        "UPDATE team_vault_objects SET deleted_at = now(), updated_at = now(), updated_by = $3 WHERE team_id = $1 AND object_id = $2",
    )
    .bind(team_id)
    .bind(&object_id)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, object_id = %object_id, "Failed to delete team vault object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_secrets(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<Vec<TeamSecretResponse>>, StatusCode> {
    require_all_team_permissions(&pool, team_id, auth.0, &[PERM_VIEW_SECRETS]).await?;

    let rows = sqlx::query_as::<_, (String, String, String, String, DateTime<Utc>)>(
        r#"SELECT secret_id, object_id, secret_type, ciphertext, updated_at
           FROM team_vault_secrets
           WHERE team_id = $1
           ORDER BY updated_at ASC"#,
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to list team vault secrets");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        rows.into_iter()
            .map(|row| TeamSecretResponse {
                secret_id: row.0,
                object_id: row.1,
                secret_type: row.2,
                ciphertext: row.3,
                updated_at: row.4,
            })
            .collect(),
    ))
}

pub async fn upsert_secret(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<UpsertSecretRequest>,
) -> Result<StatusCode, StatusCode> {
    let object_type = sqlx::query_scalar::<_, String>(
        "SELECT object_type FROM team_vault_objects WHERE team_id = $1 AND object_id = $2 AND deleted_at IS NULL",
    )
    .bind(team_id)
    .bind(&body.object_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, object_id = %body.object_id, "Failed to fetch object for secret write");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    let permission = edit_permission_for_str(&object_type).ok_or(StatusCode::BAD_REQUEST)?;
    require_all_team_permissions(&pool, team_id, auth.0, &[permission]).await?;

    sqlx::query(
        r#"INSERT INTO team_vault_secrets
           (team_id, secret_id, object_id, secret_type, ciphertext, updated_by)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (team_id, secret_id)
           DO UPDATE SET object_id = EXCLUDED.object_id,
                         secret_type = EXCLUDED.secret_type,
                         ciphertext = EXCLUDED.ciphertext,
                         updated_at = now(),
                         updated_by = EXCLUDED.updated_by"#,
    )
    .bind(team_id)
    .bind(&body.secret_id)
    .bind(&body.object_id)
    .bind(&body.secret_type)
    .bind(&body.ciphertext)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, secret_id = %body.secret_id, "Failed to upsert team vault secret");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::NO_CONTENT)
}
