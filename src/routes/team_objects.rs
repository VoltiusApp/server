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
    PERM_EDIT_IDENTITIES, PERM_EDIT_KEYS, PERM_EDIT_SNIPPETS, PERM_VIEW_SECRETS,
};
use crate::sync_notifier::{notify_team_vault_changed, SyncNotifier};

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
            Self::Connection | Self::PortForwardingRule => PERM_EDIT_CONNECTIONS,
            Self::Snippet => PERM_EDIT_SNIPPETS,
            Self::Identity => PERM_EDIT_IDENTITIES,
            Self::Key => PERM_EDIT_KEYS,
            Self::Folder | Self::SnippetFolder => PERM_EDIT_FOLDERS,
        }
    }
}

/// A secret's own type already names the kind of object it belongs to, so the
/// gate does not depend on an object row that may be soft-deleted or gone by the
/// time the secret is withdrawn. Agrees with `edit_permission_for_str` for every
/// object that can carry secrets.
fn edit_permission_for_secret_type(secret_type: &str) -> Option<i64> {
    match secret_type {
        "connection_password" | "connection_key" | "connection_passphrase" => {
            Some(PERM_EDIT_CONNECTIONS)
        }
        "identity_password" => Some(PERM_EDIT_IDENTITIES),
        "key_private" | "key_public" | "key_passphrase" => Some(PERM_EDIT_KEYS),
        _ => None,
    }
}

fn edit_permission_for_str(object_type: &str) -> Option<i64> {
    match object_type {
        "connection" | "port_forwarding_rule" => Some(PERM_EDIT_CONNECTIONS),
        "snippet" => Some(PERM_EDIT_SNIPPETS),
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
    pub updated_by: Uuid,
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

    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Option<String>,
            serde_json::Value,
            DateTime<Utc>,
            Uuid,
            Option<DateTime<Utc>>,
        ),
    >(
        r#"SELECT object_id, object_type, name, folder_id, metadata, updated_at, updated_by, deleted_at
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
                updated_by: row.6,
                deleted_at: row.7,
            })
            .collect(),
    ))
}

pub async fn upsert_object(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(sync_notifier): Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<UpsertTeamObjectRequest>,
) -> Result<StatusCode, StatusCode> {
    require_all_team_permissions(
        &pool,
        team_id,
        auth.0,
        &[body.object_type.edit_permission()],
    )
    .await?;

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

    notify_team_vault_changed(&pool, &sync_notifier, team_id, auth.0).await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_object(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(sync_notifier): Extension<SyncNotifier>,
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

    // Personal pin/hide prefs for this object become meaningless once it's
    // removed from the team vault. Cascading delete to avoid orphan rows.
    let _ = sqlx::query(
        "DELETE FROM team_user_object_prefs WHERE team_id = $1 AND object_id = $2",
    )
    .bind(team_id)
    .bind(&object_id)
    .execute(&pool)
    .await;

    // The object row is only soft-deleted, but its secrets are not: a password
    // left behind stays readable by everyone in the vault, which is the whole
    // point of removing the object. A member who pastes the object back in
    // republishes them.
    sqlx::query("DELETE FROM team_vault_secrets WHERE team_id = $1 AND object_id = $2")
        .bind(team_id)
        .bind(&object_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, object_id = %object_id, "Failed to delete team vault secrets for object");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    notify_team_vault_changed(&pool, &sync_notifier, team_id, auth.0).await;

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
    Extension(sync_notifier): Extension<SyncNotifier>,
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

    notify_team_vault_changed(&pool, &sync_notifier, team_id, auth.0).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Withdraws one secret from a team vault. Used when an object leaves the vault
/// but survives elsewhere, where `delete_object`'s cascade never runs.
pub async fn delete_secret(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(sync_notifier): Extension<SyncNotifier>,
    Path((team_id, secret_id)): Path<(Uuid, String)>,
) -> Result<StatusCode, StatusCode> {
    let secret_type = sqlx::query_scalar::<_, String>(
        "SELECT secret_type FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2",
    )
    .bind(team_id)
    .bind(&secret_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, secret_id = %secret_id, "Failed to fetch team vault secret");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    let permission =
        edit_permission_for_secret_type(&secret_type).ok_or(StatusCode::BAD_REQUEST)?;
    require_all_team_permissions(&pool, team_id, auth.0, &[permission]).await?;

    sqlx::query("DELETE FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2")
        .bind(team_id)
        .bind(&secret_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, secret_id = %secret_id, "Failed to delete team vault secret");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    notify_team_vault_changed(&pool, &sync_notifier, team_id, auth.0).await;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod authz_tests {
    use super::*;
    use crate::auth::AuthUser;
    use crate::permissions::{PERM_EDIT_CONNECTIONS, PERM_VIEW_SECRETS};
    use crate::sync_notifier::SyncNotifier;
    use crate::test_pool_or_skip;
    use crate::test_support::{member_with_role, seed_team, seed_user};
    use axum::extract::{Path, State};
    use axum::{Extension, Json};

    #[tokio::test]
    async fn list_objects_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await; // never added to team

        let res = list_objects(
            State(pool.clone()),
            Extension(AuthUser(outsider)),
            Path(team),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn upsert_object_forbidden_without_edit_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Member can VIEW secrets but cannot EDIT connections.
        let caller = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;

        let res = upsert_object(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-1".to_string(),
                object_type: TeamObjectType::Connection,
                name: Some("box".to_string()),
                folder_id: None,
                metadata: serde_json::json!({}),
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn upsert_object_ok_with_edit_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let res = upsert_object(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-2".to_string(),
                object_type: TeamObjectType::Connection,
                name: Some("box".to_string()),
                folder_id: None,
                metadata: serde_json::json!({}),
            }),
        )
        .await;

        assert!(res.is_ok(), "expected Ok, got {:?}", res.err());
    }

    #[tokio::test]
    async fn list_secrets_forbidden_without_view_secrets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await; // no VIEW_SECRETS

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(caller)), Path(team)).await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    // ── upsert_secret gates on the *object's* edit permission, not VIEW_SECRETS ──

    /// Create a connection object owned by an EDIT_CONNECTIONS member so secret
    /// writes have a target. Returns the object_id.
    async fn seed_connection_object(pool: &PgPool, team: Uuid) -> String {
        let editor = member_with_role(pool, team, PERM_EDIT_CONNECTIONS).await;
        let object_id = format!("conn-{}", Uuid::new_v4());
        upsert_object(
            State(pool.clone()),
            Extension(AuthUser(editor)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: object_id.clone(),
                object_type: TeamObjectType::Connection,
                name: Some("box".to_string()),
                folder_id: None,
                metadata: serde_json::json!({}),
            }),
        )
        .await
        .expect("seed connection object");
        object_id
    }

    fn secret_body(object_id: &str) -> UpsertSecretRequest {
        UpsertSecretRequest {
            secret_id: format!("sec-{}", Uuid::new_v4()),
            object_id: object_id.to_string(),
            secret_type: "connection_password".to_string(),
            ciphertext: "cipher".to_string(),
        }
    }

    #[tokio::test]
    async fn upsert_secret_forbidden_with_only_view_secrets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        // Caller can VIEW secrets but cannot EDIT connections — the object's gate.
        let caller = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(secret_body(&object_id)),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn upsert_secret_ok_with_object_edit_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let body = secret_body(&object_id);
        let secret_id = body.secret_id.clone();

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(body),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        // Confirm the write actually landed (not merely a non-error status).
        let persisted = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2 AND updated_by = $3)",
        )
        .bind(team)
        .bind(&secret_id)
        .bind(caller)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(persisted);
    }

    /// A connection's inline key passphrase (`passphrase:<conn_id>`) had no
    /// permitted `secret_type`, so this INSERT tripped the CHECK constraint and
    /// members got the encrypted key without the passphrase to open it.
    #[tokio::test]
    async fn upsert_secret_accepts_connection_passphrase() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let body = UpsertSecretRequest {
            secret_id: format!("passphrase:{object_id}"),
            object_id: object_id.clone(),
            secret_type: "connection_passphrase".to_string(),
            ciphertext: "cipher".to_string(),
        };
        let secret_id = body.secret_id.clone();

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(body),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        let persisted = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2)",
        )
        .bind(team)
        .bind(&secret_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(persisted);

        // The withdraw path gates on secret_type, not object_type: without the
        // mapping it answers 400 and the material stays readable in the vault.
        let res = delete_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, secret_id.clone())),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        assert!(!secret_exists(&pool, team, &secret_id).await);
    }

    #[tokio::test]
    async fn upsert_secret_not_found_for_missing_object() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Even a fully-privileged caller gets 404 when the object doesn't exist.
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(secret_body("does-not-exist")),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::NOT_FOUND);
    }

    // ── delete_secret ────────────────────────────────────────────────────────

    async fn seed_secret(pool: &PgPool, team: Uuid, object_id: &str) -> String {
        let editor = member_with_role(pool, team, PERM_EDIT_CONNECTIONS).await;
        let body = secret_body(object_id);
        let secret_id = body.secret_id.clone();
        upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(editor)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(body),
        )
        .await
        .expect("seed secret");
        secret_id
    }

    async fn secret_exists(pool: &PgPool, team: Uuid, secret_id: &str) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2)",
        )
        .bind(team)
        .bind(secret_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn delete_secret_forbidden_with_only_view_secrets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let secret_id = seed_secret(&pool, team, &object_id).await;
        let caller = member_with_role(&pool, team, PERM_VIEW_SECRETS).await;

        let res = delete_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, secret_id.clone())),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
        assert!(secret_exists(&pool, team, &secret_id).await);
    }

    #[tokio::test]
    async fn delete_secret_ok_with_object_edit_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let secret_id = seed_secret(&pool, team, &object_id).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let res = delete_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, secret_id.clone())),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        assert!(!secret_exists(&pool, team, &secret_id).await);
    }

    /// The gate reads the secret's own type, so it still works once the object
    /// has left the vault — which is exactly when this route is called.
    #[tokio::test]
    async fn delete_secret_ok_after_object_removed() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let secret_id = seed_secret(&pool, team, &object_id).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        sqlx::query("UPDATE team_vault_objects SET deleted_at = now() WHERE team_id = $1 AND object_id = $2")
            .bind(team)
            .bind(&object_id)
            .execute(&pool)
            .await
            .unwrap();

        let res = delete_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, secret_id.clone())),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        assert!(!secret_exists(&pool, team, &secret_id).await);
    }

    #[tokio::test]
    async fn delete_secret_not_found_for_missing_secret() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let res = delete_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, "does-not-exist".to_string())),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::NOT_FOUND);
    }

    /// Deleting the object takes its secrets with it — otherwise a removed
    /// password stays readable by every member with VIEW_SECRETS.
    #[tokio::test]
    async fn delete_object_cascades_to_secrets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let secret_id = seed_secret(&pool, team, &object_id).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let res = delete_object(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path((team, object_id.clone())),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        assert!(!secret_exists(&pool, team, &secret_id).await);
    }
}
