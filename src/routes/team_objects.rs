use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::permissions::{
    require_all_team_permissions, require_team_member, require_team_permissions, PermCheck,
    PERM_CONNECT, PERM_EDIT_CONNECTIONS, PERM_EDIT_FOLDERS, PERM_EDIT_IDENTITIES, PERM_EDIT_KEYS,
    PERM_EDIT_SNIPPETS, PERM_VIEW_SECRETS,
};
use crate::routes::client_version::{require_client_version, MinClientVersion};
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
    /// Accepted for wire compatibility with shipped clients and then discarded.
    /// Nothing on either side reads these columns back; persisting them leaked
    /// connection names and folder structure in plaintext (#229).
    #[allow(dead_code)]
    pub name: Option<String>,
    #[allow(dead_code)]
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
    pub key_version: i32,
}

#[derive(Debug, Serialize)]
pub struct TeamSecretResponse {
    pub secret_id: String,
    pub object_id: String,
    pub secret_type: String,
    pub ciphertext: String,
    pub key_version: i32,
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
    Extension(min_client_version): Extension<MinClientVersion>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<Uuid>,
    Json(body): Json<UpsertTeamObjectRequest>,
) -> Result<StatusCode, StatusCode> {
    require_client_version(&min_client_version, &headers)?;

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
           VALUES ($1, $2, $3, NULL, $1, NULL, $4, $5)
           ON CONFLICT (team_id, object_id)
           DO UPDATE SET object_type = EXCLUDED.object_type,
                         name = NULL,
                         folder_id = NULL,
                         metadata = EXCLUDED.metadata,
                         deleted_at = NULL,
                         updated_at = now(),
                         updated_by = EXCLUDED.updated_by"#,
    )
    .bind(team_id)
    .bind(&body.object_id)
    .bind(body.object_type.as_str())
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

/// Upper bound on one re-encryption batch. The client sends 50 at a time, but
/// the server must not depend on that: every item in a batch is one row locked
/// for the life of a single transaction, so an unbounded batch lets a member
/// hold their whole team's rows while it commits.
pub const MAX_REENCRYPT_BATCH: usize = 500;

#[derive(Debug, Deserialize)]
pub struct ReencryptItem {
    pub object_id: String,
    pub metadata: serde_json::Value,
}

/// Resolves the union of edit permissions needed to touch every object named
/// by `object_ids` (via each secret's own `object_id` for the secrets case),
/// then requires the caller hold all of them. Types are read from the
/// database, never the request, so a caller cannot relabel an object to slip
/// past the gate. An `object_ids` set matching zero rows requires nothing —
/// see `require_team_member` below for why that alone is not a hole.
async fn require_edit_permission_for_object_ids(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
    object_ids: &[String],
) -> Result<(), StatusCode> {
    let types: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT object_type FROM team_vault_objects WHERE team_id = $1 AND object_id = ANY($2)",
    )
    .bind(team_id)
    .bind(object_ids)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to read object types for re-encryption");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut required: Vec<i64> = Vec::new();
    for t in &types {
        let perm = edit_permission_for_str(t).ok_or(StatusCode::BAD_REQUEST)?;
        if !required.contains(&perm) {
            required.push(perm);
        }
    }

    require_all_team_permissions(pool, team_id, user_id, &required).await
}

/// Rewrites the metadata blob of existing rows without touching `updated_at`
/// or `updated_by`, and broadcasts once for the whole batch rather than per
/// row. Used by the client's one-time pass that encrypts objects written
/// before #229; a per-object loop through `upsert_object` would restamp the
/// whole vault as edited and fan out one SSE event per object to every member.
pub async fn reencrypt_objects(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(sync_notifier): Extension<SyncNotifier>,
    Extension(min_client_version): Extension<MinClientVersion>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<Uuid>,
    Json(items): Json<Vec<ReencryptItem>>,
) -> Result<StatusCode, StatusCode> {
    require_client_version(&min_client_version, &headers)?;

    require_team_member(&pool, team_id, auth.0).await?;

    if items.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }
    if items.len() > MAX_REENCRYPT_BATCH {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let ids: Vec<String> = items.iter().map(|i| i.object_id.clone()).collect();

    require_edit_permission_for_object_ids(&pool, team_id, auth.0, &ids).await?;

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to open re-encryption transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    for item in &items {
        sqlx::query(
            "UPDATE team_vault_objects SET metadata = $3 WHERE team_id = $1 AND object_id = $2",
        )
        .bind(team_id)
        .bind(&item.object_id)
        .bind(&item.metadata)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, object_id = %item.object_id, "Failed to re-encrypt object");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    tx.commit().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to commit re-encryption");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    notify_team_vault_changed(&pool, &sync_notifier, team_id, auth.0).await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ReencryptSecretItem {
    pub secret_id: String,
    pub ciphertext: String,
    pub key_version: i32,
}

/// Secrets sibling of `reencrypt_objects`: rewrites ciphertext + key_version
/// only, no audit stamp, one broadcast per batch. Secrets are gated by their
/// owning object's edit permission (`object_id` join), same as `upsert_secret`.
pub async fn reencrypt_secrets(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(sync_notifier): Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(items): Json<Vec<ReencryptSecretItem>>,
) -> Result<StatusCode, StatusCode> {
    require_team_member(&pool, team_id, auth.0).await?;

    if items.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }
    if items.len() > MAX_REENCRYPT_BATCH {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let secret_ids: Vec<String> = items.iter().map(|i| i.secret_id.clone()).collect();
    let distinct_requested: std::collections::HashSet<&String> = secret_ids.iter().collect();

    // A single join, not "get object_ids then check permissions for those
    // object_ids": that two-step let an orphaned secret (object_id matching
    // no live row) resolve to an empty permission set, which
    // `require_all_team_permissions` then satisfied vacuously — any bare
    // member could rewrite that secret's ciphertext (#217 review finding
    // I7). Joining here means an orphaned secret simply never appears in
    // `resolved` at all, so it can be caught below before touching permissions.
    let resolved: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT tvs.secret_id, tvo.object_id
           FROM team_vault_secrets tvs
           JOIN team_vault_objects tvo
             ON tvo.team_id = tvs.team_id AND tvo.object_id = tvs.object_id AND tvo.deleted_at IS NULL
           WHERE tvs.team_id = $1 AND tvs.secret_id = ANY($2)"#,
    )
    .bind(team_id)
    .bind(&secret_ids)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to resolve objects for secret re-encryption");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let resolved_secret_ids: std::collections::HashSet<&String> =
        resolved.iter().map(|(secret_id, _)| secret_id).collect();
    if resolved_secret_ids.len() < distinct_requested.len() {
        warn!(
            team_id = %team_id, user_id = %auth.0,
            requested = distinct_requested.len(), resolved = resolved_secret_ids.len(),
            "Secret re-encryption batch rejected: a requested secret has no live object",
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let object_ids: Vec<String> = resolved.into_iter().map(|(_, object_id)| object_id).collect();
    require_edit_permission_for_object_ids(&pool, team_id, auth.0, &object_ids).await?;

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to open secret re-encryption transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    for item in &items {
        sqlx::query(
            "UPDATE team_vault_secrets SET ciphertext = $3, key_version = $4 WHERE team_id = $1 AND secret_id = $2",
        )
        .bind(team_id)
        .bind(&item.secret_id)
        .bind(&item.ciphertext)
        .bind(item.key_version)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, secret_id = %item.secret_id, "Failed to re-encrypt secret");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    tx.commit().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to commit secret re-encryption");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    notify_team_vault_changed(&pool, &sync_notifier, team_id, auth.0).await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_object(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(sync_notifier): Extension<SyncNotifier>,
    Extension(min_client_version): Extension<MinClientVersion>,
    headers: axum::http::HeaderMap,
    Path((team_id, object_id)): Path<(Uuid, String)>,
) -> Result<StatusCode, StatusCode> {
    require_client_version(&min_client_version, &headers)?;

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
    // Ciphertext only, and useless without the vault key, which is gated the
    // same way. A connect-only member fetches these to *use* a credential;
    // VIEW_SECRETS is what lets a member read one back (issue #190).
    require_team_permissions(
        &pool,
        team_id,
        auth.0,
        PermCheck::Any(&[PERM_CONNECT, PERM_VIEW_SECRETS]),
    )
    .await?;

    let rows = sqlx::query_as::<_, (String, String, String, String, i32, DateTime<Utc>)>(
        r#"SELECT secret_id, object_id, secret_type, ciphertext, key_version, updated_at
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
                key_version: row.4,
                updated_at: row.5,
            })
            .collect(),
    ))
}

pub async fn upsert_secret(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(sync_notifier): Extension<SyncNotifier>,
    Extension(min_client_version): Extension<MinClientVersion>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<Uuid>,
    Json(body): Json<UpsertSecretRequest>,
) -> Result<StatusCode, StatusCode> {
    require_client_version(&min_client_version, &headers)?;

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
           (team_id, secret_id, object_id, secret_type, ciphertext, updated_by, key_version)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (team_id, secret_id)
           DO UPDATE SET object_id = EXCLUDED.object_id,
                         secret_type = EXCLUDED.secret_type,
                         ciphertext = EXCLUDED.ciphertext,
                         updated_at = now(),
                         updated_by = EXCLUDED.updated_by,
                         key_version = EXCLUDED.key_version"#,
    )
    .bind(team_id)
    .bind(&body.secret_id)
    .bind(&body.object_id)
    .bind(&body.secret_type)
    .bind(&body.ciphertext)
    .bind(auth.0)
    .bind(body.key_version)
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
    Extension(min_client_version): Extension<MinClientVersion>,
    headers: axum::http::HeaderMap,
    Path((team_id, secret_id)): Path<(Uuid, String)>,
) -> Result<StatusCode, StatusCode> {
    require_client_version(&min_client_version, &headers)?;

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
    use crate::permissions::{PERM_CONNECT, PERM_EDIT_CONNECTIONS, PERM_EDIT_SNIPPETS, PERM_VIEW_SECRETS};
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
    async fn upsert_object_does_not_persist_name_or_folder_id() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        upsert_object(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-1".to_string(),
                object_type: TeamObjectType::Connection,
                name: Some("prod-db-master".to_string()),
                folder_id: Some("folder-7".to_string()),
                metadata: serde_json::json!({ "host": "10.0.0.1" }),
            }),
        )
        .await
        .unwrap();

        let (name, folder_id): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT name, folder_id FROM team_vault_objects WHERE team_id = $1 AND object_id = $2",
        )
        .bind(team)
        .bind("obj-1")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(name, None, "name must not be persisted");
        assert_eq!(folder_id, None, "folder_id must not be persisted");
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            key_version: 1,
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            key_version: 1,
        };
        let secret_id = body.secret_id.clone();

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(secret_body("does-not-exist")),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::NOT_FOUND);
    }

    // ── upsert_secret stamps key_version (final review C1) ─────────────────────

    /// Fresh insert: a secret written with `key_version: 2` must persist that
    /// epoch, not silently fall back to the column default of 1.
    #[tokio::test]
    async fn upsert_secret_stamps_key_version_on_insert() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let mut body = secret_body(&object_id);
        body.key_version = 2;
        let secret_id = body.secret_id.clone();

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(body),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        let kv: i32 = sqlx::query_scalar(
            "SELECT key_version FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2",
        )
        .bind(team)
        .bind(&secret_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kv, 2, "fresh insert must persist the request's key_version");
    }

    /// Update path: re-upserting an existing secret at a new epoch must move
    /// its `key_version` forward — this is what lets `draining` clear after a
    /// rotation completes.
    #[tokio::test]
    async fn upsert_secret_stamps_key_version_on_update() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let mut body = secret_body(&object_id);
        body.key_version = 1;
        let secret_id = body.secret_id.clone();

        upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(body),
        )
        .await
        .unwrap();

        let mut update = secret_body(&object_id);
        update.secret_id = secret_id.clone();
        update.key_version = 3;

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(update),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        let kv: i32 = sqlx::query_scalar(
            "SELECT key_version FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2",
        )
        .bind(team)
        .bind(&secret_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kv, 3, "re-upsert must move key_version forward on conflict");
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(body),
        )
        .await
        .expect("seed secret");
        secret_id
    }

    // ─── GET /v1/teams/:team_id/secrets (issue #190) ─────────────────────────

    #[tokio::test]
    async fn list_secrets_ok_with_only_connect_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let secret_id = seed_secret(&pool, team, &object_id).await;
        // A connect-only member reads ciphertext to *use* a credential. Denying
        // it left the role unable to connect to any host with a stored secret.
        let caller = member_with_role(&pool, team, PERM_CONNECT).await;

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(caller)), Path(team))
            .await
            .expect("list secrets ok")
            .0;

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].secret_id, secret_id);
    }

    /// C2: without `key_version` on the wire, a client cannot tell which
    /// epoch a secret's ciphertext is under, so it can't route a stale row to
    /// the historical-key fetch. Seed two secrets at different epochs directly
    /// (bypassing `upsert_secret`, which stamps whatever the request says) and
    /// confirm each comes back tagged with its own epoch, not epoch 1 for both.
    #[tokio::test]
    async fn list_secrets_exposes_key_version_per_row() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_CONNECT).await;

        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by, key_version) \
             VALUES ($1, 'sec-old', $2, 'connection_password', 'old-cipher', $3, 1)",
        )
        .bind(team).bind(&object_id).bind(owner).execute(&pool).await.expect("seed epoch-1 secret");
        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by, key_version) \
             VALUES ($1, 'sec-new', $2, 'connection_password', 'new-cipher', $3, 3)",
        )
        .bind(team).bind(&object_id).bind(owner).execute(&pool).await.expect("seed epoch-3 secret");

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(caller)), Path(team))
            .await
            .expect("list secrets ok")
            .0;

        let old = res.iter().find(|s| s.secret_id == "sec-old").expect("old secret present");
        let new = res.iter().find(|s| s.secret_id == "sec-new").expect("new secret present");
        assert_eq!(old.key_version, 1);
        assert_eq!(new.key_version, 3);
    }

    #[tokio::test]
    async fn list_secrets_forbidden_without_connect_or_view_secrets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Edit rights on snippets grant neither bit.
        let caller = member_with_role(&pool, team, PERM_EDIT_SNIPPETS).await;

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(caller)), Path(team)).await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
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
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path((team, object_id.clone())),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        assert!(!secret_exists(&pool, team, &secret_id).await);
    }

    // ── reencrypt_objects ───────────────────────────────────────────────────

    #[tokio::test]
    async fn reencrypt_preserves_updated_at_and_updated_by() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let author = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let migrator = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        upsert_object(
            State(pool.clone()),
            Extension(AuthUser(author)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-1".to_string(),
                object_type: TeamObjectType::Connection,
                name: None,
                folder_id: None,
                metadata: serde_json::json!({ "host": "10.0.0.1" }),
            }),
        )
        .await
        .unwrap();

        let before: (chrono::DateTime<chrono::Utc>, Uuid) = sqlx::query_as(
            "SELECT updated_at, updated_by FROM team_vault_objects WHERE team_id = $1 AND object_id = $2",
        )
        .bind(team)
        .bind("obj-1")
        .fetch_one(&pool)
        .await
        .unwrap();

        reencrypt_objects(
            State(pool.clone()),
            Extension(AuthUser(migrator)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(vec![ReencryptItem {
                object_id: "obj-1".to_string(),
                metadata: serde_json::json!({ "v": 2, "enc": "Y2lwaGVy" }),
            }]),
        )
        .await
        .unwrap();

        let after: (chrono::DateTime<chrono::Utc>, Uuid, serde_json::Value) = sqlx::query_as(
            "SELECT updated_at, updated_by, metadata FROM team_vault_objects WHERE team_id = $1 AND object_id = $2",
        )
        .bind(team)
        .bind("obj-1")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            after.0, before.0,
            "re-encryption must not restamp updated_at"
        );
        assert_eq!(
            after.1, before.1,
            "re-encryption must not reassign updated_by"
        );
        assert_eq!(after.2, serde_json::json!({ "v": 2, "enc": "Y2lwaGVy" }));
    }

    #[tokio::test]
    async fn reencrypt_forbidden_when_batch_includes_an_uneditable_type() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Can edit connections, but NOT keys.
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        for (id, ty) in [
            ("c1", TeamObjectType::Connection),
            ("k1", TeamObjectType::Key),
        ] {
            sqlx::query(
                "INSERT INTO team_vault_objects (team_id, object_id, object_type, vault_id, metadata, updated_by)
                 VALUES ($1, $2, $3, $1, '{}'::jsonb, $4)",
            )
            .bind(team)
            .bind(id)
            .bind(ty.as_str())
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        }

        let res = reencrypt_objects(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(vec![
                ReencryptItem {
                    object_id: "c1".to_string(),
                    metadata: serde_json::json!({ "v": 2, "enc": "eA==" }),
                },
                ReencryptItem {
                    object_id: "k1".to_string(),
                    metadata: serde_json::json!({ "v": 2, "enc": "eQ==" }),
                },
            ]),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);

        // And nothing was written — the batch is all-or-nothing.
        let c1: serde_json::Value = sqlx::query_scalar(
            "SELECT metadata FROM team_vault_objects WHERE team_id = $1 AND object_id = 'c1'",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            c1,
            serde_json::json!({}),
            "a rejected batch must write nothing"
        );
    }

    /// A non-member submitting only nonexistent object ids must not get a
    /// `204` back — that would let anyone probe whether an object still
    /// exists in a team they no longer belong to (batching makes this many
    /// ids per request). Membership must be checked before the batch is
    /// resolved against the database, not implied by an empty permission set.
    #[tokio::test]
    async fn reencrypt_forbidden_for_a_non_member_even_with_no_matching_objects() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await; // never added to team

        let res = reencrypt_objects(
            State(pool.clone()),
            Extension(AuthUser(outsider)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(vec![ReencryptItem {
                object_id: "does-not-exist".to_string(),
                metadata: serde_json::json!({ "v": 2, "enc": "eA==" }),
            }]),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    // ── version floor ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn upsert_object_rejected_below_the_version_floor() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-client-version", "0.32.1".parse().unwrap());

        let res = upsert_object(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(Some((0, 33, 0)))),
            headers,
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-1".to_string(),
                object_type: TeamObjectType::Connection,
                name: None,
                folder_id: None,
                metadata: serde_json::json!({ "host": "10.0.0.1" }),
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::UPGRADE_REQUIRED);
    }

    #[tokio::test]
    async fn upsert_object_allowed_at_or_above_the_version_floor() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        // Exactly the floor — the boundary case worth pinning.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-client-version", "0.33.0".parse().unwrap());

        let res = upsert_object(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(Some((0, 33, 0)))),
            headers,
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-1".to_string(),
                object_type: TeamObjectType::Connection,
                name: None,
                folder_id: None,
                metadata: serde_json::json!({ "host": "10.0.0.1" }),
            }),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn list_objects_is_never_gated_by_version() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // A real team member — `seed_team` alone does not make `owner` one.
        let caller = member_with_role(&pool, team, PERM_CONNECT).await;

        // No X-Client-Version header at all. Reads must still work so an old
        // client shows a degraded vault rather than an empty one; note that
        // `list_objects` takes no `MinClientVersion`/`HeaderMap` at all, so
        // there is no way to gate it even if an operator sets a floor.
        let res = list_objects(State(pool.clone()), Extension(AuthUser(caller)), Path(team)).await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn reencrypt_rejects_a_batch_over_the_cap() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let items: Vec<ReencryptItem> = (0..=MAX_REENCRYPT_BATCH)
            .map(|i| ReencryptItem {
                object_id: format!("obj-{i}"),
                metadata: serde_json::json!({ "v": 2, "enc": "eA==" }),
            })
            .collect();

        let res = reencrypt_objects(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(items),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn reencrypt_ignores_object_ids_not_in_this_team() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let res = reencrypt_objects(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(vec![ReencryptItem {
                object_id: "does-not-exist".to_string(),
                metadata: serde_json::json!({ "v": 2, "enc": "eA==" }),
            }]),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
    }

    // ── reencrypt_secrets ───────────────────────────────────────────────────

    #[tokio::test]
    async fn reencrypt_secrets_updates_ciphertext_and_key_version() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let editor = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by, key_version) \
             VALUES ($1, 'sec-1', $2, 'connection_password', 'old-cipher', $3, 1)",
        )
        .bind(team).bind(&object_id).bind(owner).execute(&pool).await.expect("seed old secret");

        let res = reencrypt_secrets(
            State(pool.clone()),
            Extension(AuthUser(editor)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(vec![ReencryptSecretItem {
                secret_id: "sec-1".to_string(),
                ciphertext: "new-cipher".to_string(),
                key_version: 2,
            }]),
        )
        .await;

        assert_eq!(res, Ok(StatusCode::NO_CONTENT));

        let (cipher, kv): (String, i32) = sqlx::query_as(
            "SELECT ciphertext, key_version FROM team_vault_secrets WHERE team_id = $1 AND secret_id = 'sec-1'",
        )
        .bind(team).fetch_one(&pool).await.unwrap();
        assert_eq!(cipher, "new-cipher");
        assert_eq!(kv, 2);
    }

    #[tokio::test]
    async fn reencrypt_secrets_forbidden_without_the_object_edit_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_VIEW_SECRETS).await; // no EDIT_CONNECTIONS

        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by) \
             VALUES ($1, 'sec-1', $2, 'connection_password', 'old-cipher', $3)",
        )
        .bind(team).bind(&object_id).bind(owner).execute(&pool).await.expect("seed old secret");

        let res = reencrypt_secrets(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(vec![ReencryptSecretItem {
                secret_id: "sec-1".to_string(),
                ciphertext: "new-cipher".to_string(),
                key_version: 2,
            }]),
        )
        .await;

        assert_eq!(res, Err(StatusCode::FORBIDDEN));
    }

    /// I7: `require_edit_permission_for_object_ids` resolves required
    /// permissions from `team_vault_objects` rows matching the given
    /// object_ids. A secret whose `object_id` matches no live object row
    /// (orphaned — deleted object, or a bug) used to resolve to an *empty*
    /// permission set, which `require_all_team_permissions` satisfied
    /// vacuously — any bare member could overwrite that secret's ciphertext.
    /// Simulate the orphan directly via SQL, bypassing the normal
    /// object-then-secret creation order, since the live write paths cannot
    /// produce this state on their own.
    #[tokio::test]
    async fn reencrypt_secrets_rejects_a_batch_with_an_orphaned_secret() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // A bare member: on the team, but with no permission bits at all.
        let caller = member_with_role(&pool, team, 0).await;

        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by) \
             VALUES ($1, 'sec-orphan', 'no-such-object', 'connection_password', 'old-cipher', $2)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("seed orphaned secret");

        let res = reencrypt_secrets(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(vec![ReencryptSecretItem {
                secret_id: "sec-orphan".to_string(),
                ciphertext: "attacker-cipher".to_string(),
                key_version: 2,
            }]),
        )
        .await;

        assert_eq!(res, Err(StatusCode::BAD_REQUEST));

        let ciphertext: String = sqlx::query_scalar(
            "SELECT ciphertext FROM team_vault_secrets WHERE team_id = $1 AND secret_id = 'sec-orphan'",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ciphertext, "old-cipher", "a rejected batch must not touch the orphaned secret's ciphertext");
    }

    #[tokio::test]
    async fn reencrypt_secrets_forbidden_for_non_member_even_with_no_matching_rows() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await; // never added to team

        // Regression guard for the same class of bug d7ead25 fixed for objects:
        // an empty permission set from zero matching rows must not pass vacuously.
        let res = reencrypt_secrets(
            State(pool.clone()),
            Extension(AuthUser(outsider)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(vec![ReencryptSecretItem {
                secret_id: "does-not-exist".to_string(),
                ciphertext: "x".to_string(),
                key_version: 2,
            }]),
        )
        .await;

        assert_eq!(res, Err(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn reencrypt_objects_still_forbidden_for_non_member_after_the_refactor() {
        // Characterization test: the extraction in this task must not change
        // reencrypt_objects's existing membership-check behavior (the exact bug
        // d7ead25 fixed upstream of this branch).
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await;

        let res = reencrypt_objects(
            State(pool.clone()),
            Extension(AuthUser(outsider)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            axum::http::HeaderMap::new(),
            Path(team),
            Json(vec![ReencryptItem {
                object_id: "does-not-exist".to_string(),
                metadata: serde_json::json!({}),
            }]),
        )
        .await;

        assert_eq!(res, Err(StatusCode::FORBIDDEN));
    }
}
