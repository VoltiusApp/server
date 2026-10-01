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
use crate::object_authz::{
    gc_rule_sets, live_rule_set_ids, object_row, record_member_client, rule_set_in_team, ObjectAuthz,
};
use crate::permissions::{
    PERM_CONNECT, PERM_EDIT_CONNECTIONS, PERM_EDIT_FOLDERS, PERM_EDIT_IDENTITIES, PERM_EDIT_KEYS,
    PERM_EDIT_SNIPPETS, PERM_MANAGE_ROLES, PERM_VIEW,
};
use crate::routes::client_version::{require_client_version, require_rule_set_feature, MinClientVersion};
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

/// Gated from the secret's own type so a soft-deleted or missing owner still resolves.
fn edit_permission_for_secret_type(secret_type: &str) -> Option<i64> {
    secret_owner_type(secret_type).and_then(edit_permission_for_str)
}

fn secret_owner_type(secret_type: &str) -> Option<&'static str> {
    match secret_type {
        "connection_password"
        | "connection_key"
        | "connection_passphrase"
        | "connection_proxy_password" => Some("connection"),
        "identity_password" => Some("identity"),
        "key_private" | "key_public" | "key_passphrase" => Some("key"),
        _ => None,
    }
}

/// Inverse of the client's `teamSecretFromLocalKey`; a colon in a connection key id would alias `key:<id>:<part>`.
fn canonical_secret_id(object_id: &str, secret_type: &str) -> Option<String> {
    Some(match secret_type {
        "connection_password" => format!("password:{object_id}"),
        "connection_key" if !object_id.contains(':') => format!("key:{object_id}"),
        "connection_passphrase" => format!("passphrase:{object_id}"),
        "connection_proxy_password" if object_id != "__global__" => format!("proxy_password:{object_id}"),
        "identity_password" => format!("identity:{object_id}:password"),
        "key_private" => format!("key:{object_id}:private"),
        "key_public" => format!("key:{object_id}:public"),
        "key_passphrase" => format!("key:{object_id}:passphrase"),
        _ => return None,
    })
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

fn require_edit_on(authz: &ObjectAuthz, rows: &[(String, Option<Uuid>)]) -> Result<(), StatusCode> {
    if rows.iter().any(|(_, set)| !authz.can(*set, PERM_VIEW)) {
        return Err(StatusCode::NOT_FOUND);
    }
    for (object_type, set) in rows {
        let perm = edit_permission_for_str(object_type).ok_or(StatusCode::BAD_REQUEST)?;
        if !authz.can(*set, perm) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(())
}

async fn folder_rule_set(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    team_id: Uuid,
    folder_id: &str,
) -> Result<Option<Uuid>, StatusCode> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT rule_set_id FROM team_vault_objects \
         WHERE team_id = $1 AND object_id = $2 AND object_type IN ('folder', 'snippet_folder')",
    )
    .bind(team_id)
    .bind(folder_id)
    .fetch_optional(&mut **tx)
    .await
    .map(Option::flatten)
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to read the parent folder's rule set");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<Uuid>>, D::Error> {
    Option::<Uuid>::deserialize(d).map(Some)
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
    #[serde(default, deserialize_with = "present")]
    pub rule_set_id: Option<Option<Uuid>>,
    /// A folder whose rule set a new row takes when the client cannot resolve that folder itself.
    #[serde(default)]
    pub rules_from_folder: Option<String>,
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
    pub rule_set_id: Option<Uuid>,
    pub my_permissions: i64,
}

/// Absent-key_version defaults to epoch 1 so a client that predates DEK
/// rotation (#217) — which never sent this field before it existed — keeps
/// working. Safe unconditionally today: no team has ever rotated, so every
/// team's current epoch is still 1.
fn default_key_version_one() -> i32 {
    1
}

#[derive(Debug, Deserialize)]
pub struct UpsertSecretRequest {
    pub secret_id: String,
    pub object_id: String,
    pub secret_type: String,
    pub ciphertext: String,
    #[serde(default = "default_key_version_one")]
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
    headers: axum::http::HeaderMap,
    Path(team_id): Path<Uuid>,
) -> Result<Json<Vec<TeamObjectResponse>>, StatusCode> {
    let authz = ObjectAuthz::load(&pool, team_id, auth.0).await?.ok_or(StatusCode::FORBIDDEN)?;
    require_rule_set_feature(&headers)?;
    record_member_client(&pool, team_id, auth.0, &headers).await;

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
            Option<Uuid>,
        ),
    >(
        r#"SELECT object_id, object_type, name, folder_id, metadata, updated_at, updated_by, deleted_at, rule_set_id
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
            .filter_map(|row| {
                let my_permissions = authz.mask(row.8);
                (my_permissions & PERM_VIEW != 0).then_some(TeamObjectResponse {
                    object_id: row.0,
                    object_type: row.1,
                    name: row.2,
                    folder_id: row.3,
                    metadata: row.4,
                    updated_at: row.5,
                    updated_by: row.6,
                    deleted_at: row.7,
                    rule_set_id: row.8,
                    my_permissions,
                })
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

    require_rule_set_feature(&headers)?;
    let authz = ObjectAuthz::load(&pool, team_id, auth.0).await?.ok_or(StatusCode::FORBIDDEN)?;

    if let Some(Some(target)) = body.rule_set_id {
        if !rule_set_in_team(&pool, team_id, target).await? {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to open object upsert transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Locked here so a concurrent repoint/create of the same row cannot
    // commit between this read and our write below.
    let existing = sqlx::query_as::<_, (String, Option<Uuid>)>(
        "SELECT object_type, rule_set_id FROM team_vault_objects WHERE team_id = $1 AND object_id = $2 FOR UPDATE",
    )
    .bind(team_id)
    .bind(&body.object_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, object_id = %body.object_id, "Failed to lock team vault object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let body_edit = body.object_type.edit_permission();
    let current = existing.as_ref().and_then(|(_, rule_set_id)| *rule_set_id);
    let target = match (body.rule_set_id, &existing, &body.rules_from_folder) {
        (Some(target), _, _) => target,
        (None, None, Some(folder_id)) => folder_rule_set(&mut tx, team_id, folder_id).await?,
        (None, _, _) => current,
    };

    match &existing {
        None if !authz.can(target, body_edit) => return Err(StatusCode::FORBIDDEN),
        None => {}
        Some((object_type, _)) => {
            if !authz.can(current, PERM_VIEW) {
                return Err(StatusCode::NOT_FOUND);
            }
            let stored_edit = edit_permission_for_str(object_type).ok_or(StatusCode::BAD_REQUEST)?;
            if !authz.can(current, stored_edit | body_edit) {
                return Err(StatusCode::FORBIDDEN);
            }
            if target != current && !(authz.can(current, PERM_MANAGE_ROLES) && authz.can(target, PERM_MANAGE_ROLES)) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    let query = if existing.is_some() {
        sqlx::query(
            r#"UPDATE team_vault_objects
               SET object_type = $3, name = NULL, folder_id = NULL, metadata = $4,
                   deleted_at = NULL, updated_at = now(), updated_by = $5, rule_set_id = $6
               WHERE team_id = $1 AND object_id = $2"#,
        )
    } else {
        sqlx::query(
            r#"INSERT INTO team_vault_objects
               (team_id, object_id, object_type, name, vault_id, folder_id, metadata, updated_by, rule_set_id)
               VALUES ($1, $2, $3, NULL, $1, NULL, $4, $5, $6)
               ON CONFLICT (team_id, object_id) DO NOTHING"#,
        )
    };
    let result = query
        .bind(team_id)
        .bind(&body.object_id)
        .bind(body.object_type.as_str())
        .bind(&body.metadata)
        .bind(auth.0)
        .bind(target)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, object_id = %body.object_id, "Failed to upsert team vault object");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if existing.is_none() && result.rows_affected() == 0 {
        return Err(StatusCode::CONFLICT);
    }

    if let Some(old) = current.filter(|_| target != current) {
        gc_rule_sets(&mut tx, team_id, &[old]).await.map_err(|e| {
            error!(error = %e, team_id = %team_id, "Failed to collect rule sets");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }
    tx.commit().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to commit object upsert");
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
    require_rule_set_feature(&headers)?;

    let authz = ObjectAuthz::load(&pool, team_id, auth.0).await?.ok_or(StatusCode::FORBIDDEN)?;

    if items.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }
    if items.len() > MAX_REENCRYPT_BATCH {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let ids: Vec<String> = items.iter().map(|i| i.object_id.clone()).collect();

    let rows: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT object_type, rule_set_id FROM team_vault_objects WHERE team_id = $1 AND object_id = ANY($2)",
    )
    .bind(team_id)
    .bind(&ids)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to read objects for re-encryption");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    require_edit_on(&authz, &rows)?;

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
    headers: axum::http::HeaderMap,
    Path(team_id): Path<Uuid>,
    Json(items): Json<Vec<ReencryptSecretItem>>,
) -> Result<StatusCode, StatusCode> {
    require_rule_set_feature(&headers)?;

    let authz = ObjectAuthz::load(&pool, team_id, auth.0).await?.ok_or(StatusCode::FORBIDDEN)?;

    if items.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }
    if items.len() > MAX_REENCRYPT_BATCH {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let secret_ids: Vec<String> = items.iter().map(|i| i.secret_id.clone()).collect();
    let distinct_requested: std::collections::HashSet<&String> = secret_ids.iter().collect();

    // A join, not a two-step resolve-then-check: the two-step form lets an
    // orphaned secret resolve to an empty permission set and pass vacuously.
    let resolved: Vec<(String, String, Option<Uuid>)> = sqlx::query_as(
        r#"SELECT tvs.secret_id, tvo.object_type, tvo.rule_set_id
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
        resolved.iter().map(|(secret_id, _, _)| secret_id).collect();
    if resolved_secret_ids.len() < distinct_requested.len() {
        warn!(
            team_id = %team_id, user_id = %auth.0,
            requested = distinct_requested.len(), resolved = resolved_secret_ids.len(),
            "Secret re-encryption batch rejected: a requested secret has no live object",
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    require_edit_on(&authz, &resolved.into_iter().map(|(_, t, s)| (t, s)).collect::<Vec<_>>())?;

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

    require_rule_set_feature(&headers)?;
    let authz = ObjectAuthz::load(&pool, team_id, auth.0).await?.ok_or(StatusCode::FORBIDDEN)?;
    let row = object_row(&pool, team_id, &object_id).await?.ok_or(StatusCode::NOT_FOUND)?;
    require_edit_on(&authz, &[(row.object_type, row.rule_set_id)])?;

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
    headers: axum::http::HeaderMap,
    Path(team_id): Path<Uuid>,
) -> Result<Json<Vec<TeamSecretResponse>>, StatusCode> {
    let authz = ObjectAuthz::load(&pool, team_id, auth.0).await?.ok_or(StatusCode::FORBIDDEN)?;
    require_rule_set_feature(&headers)?;
    if !authz.grants_anywhere(&live_rule_set_ids(&pool, team_id).await?, PERM_CONNECT) {
        return Err(StatusCode::FORBIDDEN);
    }

    let rows = sqlx::query_as::<_, (String, String, String, String, i32, DateTime<Utc>, Option<Uuid>)>(
        r#"SELECT s.secret_id, s.object_id, s.secret_type, s.ciphertext, s.key_version, s.updated_at, o.rule_set_id
           FROM team_vault_secrets s
           LEFT JOIN team_vault_objects o ON o.team_id = s.team_id AND o.object_id = s.object_id
           WHERE s.team_id = $1
           ORDER BY s.updated_at ASC"#,
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
            .filter(|row| authz.can(row.6, PERM_CONNECT))
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
    require_rule_set_feature(&headers)?;
    let authz = ObjectAuthz::load(&pool, team_id, auth.0).await?.ok_or(StatusCode::FORBIDDEN)?;
    if canonical_secret_id(&body.object_id, &body.secret_type).as_deref() != Some(body.secret_id.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to open secret upsert transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Locks the row if one already exists, so a concurrent write cannot
    // repoint it before the owner check below runs.
    let existing = sqlx::query_as::<_, (String, String)>(
        "SELECT object_id, secret_type FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2 FOR UPDATE",
    )
    .bind(team_id)
    .bind(&body.secret_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, secret_id = %body.secret_id, "Failed to lock existing team vault secret");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let target = sqlx::query_as::<_, (String, Option<Uuid>)>(
        "SELECT object_type, rule_set_id FROM team_vault_objects WHERE team_id = $1 AND object_id = $2 AND deleted_at IS NULL FOR SHARE",
    )
    .bind(team_id)
    .bind(&body.object_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, object_id = %body.object_id, "Failed to fetch object for secret write");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    let had_existing = existing.is_some();
    let target_matches_type = secret_owner_type(&body.secret_type) == Some(target.0.as_str());

    // A pre-existing secret may belong to a different object than the one
    // named in the request; that owner must be authorized too.
    let mut rows = vec![target];
    let mut orphan_permission = None;
    if let Some((owner_id, secret_type)) = existing.filter(|(owner_id, _)| owner_id != &body.object_id) {
        let owner = sqlx::query_as::<_, (String, Option<Uuid>)>(
            "SELECT object_type, rule_set_id FROM team_vault_objects WHERE team_id = $1 AND object_id = $2 FOR SHARE",
        )
        .bind(team_id)
        .bind(&owner_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, object_id = %owner_id, "Failed to fetch the secret's current owner object");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        match owner {
            Some(row) => rows.push(row),
            None => {
                orphan_permission =
                    Some(edit_permission_for_secret_type(&secret_type).ok_or(StatusCode::BAD_REQUEST)?);
            }
        }
    }

    require_edit_on(&authz, &rows)?;
    if let Some(permission) = orphan_permission {
        if !authz.can(None, permission) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    if !target_matches_type {
        return Err(StatusCode::BAD_REQUEST);
    }

    let query = if had_existing {
        sqlx::query(
            r#"UPDATE team_vault_secrets
               SET object_id = $3, secret_type = $4, ciphertext = $5,
                   updated_at = now(), updated_by = $6, key_version = $7
               WHERE team_id = $1 AND secret_id = $2"#,
        )
    } else {
        sqlx::query(
            r#"INSERT INTO team_vault_secrets
               (team_id, secret_id, object_id, secret_type, ciphertext, updated_by, key_version)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (team_id, secret_id) DO NOTHING"#,
        )
    };
    let result = query
        .bind(team_id)
        .bind(&body.secret_id)
        .bind(&body.object_id)
        .bind(&body.secret_type)
        .bind(&body.ciphertext)
        .bind(auth.0)
        .bind(body.key_version)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, secret_id = %body.secret_id, "Failed to upsert team vault secret");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !had_existing && result.rows_affected() == 0 {
        return Err(StatusCode::CONFLICT);
    }

    tx.commit().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to commit secret upsert");
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
    require_rule_set_feature(&headers)?;
    let authz = ObjectAuthz::load(&pool, team_id, auth.0).await?.ok_or(StatusCode::FORBIDDEN)?;

    let (secret_type, object) = sqlx::query_as::<_, (String, Option<String>, Option<Uuid>)>(
        "SELECT s.secret_type, o.object_type, o.rule_set_id FROM team_vault_secrets s \
         LEFT JOIN team_vault_objects o ON o.team_id = s.team_id AND o.object_id = s.object_id \
         WHERE s.team_id = $1 AND s.secret_id = $2",
    )
    .bind(team_id)
    .bind(&secret_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, secret_id = %secret_id, "Failed to fetch team vault secret");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .map(|(t, object_type, set)| (t, object_type.map(|_| set)))
    .ok_or(StatusCode::NOT_FOUND)?;

    let set = object.flatten();
    if object.is_some() && !authz.can(set, PERM_VIEW) {
        return Err(StatusCode::NOT_FOUND);
    }
    let permission = edit_permission_for_secret_type(&secret_type).ok_or(StatusCode::BAD_REQUEST)?;
    if !authz.can(set, permission) {
        return Err(StatusCode::FORBIDDEN);
    }

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
    use crate::permissions::{
        PERM_CONNECT, PERM_COPY_SECRETS, PERM_EDIT_CONNECTIONS, PERM_EDIT_SNIPPETS, PERM_VIEW, PERM_VIEW_SECRETS,
    };
    use crate::sync_notifier::SyncNotifier;
    use crate::test_pool_or_skip;
    use crate::test_support::{
        hidden_object_fixture, member_with_role, rule_set_client_headers, seed_rule_set, seed_team,
        seed_user, set_user_tier, BillingMode,
    };
    use axum::extract::{Path, State};
    use axum::{Extension, Json};

    #[test]
    fn upsert_secret_request_defaults_key_version_when_field_is_absent() {
        // Any client that predates #217 has never sent key_version at all —
        // this must not 422 it, or every currently-released client breaks
        // the instant it tries to save a team vault secret.
        let body: UpsertSecretRequest = serde_json::from_str(
            r#"{"secret_id":"s1","object_id":"o1","secret_type":"connection_password","ciphertext":"c"}"#,
        )
        .expect("body without key_version must still deserialize");
        assert_eq!(body.key_version, 1);
    }

    #[tokio::test]
    async fn list_objects_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await; // never added to team

        let res = list_objects(
            State(pool.clone()),
            Extension(AuthUser(outsider)),
            rule_set_client_headers(),
            Path(team),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    async fn listed_ids(pool: &PgPool, team: Uuid, user: Uuid) -> Vec<String> {
        list_objects(State(pool.clone()), Extension(AuthUser(user)), rule_set_client_headers(), Path(team))
            .await
            .expect("list objects")
            .0
            .into_iter()
            .map(|o| o.object_id)
            .collect()
    }

    #[tokio::test]
    async fn a_downgraded_team_can_point_a_new_object_at_a_hidden_set() {
        let _env = BillingMode::hosted();
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "folder", PERM_EDIT_CONNECTIONS).await;
        set_user_tier(&pool, f.owner, "teams").await;
        crate::test_support::grant_builtin_role(&pool, f.team, f.admin, "owner").await;

        let res = upsert_object(
            State(pool.clone()),
            Extension(AuthUser(f.admin)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path(f.team),
            Json(UpsertTeamObjectRequest {
                object_id: "child-host".to_string(),
                object_type: TeamObjectType::Connection,
                name: None,
                folder_id: None,
                metadata: serde_json::json!({}),
                rule_set_id: Some(Some(f.rule_set)),
                rules_from_folder: None,
            }),
        )
        .await;
        assert!(res.is_ok(), "pointing at an existing set must stay ungated, got {:?}", res.err());

        let blocked_sees = listed_ids(&pool, f.team, f.blocked).await;
        assert!(!blocked_sees.contains(&"child-host".to_string()));
        assert!(!listed_ids(&pool, f.team, f.viewer).await.contains(&"child-host".to_string()));
    }

    #[tokio::test]
    async fn list_objects_omits_an_object_the_caller_cannot_view() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        assert!(!listed_ids(&pool, f.team, f.blocked).await.contains(&f.object_id));
    }

    #[tokio::test]
    async fn list_objects_keeps_it_for_the_member_it_is_shared_with() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        let rows = list_objects(State(pool.clone()), Extension(AuthUser(f.viewer)), rule_set_client_headers(), Path(f.team))
            .await
            .unwrap()
            .0;
        let row = rows.iter().find(|o| o.object_id == f.object_id).expect("viewer sees it");
        assert_eq!(row.rule_set_id, Some(f.rule_set));
        assert_eq!(row.my_permissions, PERM_VIEW | PERM_CONNECT);
    }

    #[tokio::test]
    async fn list_objects_shows_everything_to_an_administrator() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        assert!(listed_ids(&pool, f.team, f.admin).await.contains(&f.object_id));
    }

    #[tokio::test]
    async fn list_objects_hides_everything_from_a_role_without_view() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        crate::test_support::seed_team_object(&pool, team, owner, "plain", "connection").await;
        let role = crate::test_support::seed_role(&pool, team, "no-view", PERM_CONNECT).await;
        let member = seed_user(&pool).await;
        crate::test_support::add_member(&pool, team, member).await;
        crate::test_support::assign_role(&pool, team, member, role).await;
        assert!(listed_ids(&pool, team, member).await.is_empty());
    }

    #[tokio::test]
    async fn list_objects_is_426_for_an_old_client_on_a_team_without_rule_sets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT).await;
        let res = list_objects(State(pool.clone()), Extension(AuthUser(member)), axum::http::HeaderMap::new(), Path(team)).await;
        assert_eq!(res.unwrap_err(), axum::http::StatusCode::UPGRADE_REQUIRED);
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
            rule_set_client_headers(),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-1".to_string(),
                object_type: TeamObjectType::Connection,
                name: Some("box".to_string()),
                folder_id: None,
                metadata: serde_json::json!({}),
                rule_set_id: None,
                rules_from_folder: None,
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
            rule_set_client_headers(),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-2".to_string(),
                object_type: TeamObjectType::Connection,
                name: Some("box".to_string()),
                folder_id: None,
                metadata: serde_json::json!({}),
                rule_set_id: None,
                rules_from_folder: None,
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
            rule_set_client_headers(),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-1".to_string(),
                object_type: TeamObjectType::Connection,
                name: Some("prod-db-master".to_string()),
                folder_id: Some("folder-7".to_string()),
                metadata: serde_json::json!({ "host": "10.0.0.1" }),
                rule_set_id: None,
                rules_from_folder: None,
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

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(caller)), rule_set_client_headers(), Path(team)).await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    async fn listed_secret_objects(pool: &PgPool, team: Uuid, user: Uuid) -> Result<Vec<String>, axum::http::StatusCode> {
        list_secrets(State(pool.clone()), Extension(AuthUser(user)), rule_set_client_headers(), Path(team))
            .await
            .map(|r| r.0.into_iter().map(|s| s.object_id).collect())
    }

    async fn seed_secret_row(pool: &PgPool, team: Uuid, owner: Uuid, object_id: &str) {
        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by)
             VALUES ($1, $2, $3, 'connection_password', 'c', $4)",
        )
        .bind(team)
        .bind(format!("password:{object_id}"))
        .bind(object_id)
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn list_secrets_omits_secrets_of_a_hidden_object() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        seed_secret_row(&pool, f.team, f.owner, &f.object_id).await;
        assert!(!listed_secret_objects(&pool, f.team, f.blocked).await.unwrap().contains(&f.object_id));
    }

    #[tokio::test]
    async fn list_secrets_serves_them_to_the_viewer_and_the_admin() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_CONNECT).await;
        seed_secret_row(&pool, f.team, f.owner, &f.object_id).await;
        assert!(listed_secret_objects(&pool, f.team, f.viewer).await.unwrap().contains(&f.object_id));
        assert!(listed_secret_objects(&pool, f.team, f.admin).await.unwrap().contains(&f.object_id));
    }

    #[tokio::test]
    async fn list_secrets_serves_a_junior_the_one_host_granted_to_them() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let junior = member_with_role(&pool, team, 0).await;
        crate::test_support::seed_team_object(&pool, team, owner, "granted", "connection").await;
        crate::test_support::seed_team_object(&pool, team, owner, "other", "connection").await;
        seed_secret_row(&pool, team, owner, "granted").await;
        seed_secret_row(&pool, team, owner, "other").await;
        let set = seed_rule_set(&pool, team, owner, &[("member", Some(junior), PERM_CONNECT, 0)]).await;
        crate::test_support::point_object(&pool, team, "granted", Some(set)).await;

        assert_eq!(listed_secret_objects(&pool, team, junior).await.unwrap(), vec!["granted".to_string()]);
    }

    #[tokio::test]
    async fn list_secrets_withholds_a_host_whose_connect_is_denied() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT | PERM_VIEW_SECRETS).await;
        crate::test_support::seed_team_object(&pool, team, owner, "locked", "connection").await;
        crate::test_support::seed_team_object(&pool, team, owner, "open", "connection").await;
        seed_secret_row(&pool, team, owner, "locked").await;
        seed_secret_row(&pool, team, owner, "open").await;
        let set = seed_rule_set(&pool, team, owner, &[("member", Some(member), 0, PERM_CONNECT)]).await;
        crate::test_support::point_object(&pool, team, "locked", Some(set)).await;

        assert_eq!(listed_secret_objects(&pool, team, member).await.unwrap(), vec!["open".to_string()]);
    }

    #[tokio::test]
    async fn list_secrets_forbidden_with_view_secrets_but_no_connect() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let reader = member_with_role(&pool, team, PERM_VIEW_SECRETS | PERM_COPY_SECRETS).await;

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(reader)), rule_set_client_headers(), Path(team)).await;

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
            rule_set_client_headers(),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: object_id.clone(),
                object_type: TeamObjectType::Connection,
                name: Some("box".to_string()),
                folder_id: None,
                metadata: serde_json::json!({}),
                rule_set_id: None,
                rules_from_folder: None,
            }),
        )
        .await
        .expect("seed connection object");
        object_id
    }

    fn secret_body(object_id: &str) -> UpsertSecretRequest {
        UpsertSecretRequest {
            secret_id: format!("password:{object_id}"),
            object_id: object_id.to_string(),
            secret_type: "connection_password".to_string(),
            ciphertext: "cipher".to_string(),
            key_version: 1,
        }
    }

    async fn upsert_secret_body(pool: &PgPool, team: Uuid, user: Uuid, body: UpsertSecretRequest) -> Result<StatusCode, StatusCode> {
        upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path(team),
            Json(body),
        )
        .await
    }

    #[test]
    fn canonical_secret_ids_match_the_client_key_names() {
        let cases = [
            ("connection_password", "password:o"),
            ("connection_key", "key:o"),
            ("connection_passphrase", "passphrase:o"),
            ("connection_proxy_password", "proxy_password:o"),
            ("identity_password", "identity:o:password"),
            ("key_private", "key:o:private"),
            ("key_public", "key:o:public"),
            ("key_passphrase", "key:o:passphrase"),
        ];
        for (secret_type, id) in cases {
            assert_eq!(canonical_secret_id("o", secret_type).as_deref(), Some(id));
            assert!(secret_owner_type(secret_type).is_some());
        }
        assert_eq!(canonical_secret_id("o", "bogus"), None);
        assert_eq!(canonical_secret_id("k:passphrase", "connection_key"), None);
        assert_eq!(canonical_secret_id("__global__", "connection_proxy_password"), None);
    }

    #[tokio::test]
    async fn a_connection_named_like_a_key_part_cannot_alias_that_keys_secret() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        crate::test_support::seed_team_object(&pool, team, owner, "k:passphrase", "connection").await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let body = UpsertSecretRequest {
            secret_id: "key:k:passphrase".to_string(),
            object_id: "k:passphrase".to_string(),
            secret_type: "connection_key".to_string(),
            ciphertext: "cipher".to_string(),
            key_version: 1,
        };

        assert_eq!(upsert_secret_body(&pool, team, caller, body).await.unwrap_err(), StatusCode::BAD_REQUEST);
        assert!(!secret_exists(&pool, team, "key:k:passphrase").await);
    }

    #[tokio::test]
    async fn a_hidden_target_of_the_wrong_type_answers_404_not_400() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "key", PERM_EDIT_KEYS | PERM_EDIT_CONNECTIONS).await;
        assert_eq!(secret_upsert_as(&pool, f.team, f.blocked, &f.object_id).await.unwrap_err(), StatusCode::NOT_FOUND);
        assert_eq!(secret_upsert_as(&pool, f.team, f.viewer, &f.object_id).await.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upsert_secret_rejects_a_secret_id_that_does_not_belong_to_the_object() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        for secret_id in ["sec-free-form".to_string(), "password:someone-else".to_string(), format!("key:{object_id}")] {
            let mut body = secret_body(&object_id);
            body.secret_id = secret_id.clone();
            assert_eq!(
                upsert_secret_body(&pool, team, caller, body).await.unwrap_err(),
                StatusCode::BAD_REQUEST,
                "{secret_id}"
            );
        }
        assert!(!secret_exists(&pool, team, "password:someone-else").await);
    }

    #[tokio::test]
    async fn upsert_secret_rejects_a_secret_type_foreign_to_the_object() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS | PERM_EDIT_KEYS).await;
        let body = UpsertSecretRequest {
            secret_id: format!("key:{object_id}:private"),
            object_id: object_id.clone(),
            secret_type: "key_private".to_string(),
            ciphertext: "cipher".to_string(),
            key_version: 1,
        };

        assert_eq!(upsert_secret_body(&pool, team, caller, body).await.unwrap_err(), StatusCode::BAD_REQUEST);
        assert!(!secret_exists(&pool, team, &format!("key:{object_id}:private")).await);
    }

    #[tokio::test]
    async fn a_blocked_member_cannot_squat_a_hidden_objects_secret_id() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        crate::test_support::seed_team_object(&pool, f.team, f.owner, "visible", "connection").await;
        let mut body = secret_body("visible");
        body.secret_id = format!("password:{}", f.object_id);

        assert_eq!(upsert_secret_body(&pool, f.team, f.blocked, body).await.unwrap_err(), StatusCode::BAD_REQUEST);
        assert!(!secret_exists(&pool, f.team, &format!("password:{}", f.object_id)).await);
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
            Path((team, secret_id.clone())),
        )
        .await;

        assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);
        assert!(!secret_exists(&pool, team, &secret_id).await);
    }

    #[tokio::test]
    async fn upsert_secret_accepts_connection_proxy_password() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let object_id = seed_connection_object(&pool, team).await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let body = UpsertSecretRequest {
            secret_id: format!("proxy_password:{object_id}"),
            object_id: object_id.clone(),
            secret_type: "connection_proxy_password".to_string(),
            ciphertext: "cipher".to_string(),
            key_version: 1,
        };
        let secret_id = body.secret_id.clone();

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
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
    }

    #[test]
    fn proxy_password_needs_edit_connections() {
        assert_eq!(
            edit_permission_for_secret_type("connection_proxy_password"),
            Some(PERM_EDIT_CONNECTIONS)
        );
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(caller)), rule_set_client_headers(), Path(team))
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

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(caller)), rule_set_client_headers(), Path(team))
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

        let res = list_secrets(State(pool.clone()), Extension(AuthUser(caller)), rule_set_client_headers(), Path(team)).await;

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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
            Path(team),
            Json(UpsertTeamObjectRequest {
                object_id: "obj-1".to_string(),
                object_type: TeamObjectType::Connection,
                name: None,
                folder_id: None,
                metadata: serde_json::json!({ "host": "10.0.0.1" }),
                rule_set_id: None,
                rules_from_folder: None,
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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

        let mut headers = rule_set_client_headers();
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
                rule_set_id: None,
                rules_from_folder: None,
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
        let mut headers = rule_set_client_headers();
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
                rule_set_id: None,
                rules_from_folder: None,
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

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-client-features", "rule-sets".parse().unwrap());
        let res = list_objects(State(pool.clone()), Extension(AuthUser(caller)), headers, Path(team)).await;

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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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

    /// An orphaned secret must not resolve to an empty permission set that
    /// passes vacuously; simulated directly via SQL.
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
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
            rule_set_client_headers(),
            Path(team),
            Json(vec![ReencryptItem {
                object_id: "does-not-exist".to_string(),
                metadata: serde_json::json!({}),
            }]),
        )
        .await;

        assert_eq!(res, Err(StatusCode::FORBIDDEN));
    }

    // ── rule_set_id pointer semantics ─────────────────────────────────────

    fn object_body(object_id: &str, rule_set_id: Option<Option<Uuid>>) -> UpsertTeamObjectRequest {
        UpsertTeamObjectRequest {
            object_id: object_id.to_string(),
            object_type: TeamObjectType::Connection,
            name: None,
            folder_id: None,
            metadata: serde_json::json!({ "v": 2 }),
            rule_set_id,
            rules_from_folder: None,
        }
    }

    async fn object_exists(pool: &PgPool, team: Uuid, object_id: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM team_vault_objects WHERE team_id = $1 AND object_id = $2)")
            .bind(team)
            .bind(object_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    fn body_in_folder(object_id: &str, folder_id: &str) -> UpsertTeamObjectRequest {
        UpsertTeamObjectRequest { rules_from_folder: Some(folder_id.to_string()), ..object_body(object_id, None) }
    }

    async fn upsert_as(pool: &PgPool, team: Uuid, user: Uuid, headers: axum::http::HeaderMap, body: UpsertTeamObjectRequest) -> Result<StatusCode, StatusCode> {
        upsert_object(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            headers,
            Path(team),
            Json(body),
        )
        .await
    }

    async fn stored_pointer(pool: &PgPool, team: Uuid, object_id: &str) -> Option<Uuid> {
        sqlx::query_scalar("SELECT rule_set_id FROM team_vault_objects WHERE team_id = $1 AND object_id = $2")
            .bind(team)
            .bind(object_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[test]
    fn rule_set_id_distinguishes_absent_from_null() {
        let absent: UpsertTeamObjectRequest = serde_json::from_str(
            r#"{"object_id":"o","object_type":"connection","metadata":{}}"#,
        ).unwrap();
        let null: UpsertTeamObjectRequest = serde_json::from_str(
            r#"{"object_id":"o","object_type":"connection","metadata":{},"rule_set_id":null}"#,
        ).unwrap();
        assert_eq!(absent.rule_set_id, None);
        assert_eq!(null.rule_set_id, Some(None));
        assert_eq!(absent.rules_from_folder, None);
    }

    #[tokio::test]
    async fn editing_a_hidden_object_answers_404() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        let res = upsert_as(&pool, f.team, f.blocked, rule_set_client_headers(), object_body(&f.object_id, None)).await;
        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn deleting_a_hidden_object_answers_404() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        let res = delete_object(
            State(pool.clone()),
            Extension(AuthUser(f.blocked)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path((f.team, f.object_id.clone())),
        )
        .await;
        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_viewer_and_the_admin_can_edit_it_and_the_pointer_is_kept() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        upsert_as(&pool, f.team, f.viewer, rule_set_client_headers(), object_body(&f.object_id, None)).await.unwrap();
        upsert_as(&pool, f.team, f.admin, rule_set_client_headers(), object_body(&f.object_id, None)).await.unwrap();
        assert_eq!(stored_pointer(&pool, f.team, &f.object_id).await, Some(f.rule_set));
    }

    #[tokio::test]
    async fn an_old_client_save_is_426_on_a_team_without_rule_sets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let editor = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        upsert_as(&pool, team, editor, rule_set_client_headers(), object_body("o-1", None)).await.unwrap();

        let res = upsert_as(&pool, team, editor, axum::http::HeaderMap::new(), object_body("o-2", None)).await;
        assert_eq!(res.unwrap_err(), StatusCode::UPGRADE_REQUIRED);
        assert_eq!(listed_ids(&pool, team, editor).await, vec!["o-1".to_string()]);
    }

    #[tokio::test]
    async fn creating_inside_a_restricted_set_needs_edit_through_that_set() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let editor = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let locked = seed_rule_set(&pool, team, owner, &[("everyone", None, 0, PERM_EDIT_CONNECTIONS)]).await;
        let open = seed_rule_set(&pool, team, owner, &[]).await;

        let denied = upsert_as(&pool, team, editor, rule_set_client_headers(), object_body("new-1", Some(Some(locked)))).await;
        assert_eq!(denied.unwrap_err(), StatusCode::FORBIDDEN);
        upsert_as(&pool, team, editor, rule_set_client_headers(), object_body("new-2", Some(Some(open)))).await.unwrap();
        assert_eq!(stored_pointer(&pool, team, "new-2").await, Some(open));
    }

    #[tokio::test]
    async fn creating_with_an_unknown_rule_set_is_400() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let editor = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let res = upsert_as(&pool, team, editor, rule_set_client_headers(), object_body("new-3", Some(Some(Uuid::new_v4())))).await;
        assert_eq!(res.unwrap_err(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_new_object_takes_the_rule_set_of_its_unresolved_folder() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "folder", PERM_EDIT_CONNECTIONS).await;
        upsert_as(&pool, f.team, f.viewer, rule_set_client_headers(), body_in_folder("child-1", &f.object_id)).await.unwrap();
        assert_eq!(stored_pointer(&pool, f.team, "child-1").await, Some(f.rule_set));
        assert!(!listed_ids(&pool, f.team, f.blocked).await.contains(&"child-1".to_string()));
    }

    #[tokio::test]
    async fn creating_in_a_folder_hidden_from_the_creator_is_refused() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "folder", PERM_EDIT_CONNECTIONS).await;
        let res = upsert_as(&pool, f.team, f.blocked, rule_set_client_headers(), body_in_folder("child-7", &f.object_id)).await;
        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
        assert!(!object_exists(&pool, f.team, "child-7").await);
    }

    #[tokio::test]
    async fn a_new_object_takes_the_rule_set_of_a_deleted_folder() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "folder", PERM_EDIT_CONNECTIONS).await;
        sqlx::query("UPDATE team_vault_objects SET deleted_at = now() WHERE team_id = $1 AND object_id = $2")
            .bind(f.team).bind(&f.object_id).execute(&pool).await.unwrap();
        upsert_as(&pool, f.team, f.viewer, rule_set_client_headers(), body_in_folder("child-2", &f.object_id)).await.unwrap();
        assert_eq!(stored_pointer(&pool, f.team, "child-2").await, Some(f.rule_set));
    }

    #[tokio::test]
    async fn a_folder_hint_that_is_not_a_folder_of_the_team_is_team_wide() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        upsert_as(&pool, f.team, f.viewer, rule_set_client_headers(), body_in_folder("child-3", &f.object_id)).await.unwrap();
        upsert_as(&pool, f.team, f.viewer, rule_set_client_headers(), body_in_folder("child-4", "no-such-folder")).await.unwrap();
        assert_eq!(stored_pointer(&pool, f.team, "child-3").await, None);
        assert_eq!(stored_pointer(&pool, f.team, "child-4").await, None);
    }

    #[tokio::test]
    async fn a_folder_hint_never_overrides_an_explicit_pointer_or_an_existing_row() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "folder", PERM_EDIT_CONNECTIONS).await;
        let explicit = UpsertTeamObjectRequest { rule_set_id: Some(None), ..body_in_folder("child-5", &f.object_id) };
        upsert_as(&pool, f.team, f.viewer, rule_set_client_headers(), explicit).await.unwrap();
        assert_eq!(stored_pointer(&pool, f.team, "child-5").await, None);

        upsert_as(&pool, f.team, f.viewer, rule_set_client_headers(), body_in_folder("child-5", &f.object_id)).await.unwrap();
        assert_eq!(stored_pointer(&pool, f.team, "child-5").await, None);
    }

    #[tokio::test]
    async fn a_folder_that_denies_edit_refuses_the_new_object() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let editor = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        crate::test_support::seed_team_object(&pool, team, owner, "locked-folder", "folder").await;
        let locked = seed_rule_set(&pool, team, owner, &[("everyone", None, 0, PERM_EDIT_CONNECTIONS)]).await;
        crate::test_support::point_object(&pool, team, "locked-folder", Some(locked)).await;

        let res = upsert_as(&pool, team, editor, rule_set_client_headers(), body_in_folder("child-6", "locked-folder")).await;
        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
        assert!(!object_exists(&pool, team, "child-6").await);
    }

    #[tokio::test]
    async fn repointing_needs_manage_on_both_sets_and_collects_the_orphan() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let editor = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;
        let manager = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS | crate::permissions::PERM_MANAGE_ROLES).await;
        crate::test_support::seed_team_object(&pool, team, owner, "o-2", "connection").await;
        let old = seed_rule_set(&pool, team, owner, &[]).await;
        let new = seed_rule_set(&pool, team, owner, &[]).await;
        crate::test_support::point_object(&pool, team, "o-2", Some(old)).await;

        let denied = upsert_as(&pool, team, editor, rule_set_client_headers(), object_body("o-2", Some(Some(new)))).await;
        assert_eq!(denied.unwrap_err(), StatusCode::FORBIDDEN);

        upsert_as(&pool, team, manager, rule_set_client_headers(), object_body("o-2", Some(Some(new)))).await.unwrap();
        assert_eq!(stored_pointer(&pool, team, "o-2").await, Some(new));
        let old_left: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM team_rule_sets WHERE id = $1)")
            .bind(old).fetch_one(&pool).await.unwrap();
        assert!(!old_left, "the set nobody points at any more is collected");
    }

    #[tokio::test]
    async fn a_soft_deleted_restricted_object_is_restored_still_restricted() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        delete_object(
            State(pool.clone()),
            Extension(AuthUser(f.viewer)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path((f.team, f.object_id.clone())),
        )
        .await
        .unwrap();
        assert_eq!(stored_pointer(&pool, f.team, &f.object_id).await, Some(f.rule_set));

        upsert_as(&pool, f.team, f.viewer, rule_set_client_headers(), object_body(&f.object_id, None)).await.unwrap();
        assert!(!listed_ids(&pool, f.team, f.blocked).await.contains(&f.object_id));
    }

    // Proxy for a concurrent create racing a hidden row into existence: the row must lock first.
    #[tokio::test]
    async fn creating_over_a_hidden_object_answers_404_and_does_not_overwrite() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        let res = upsert_as(&pool, f.team, f.blocked, rule_set_client_headers(), object_body(&f.object_id, None)).await;
        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
        assert_eq!(stored_pointer(&pool, f.team, &f.object_id).await, Some(f.rule_set));
    }

    #[tokio::test]
    async fn repointing_to_team_wide_still_needs_manage_on_the_current_set() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let manager = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS | crate::permissions::PERM_MANAGE_ROLES).await;
        crate::test_support::seed_team_object(&pool, team, owner, "o-4", "connection").await;
        let locked = seed_rule_set(&pool, team, owner, &[("everyone", None, 0, crate::permissions::PERM_MANAGE_ROLES)]).await;
        crate::test_support::point_object(&pool, team, "o-4", Some(locked)).await;

        let res = upsert_as(&pool, team, manager, rule_set_client_headers(), object_body("o-4", Some(None))).await;
        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
        assert_eq!(stored_pointer(&pool, team, "o-4").await, Some(locked));
    }

    #[tokio::test]
    async fn changing_the_stored_type_needs_edit_on_both_types() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        crate::test_support::seed_team_object(&pool, team, owner, "k-1", "key").await;
        let caller = member_with_role(&pool, team, PERM_EDIT_CONNECTIONS).await;

        let res = upsert_as(&pool, team, caller, rule_set_client_headers(), object_body("k-1", None)).await;
        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
        let stored_type: String = sqlx::query_scalar(
            "SELECT object_type FROM team_vault_objects WHERE team_id = $1 AND object_id = $2",
        )
        .bind(team)
        .bind("k-1")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored_type, "key");
    }

    #[tokio::test]
    async fn a_viewer_without_edit_gets_forbidden_not_missing_on_upsert_and_delete() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let viewer = member_with_role(&pool, team, 0).await;
        crate::test_support::seed_team_object(&pool, team, owner, "v-1", "connection").await;
        let set = seed_rule_set(&pool, team, owner, &[]).await;
        crate::test_support::point_object(&pool, team, "v-1", Some(set)).await;

        let res = upsert_as(&pool, team, viewer, rule_set_client_headers(), object_body("v-1", None)).await;
        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);

        let res = delete_object(
            State(pool.clone()),
            Extension(AuthUser(viewer)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path((team, "v-1".to_string())),
        )
        .await;
        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
    }

    // ── secret writes and re-encryption are checked per object ─────────────

    async fn secret_upsert_as(pool: &PgPool, team: Uuid, user: Uuid, object_id: &str) -> Result<StatusCode, StatusCode> {
        upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path(team),
            Json(secret_body(object_id)),
        )
        .await
    }

    #[tokio::test]
    async fn writing_a_secret_of_a_hidden_object_answers_404() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        assert_eq!(secret_upsert_as(&pool, f.team, f.blocked, &f.object_id).await.unwrap_err(), StatusCode::NOT_FOUND);
        assert!(secret_upsert_as(&pool, f.team, f.viewer, &f.object_id).await.is_ok());
        assert!(secret_upsert_as(&pool, f.team, f.admin, &f.object_id).await.is_ok());
    }

    async fn seed_row_owned_by_another_object(pool: &PgPool, f: &crate::test_support::HiddenObjectFixture, named_for: &str) -> String {
        let secret_id = format!("password:{named_for}");
        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by)
             VALUES ($1, $2, $3, 'connection_password', 'c', $4)",
        )
        .bind(f.team)
        .bind(&secret_id)
        .bind(&f.object_id)
        .bind(f.owner)
        .execute(pool)
        .await
        .unwrap();
        secret_id
    }

    #[tokio::test]
    async fn upsert_secret_cannot_repoint_a_hidden_owner_to_a_visible_object() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        crate::test_support::seed_team_object(&pool, f.team, f.owner, "visible", "connection").await;
        let secret_id = seed_row_owned_by_another_object(&pool, &f, "visible").await;

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(f.blocked)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path(f.team),
            Json(UpsertSecretRequest {
                secret_id: secret_id.clone(),
                object_id: "visible".to_string(),
                secret_type: "connection_password".to_string(),
                ciphertext: "attacker-cipher".to_string(),
                key_version: 1,
            }),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);

        let (object_id, ciphertext): (String, String) = sqlx::query_as(
            "SELECT object_id, ciphertext FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2",
        )
        .bind(f.team)
        .bind(&secret_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(object_id, f.object_id, "the hidden secret must not be repointed");
        assert_eq!(ciphertext, "c", "the hidden secret's ciphertext must not be overwritten");
    }

    #[tokio::test]
    async fn upsert_secret_moves_between_two_objects_the_caller_may_edit() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        crate::test_support::seed_team_object(&pool, f.team, f.owner, "visible", "connection").await;
        let secret_id = seed_row_owned_by_another_object(&pool, &f, "visible").await;

        let res = upsert_secret(
            State(pool.clone()),
            Extension(AuthUser(f.viewer)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path(f.team),
            Json(UpsertSecretRequest {
                secret_id: secret_id.clone(),
                object_id: "visible".to_string(),
                secret_type: "connection_password".to_string(),
                ciphertext: "moved-cipher".to_string(),
                key_version: 1,
            }),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);

        let (object_id, ciphertext): (String, String) = sqlx::query_as(
            "SELECT object_id, ciphertext FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2",
        )
        .bind(f.team)
        .bind(&secret_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(object_id, "visible", "the viewer may edit both objects, so the move must land");
        assert_eq!(ciphertext, "moved-cipher");
    }

    #[tokio::test]
    async fn upsert_secret_insert_reports_zero_rows_when_a_row_wins_the_race() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        crate::test_support::seed_team_object(&pool, team, owner, "obj-1", "connection").await;
        let secret_id = "password:obj-1".to_string();

        let mut tx = pool.begin().await.unwrap();
        let existing = sqlx::query_as::<_, (String, String)>(
            "SELECT object_id, secret_type FROM team_vault_secrets WHERE team_id = $1 AND secret_id = $2 FOR UPDATE",
        )
        .bind(team)
        .bind(&secret_id)
        .fetch_optional(&mut *tx)
        .await
        .unwrap();
        assert!(existing.is_none(), "no row yet, so FOR UPDATE locks nothing");

        seed_secret_row(&pool, team, owner, "obj-1").await;

        let result = sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by, key_version)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (team_id, secret_id) DO NOTHING",
        )
        .bind(team)
        .bind(&secret_id)
        .bind("obj-1")
        .bind("connection_password")
        .bind("attacker-cipher")
        .bind(owner)
        .bind(1i32)
        .execute(&mut *tx)
        .await
        .unwrap();

        assert_eq!(result.rows_affected(), 0, "the fix must turn the interleaved insert into a 409, not a silent overwrite");
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn deleting_a_secret_of_a_hidden_object_answers_404() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        seed_secret_row(&pool, f.team, f.owner, &f.object_id).await;
        let res = delete_secret(
            State(pool.clone()),
            Extension(AuthUser(f.blocked)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path((f.team, format!("password:{}", f.object_id))),
        )
        .await;
        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn reencrypting_a_batch_with_a_hidden_object_answers_404() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        let res = reencrypt_objects(
            State(pool.clone()),
            Extension(AuthUser(f.blocked)),
            Extension(SyncNotifier::new()),
            Extension(MinClientVersion(None)),
            rule_set_client_headers(),
            Path(f.team),
            Json(vec![ReencryptItem { object_id: f.object_id.clone(), metadata: serde_json::json!({}) }]),
        )
        .await;
        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_non_admin_rotation_leaves_hidden_rows_and_an_admin_finishes_them() {
        let pool = test_pool_or_skip!();
        let f = hidden_object_fixture(&pool, "connection", PERM_EDIT_CONNECTIONS).await;
        crate::test_support::seed_team_object(&pool, f.team, f.owner, "visible", "connection").await;
        seed_secret_row(&pool, f.team, f.owner, "visible").await;
        seed_secret_row(&pool, f.team, f.owner, &f.object_id).await;
        let rewrite = |ids: Vec<String>| {
            ids.into_iter()
                .map(|object_id| ReencryptSecretItem { secret_id: format!("password:{object_id}"), ciphertext: "c2".into(), key_version: 2 })
                .collect::<Vec<_>>()
        };
        let run = |user: Uuid, items: Vec<ReencryptSecretItem>| {
            let pool = pool.clone();
            async move {
                reencrypt_secrets(
                    State(pool),
                    Extension(AuthUser(user)),
                    Extension(SyncNotifier::new()),
                    rule_set_client_headers(),
                    Path(f.team),
                    Json(items),
                )
                .await
            }
        };

        assert_eq!(run(f.blocked, rewrite(vec![f.object_id.clone()])).await.unwrap_err(), StatusCode::NOT_FOUND);
        run(f.blocked, rewrite(vec!["visible".into()])).await.unwrap();
        let stale: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_vault_secrets WHERE team_id = $1 AND key_version < 2")
            .bind(f.team).fetch_one(&pool).await.unwrap();
        assert_eq!(stale, 1);

        run(f.admin, rewrite(vec![f.object_id.clone()])).await.unwrap();
        let stale: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_vault_secrets WHERE team_id = $1 AND key_version < 2")
            .bind(f.team).fetch_one(&pool).await.unwrap();
        assert_eq!(stale, 0);
    }
}
