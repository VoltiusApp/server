use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::permissions::{is_team_member, PermCheck};
use crate::self_host;
use crate::sync_notifier::{notify_team_vault_changed, SyncNotifier};

const MAX_TEAM_BLOB_SIZE: usize = 10 * 1024 * 1024; // 10 MB

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Returns Ok if the vault owner has a Teams or Business subscription.
/// In self-hosted mode this is a no-op — every tier is unlocked.
async fn require_teams_tier_for_vault(pool: &PgPool, team_id: Uuid) -> Result<(), StatusCode> {
    if self_host::is_self_hosted() {
        return Ok(());
    }
    let tier = sqlx::query_scalar::<_, String>(
        "SELECT u.subscription_tier FROM teams t \
         JOIN users u ON u.id = t.owner_id \
         WHERE t.id = $1",
    )
    .bind(team_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to fetch vault owner tier");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match tier.as_str() {
        "teams" | "business" => Ok(()),
        _ => Err(StatusCode::PAYMENT_REQUIRED),
    }
}

/// `MAX(key_version)` for a team, defaulting to 1 for a team that has never
/// rotated (no `team_key_epochs` row — every team predates this feature).
async fn current_epoch(pool: &PgPool, team_id: Uuid) -> Result<i32, StatusCode> {
    let max: Option<i32> = sqlx::query_scalar(
        "SELECT MAX(key_version) FROM team_key_epochs WHERE team_id = $1",
    )
    .bind(team_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to compute current key epoch");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(max.unwrap_or(1))
}

/// Membership + Teams-tier + permission preamble shared by every team vault route.
///
/// `action` names the attempted operation so the non-member warning stays greppable.
async fn require_vault_access(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
    action: &str,
    check: PermCheck<'_>,
) -> Result<(), StatusCode> {
    if !is_team_member(pool, team_id, user_id).await? {
        warn!(team_id = %team_id, user_id = %user_id, action, "Non-member tried to access team vault");
        return Err(StatusCode::FORBIDDEN);
    }
    require_teams_tier_for_vault(pool, team_id).await?;
    crate::permissions::require_team_permissions(pool, team_id, user_id, check).await
}

/// A connect-only member needs the vault key to decrypt the credentials they
/// are allowed to *use*; VIEW_SECRETS is what lets a member *read* one
/// (issue #190). Shared by every route that gates on this pair — the
/// whole-vault ciphertext stays VIEW_SECRETS-only, see `get_team_blob`.
const CONNECT_OR_VIEW_SECRETS: PermCheck<'static> = PermCheck::Any(&[
    crate::permissions::PERM_CONNECT,
    crate::permissions::PERM_VIEW_SECRETS,
]);

// ─── GET /v1/teams/:team_id/vault-key ────────────────────────────────────────

#[derive(Serialize)]
pub struct VaultKeyResponse {
    pub wrapped_key: String,
    pub wrapped_by_user_id: Uuid,
    pub key_version: i32,
}

pub async fn get_my_vault_key(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<VaultKeyResponse>, StatusCode> {
    require_vault_access(
        &pool,
        team_id,
        auth.0,
        "get_vault_key",
        CONNECT_OR_VIEW_SECRETS,
    )
    .await?;

    let row = sqlx::query_as::<_, (String, Uuid, i32)>(
        "SELECT wrapped_key, wrapped_by, key_version FROM team_vault_keys \
         WHERE team_id = $1 AND user_id = $2 \
         ORDER BY key_version DESC LIMIT 1",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %auth.0, "Failed to fetch vault key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!(team_id = %team_id, user_id = %auth.0, "Vault key not found for user");
        StatusCode::NOT_FOUND
    })?;

    info!(team_id = %team_id, user_id = %auth.0, "Vault key fetched");
    Ok(Json(VaultKeyResponse {
        wrapped_key: row.0,
        wrapped_by_user_id: row.1,
        key_version: row.2,
    }))
}

// ─── GET /v1/teams/:team_id/vault-key/:version ───────────────────────────────

/// Fetch a *specific* historical epoch's wrapped key. Only used when decoding
/// a row whose `key_version` (secrets/blob column, or `kv` inside an object's
/// envelope) is behind the team's current epoch — the normal read path is
/// still `get_my_vault_key`, unchanged, for the current epoch.
pub async fn get_vault_key_at_version(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path((team_id, version)): Path<(Uuid, i32)>,
) -> Result<Json<VaultKeyResponse>, StatusCode> {
    require_vault_access(
        &pool,
        team_id,
        auth.0,
        "get_vault_key_at_version",
        CONNECT_OR_VIEW_SECRETS,
    )
    .await?;

    let row = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT wrapped_key, wrapped_by FROM team_vault_keys WHERE team_id = $1 AND user_id = $2 AND key_version = $3",
    )
    .bind(team_id)
    .bind(auth.0)
    .bind(version)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %auth.0, version, "Failed to fetch vault key at version");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(VaultKeyResponse {
        wrapped_key: row.0,
        wrapped_by_user_id: row.1,
        key_version: version,
    }))
}

// ─── GET /v1/teams/:team_id/vault-key/rotation-status ────────────────────────

#[derive(Serialize)]
pub struct RotationStatusResponse {
    pub stale: bool,
    pub draining: bool,
}

/// Does any ciphertext row for `team_id` still sit on an epoch behind
/// `epoch`? Shared by `get_rotation_status` (reporting) and `rotate_vault_key`
/// (enforcement — the spec forbids stacking a new epoch while a prior one is
/// still draining, #217 review finding I4).
///
/// `team_vault_objects.metadata->>'kv'` is client-supplied JSON (any member
/// with an edit permission can write it via `upsert_object`), so the cast only
/// fires when the value is actually a JSON number — a non-numeric `kv` (bug
/// or malice) falls back to epoch 1 instead of raising a Postgres cast error
/// that would 500 this query for the whole team on every future call (#217
/// review finding I6).
async fn is_draining(pool: &PgPool, team_id: Uuid, epoch: i32) -> Result<bool, StatusCode> {
    sqlx::query_scalar(
        r#"SELECT
             EXISTS(SELECT 1 FROM team_vault_secrets WHERE team_id = $1 AND key_version < $2)
             OR EXISTS(SELECT 1 FROM team_vault_objects WHERE team_id = $1 AND deleted_at IS NULL
                       AND (CASE WHEN jsonb_typeof(metadata->'kv') = 'number'
                                 THEN (metadata->>'kv')::int
                                 ELSE 1
                            END) < $2)
             OR EXISTS(SELECT 1 FROM team_sync_blobs WHERE team_id = $1 AND key_version < $2)
           "#,
    )
    .bind(team_id)
    .bind(epoch)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to compute rotation draining state");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

pub async fn get_rotation_status(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<RotationStatusResponse>, StatusCode> {
    require_vault_access(
        &pool,
        team_id,
        auth.0,
        "get_rotation_status",
        CONNECT_OR_VIEW_SECRETS,
    )
    .await?;

    let epoch = current_epoch(&pool, team_id).await?;

    // stale: does a team member with a public key on file lack a row at the
    // current epoch? A member with no public key can never be covered (they
    // cannot receive a wrapped key), so they are excluded entirely.
    let stale: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
             SELECT 1 FROM team_members tm
             JOIN users u ON u.id = tm.user_id
             WHERE tm.team_id = $1
               AND u.public_key IS NOT NULL
               AND NOT EXISTS (
                 SELECT 1 FROM team_vault_keys tvk
                 WHERE tvk.team_id = tm.team_id AND tvk.user_id = tm.user_id AND tvk.key_version = $2
               )
           )"#,
    )
    .bind(team_id)
    .bind(epoch)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to compute rotation staleness");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let draining = is_draining(&pool, team_id, epoch).await?;

    Ok(Json(RotationStatusResponse { stale, draining }))
}

// ─── GET /v1/teams/:team_id/vault-key/holders ────────────────────────────────

/// List the user_ids that already hold a wrapped copy of the team vault key.
///
/// A key-holder client uses this to reconcile distribution: members present in
/// `team_members` but absent from this list are missing their key and need one
/// wrapped for them (issue #41). Returns only user_ids — no key material — so
/// the response is safe for any member who can view the vault to read.
pub async fn get_vault_key_holders(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<Vec<Uuid>>, StatusCode> {
    require_vault_access(
        &pool,
        team_id,
        auth.0,
        "list_vault_key_holders",
        PermCheck::All(&[crate::permissions::PERM_VIEW_SECRETS]),
    )
    .await?;

    // Must agree with `rotation-status`'s `stale` check: a member holding only
    // an old-epoch row has not been covered by the current rotation and must
    // not be reported here as "already has a key" (#217 review finding I3).
    let epoch = current_epoch(&pool, team_id).await?;

    let holders = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM team_vault_keys WHERE team_id = $1 AND key_version = $2",
    )
    .bind(team_id)
    .bind(epoch)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to list vault key holders");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(holders))
}

// ─── PUT /v1/teams/:team_id/vault-key ────────────────────────────────────────

#[derive(Deserialize)]
pub struct WrappedKeyEntry {
    pub user_id: Uuid,
    pub wrapped_key: String,
}

#[derive(Deserialize)]
pub struct PutVaultKeysRequest {
    pub keys: Vec<WrappedKeyEntry>,
}

fn vault_key_notification_targets(actor_user_id: Uuid, keys: &[WrappedKeyEntry]) -> Vec<Uuid> {
    let mut seen = std::collections::HashSet::new();
    keys.iter()
        .filter_map(|entry| {
            if entry.user_id == actor_user_id || !seen.insert(entry.user_id) {
                None
            } else {
                Some(entry.user_id)
            }
        })
        .collect()
}

pub async fn put_vault_keys(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(sync_notifier): axum::Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<PutVaultKeysRequest>,
) -> Result<StatusCode, StatusCode> {
    require_vault_access(
        &pool,
        team_id,
        auth.0,
        "put_vault_keys",
        PermCheck::All(&[
            crate::permissions::PERM_VIEW_SECRETS,
            crate::permissions::PERM_COPY_SECRETS,
        ]),
    )
    .await?;

    if body.keys.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate all target users are current team members
    let member_ids: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM team_members WHERE team_id = $1",
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to fetch team members for key validation");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let member_set: std::collections::HashSet<Uuid> = member_ids.into_iter().collect();

    for entry in &body.keys {
        if !member_set.contains(&entry.user_id) {
            warn!(team_id = %team_id, target_user_id = %entry.user_id, "Key upsert rejected: user not in team");
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // put_vault_keys never creates a new epoch — only rotate_vault_key does —
    // so every write here targets the team's current epoch.
    let version = current_epoch(&pool, team_id).await?;

    // Upsert each wrapped key entry
    for entry in &body.keys {
        sqlx::query(
            r#"
            INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (team_id, user_id, key_version)
            DO UPDATE SET wrapped_key = EXCLUDED.wrapped_key, wrapped_by = EXCLUDED.wrapped_by
            "#,
        )
        .bind(team_id)
        .bind(entry.user_id)
        .bind(&entry.wrapped_key)
        .bind(auth.0)
        .bind(version)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, target_user_id = %entry.user_id, "Failed to upsert vault key");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    info!(team_id = %team_id, upserter = %auth.0, key_count = body.keys.len(), "Vault keys upserted");
    for user_id in vault_key_notification_targets(auth.0, &body.keys) {
        sync_notifier.notify_membership_changed(user_id);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ─── POST /v1/teams/:team_id/vault-key/rotate ────────────────────────────────

#[derive(Deserialize)]
pub struct RotateVaultKeyRequest {
    pub keys: Vec<WrappedKeyEntry>,
}

/// Atomically mints a new key epoch: validates the caller wrapped the new DEK
/// for every current member who has a public key (no more, no fewer — a set
/// that misses one locks them out; requiring them to be a *current* member
/// only, never mind the extras, keeps this simple since callers build the
/// list from a fresh member fetch), inserts the epoch ledger row and every
/// wrapped-key row in one transaction.
pub async fn rotate_vault_key(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(sync_notifier): axum::Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<RotateVaultKeyRequest>,
) -> Result<StatusCode, StatusCode> {
    require_vault_access(
        &pool,
        team_id,
        auth.0,
        "rotate_vault_key",
        PermCheck::All(&[
            crate::permissions::PERM_VIEW_SECRETS,
            crate::permissions::PERM_COPY_SECRETS,
        ]),
    )
    .await?;

    let required_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT tm.user_id FROM team_members tm
           JOIN users u ON u.id = tm.user_id
           WHERE tm.team_id = $1 AND u.public_key IS NOT NULL"#,
    )
    .bind(team_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to fetch keyed members for rotation");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let required_set: std::collections::HashSet<Uuid> = required_ids.into_iter().collect();
    let provided_set: std::collections::HashSet<Uuid> = body.keys.iter().map(|k| k.user_id).collect();

    if required_set != provided_set {
        warn!(
            team_id = %team_id, user_id = %auth.0,
            required = required_set.len(), provided = provided_set.len(),
            "Rotation rejected: provided key set does not match current keyed membership",
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let epoch = current_epoch(&pool, team_id).await?;

    // The spec forbids stacking a new epoch while the current one hasn't
    // fully drained: minting epoch N+1 here would leave epoch-N ciphertext
    // stranded behind two rotations instead of one. Only the client was
    // previously asked to honor this (#217 review finding I4).
    if is_draining(&pool, team_id, epoch).await? {
        warn!(team_id = %team_id, user_id = %auth.0, epoch, "Rotation rejected: team is still draining a prior epoch");
        return Err(StatusCode::CONFLICT);
    }

    let next_version = epoch + 1;

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to open rotation transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, $2, $3)")
        .bind(team_id)
        .bind(next_version)
        .bind(auth.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, "Failed to insert key epoch");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    for entry in &body.keys {
        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(team_id)
        .bind(entry.user_id)
        .bind(&entry.wrapped_key)
        .bind(auth.0)
        .bind(next_version)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, target_user_id = %entry.user_id, "Failed to insert rotated key");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    tx.commit().await.map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to commit rotation");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(team_id = %team_id, rotated_by = %auth.0, new_epoch = next_version, member_count = body.keys.len(), "Team vault key rotated");
    for user_id in vault_key_notification_targets(auth.0, &body.keys) {
        sync_notifier.notify_membership_changed(user_id);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ─── GET /v1/teams/:team_id/sync-blob ────────────────────────────────────────

#[derive(Serialize)]
pub struct TeamBlobResponse {
    pub blob: String, // base64
    pub updated_at: DateTime<Utc>,
    pub key_version: i32,
}

pub async fn get_team_blob(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<TeamBlobResponse>, StatusCode> {
    // The legacy blob carries every object AND every secret in one ciphertext, so
    // reading it requires the same secret-level rights its writer does. Members
    // without PERM_VIEW_SECRETS read the vault through the object routes instead.
    require_vault_access(
        &pool,
        team_id,
        auth.0,
        "get_team_blob",
        PermCheck::All(&[crate::permissions::PERM_VIEW_SECRETS]),
    )
    .await?;

    let row = sqlx::query_as::<_, (Vec<u8>, DateTime<Utc>, i32)>(
        "SELECT blob, updated_at, key_version FROM team_sync_blobs WHERE team_id = $1",
    )
    .bind(team_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to fetch team blob");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!(team_id = %team_id, "Team sync blob not found");
        StatusCode::NOT_FOUND
    })?;

    info!(team_id = %team_id, user_id = %auth.0, "Team sync blob fetched");
    Ok(Json(TeamBlobResponse {
        blob: base64::engine::general_purpose::STANDARD.encode(&row.0),
        updated_at: row.1,
        key_version: row.2,
    }))
}

// ─── PUT /v1/teams/:team_id/sync-blob ────────────────────────────────────────

/// Default for `PutTeamBlobRequest::key_version` when a pre-#217 client omits
/// the field entirely: treat it as epoch 1 rather than 422ing the request.
fn default_key_version_one() -> i32 {
    1
}

#[derive(Deserialize)]
pub struct PutTeamBlobRequest {
    pub blob: String, // base64
    #[serde(default = "default_key_version_one")]
    pub key_version: i32,
}

pub async fn put_team_blob(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(sync_notifier): axum::Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<PutTeamBlobRequest>,
) -> Result<StatusCode, StatusCode> {
    // Legacy whole-blob writes can replace every object and secret in a team
    // vault. Keep this endpoint for migration/bootstrap, but require broad
    // rights so lower-privilege roles cannot bypass object-level routes.
    require_vault_access(
        &pool,
        team_id,
        auth.0,
        "put_team_blob",
        PermCheck::All(&[
            crate::permissions::PERM_EDIT_CONNECTIONS,
            crate::permissions::PERM_EDIT_IDENTITIES,
            crate::permissions::PERM_EDIT_KEYS,
            crate::permissions::PERM_EDIT_FOLDERS,
            crate::permissions::PERM_VIEW_SECRETS,
            crate::permissions::PERM_COPY_SECRETS,
        ]),
    )
    .await?;

    let blob_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.blob)
        .map_err(|_| {
            warn!(team_id = %team_id, user_id = %auth.0, "Invalid base64 team blob payload");
            StatusCode::BAD_REQUEST
        })?;

    if blob_bytes.len() > MAX_TEAM_BLOB_SIZE {
        warn!(
            team_id = %team_id,
            user_id = %auth.0,
            blob_size = blob_bytes.len(),
            max_blob_size = MAX_TEAM_BLOB_SIZE,
            "Team blob payload exceeds size limit"
        );
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let size_bytes = blob_bytes.len() as i32;

    sqlx::query(
        r#"
        INSERT INTO team_sync_blobs (team_id, blob, size_bytes, updated_by, key_version)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (team_id)
        DO UPDATE SET blob = EXCLUDED.blob, size_bytes = EXCLUDED.size_bytes,
                      updated_by = EXCLUDED.updated_by, updated_at = now(),
                      key_version = EXCLUDED.key_version
        "#,
    )
    .bind(team_id)
    .bind(&blob_bytes)
    .bind(size_bytes)
    .bind(auth.0)
    .bind(body.key_version)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %auth.0, "Failed to upsert team sync blob");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(team_id = %team_id, user_id = %auth.0, blob_size = blob_bytes.len(), "Team sync blob upserted");

    notify_team_vault_changed(&pool, &sync_notifier, team_id, auth.0).await;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_vault_notification_payload_uses_team_prefix() {
        let team_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();

        assert_eq!(
            crate::sync_notifier::team_vault_notification_payload(team_id),
            "team:11111111-1111-4111-8111-111111111111"
        );
    }

    #[test]
    fn vault_key_update_notifies_targets_except_actor_once() {
        let actor = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let target = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();

        let targets = vault_key_notification_targets(
            actor,
            &[
                WrappedKeyEntry { user_id: actor, wrapped_key: "self".to_string() },
                WrappedKeyEntry { user_id: target, wrapped_key: "target-1".to_string() },
                WrappedKeyEntry { user_id: target, wrapped_key: "target-2".to_string() },
            ],
        );

        assert_eq!(targets, vec![target]);
    }

    // ─── GET /v1/teams/:team_id/vault-key/holders (issue #41) ────────────────

    use crate::auth::AuthUser;
    use crate::permissions::PERM_CONNECT;
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, assign_role, member_with_role, seed_role, seed_team, seed_user};
    use axum::extract::{Path, State};
    use axum::Extension;

    /// Give `user` a role granting PERM_VIEW_SECRETS in `team`.
    async fn grant_view_secrets(pool: &PgPool, team: Uuid, user: Uuid) {
        let role = seed_role(pool, team, "viewer", crate::permissions::PERM_VIEW_SECRETS).await;
        assign_role(pool, team, user, role).await;
    }

    /// Give `user` a role granting PERM_VIEW_SECRETS | PERM_COPY_SECRETS in `team`
    /// — the pair `put_vault_keys` requires of the caller distributing keys.
    async fn grant_view_secrets_and_copy(pool: &PgPool, team: Uuid, user: Uuid) {
        let role = seed_role(
            pool,
            team,
            "key-distributor",
            crate::permissions::PERM_VIEW_SECRETS | crate::permissions::PERM_COPY_SECRETS,
        )
        .await;
        assign_role(pool, team, user, role).await;
    }

    async fn insert_vault_key(pool: &PgPool, team: Uuid, user: Uuid, wrapped_by: Uuid) {
        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by) \
             VALUES ($1, $2, 'wrapped', $3)",
        )
        .bind(team)
        .bind(user)
        .bind(wrapped_by)
        .execute(pool)
        .await
        .expect("insert vault key");
    }

    #[tokio::test]
    async fn holders_lists_only_members_with_a_key() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;

        // A second member has joined but no key has been distributed to them yet.
        let keyless = seed_user(&pool).await;
        add_member(&pool, team, keyless).await;

        // Only the owner holds a key.
        insert_vault_key(&pool, team, owner, owner).await;

        let holders = get_vault_key_holders(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("holders ok")
            .0;

        assert_eq!(holders, vec![owner]);
        assert!(!holders.contains(&keyless), "keyless member must be absent");
    }

    /// I3: holders must be epoch-aware so it agrees with `rotation-status`'s
    /// `stale` check. A member holding only an old-epoch row is NOT covered by
    /// the current rotation and must not be reported as "already has a key",
    /// or the client's `reconcileTeamVaultKeys` would skip them forever.
    #[tokio::test]
    async fn holders_excludes_a_member_whose_only_row_is_an_old_epoch() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;

        // Team has rotated: current epoch is 2.
        sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, 2, $2)")
            .bind(team).bind(owner).execute(&pool).await.expect("epoch 2 ledger");

        // `owner` was wrapped a key at the new epoch...
        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) VALUES ($1, $2, 'k2', $2, 2)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("owner epoch 2 key");

        // ...but a second member only ever held the old epoch 1 key.
        let stale_member = seed_user(&pool).await;
        add_member(&pool, team, stale_member).await;
        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) VALUES ($1, $2, 'k1', $3, 1)",
        )
        .bind(team).bind(stale_member).bind(owner).execute(&pool).await.expect("stale member epoch 1 key");

        let holders = get_vault_key_holders(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("holders ok")
            .0;

        assert_eq!(holders, vec![owner], "only the current-epoch row counts as held");
        assert!(
            !holders.contains(&stale_member),
            "a member covering only an old epoch must not be reported as a holder"
        );
    }

    #[tokio::test]
    async fn holders_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await;

        let res = get_vault_key_holders(State(pool.clone()), Extension(AuthUser(outsider)), Path(team)).await;

        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
    }

    // ─── GET /v1/teams/:team_id/sync-blob (issue #187) ───────────────────────

    async fn insert_team_blob(pool: &PgPool, team: Uuid, updated_by: Uuid) {
        sqlx::query(
            "INSERT INTO team_sync_blobs (team_id, blob, size_bytes, updated_by) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(team)
        .bind(b"ciphertext".to_vec())
        .bind(10_i32)
        .bind(updated_by)
        .execute(pool)
        .await
        .expect("insert team blob");
    }

    #[tokio::test]
    async fn blob_forbidden_without_view_secrets_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        insert_team_blob(&pool, team, owner).await;

        // connect-only: no PERM_VIEW_SECRETS, so the whole-vault ciphertext —
        // which carries every secret — must stay out of reach.
        let connect_only = seed_user(&pool).await;
        add_member(&pool, team, connect_only).await;
        grant_connect_only(&pool, team, connect_only).await;

        let res = get_team_blob(State(pool.clone()), Extension(AuthUser(connect_only)), Path(team)).await;

        // `.err()` rather than `unwrap_err()`: TeamBlobResponse has no Debug.
        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn blob_readable_with_view_secrets_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;
        insert_team_blob(&pool, team, owner).await;

        let res = get_team_blob(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("blob ok")
            .0;

        assert!(!res.blob.is_empty());
    }

    // ─── GET /v1/teams/:team_id/vault-key (issue #190) ───────────────────────

    /// Give `user` a connect-only role: PERM_CONNECT and nothing else.
    async fn grant_connect_only(pool: &PgPool, team: Uuid, user: Uuid) {
        let role = seed_role(pool, team, "connect-only", PERM_CONNECT).await;
        assign_role(pool, team, user, role).await;
    }

    #[tokio::test]
    async fn vault_key_readable_with_connect_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;

        // A connect-only member cannot use a stored credential without the key
        // that decrypts it, so CONNECT alone must reach this route.
        let connect_only = seed_user(&pool).await;
        add_member(&pool, team, connect_only).await;
        grant_connect_only(&pool, team, connect_only).await;
        insert_vault_key(&pool, team, connect_only, owner).await;

        let res = get_my_vault_key(State(pool.clone()), Extension(AuthUser(connect_only)), Path(team))
            .await
            .expect("vault key ok")
            .0;

        assert_eq!(res.wrapped_key, "wrapped");
        assert_eq!(res.wrapped_by_user_id, owner);
    }

    #[tokio::test]
    async fn my_vault_key_returns_the_current_epoch_when_multiple_rows_exist() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;

        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) VALUES ($1, $2, 'old', $2, 1)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("epoch 1");
        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) VALUES ($1, $2, 'current', $2, 2)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("epoch 2");

        let res = get_my_vault_key(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("vault key ok")
            .0;

        assert_eq!(res.wrapped_key, "current");
        assert_eq!(res.key_version, 2);
    }

    #[tokio::test]
    async fn vault_key_forbidden_without_connect_or_view_secrets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Member of the team but granted no roles → neither bit.
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;
        insert_vault_key(&pool, team, member, owner).await;

        let res = get_my_vault_key(State(pool.clone()), Extension(AuthUser(member)), Path(team)).await;

        // `.err()` rather than `unwrap_err()`: VaultKeyResponse has no Debug.
        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn vault_key_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await;

        let res = get_my_vault_key(State(pool.clone()), Extension(AuthUser(outsider)), Path(team)).await;

        // `.err()` rather than `unwrap_err()`: VaultKeyResponse has no Debug.
        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn blob_still_forbidden_for_connect_only_after_key_widening() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        insert_team_blob(&pool, team, owner).await;

        // Widening the key route to CONNECT would be a whole-vault leak if the
        // legacy blob followed it. It must not (issue #187, then #190).
        let connect_only = seed_user(&pool).await;
        add_member(&pool, team, connect_only).await;
        grant_connect_only(&pool, team, connect_only).await;
        insert_vault_key(&pool, team, connect_only, owner).await;

        let res = get_team_blob(State(pool.clone()), Extension(AuthUser(connect_only)), Path(team)).await;

        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn get_team_blob_returns_its_key_version() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;

        sqlx::query(
            "INSERT INTO team_sync_blobs (team_id, blob, size_bytes, updated_by, key_version) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(team).bind(b"ciphertext".to_vec()).bind(10_i32).bind(owner).bind(2_i32)
        .execute(&pool).await.expect("insert blob at epoch 2");

        let res = get_team_blob(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("blob ok")
            .0;

        assert_eq!(res.key_version, 2);
    }

    #[tokio::test]
    async fn put_team_blob_persists_the_provided_key_version() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets_and_copy(&pool, team, owner).await;
        // put_team_blob also requires EDIT_* — grant the full set the route checks.
        let role = seed_role(&pool, team, "blob-writer", crate::permissions::PERM_EDIT_CONNECTIONS
            | crate::permissions::PERM_EDIT_IDENTITIES | crate::permissions::PERM_EDIT_KEYS
            | crate::permissions::PERM_EDIT_FOLDERS | crate::permissions::PERM_VIEW_SECRETS
            | crate::permissions::PERM_COPY_SECRETS).await;
        assign_role(&pool, team, owner, role).await;

        use base64::Engine;
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(b"new-ciphertext");

        let res = put_team_blob(
            State(pool.clone()),
            Extension(AuthUser(owner)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(PutTeamBlobRequest { blob: body_b64, key_version: 3 }),
        )
        .await;

        assert_eq!(res, Ok(StatusCode::NO_CONTENT));

        let kv: i32 = sqlx::query_scalar("SELECT key_version FROM team_sync_blobs WHERE team_id = $1")
            .bind(team).fetch_one(&pool).await.unwrap();
        assert_eq!(kv, 3);
    }

    /// I5: a pre-#217 client's body carries no `key_version` field at all.
    /// It must still deserialize (as epoch 1), not 422 the whole request.
    #[test]
    fn put_team_blob_request_defaults_key_version_when_field_is_absent() {
        let body: PutTeamBlobRequest =
            serde_json::from_str(r#"{"blob": "abc"}"#).expect("must deserialize without key_version");

        assert_eq!(body.key_version, 1);
    }

    // ─── GET /v1/teams/:team_id/vault-key/:version (#217) ────────────────────

    #[tokio::test]
    async fn vault_key_at_version_returns_the_requested_epoch_not_the_latest() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;

        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) \
             VALUES ($1, $2, 'old-wrapped', $2, 1)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("epoch 1");
        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) \
             VALUES ($1, $2, 'new-wrapped', $2, 2)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("epoch 2");

        let res = get_vault_key_at_version(State(pool.clone()), Extension(AuthUser(owner)), Path((team, 1)))
            .await
            .expect("epoch 1 ok")
            .0;

        assert_eq!(res.wrapped_key, "old-wrapped");
        assert_eq!(res.key_version, 1);
    }

    #[tokio::test]
    async fn vault_key_at_version_404_when_this_member_has_no_row_at_that_version() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;

        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) \
             VALUES ($1, $2, 'only-epoch-2', $2, 2)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("epoch 2 only");

        let res = get_vault_key_at_version(State(pool.clone()), Extension(AuthUser(owner)), Path((team, 1))).await;

        assert_eq!(res.err(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn vault_key_at_version_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await;

        let res = get_vault_key_at_version(State(pool.clone()), Extension(AuthUser(outsider)), Path((team, 1))).await;

        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
    }

    // ─── GET /v1/teams/:team_id/vault-key/rotation-status (#217) ─────────────

    #[tokio::test]
    async fn rotation_status_not_stale_when_every_keyed_member_holds_the_current_epoch() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;
        insert_vault_key(&pool, team, owner, owner).await; // key_version defaults to 1

        let res = get_rotation_status(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("status ok")
            .0;

        assert!(!res.stale);
        assert!(!res.draining);
    }

    #[tokio::test]
    async fn rotation_status_stale_when_a_member_has_no_row_at_the_current_epoch() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;
        insert_vault_key(&pool, team, owner, owner).await;

        // A second member joined but has never been wrapped a key at all.
        let newcomer = seed_user(&pool).await;
        add_member(&pool, team, newcomer).await;
        sqlx::query("UPDATE users SET public_key = 'newcomer-pubkey' WHERE id = $1")
            .bind(newcomer).execute(&pool).await.expect("give newcomer a public key");

        let res = get_rotation_status(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("status ok")
            .0;

        assert!(res.stale);
    }

    #[tokio::test]
    async fn rotation_status_ignores_members_with_no_public_key() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;
        insert_vault_key(&pool, team, owner, owner).await;

        // A member with no public key on file can never receive a wrapped key,
        // so their absence from team_vault_keys must not force stale=true forever.
        let keyless = seed_user(&pool).await;
        add_member(&pool, team, keyless).await;
        sqlx::query("UPDATE users SET public_key = NULL WHERE id = $1")
            .bind(keyless).execute(&pool).await.expect("clear public key");

        let res = get_rotation_status(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("status ok")
            .0;

        assert!(!res.stale, "a keyless member must not count against coverage");
    }

    #[tokio::test]
    async fn rotation_status_draining_when_a_secret_row_is_behind_the_current_epoch() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;

        // Current epoch is 2 (both a key row and an epoch ledger row at 2)...
        sqlx::query("INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) VALUES ($1, $2, 'k2', $2, 2)")
            .bind(team).bind(owner).execute(&pool).await.expect("epoch 2 key");
        sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, 2, $2)")
            .bind(team).bind(owner).execute(&pool).await.expect("epoch 2 ledger");

        // ...but a secret row is still on epoch 1.
        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by, key_version) \
             VALUES ($1, 'sec-1', 'obj-1', 'connection_password', 'cipher', $2, 1)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("stale secret");

        let res = get_rotation_status(State(pool.clone()), Extension(AuthUser(owner)), Path(team))
            .await
            .expect("status ok")
            .0;

        assert!(res.draining);
    }

    /// I6: a malformed `kv` in an object's metadata (any editor can write
    /// this shape via `upsert_object`) must not 500 the whole team's
    /// rotation-status forever. A non-numeric `kv` falls back to epoch 1, so
    /// with a current epoch of 2 the row still correctly counts as draining.
    #[tokio::test]
    async fn rotation_status_survives_a_non_numeric_kv_in_object_metadata() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets(&pool, team, owner).await;

        // Current epoch is 2...
        sqlx::query("INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) VALUES ($1, $2, 'k2', $2, 2)")
            .bind(team).bind(owner).execute(&pool).await.expect("epoch 2 key");
        sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, 2, $2)")
            .bind(team).bind(owner).execute(&pool).await.expect("epoch 2 ledger");

        // ...but an object's metadata carries a garbage (non-numeric) `kv`.
        sqlx::query(
            "INSERT INTO team_vault_objects (team_id, object_id, object_type, vault_id, metadata, updated_by) \
             VALUES ($1, 'obj-garbage', 'connection', $1, $2, $3)",
        )
        .bind(team)
        .bind(serde_json::json!({ "v": 2, "enc": "x", "kv": "garbage" }))
        .bind(owner)
        .execute(&pool)
        .await
        .expect("seed object with malformed kv");

        let res = get_rotation_status(State(pool.clone()), Extension(AuthUser(owner)), Path(team)).await;

        let status = res.expect("a non-numeric kv must not error the route").0;
        assert!(
            status.draining,
            "a non-numeric kv falls back to epoch 1, which is behind the current epoch of 2"
        );
    }

    #[tokio::test]
    async fn rotation_status_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await;

        let res = get_rotation_status(State(pool.clone()), Extension(AuthUser(outsider)), Path(team)).await;

        assert_eq!(res.err(), Some(StatusCode::FORBIDDEN));
    }

    // ─── POST /v1/teams/:team_id/vault-key/rotate (#217) ─────────────────────

    #[tokio::test]
    async fn rotate_creates_a_new_epoch_and_ledger_row() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets_and_copy(&pool, team, owner).await;
        insert_vault_key(&pool, team, owner, owner).await; // epoch 1

        let res = rotate_vault_key(
            State(pool.clone()),
            Extension(AuthUser(owner)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(RotateVaultKeyRequest {
                keys: vec![WrappedKeyEntry { user_id: owner, wrapped_key: "wrapped-epoch-2".to_string() }],
            }),
        )
        .await;

        assert_eq!(res, Ok(StatusCode::NO_CONTENT));

        let epoch: i32 = sqlx::query_scalar("SELECT MAX(key_version) FROM team_key_epochs WHERE team_id = $1")
            .bind(team).fetch_one(&pool).await.unwrap();
        assert_eq!(epoch, 2);

        let wrapped: String = sqlx::query_scalar(
            "SELECT wrapped_key FROM team_vault_keys WHERE team_id = $1 AND user_id = $2 AND key_version = 2",
        )
        .bind(team).bind(owner).fetch_one(&pool).await.unwrap();
        assert_eq!(wrapped, "wrapped-epoch-2");
    }

    /// I4: the spec forbids stacking epoch N+1 while epoch N is still
    /// draining. Only the client honored this before — assert the server
    /// now rejects the mint outright and writes nothing.
    #[tokio::test]
    async fn rotate_rejected_while_the_current_epoch_is_still_draining() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets_and_copy(&pool, team, owner).await;

        // Current epoch is 2...
        sqlx::query("INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) VALUES ($1, $2, 'k2', $2, 2)")
            .bind(team).bind(owner).execute(&pool).await.expect("epoch 2 key");
        sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, 2, $2)")
            .bind(team).bind(owner).execute(&pool).await.expect("epoch 2 ledger");

        // ...but a secret ciphertext row is still on epoch 1 — the team has
        // not finished draining epoch 1 yet.
        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by, key_version) \
             VALUES ($1, 'sec-1', 'obj-1', 'connection_password', 'cipher', $2, 1)",
        )
        .bind(team).bind(owner).execute(&pool).await.expect("draining secret");

        let res = rotate_vault_key(
            State(pool.clone()),
            Extension(AuthUser(owner)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(RotateVaultKeyRequest {
                keys: vec![WrappedKeyEntry { user_id: owner, wrapped_key: "wrapped-epoch-3".to_string() }],
            }),
        )
        .await;

        assert_eq!(res, Err(StatusCode::CONFLICT));

        let max_epoch: i32 = sqlx::query_scalar("SELECT MAX(key_version) FROM team_key_epochs WHERE team_id = $1")
            .bind(team).fetch_one(&pool).await.unwrap();
        assert_eq!(max_epoch, 2, "a rejected rotation must not insert a new epoch row");
    }

    #[tokio::test]
    async fn rotate_rejects_a_set_that_omits_a_current_keyed_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets_and_copy(&pool, team, owner).await;
        insert_vault_key(&pool, team, owner, owner).await;

        let other = seed_user(&pool).await;
        add_member(&pool, team, other).await;
        sqlx::query("UPDATE users SET public_key = 'other-pubkey' WHERE id = $1").bind(other).execute(&pool).await.unwrap();

        // Omits `other`, who has a public key and must be covered.
        let res = rotate_vault_key(
            State(pool.clone()),
            Extension(AuthUser(owner)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(RotateVaultKeyRequest {
                keys: vec![WrappedKeyEntry { user_id: owner, wrapped_key: "w2".to_string() }],
            }),
        )
        .await;

        assert_eq!(res, Err(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn rotate_ignores_a_member_with_no_public_key() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets_and_copy(&pool, team, owner).await;
        insert_vault_key(&pool, team, owner, owner).await;

        let keyless = seed_user(&pool).await;
        add_member(&pool, team, keyless).await;
        sqlx::query("UPDATE users SET public_key = NULL WHERE id = $1").bind(keyless).execute(&pool).await.unwrap();

        // Does not include `keyless` — must still succeed, since they cannot be wrapped for.
        let res = rotate_vault_key(
            State(pool.clone()),
            Extension(AuthUser(owner)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(RotateVaultKeyRequest {
                keys: vec![WrappedKeyEntry { user_id: owner, wrapped_key: "w2".to_string() }],
            }),
        )
        .await;

        assert_eq!(res, Ok(StatusCode::NO_CONTENT));
    }

    #[tokio::test]
    async fn rotate_forbidden_without_copy_secrets() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = member_with_role(&pool, team, crate::permissions::PERM_VIEW_SECRETS).await; // no COPY_SECRETS

        let res = rotate_vault_key(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(RotateVaultKeyRequest { keys: vec![] }),
        )
        .await;

        assert_eq!(res, Err(StatusCode::FORBIDDEN));
    }

    // ─── PUT /v1/teams/:team_id/vault-key (multi-epoch migration fix) ────────

    #[tokio::test]
    async fn put_vault_keys_still_works_after_the_multi_epoch_migration() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        add_member(&pool, team, owner).await;
        grant_view_secrets_and_copy(&pool, team, owner).await;

        let res = put_vault_keys(
            State(pool.clone()),
            Extension(AuthUser(owner)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(PutVaultKeysRequest {
                keys: vec![WrappedKeyEntry { user_id: owner, wrapped_key: "wrapped".to_string() }],
            }),
        )
        .await;

        assert_eq!(res, Ok(StatusCode::NO_CONTENT));

        let (wrapped, kv): (String, i32) = sqlx::query_as(
            "SELECT wrapped_key, key_version FROM team_vault_keys WHERE team_id = $1 AND user_id = $2",
        )
        .bind(team).bind(owner).fetch_one(&pool).await.unwrap();
        assert_eq!(wrapped, "wrapped");
        assert_eq!(kv, 1); // no rotation has happened yet, so current epoch is 1

        // Calling it again (re-distribution) must still succeed — the ON CONFLICT
        // target must actually match the real constraint now.
        let res2 = put_vault_keys(
            State(pool.clone()),
            Extension(AuthUser(owner)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(PutVaultKeysRequest {
                keys: vec![WrappedKeyEntry { user_id: owner, wrapped_key: "wrapped-2".to_string() }],
            }),
        )
        .await;
        assert_eq!(res2, Ok(StatusCode::NO_CONTENT));
    }

    #[tokio::test]
    async fn holders_forbidden_without_view_secrets_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Member of the team but granted no roles → no PERM_VIEW_SECRETS.
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;

        let res = get_vault_key_holders(State(pool.clone()), Extension(AuthUser(member)), Path(team)).await;

        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod epoch_migration_tests {
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_team, seed_user};
    use uuid::Uuid;

    #[tokio::test]
    async fn team_vault_keys_allows_two_epochs_for_the_same_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;

        sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) \
             VALUES ($1, $2, 'k1', $2, 1)",
        )
        .bind(team)
        .bind(owner)
        .execute(&pool)
        .await
        .expect("insert epoch 1");

        // Would violate the old (team_id, user_id) primary key; must succeed now.
        let second = sqlx::query(
            "INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by, key_version) \
             VALUES ($1, $2, 'k2', $2, 2)",
        )
        .bind(team)
        .bind(owner)
        .execute(&pool)
        .await;

        assert!(second.is_ok(), "expected a second epoch row to insert, got {:?}", second.err());
    }

    #[tokio::test]
    async fn existing_rows_default_to_key_version_one() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;

        sqlx::query(
            "INSERT INTO team_vault_secrets (team_id, secret_id, object_id, secret_type, ciphertext, updated_by) \
             VALUES ($1, 'sec-1', 'obj-1', 'connection_password', 'cipher', $2)",
        )
        .bind(team)
        .bind(owner)
        .execute(&pool)
        .await
        .expect("insert secret without key_version");

        let kv: i32 = sqlx::query_scalar(
            "SELECT key_version FROM team_vault_secrets WHERE team_id = $1 AND secret_id = 'sec-1'",
        )
        .bind(team)
        .fetch_one(&pool)
        .await
        .expect("read key_version");

        assert_eq!(kv, 1);
    }

    #[tokio::test]
    async fn team_key_epochs_rejects_duplicate_version_for_same_team() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;

        sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, 1, $2)")
            .bind(team)
            .bind(owner)
            .execute(&pool)
            .await
            .expect("insert epoch 1 row");

        let dup = sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, 1, $2)")
            .bind(team)
            .bind(owner)
            .execute(&pool)
            .await;

        assert!(dup.is_err(), "duplicate (team_id, key_version) must be rejected by the primary key");
        let _ = Uuid::new_v4(); // keep uuid import used if the above changes
    }
}
