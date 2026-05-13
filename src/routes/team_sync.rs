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
use crate::sync_notifier::SyncNotifier;

const MAX_TEAM_BLOB_SIZE: usize = 10 * 1024 * 1024; // 10 MB

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Returns true if the given user is a member of the given team.
async fn is_team_member(pool: &PgPool, team_id: Uuid, user_id: Uuid) -> Result<bool, StatusCode> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to check team membership");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Returns Ok if the vault owner has a Teams or Business subscription.
async fn require_teams_tier_for_vault(pool: &PgPool, team_id: Uuid) -> Result<(), StatusCode> {
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

// ─── GET /v1/teams/:team_id/vault-key ────────────────────────────────────────

#[derive(Serialize)]
pub struct VaultKeyResponse {
    pub wrapped_key: String,
    pub wrapped_by_user_id: Uuid,
}

pub async fn get_my_vault_key(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<VaultKeyResponse>, StatusCode> {
    if !is_team_member(&pool, team_id, auth.0).await? {
        warn!(team_id = %team_id, user_id = %auth.0, "Non-member tried to get vault key");
        return Err(StatusCode::FORBIDDEN);
    }
    require_teams_tier_for_vault(&pool, team_id).await?;
    crate::permissions::require_all_team_permissions(
        &pool,
        team_id,
        auth.0,
        &[crate::permissions::PERM_VIEW_SECRETS],
    )
    .await?;

    let row = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT wrapped_key, wrapped_by FROM team_vault_keys WHERE team_id = $1 AND user_id = $2",
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
    }))
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

pub async fn put_vault_keys(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<PutVaultKeysRequest>,
) -> Result<StatusCode, StatusCode> {
    if !is_team_member(&pool, team_id, auth.0).await? {
        warn!(team_id = %team_id, user_id = %auth.0, "Non-member tried to put vault keys");
        return Err(StatusCode::FORBIDDEN);
    }
    require_teams_tier_for_vault(&pool, team_id).await?;
    crate::permissions::require_all_team_permissions(
        &pool,
        team_id,
        auth.0,
        &[
            crate::permissions::PERM_VIEW_SECRETS,
            crate::permissions::PERM_COPY_SECRETS,
        ],
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

    // Upsert each wrapped key entry
    for entry in &body.keys {
        sqlx::query(
            r#"
            INSERT INTO team_vault_keys (team_id, user_id, wrapped_key, wrapped_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (team_id, user_id)
            DO UPDATE SET wrapped_key = EXCLUDED.wrapped_key, wrapped_by = EXCLUDED.wrapped_by
            "#,
        )
        .bind(team_id)
        .bind(entry.user_id)
        .bind(&entry.wrapped_key)
        .bind(auth.0)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, target_user_id = %entry.user_id, "Failed to upsert vault key");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    info!(team_id = %team_id, upserter = %auth.0, key_count = body.keys.len(), "Vault keys upserted");
    Ok(StatusCode::NO_CONTENT)
}

// ─── GET /v1/teams/:team_id/sync-blob ────────────────────────────────────────

#[derive(Serialize)]
pub struct TeamBlobResponse {
    pub blob: String, // base64
    pub updated_at: DateTime<Utc>,
}

pub async fn get_team_blob(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<TeamBlobResponse>, StatusCode> {
    if !is_team_member(&pool, team_id, auth.0).await? {
        warn!(team_id = %team_id, user_id = %auth.0, "Non-member tried to get team blob");
        return Err(StatusCode::FORBIDDEN);
    }
    require_teams_tier_for_vault(&pool, team_id).await?;

    let row = sqlx::query_as::<_, (Vec<u8>, DateTime<Utc>)>(
        "SELECT blob, updated_at FROM team_sync_blobs WHERE team_id = $1",
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
    }))
}

// ─── PUT /v1/teams/:team_id/sync-blob ────────────────────────────────────────

#[derive(Deserialize)]
pub struct PutTeamBlobRequest {
    pub blob: String, // base64
}

pub async fn put_team_blob(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(sync_notifier): axum::Extension<SyncNotifier>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<PutTeamBlobRequest>,
) -> Result<StatusCode, StatusCode> {
    if !is_team_member(&pool, team_id, auth.0).await? {
        warn!(team_id = %team_id, user_id = %auth.0, "Non-member tried to put team blob");
        return Err(StatusCode::FORBIDDEN);
    }
    require_teams_tier_for_vault(&pool, team_id).await?;

    // Legacy whole-blob writes can replace every object and secret in a team
    // vault. Keep this endpoint for migration/bootstrap, but require broad
    // rights so lower-privilege roles cannot bypass object-level routes.
    crate::permissions::require_all_team_permissions(
        &pool,
        team_id,
        auth.0,
        &[
            crate::permissions::PERM_EDIT_CONNECTIONS,
            crate::permissions::PERM_EDIT_IDENTITIES,
            crate::permissions::PERM_EDIT_KEYS,
            crate::permissions::PERM_EDIT_FOLDERS,
            crate::permissions::PERM_VIEW_SECRETS,
            crate::permissions::PERM_COPY_SECRETS,
        ],
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
        INSERT INTO team_sync_blobs (team_id, blob, size_bytes, updated_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (team_id)
        DO UPDATE SET blob = EXCLUDED.blob, size_bytes = EXCLUDED.size_bytes,
                      updated_by = EXCLUDED.updated_by, updated_at = now()
        "#,
    )
    .bind(team_id)
    .bind(&blob_bytes)
    .bind(size_bytes)
    .bind(auth.0)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %auth.0, "Failed to upsert team sync blob");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(team_id = %team_id, user_id = %auth.0, blob_size = blob_bytes.len(), "Team sync blob upserted");

    // Fan out a personal SSE notification to every other team member so their
    // single persistent SSE connection handles the team update without needing
    // a separate per-team SSE stream.
    let member_ids: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM team_members WHERE team_id = $1 AND user_id != $2",
    )
    .bind(team_id)
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let payload = format!("team:{}", team_id);
    for member_id in member_ids {
        sync_notifier.notify(member_id, payload.clone());
    }

    Ok(StatusCode::NO_CONTENT)
}
