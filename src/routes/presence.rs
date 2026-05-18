use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::sync_notifier::SyncNotifier;
use crate::UsageMap;

#[derive(Debug, Deserialize)]
pub struct ConnectionUsageRequest {
    pub connection_id: String,
    pub in_use: bool,
}

#[derive(Debug, Serialize)]
pub struct ConnectionUsageEntry {
    pub connection_id: String,
    pub user_ids: Vec<Uuid>,
}

/// Returns the user IDs of teammates currently broadcasting "in use" for connections
/// the caller has access to.
pub async fn get_connection_usage(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(usage_map): Extension<UsageMap>,
) -> Result<Json<Vec<ConnectionUsageEntry>>, StatusCode> {
    // Connections the caller can see (their own teams' team-vault connections).
    let accessible: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT tvo.object_id
           FROM team_vault_objects tvo
           JOIN team_members tm ON tm.team_id = tvo.team_id
           WHERE tm.user_id = $1
             AND tvo.object_type = 'connection'
             AND tvo.deleted_at IS NULL"#,
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to list accessible connections for presence snapshot");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if accessible.is_empty() {
        return Ok(Json(Vec::new()));
    }

    let accessible_set: std::collections::HashSet<&str> =
        accessible.iter().map(String::as_str).collect();

    // Teammates of the caller (across any shared team).
    let teammates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT tm2.user_id \
         FROM team_members tm1 \
         JOIN team_members tm2 ON tm1.team_id = tm2.team_id \
         WHERE tm1.user_id = $1 AND tm2.user_id != $1",
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to list teammates for presence snapshot");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Build connection_id -> [user_ids] by intersecting each teammate's usage set
    // with the accessible-connections set.
    let mut grouped: HashMap<String, Vec<Uuid>> = HashMap::new();
    for teammate in teammates {
        if let Some(entry) = usage_map.get(&teammate) {
            for conn_id in entry.value().iter() {
                if accessible_set.contains(conn_id.as_str()) {
                    grouped
                        .entry(conn_id.clone())
                        .or_default()
                        .push(teammate);
                }
            }
        }
    }

    let response: Vec<ConnectionUsageEntry> = grouped
        .into_iter()
        .map(|(connection_id, user_ids)| ConnectionUsageEntry {
            connection_id,
            user_ids,
        })
        .collect();

    Ok(Json(response))
}

/// Caller announces they started or stopped using a connection.
/// Server validates the caller has access to the connection, mutates UsageMap,
/// and fans out a ConnectionUsageChanged event to teammates with access.
pub async fn post_connection_usage(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(usage_map): Extension<UsageMap>,
    Extension(notifier): Extension<SyncNotifier>,
    Json(body): Json<ConnectionUsageRequest>,
) -> Result<StatusCode, StatusCode> {
    // Find all teams that own this connection. If empty, this isn't a team-vault
    // connection (or doesn't exist) — reject. The caller must be a member of at
    // least one of those teams.
    let owning_teams: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT DISTINCT team_id
           FROM team_vault_objects
           WHERE object_id = $1
             AND object_type = 'connection'
             AND deleted_at IS NULL"#,
    )
    .bind(&body.connection_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, connection_id = %body.connection_id, "Failed to look up connection owning teams");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if owning_teams.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Verify the caller is a member of at least one owning team.
    let caller_is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE user_id = $1 AND team_id = ANY($2))",
    )
    .bind(auth.0)
    .bind(&owning_teams)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to check team membership for usage broadcast");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !caller_is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    // Mutate the in-memory map. If the resulting set is empty, drop the entry.
    if body.in_use {
        usage_map
            .entry(auth.0)
            .or_default()
            .insert(body.connection_id.clone());
    } else {
        let mut should_remove = false;
        if let Some(entry) = usage_map.get(&auth.0) {
            entry.value().remove(&body.connection_id);
            should_remove = entry.value().is_empty();
        }
        if should_remove {
            usage_map.remove(&auth.0);
        }
    }

    // Fan out to teammates that share at least one owning team (and aren't the caller).
    let recipients: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_id FROM team_members WHERE team_id = ANY($1) AND user_id != $2",
    )
    .bind(&owning_teams)
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to list usage fan-out recipients");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    for recipient in recipients {
        notifier.notify_connection_usage_changed(
            recipient,
            auth.0,
            body.connection_id.clone(),
            body.in_use,
        );
    }

    Ok(StatusCode::NO_CONTENT)
}
