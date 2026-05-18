use axum::{extract::State, http::StatusCode, response::sse::{Event, KeepAlive, Sse}, Json};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};
use uuid::Uuid;
use crate::auth::AuthUser;
use crate::sync_notifier::{SyncEvent, SyncNotifier};
use crate::{PresenceMap, UsageMap};

const MAX_BLOB_SIZE: usize = 5 * 1024 * 1024; // 5 MB

// ─── Get blob ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GetBlobQuery {
    pub device_id: Option<String>,
}

#[derive(Serialize)]
pub struct BlobResponse {
    pub blob: String, // base64
    pub metadata: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

pub async fn get_blob(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Query(query): axum::extract::Query<GetBlobQuery>,
) -> Result<Json<BlobResponse>, StatusCode> {
    let row = if let Some(device_id) = &query.device_id {
        sqlx::query_as::<_, (Vec<u8>, serde_json::Value, DateTime<Utc>)>(
            "SELECT blob, metadata, updated_at FROM sync_blobs WHERE user_id = $1 AND device_id = $2",
        )
        .bind(auth.0)
        .bind(device_id)
        .fetch_optional(&pool)
        .await
    } else {
        sqlx::query_as::<_, (Vec<u8>, serde_json::Value, DateTime<Utc>)>(
            "SELECT blob, metadata, updated_at FROM sync_blobs WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(auth.0)
        .fetch_optional(&pool)
        .await
    }
    .map_err(|err| {
        error!(error = %err, user_id = %auth.0, "Failed to fetch sync blob");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!(user_id = %auth.0, device_id = ?query.device_id, "Sync blob not found");
        StatusCode::NOT_FOUND
    })?;

    info!(user_id = %auth.0, device_id = ?query.device_id, "Sync blob fetched");

    Ok(Json(BlobResponse {
        blob: base64::engine::general_purpose::STANDARD.encode(&row.0),
        metadata: row.1,
        updated_at: row.2,
    }))
}

// ─── Put blob ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PutBlobRequest {
    pub device_id: String,
    pub blob: String, // base64
    pub metadata: serde_json::Value,
}

#[derive(Serialize)]
pub struct PutBlobResponse {
    pub updated_at: DateTime<Utc>,
}

pub async fn put_blob(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    Json(body): Json<PutBlobRequest>,
) -> Result<Json<PutBlobResponse>, StatusCode> {
    let blob_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.blob)
        .map_err(|_| {
            warn!(user_id = %auth.0, device_id = %body.device_id, "Invalid base64 blob payload");
            StatusCode::BAD_REQUEST
        })?;

    if blob_bytes.len() > MAX_BLOB_SIZE {
        warn!(
            user_id = %auth.0,
            device_id = %body.device_id,
            blob_size = blob_bytes.len(),
            max_blob_size = MAX_BLOB_SIZE,
            "Blob payload exceeds size limit"
        );
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let size_bytes = blob_bytes.len() as i32;

    let row = sqlx::query_as::<_, (DateTime<Utc>,)>(
        r#"
        INSERT INTO sync_blobs (user_id, device_id, blob, metadata, size_bytes)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id, device_id)
        DO UPDATE SET blob = EXCLUDED.blob, metadata = EXCLUDED.metadata,
                      size_bytes = EXCLUDED.size_bytes, updated_at = now()
        RETURNING updated_at
        "#,
    )
    .bind(auth.0)
    .bind(&body.device_id)
    .bind(&blob_bytes)
    .bind(&body.metadata)
    .bind(size_bytes)
    .fetch_one(&pool)
    .await
    .map_err(|err| {
        error!(error = %err, user_id = %auth.0, device_id = %body.device_id, "Failed to upsert sync blob");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        user_id = %auth.0,
        device_id = %body.device_id,
        blob_size = blob_bytes.len(),
        "Sync blob upserted"
    );

    notifier.notify(auth.0, body.device_id.clone());

    Ok(Json(PutBlobResponse {
        updated_at: row.0,
    }))
}

// ─── List devices ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub metadata: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceInfo>,
}

pub async fn list_devices(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<DevicesResponse>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, serde_json::Value, DateTime<Utc>)>(
        "SELECT device_id, metadata, updated_at FROM sync_blobs WHERE user_id = $1 ORDER BY updated_at DESC",
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|err| {
        error!(error = %err, user_id = %auth.0, "Failed to list sync devices");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(user_id = %auth.0, device_count = rows.len(), "Sync devices listed");

    let devices = rows
        .into_iter()
        .map(|(device_id, metadata, updated_at)| DeviceInfo {
            device_id,
            metadata,
            updated_at,
        })
        .collect();

    Ok(Json(DevicesResponse { devices }))
}

// ─── Delete blob ─────────────────────────────────────────────────────────────

pub async fn delete_blob(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("DELETE FROM sync_blobs WHERE user_id = $1 AND device_id = $2")
        .bind(auth.0)
        .bind(&device_id)
        .execute(&pool)
        .await
        .map_err(|err| {
            error!(error = %err, user_id = %auth.0, device_id = %device_id, "Failed to delete sync blob");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(user_id = %auth.0, device_id = %device_id, "Sync blob deleted");

    Ok(StatusCode::NO_CONTENT)
}

// ─── SSE stream ──────────────────────────────────────────────────────────────

const TEAMMATES_SQL: &str =
    "SELECT DISTINCT tm2.user_id \
     FROM team_members tm1 \
     JOIN team_members tm2 ON tm1.team_id = tm2.team_id \
     WHERE tm1.user_id = $1 AND tm2.user_id != $1";

struct PresenceGuard {
    user_id: Uuid,
    presence: PresenceMap,
    usage: UsageMap,
    notifier: SyncNotifier,
    pool: PgPool,
}

impl Drop for PresenceGuard {
    fn drop(&mut self) {
        self.presence.remove(&self.user_id);
        // Snapshot and clear any in-flight connection-usage entries before fan-out.
        let stale_connections: Vec<String> = self
            .usage
            .remove(&self.user_id)
            .map(|(_, set)| set.iter().map(|s| s.clone()).collect())
            .unwrap_or_default();
        let (notifier, pool, user_id) = (self.notifier.clone(), self.pool.clone(), self.user_id);
        tokio::spawn(async move {
            let teammates: Vec<Uuid> = sqlx::query_scalar(TEAMMATES_SQL)
                .bind(user_id)
                .fetch_all(&pool)
                .await
                .unwrap_or_default();
            for recipient in &teammates {
                notifier.notify_presence_changed(*recipient, user_id, false);
            }
            // For each connection the user was broadcasting, fan out stop events to
            // teammates that share at least one team owning that connection.
            for connection_id in stale_connections {
                let recipients: Vec<Uuid> = sqlx::query_scalar(
                    r#"SELECT DISTINCT tm.user_id
                       FROM team_members tm
                       JOIN team_vault_objects tvo ON tvo.team_id = tm.team_id
                       WHERE tvo.object_id = $1
                         AND tvo.object_type = 'connection'
                         AND tvo.deleted_at IS NULL
                         AND tm.user_id != $2"#,
                )
                .bind(&connection_id)
                .bind(user_id)
                .fetch_all(&pool)
                .await
                .unwrap_or_default();
                for recipient in recipients {
                    notifier.notify_connection_usage_changed(
                        recipient,
                        user_id,
                        connection_id.clone(),
                        false,
                    );
                }
            }
        });
    }
}

/// Long-lived SSE connection. Sends the pusher's device_id whenever another
/// device uploads a blob for this account. The client ignores events where
/// the device_id matches its own (preventing push→event→push loops).
pub async fn sync_stream(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::Extension(presence): axum::Extension<PresenceMap>,
    axum::Extension(usage): axum::Extension<UsageMap>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let user_id = auth.0;

    // Register as online and fan-out to teammates.
    presence.insert(user_id, ());
    let teammates: Vec<Uuid> = sqlx::query_scalar(TEAMMATES_SQL)
        .bind(user_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
    for recipient in &teammates {
        notifier.notify_presence_changed(*recipient, user_id, true);
    }

    let rx = notifier.subscribe();
    let guard = PresenceGuard { user_id, presence, usage, notifier: notifier.clone(), pool };

    let stream = BroadcastStream::new(rx).filter_map(move |msg| {
        let _guard = &guard;
        match msg {
            Ok(SyncEvent::BlobPushed { user_id: uid, device_id }) if uid == user_id => {
                Some(Ok(Event::default().data(device_id)))
            }
            Ok(SyncEvent::MembershipChanged { user_id: uid }) if uid == user_id => {
                Some(Ok(Event::default().data("membership_changed")))
            }
            Ok(SyncEvent::PresenceChanged { recipient, subject, online }) if recipient == user_id => {
                let status = if online { "online" } else { "offline" };
                Some(Ok(Event::default().data(format!("presence:{}:{}", subject, status))))
            }
            Ok(SyncEvent::ConnectionUsageChanged { recipient, subject, connection_id, in_use })
                if recipient == user_id =>
            {
                let flag = if in_use { 1 } else { 0 };
                Some(Ok(Event::default().data(format!(
                    "using:{}:{}:{}",
                    subject, connection_id, flag
                ))))
            }
            Ok(_) => None,
            // Lagged: we missed some events, tell the client to sync anyway
            Err(_) => Some(Ok(Event::default().data("sync"))),
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("heartbeat"),
    )
}
