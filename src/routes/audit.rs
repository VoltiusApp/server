use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::net::SocketAddr;
use tracing::{error, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::permissions::{has_team_permission, PERM_CONNECT, PERM_VIEW_AUDIT_LOG};
use crate::rate_limit::RateLimiter;

// ─── Rate limiter newtype ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuditClientRateLimiter(pub RateLimiter<Uuid>);

// ─── Write helper (called from other route modules) ───────────────────────────

pub async fn write_audit_event(
    pool: PgPool,
    team_id: Uuid,
    actor_id: Uuid,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<String>,
    target_name: Option<String>,
    metadata: Option<Value>,
) {
    let result = sqlx::query(
        r#"INSERT INTO audit_logs
           (team_id, actor_id, action, source, target_type, target_id, target_name, metadata)
           VALUES ($1, $2, $3, 'server', $4, $5, $6, $7)"#,
    )
    .bind(team_id)
    .bind(actor_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(target_name)
    .bind(metadata)
    .execute(&pool)
    .await;

    if let Err(e) = result {
        warn!(error = %e, team_id = %team_id, action = %action, "Failed to write audit event");
    }
}

// ─── Response types ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AuditLogRow {
    pub id: i64,
    pub team_id: Uuid,
    pub vault_id: Option<Uuid>,
    pub actor_id: Uuid,
    pub actor_name: String,
    pub action: String,
    pub source: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub target_name: Option<String>,
    pub metadata: Option<Value>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct AuditLogsResponse {
    pub logs: Vec<AuditLogRow>,
    pub total: i64,
}

// ─── Query parameters ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub vault_id: Option<Uuid>,
    pub action: Option<String>,
    pub actor_id: Option<Uuid>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Deserialize)]
pub struct ExportQuery {
    pub format: Option<String>,
    pub vault_id: Option<Uuid>,
    pub action: Option<String>,
    pub actor_id: Option<Uuid>,
    pub from: Option<String>,
    pub to: Option<String>,
}

// ─── GET /v1/teams/:team_id/audit-logs ────────────────────────────────────────

pub async fn list_audit_logs(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
    Query(params): Query<AuditQuery>,
) -> Result<Json<AuditLogsResponse>, StatusCode> {
    let can_view = has_team_permission(&pool, team_id, auth.0, PERM_VIEW_AUDIT_LOG).await?;
    if !can_view {
        warn!(team_id = %team_id, user_id = %auth.0, "Insufficient permission to view audit logs");
        return Err(StatusCode::FORBIDDEN);
    }

    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let from_dt = params
        .from
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let to_dt = params
        .to
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM audit_logs al
           WHERE al.team_id = $1
              AND ($2::text IS NULL OR al.action = $2)
              AND ($3::uuid IS NULL OR al.actor_id = $3::uuid)
              AND ($4::timestamptz IS NULL OR al.created_at >= $4::timestamptz)
              AND ($5::timestamptz IS NULL OR al.created_at <= $5::timestamptz)
              AND ($6::uuid IS NULL OR al.vault_id = $6::uuid)"#,
    )
    .bind(team_id)
    .bind(&params.action)
    .bind(params.actor_id)
    .bind(from_dt)
    .bind(to_dt)
    .bind(params.vault_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to count audit logs");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let logs = sqlx::query_as::<_, AuditLogRow>(
        r#"SELECT
               al.id, al.team_id, al.vault_id, al.actor_id,
               u.display_name AS actor_name,
               al.action, al.source, al.target_type, al.target_id, al.target_name,
               al.metadata, al.ip_address::text AS ip_address, al.created_at
           FROM audit_logs al
           JOIN users u ON u.id = al.actor_id
           WHERE al.team_id = $1
              AND ($2::text IS NULL OR al.action = $2)
              AND ($3::uuid IS NULL OR al.actor_id = $3::uuid)
              AND ($4::timestamptz IS NULL OR al.created_at >= $4::timestamptz)
              AND ($5::timestamptz IS NULL OR al.created_at <= $5::timestamptz)
              AND ($6::uuid IS NULL OR al.vault_id = $6::uuid)
            ORDER BY al.created_at DESC
            LIMIT $7 OFFSET $8"#,
    )
    .bind(team_id)
    .bind(&params.action)
    .bind(params.actor_id)
    .bind(from_dt)
    .bind(to_dt)
    .bind(params.vault_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch audit logs");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(AuditLogsResponse { logs, total }))
}

// ─── GET /v1/teams/:team_id/audit-logs/export ─────────────────────────────────

pub async fn export_audit_logs(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(team_id): Path<Uuid>,
    Query(params): Query<ExportQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let can_view = has_team_permission(&pool, team_id, auth.0, PERM_VIEW_AUDIT_LOG).await?;
    if !can_view {
        warn!(team_id = %team_id, user_id = %auth.0, "Insufficient permission to export audit logs");
        return Err(StatusCode::FORBIDDEN);
    }

    let from_dt = params
        .from
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let to_dt = params
        .to
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let logs = sqlx::query_as::<_, AuditLogRow>(
        r#"SELECT
               al.id, al.team_id, al.vault_id, al.actor_id,
               u.display_name AS actor_name,
               al.action, al.source, al.target_type, al.target_id, al.target_name,
               al.metadata, al.ip_address::text AS ip_address, al.created_at
           FROM audit_logs al
           JOIN users u ON u.id = al.actor_id
           WHERE al.team_id = $1
              AND ($2::text IS NULL OR al.action = $2)
              AND ($3::uuid IS NULL OR al.actor_id = $3::uuid)
              AND ($4::timestamptz IS NULL OR al.created_at >= $4::timestamptz)
              AND ($5::timestamptz IS NULL OR al.created_at <= $5::timestamptz)
              AND ($6::uuid IS NULL OR al.vault_id = $6::uuid)
            ORDER BY al.created_at DESC"#,
    )
    .bind(team_id)
    .bind(&params.action)
    .bind(params.actor_id)
    .bind(from_dt)
    .bind(to_dt)
    .bind(params.vault_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to export audit logs");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let format = params.format.as_deref().unwrap_or("json");

    match format {
        "csv" => {
            let mut csv = String::from(
                "id,team_id,vault_id,actor_id,actor_name,action,source,target_type,target_id,target_name,ip_address,created_at,metadata\n",
            );
            for log in &logs {
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    log.id,
                    log.team_id,
                    log.vault_id.map(|v| v.to_string()).unwrap_or_default(),
                    log.actor_id,
                    csv_escape(&log.actor_name),
                    log.action,
                    log.source,
                    log.target_type.as_deref().unwrap_or(""),
                    log.target_id.as_deref().unwrap_or(""),
                    csv_escape(log.target_name.as_deref().unwrap_or("")),
                    log.ip_address.as_deref().unwrap_or(""),
                    log.created_at.to_rfc3339(),
                    csv_escape(
                        &log.metadata
                            .as_ref()
                            .map(|m| m.to_string())
                            .unwrap_or_default()
                    ),
                ));
            }
            Ok((
                [
                    (header::CONTENT_TYPE, "text/csv"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"audit-logs.csv\"",
                    ),
                ],
                csv,
            )
                .into_response())
        }
        _ => {
            let body = serde_json::to_string(&logs).map_err(|e| {
                error!(error = %e, "Failed to serialize audit logs");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            Ok((
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"audit-logs.json\"",
                    ),
                ],
                body,
            )
                .into_response())
        }
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ─── POST /v1/teams/:team_id/audit-logs/client ───────────────────────────────

const CLIENT_WHITELIST: &[&str] = &[
    "connection.started",
    "connection.ended",
    "secret.viewed",
    "connection.created",
    "connection.updated",
    "connection.deleted",
    "identity.created",
    "identity.updated",
    "identity.deleted",
    "key.created",
    "key.updated",
    "key.deleted",
    "snippet.created",
    "snippet.updated",
    "snippet.deleted",
    "folder.created",
    "folder.updated",
    "folder.deleted",
    "port_forward.created",
    "port_forward.updated",
    "port_forward.deleted",
];

#[derive(Deserialize)]
pub struct ClientEventRequest {
    pub action: String,
    pub vault_id: Option<Uuid>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub target_name: Option<String>,
    pub metadata: Option<Value>,
    pub occurred_at: String,
}

pub async fn report_client_event(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(limiter): Extension<AuditClientRateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<ClientEventRequest>,
) -> Result<StatusCode, StatusCode> {
    if !CLIENT_WHITELIST.contains(&body.action.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !limiter.0.check(team_id).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let can_connect = has_team_permission(&pool, team_id, auth.0, PERM_CONNECT).await?;
    if !can_connect {
        return Err(StatusCode::FORBIDDEN);
    }

    let occurred_at = DateTime::parse_from_rfc3339(&body.occurred_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let ip_str = addr.ip().to_string();

    sqlx::query(
        r#"INSERT INTO audit_logs
           (team_id, vault_id, actor_id, action, source, target_type, target_id, target_name,
            metadata, ip_address, created_at)
           VALUES ($1, $2, $3, $4, 'client', $5, $6, $7, $8, $9::inet, $10)"#,
    )
    .bind(team_id)
    .bind(body.vault_id)
    .bind(auth.0)
    .bind(&body.action)
    .bind(&body.target_type)
    .bind(&body.target_id)
    .bind(&body.target_name)
    .bind(&body.metadata)
    .bind(&ip_str)
    .bind(occurred_at)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to insert client audit event");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::NO_CONTENT)
}
