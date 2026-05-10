use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::routes::audit::write_audit_event;
use crate::sync_notifier::SyncNotifier;

// ─── Get invitation details (public — no auth required) ───────────────────────

#[derive(Serialize)]
pub struct InvitationDetails {
    pub team_name: String,
    pub inviter_email: String,
    pub role: String,
    pub expires_at: i64,
}

pub async fn get_invitation(
    State(pool): State<PgPool>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<Json<InvitationDetails>, StatusCode> {
    let row = sqlx::query_as::<_, (String, Option<String>, String, chrono::DateTime<chrono::Utc>)>(
        r#"SELECT t.name, u.email, pi.role, pi.expires_at
           FROM pending_invitations pi
           JOIN teams t ON t.id = pi.team_id
           LEFT JOIN users u ON u.id = pi.invited_by
           WHERE pi.token = $1
             AND pi.accepted_at IS NULL
             AND pi.expires_at > now()"#,
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch invitation");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(InvitationDetails {
        team_name: row.0,
        inviter_email: row.1.unwrap_or_else(|| "A teammate".to_string()),
        role: row.2,
        expires_at: row.3.timestamp(),
    }))
}

// ─── Accept invitation (authed) ───────────────────────────────────────────────

pub async fn accept_invitation(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<StatusCode, StatusCode> {
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, String)>(
        r#"SELECT pi.id, pi.team_id, pi.email, pi.role
           FROM pending_invitations pi
           WHERE pi.token = $1
             AND pi.accepted_at IS NULL
             AND pi.expires_at > now()"#,
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch invitation for acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!("Invitation not found or expired: {token}");
        StatusCode::NOT_FOUND
    })?;

    let (invitation_id, team_id, invited_email, role) = row;

    let user_email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch accepting user email");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if user_email.to_lowercase() != invited_email.to_lowercase() {
        warn!(
            user_id = %auth.0,
            user_email = %user_email,
            invited_email = %invited_email,
            "Email mismatch on invitation acceptance"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin transaction for invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Add to team_members (no role column after migration)
    sqlx::query(
        "INSERT INTO team_members (team_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(team_id)
    .bind(auth.0)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to add member on invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Assign the builtin role stored in the invitation
    sqlx::query(
        r#"INSERT INTO team_member_roles (team_id, user_id, role_id)
           SELECT $1, $2, tr.id FROM team_roles tr
           WHERE tr.team_id = $1 AND tr.name = $3 AND tr.is_builtin = TRUE
           ON CONFLICT DO NOTHING"#,
    )
    .bind(team_id)
    .bind(auth.0)
    .bind(&role)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to assign role on invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Mark invitation accepted
    sqlx::query("UPDATE pending_invitations SET accepted_at = now() WHERE id = $1")
        .bind(invitation_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to mark invitation accepted");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(user_id = %auth.0, team_id = %team_id, role = %role, "Invitation accepted");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.joined",
        Some("user"),
        Some(auth.0.to_string()),
        Some(user_email.clone()),
        Some(json!({ "role": role, "via": "invitation" })),
    ));
    notifier.notify_membership_changed(auth.0);
    Ok(StatusCode::NO_CONTENT)
}
