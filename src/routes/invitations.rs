use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::routes::audit::write_audit_event;
use crate::routes::teams::notify_team_members_changed;
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
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── List my pending invitations (in-app consent flow) ────────────────────────

#[derive(Serialize)]
pub struct MyPendingInvitation {
    pub id: Uuid,
    pub team_id: Uuid,
    pub team_name: String,
    pub inviter_email: Option<String>,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_my_pending_invitations(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<Vec<MyPendingInvitation>>, StatusCode> {
    let rows = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>, String, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>(
        r#"SELECT pi.id, pi.team_id, t.name, u.email, pi.role, pi.created_at, pi.expires_at
           FROM pending_invitations pi
           JOIN teams t ON t.id = pi.team_id
           LEFT JOIN users u ON u.id = pi.invited_by
           WHERE pi.user_id = $1
             AND pi.accepted_at IS NULL
             AND pi.expires_at > now()
           ORDER BY pi.created_at DESC"#,
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list pending invitations for user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, team_id, team_name, inviter_email, role, created_at, expires_at)| {
                MyPendingInvitation { id, team_id, team_name, inviter_email, role, created_at, expires_at }
            })
            .collect(),
    ))
}

// ─── Accept my pending invitation ─────────────────────────────────────────────

pub async fn accept_my_pending_invitation(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(invitation_id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let row = sqlx::query_as::<_, (Uuid, String)>(
        r#"SELECT team_id, role FROM pending_invitations
           WHERE id = $1 AND user_id = $2
             AND accepted_at IS NULL AND expires_at > now()"#,
    )
    .bind(invitation_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch pending invitation for acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!(invitation_id = %invitation_id, user_id = %auth.0, "Pending invitation not found");
        StatusCode::NOT_FOUND
    })?;

    let (team_id, role) = row;

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin transaction for invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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

    let user_email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();

    info!(user_id = %auth.0, team_id = %team_id, role = %role, "Pending invitation accepted in-app");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.joined",
        Some("user"),
        Some(auth.0.to_string()),
        user_email,
        Some(json!({ "role": role, "via": "in_app_invite" })),
    ));
    notifier.notify_membership_changed(auth.0);
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Decline my pending invitation ────────────────────────────────────────────

pub async fn decline_my_pending_invitation(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(invitation_id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let team_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT team_id FROM pending_invitations WHERE id = $1 AND user_id = $2 AND accepted_at IS NULL",
    )
    .bind(invitation_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch pending invitation for decline");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!(invitation_id = %invitation_id, user_id = %auth.0, "Pending invitation not found for decline");
        StatusCode::NOT_FOUND
    })?;

    sqlx::query("DELETE FROM pending_invitations WHERE id = $1")
        .bind(invitation_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to delete declined invitation");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(user_id = %auth.0, team_id = %team_id, "Pending invitation declined");
    // Notify team so the inviter's pending list refreshes
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}
