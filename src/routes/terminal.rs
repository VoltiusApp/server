use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::{jwt::validate_token, AuthClaims, AuthUser};
use crate::terminal_manager::{Participant, TerminalManager, BROADCAST_CAPACITY};

/// Tier the given account is entitled to right now, with expired trials counted
/// as `free`. Falls back to `free` if the row can't be read.
async fn owner_effective_tier(pool: &PgPool, user_id: Uuid) -> String {
    match sqlx::query_as::<_, (String, Option<chrono::DateTime<Utc>>, bool, Option<String>)>(
        "SELECT subscription_tier, trial_ends_at, admin_override, ls_subscription_id FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    {
        Ok((tier, trial_ends_at, admin_override, ls_subscription_id)) => {
            crate::entitlement::effective_tier(
                &tier,
                trial_ends_at,
                ls_subscription_id.is_some(),
                admin_override,
                Utc::now(),
            )
            .to_string()
        }
        Err(_) => "free".to_string(),
    }
}

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    /// Vaults whose members can join (multi-vault support).
    /// Required for visibility="vault"; unused for visibility="invite_link"/"direct".
    #[serde(default)]
    pub vault_ids: Vec<Uuid>,
    pub connection_name: String,
    /// "vault" (default) | "invite_link" | "direct"
    pub visibility: Option<String>,
    /// Per-user wrapped session keys (E2EE) — used for vault sessions.
    #[serde(default)]
    pub participant_keys: Vec<ParticipantKeyEntry>,
    /// Raw session key bytes (base64) — used for invite_link sessions (no per-user E2EE).
    pub session_key_bytes: Option<String>,
    /// Role filter — if non-empty, only members with one of these roles can join.
    /// Values: "owner" | "manager" | "editor" | "member". Empty = all roles.
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    /// Named teammates granted access individually (visibility "direct", or
    /// alongside a vault share). Each entry carries that user's wrapped key.
    #[serde(default)]
    pub invitees: Vec<ParticipantKeyEntry>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ParticipantKeyEntry {
    pub user_id: Uuid,
    pub wrapped_key: String,
}

#[derive(Serialize)]
pub struct CreateSessionResponse {
    pub session_id: Uuid,
    /// Only set for invite_link sessions.
    pub invite_token: Option<String>,
}

#[derive(Serialize)]
pub struct ActiveSession {
    pub id: Uuid,
    pub connection_name: String,
    pub host_user_id: Uuid,
    pub host_public_key: String,
    pub visibility: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub participant_count: i64,
    pub participants: Vec<Participant>,
    /// Team IDs (= vault IDs on the client) this session is shared with.
    /// Empty for invite_link sessions.
    pub vault_ids: Vec<Uuid>,
    /// Set when the caller reaches this session through an individual grant
    /// (#66) rather than a vault share — names who invited them.
    pub invited_by: Option<Uuid>,
}

#[derive(Serialize)]
pub struct SessionKeyResponse {
    /// Set for vault sessions: wrapped with recipient's X25519 key.
    pub wrapped_key: Option<String>,
    /// Set for invite_link sessions: raw key bytes (base64), no E2EE.
    pub raw_key: Option<String>,
    pub host_public_key: String,
}

/// True when the two users are members of at least one team in common.
pub(crate) async fn shares_a_team(pool: &PgPool, a: Uuid, b: Uuid) -> Result<bool, StatusCode> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(\
           SELECT 1 FROM team_members ma \
           JOIN team_members mb ON mb.team_id = ma.team_id \
           WHERE ma.user_id = $1 AND mb.user_id = $2)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to check shared team membership");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Grants one named user access to a session: the durable row, the wrapped key,
/// the in-memory authorization set, and the push. The single grant path — both
/// `create_session` with visibility "direct" and the invitees endpoint call it.
pub(crate) async fn grant_invitee(
    pool: &PgPool,
    notifier: &crate::sync_notifier::SyncNotifier,
    manager: &TerminalManager,
    session_id: Uuid,
    host_user_id: Uuid,
    user_id: Uuid,
    wrapped_key: &str,
) -> Result<(), StatusCode> {
    // A direct session has no vault, so none of the vault permission checks
    // apply to it. Without this the host could grant an arbitrary user id.
    if user_id != host_user_id && !shares_a_team(pool, host_user_id, user_id).await? {
        warn!(host = %host_user_id, invitee = %user_id, "Invite rejected: not a teammate");
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query(
        "INSERT INTO terminal_session_invitees (session_id, user_id, invited_by) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(host_user_id)
    .execute(pool)
    .await
    .map_err(|e| {
        error!(error = %e, session_id = %session_id, "Failed to insert session invitee");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        "INSERT INTO terminal_session_keys (session_id, user_id, wrapped_key) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(wrapped_key)
    .execute(pool)
    .await
    .map_err(|e| {
        error!(error = %e, session_id = %session_id, "Failed to insert invitee session key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some(state) = manager.sessions.lock().await.get_mut(&session_id) {
        state.invitees.insert(user_id);
    }

    notifier.notify_session_shared(user_id, session_id, host_user_id);
    Ok(())
}

/// Concurrent-session cap for a host billed on their own plan — `invite_link`
/// and `direct` sessions, which have no vault owner to bill against.
/// `None` means the tier may not host at all.
fn host_tier_session_limit(tier: &str) -> Option<i64> {
    match tier {
        "business" => Some(20),
        "teams" => Some(5),
        "pro" => Some(1),
        _ => None,
    }
}

// ─── Create terminal session ──────────────────────────────────────────────────

pub async fn create_session(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(auth_claims): Extension<AuthClaims>,
    Extension(manager): Extension<TerminalManager>,
    Extension(notifier): Extension<crate::sync_notifier::SyncNotifier>,
    Json(body): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<CreateSessionResponse>), StatusCode> {
    let visibility = body.visibility.as_deref().unwrap_or("vault").to_string();

    let mut vault_owner_id: Option<Uuid> = None;

    // For vault sessions: verify the host is a member of at least one vault
    if visibility == "vault" {
        if body.vault_ids.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let member_of_any = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = ANY($1) AND user_id = $2)",
        )
        .bind(&body.vault_ids)
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to check vault membership");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if !member_of_any {
            return Err(StatusCode::FORBIDDEN);
        }

        // Check START_TERMINAL_SESSION permission (custom roles may restrict this)
        let can_start = crate::permissions::has_any_team_permission(
            &pool, &body.vault_ids, auth.0, crate::permissions::PERM_START_TERMINAL_SESSION,
        )
        .await?;
        if !can_start {
            warn!(user_id = %auth.0, "Insufficient permission to start terminal session");
            return Err(StatusCode::FORBIDDEN);
        }

        // Tier check: pick the highest-tier owner across all requested vaults
        let row = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT t.owner_id, u.subscription_tier \
             FROM teams t JOIN users u ON u.id = t.owner_id \
             WHERE t.id = ANY($1) \
             ORDER BY CASE u.subscription_tier \
               WHEN 'business' THEN 0 WHEN 'teams' THEN 1 ELSE 2 END \
             LIMIT 1",
        )
        .bind(&body.vault_ids)
        .fetch_one(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let (owner_id, owner_tier) = row;
        vault_owner_id = Some(owner_id);

        let session_limit: i64 = match owner_tier.as_str() {
            "business" => 20,
            "teams"    => 5,
            _          => return Err(StatusCode::PAYMENT_REQUIRED),
        };

        let active_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT ts.id) \
             FROM terminal_sessions ts \
             JOIN terminal_session_vaults tsv ON tsv.session_id = ts.id \
             JOIN teams t ON t.id = tsv.team_id \
             WHERE t.owner_id = $1 AND ts.ended_at IS NULL",
        )
        .bind(owner_id)
        .fetch_one(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if active_count >= session_limit {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    } else {
        // invite_link and direct visibility: gate on the host's own JWT tier
        if visibility == "direct" && body.invitees.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }

        let session_limit = host_tier_session_limit(auth_claims.0.tier.as_str())
            .ok_or(StatusCode::PAYMENT_REQUIRED)?;

        let active_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM terminal_sessions \
             WHERE host_user_id = $1 AND ended_at IS NULL",
        )
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if active_count >= session_limit {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Generate invite token for invite_link sessions
    let invite_token: Option<String> = if visibility == "invite_link" {
        Some(Uuid::new_v4().to_string().replace('-', ""))
    } else {
        None
    };

    // Insert session record
    let session_id = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO terminal_sessions
           (host_user_id, connection_name, visibility, session_key_bytes, allowed_roles, invite_token)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id"#,
    )
    .bind(auth.0)
    .bind(&body.connection_name)
    .bind(&visibility)
    .bind(&body.session_key_bytes)
    .bind(&body.allowed_roles)
    .bind(&invite_token)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to insert terminal session");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Insert vault associations
    for vault_id in &body.vault_ids {
        sqlx::query(
            "INSERT INTO terminal_session_vaults (session_id, team_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(session_id)
        .bind(vault_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, session_id = %session_id, vault_id = %vault_id, "Failed to insert session vault");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Insert wrapped keys for vault participants (E2EE)
    for entry in &body.participant_keys {
        sqlx::query(
            "INSERT INTO terminal_session_keys (session_id, user_id, wrapped_key) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(session_id)
        .bind(entry.user_id)
        .bind(&entry.wrapped_key)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, session_id = %session_id, "Failed to insert session key");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Notified last: a recipient acting on the push before its wrapped key row
    // lands gets a 404 from get_my_session_key.
    if !body.vault_ids.is_empty() {
        crate::sync_notifier::notify_team_members(&pool, &body.vault_ids, auth.0, |recipient| {
            notifier.notify_session_shared(recipient, session_id, auth.0);
        })
        .await;
    }

    // Get host public key
    let host_public_key = sqlx::query_scalar::<_, String>("SELECT public_key FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get host public key");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Create in-memory session state
    let (tx, _) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);
    {
        let mut sessions = manager.sessions.lock().await;
        sessions.insert(
            session_id,
            crate::terminal_manager::SessionState {
                vault_ids: body.vault_ids.clone(),
                allowed_roles: body.allowed_roles.clone(),
                invite_token: invite_token.clone(),
                invitees: std::collections::HashSet::new(),
                host_user_id: auth.0,
                host_public_key,
                visibility: visibility.clone(),
                vault_owner_id,
                participants: std::collections::HashMap::new(),
                control_holder: auth.0,
                pending_control_request: None,
                tx,
                output_history: std::collections::VecDeque::new(),
            },
        );
    }

    // Named invitees: after the in-memory session state exists (grant_invitee
    // fills its invitees set) and last, so a recipient acting on the push
    // before their wrapped key row lands gets a 404 from get_my_session_key.
    for entry in &body.invitees {
        grant_invitee(
            &pool,
            &notifier,
            &manager,
            session_id,
            auth.0,
            entry.user_id,
            &entry.wrapped_key,
        )
        .await?;
    }

    info!(session_id = %session_id, visibility = %visibility, vault_count = body.vault_ids.len(), "Terminal session created");
    Ok((StatusCode::CREATED, Json(CreateSessionResponse { session_id, invite_token })))
}

// ─── List active sessions (vault sessions the user is part of) ────────────────

type VisibleSessionRow = (
    Uuid,
    String,
    Uuid,
    String,
    chrono::DateTime<Utc>,
    Vec<Uuid>,
    Option<Uuid>,
);

/// Sessions `user_id` may see: their own, ones they hold an individual grant
/// (#66) on, and vault sessions shared with a team they belong to (respecting
/// the role filter if set). Invite-link sessions are reachable only via the
/// link, never listed here.
async fn visible_sessions(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<VisibleSessionRow>, StatusCode> {
    sqlx::query_as::<_, VisibleSessionRow>(
        r#"
        SELECT
            ts.id,
            ts.connection_name,
            ts.host_user_id,
            ts.visibility,
            ts.created_at,
            COALESCE(
                (SELECT array_agg(tsv.team_id) FROM terminal_session_vaults tsv WHERE tsv.session_id = ts.id),
                ARRAY[]::uuid[]
            ) AS vault_ids,
            (SELECT tsi.invited_by FROM terminal_session_invitees tsi
              WHERE tsi.session_id = ts.id AND tsi.user_id = $1) AS invited_by
        FROM terminal_sessions ts
        WHERE ts.ended_at IS NULL
          AND (
            ts.host_user_id = $1
            OR EXISTS (SELECT 1 FROM terminal_session_invitees tsi
                        WHERE tsi.session_id = ts.id AND tsi.user_id = $1)
            OR (
              ts.visibility = 'vault'
              AND EXISTS (
                SELECT 1
                FROM terminal_session_vaults tsv
                JOIN team_members tm ON tm.team_id = tsv.team_id AND tm.user_id = $1
                WHERE tsv.session_id = ts.id
                  AND EXISTS (
                    SELECT 1
                    FROM team_member_roles tmr_perm
                    JOIN team_roles tr_perm ON tr_perm.id = tmr_perm.role_id
                    WHERE tmr_perm.team_id = tsv.team_id
                      AND tmr_perm.user_id = $1
                      AND (tr_perm.permissions & $2) != 0
                  )
                  AND (
                    array_length(ts.allowed_roles, 1) IS NULL
                    OR cardinality(ts.allowed_roles) = 0
                    OR EXISTS (
                      SELECT 1
                      FROM team_member_roles tmr
                      JOIN team_roles tr ON tr.id = tmr.role_id
                      WHERE tmr.team_id = tsv.team_id
                        AND tmr.user_id = $1
                        AND tr.name = ANY(ts.allowed_roles)
                    )
                  )
              )
            )
          )
        ORDER BY ts.created_at DESC
        "#,
    )
    .bind(user_id)
    .bind(crate::permissions::PERM_VIEW_TERMINAL_SESSIONS)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list active sessions");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

pub async fn list_active_sessions(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(manager): Extension<TerminalManager>,
) -> Result<Json<Vec<ActiveSession>>, StatusCode> {
    let rows = visible_sessions(&pool, auth.0).await?;

    let sessions_lock = manager.sessions.lock().await;
    let result = rows
        .into_iter()
        .filter(|(id, ..)| sessions_lock.contains_key(id))
        .map(
            |(id, connection_name, host_user_id, visibility, created_at, vault_ids, invited_by)| {
                let (participant_count, participants, host_public_key) = sessions_lock
                    .get(&id)
                    .map(|s| {
                        let ps: Vec<Participant> = s.participants.values().cloned().collect();
                        (ps.len() as i64, ps, s.host_public_key.clone())
                    })
                    .unwrap_or_default();
                ActiveSession {
                    id,
                    connection_name,
                    host_user_id,
                    host_public_key,
                    visibility,
                    created_at,
                    participant_count,
                    participants,
                    vault_ids,
                    invited_by,
                }
            },
        )
        .collect();

    Ok(Json(result))
}

// ─── Get my session key ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GetKeyQuery {
    pub invite_token: Option<String>,
}

pub async fn get_my_session_key(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Path(session_id): Path<Uuid>,
    Query(query): Query<GetKeyQuery>,
) -> Result<Json<SessionKeyResponse>, StatusCode> {
    // First try a wrapped key entry (vault sessions with per-user E2EE wrapping)
    let wrapped = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT tsk.wrapped_key, u.public_key
        FROM terminal_session_keys tsk
        JOIN terminal_sessions ts ON ts.id = tsk.session_id
        JOIN users u ON u.id = ts.host_user_id
        WHERE tsk.session_id = $1 AND tsk.user_id = $2
          AND ts.ended_at IS NULL
        "#,
    )
    .bind(session_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to get wrapped session key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some((wrapped_key, host_public_key)) = wrapped {
        return Ok(Json(SessionKeyResponse {
            wrapped_key: Some(wrapped_key),
            raw_key: None,
            host_public_key,
        }));
    }

    // Invite link session: validate token, return raw key
    if let Some(token) = &query.invite_token {
        let row = sqlx::query_as::<_, (Option<String>, String, Option<String>)>(
            r#"
            SELECT ts.session_key_bytes, u.public_key, ts.invite_token
            FROM terminal_sessions ts
            JOIN users u ON u.id = ts.host_user_id
            WHERE ts.id = $1 AND ts.visibility = 'invite_link' AND ts.ended_at IS NULL
            "#,
        )
        .bind(session_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get invite_link session key");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

        let (session_key_bytes, host_public_key, stored_token) = row;

        if stored_token.as_deref() != Some(token.as_str()) {
            return Err(StatusCode::FORBIDDEN);
        }

        let raw_key = session_key_bytes.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok(Json(SessionKeyResponse {
            wrapped_key: None,
            raw_key: Some(raw_key),
            host_public_key,
        }));
    }

    Err(StatusCode::NOT_FOUND)
}

/// Confirms `caller` is the host of a still-active session, or fails with the
/// status the caller should return: `NOT_FOUND` if the session doesn't exist
/// or has already ended, `FORBIDDEN` if `caller` isn't its host. Shared by
/// `end_session` and `invite_to_session` — both gate on exactly this check.
async fn require_active_session_host(
    pool: &PgPool,
    session_id: Uuid,
    caller: Uuid,
) -> Result<(), StatusCode> {
    let host_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT host_user_id FROM terminal_sessions WHERE id = $1 AND ended_at IS NULL",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to get session host");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if host_id != caller {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(())
}

// ─── End session ─────────────────────────────────────────────────────────────

/// Everyone who should be told this session ended: team members of its vaults
/// plus individually invited users, minus the host.
async fn session_end_recipients(
    pool: &PgPool,
    session_id: Uuid,
    host_user_id: Uuid,
) -> Result<Vec<Uuid>, StatusCode> {
    let team_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT team_id FROM terminal_session_vaults WHERE session_id = $1")
            .bind(session_id)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to load session vault teams");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    let mut recipients = std::collections::HashSet::new();
    crate::sync_notifier::notify_team_members(pool, &team_ids, host_user_id, |member_id| {
        recipients.insert(member_id);
    })
    .await;

    let invitee_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM terminal_session_invitees WHERE session_id = $1")
            .bind(session_id)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to load session invitees");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    recipients.extend(invitee_ids);
    recipients.remove(&host_user_id);

    Ok(recipients.into_iter().collect())
}

pub async fn end_session(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(manager): Extension<TerminalManager>,
    Extension(notifier): Extension<crate::sync_notifier::SyncNotifier>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    require_active_session_host(&pool, session_id, auth.0).await?;

    sqlx::query("UPDATE terminal_sessions SET ended_at = now() WHERE id = $1")
        .bind(session_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to end session in DB");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    {
        let mut sessions = manager.sessions.lock().await;
        if let Some(state) = sessions.remove(&session_id) {
            let _ = state.tx.send(r#"{"type":"session_ended"}"#.to_string());
        }
    }

    let recipients = session_end_recipients(&pool, session_id, auth.0).await?;
    for recipient in recipients {
        notifier.notify_session_ended(recipient, session_id);
    }

    info!(session_id = %session_id, "Terminal session ended");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Invite a teammate directly ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct InviteToSessionRequest {
    pub user_id: Uuid,
    pub wrapped_key: String,
}

pub async fn invite_to_session(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(manager): Extension<TerminalManager>,
    Extension(notifier): Extension<crate::sync_notifier::SyncNotifier>,
    Path(session_id): Path<Uuid>,
    Json(body): Json<InviteToSessionRequest>,
) -> Result<StatusCode, StatusCode> {
    require_active_session_host(&pool, session_id, auth.0).await?;

    grant_invitee(
        &pool,
        &notifier,
        &manager,
        session_id,
        auth.0,
        body.user_id,
        &body.wrapped_key,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── WebSocket handler ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: String,
    pub display_name: Option<String>,
    /// Required when joining invite_link sessions
    pub invite_token: Option<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(session_id): Path<Uuid>,
    Query(query): Query<WsQuery>,
    State(pool): State<PgPool>,
    Extension(manager): Extension<TerminalManager>,
) -> impl IntoResponse {
    let user_id = match validate_token(&query.token, "access") {
        Ok(claims) => claims.sub,
        Err(_) => {
            warn!(session_id = %session_id, "WS upgrade rejected: invalid token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let display_name = query
        .display_name
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| user_id.to_string());

    ws.on_upgrade(move |socket| {
        handle_socket(socket, session_id, user_id, display_name, query.invite_token, pool, manager)
    })
}

#[allow(clippy::too_many_arguments)]
async fn is_authorized_participant(
    pool: &PgPool,
    user_id: Uuid,
    host_user_id: Uuid,
    visibility: &str,
    vault_ids: &[Uuid],
    allowed_roles: &[String],
    stored_token: Option<&str>,
    presented_token: Option<&str>,
    invitees: &std::collections::HashSet<Uuid>,
) -> bool {
    if user_id == host_user_id {
        return true;
    }
    if invitees.contains(&user_id) {
        return true;
    }
    if visibility == "invite_link" {
        // Invite link: validate token
        return presented_token.is_some() && presented_token == stored_token;
    }
    // Vault session: user must be a member of one of the session's vaults,
    // satisfy the role filter (if any), and have JOIN_TERMINAL_SESSION permission.
    if vault_ids.is_empty() {
        return false;
    }
    let is_member = if allowed_roles.is_empty() {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = ANY($1) AND user_id = $2)",
        )
        .bind(vault_ids)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap_or(false)
    } else {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(\
              SELECT 1 FROM team_members tm \
              JOIN team_member_roles tmr ON tmr.team_id = tm.team_id AND tmr.user_id = tm.user_id \
              JOIN team_roles tr ON tr.id = tmr.role_id \
              WHERE tm.team_id = ANY($1) AND tm.user_id = $2 AND tr.name = ANY($3)\
            )",
        )
        .bind(vault_ids)
        .bind(user_id)
        .bind(allowed_roles)
        .fetch_one(pool)
        .await
        .unwrap_or(false)
    };
    is_member
        && crate::permissions::has_any_team_permission(
            pool,
            vault_ids,
            user_id,
            crate::permissions::PERM_JOIN_TERMINAL_SESSION,
        )
        .await
        .unwrap_or(false)
}

async fn handle_socket(
    socket: WebSocket,
    session_id: Uuid,
    user_id: Uuid,
    display_name: String,
    invite_token: Option<String>,
    pool: PgPool,
    manager: TerminalManager,
) {
    // Fetch session state from in-memory manager
    let session_info = {
        let sessions = manager.sessions.lock().await;
        sessions.get(&session_id).map(|s| {
            (
                s.vault_ids.clone(),
                s.visibility.clone(),
                s.allowed_roles.clone(),
                s.invite_token.clone(),
                s.host_user_id,
                s.vault_owner_id,
                s.invitees.clone(),
            )
        })
    };

    let (
        vault_ids,
        visibility,
        allowed_roles,
        stored_token,
        host_user_id,
        vault_owner_id,
        invitees,
    ) = match session_info {
        Some(info) => info,
        None => {
            warn!(session_id = %session_id, user_id = %user_id, "WS: session not found");
            return;
        }
    };

    let authorized = is_authorized_participant(
        &pool,
        user_id,
        host_user_id,
        &visibility,
        &vault_ids,
        &allowed_roles,
        stored_token.as_deref(),
        invite_token.as_deref(),
        &invitees,
    )
    .await;

    if !authorized {
        warn!(session_id = %session_id, user_id = %user_id, "WS: unauthorized user rejected");
        return;
    }

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Participant cap: guests only (host is always allowed)
    if user_id != host_user_id {
        let tier_owner = vault_owner_id.unwrap_or(host_user_id);
        let effective_tier = owner_effective_tier(&pool, tier_owner).await;

        let guest_cap: usize = match effective_tier.as_str() {
            "business" => 50,
            "teams"    => 10,
            "pro"      => 1,
            _          => 0,
        };

        let current_guests = {
            let sessions = manager.sessions.lock().await;
            sessions.get(&session_id).map(|s| {
                s.participants.values().filter(|p| p.user_id != host_user_id).count()
            }).unwrap_or(0)
        };

        if current_guests >= guest_cap {
            warn!(session_id = %session_id, user_id = %user_id, guest_cap, "Participant cap reached");
            return;
        }
    }

    let (tx, participant_list_json) = {
        let mut sessions = manager.sessions.lock().await;
        let state = match sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return,
        };

        state.participants.insert(
            user_id,
            Participant {
                user_id,
                display_name: display_name.clone(),
            },
        );

        let participant_list: Vec<&Participant> = state.participants.values().collect();
        let list_json = serde_json::json!({
            "type": "participant_list",
            "participants": participant_list
        })
        .to_string();

        let tx = state.tx.clone();
        (tx, list_json)
    };

    // Subscribe before anything else so live messages buffer while we replay history.
    let mut rx = tx.subscribe();

    // Grab history snapshot under the lock, then release before any async sends.
    let history_snapshot: Vec<String> = {
        let sessions = manager.sessions.lock().await;
        sessions
            .get(&session_id)
            .map(|s| s.output_history.iter().cloned().collect())
            .unwrap_or_default()
    };

    if ws_sender
        .send(Message::Text(participant_list_json.clone()))
        .await
        .is_err()
    {
        cleanup_participant(&manager, session_id, user_id, &tx, &pool).await;
        return;
    }

    // Replay terminal history so the new joiner sees what happened before they joined.
    for msg in history_snapshot {
        if ws_sender.send(Message::Text(msg)).await.is_err() {
            cleanup_participant(&manager, session_id, user_id, &tx, &pool).await;
            return;
        }
    }

    let joined_msg = serde_json::json!({
        "type": "participant_joined",
        "user_id": user_id,
        "display_name": display_name,
    })
    .to_string();
    let _ = tx.send(joined_msg);

    info!(session_id = %session_id, user_id = %user_id, "WS participant joined");

    let send_task = {
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(msg) => {
                        if ws_sender.send(Message::Text(msg)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(session_id = %session_id, user_id = %user_id, lagged = n, "WS broadcast lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    };

    while let Some(Ok(msg)) = ws_receiver.next().await {
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            Message::Ping(p) => {
                let _ = p;
                continue;
            }
            _ => continue,
        };

        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };

        let msg_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match msg_type {
            "output" | "input" => {
                let relay = serde_json::json!({
                    "type": msg_type,
                    "from": user_id,
                    "data": parsed.get("data"),
                })
                .to_string();

                // Keep a rolling history of output messages for late-join replay.
                // Input messages are not replayed — only rendered output matters.
                if msg_type == "output" {
                    let mut sessions = manager.sessions.lock().await;
                    if let Some(state) = sessions.get_mut(&session_id) {
                        if state.output_history.len() >= crate::terminal_manager::OUTPUT_HISTORY_MAX {
                            state.output_history.pop_front();
                        }
                        state.output_history.push_back(relay.clone());
                    }
                }

                let _ = tx.send(relay);
            }

            "request_control" => {
                let mut sessions = manager.sessions.lock().await;
                if let Some(state) = sessions.get_mut(&session_id) {
                    if state.control_holder != user_id {
                        state.pending_control_request = Some(user_id);
                        let update = serde_json::json!({
                            "type": "control_update",
                            "holder": state.control_holder,
                            "requester": user_id,
                        })
                        .to_string();
                        let _ = state.tx.send(update);
                    }
                }
            }

            "grant_control" => {
                let mut sessions = manager.sessions.lock().await;
                if let Some(state) = sessions.get_mut(&session_id) {
                    if state.host_user_id == user_id {
                        if let Some(target) = parsed
                            .get("target_user_id")
                            .and_then(|v| v.as_str())
                            .and_then(|s| Uuid::parse_str(s).ok())
                        {
                            state.control_holder = target;
                            state.pending_control_request = None;
                            let update = serde_json::json!({
                                "type": "control_update",
                                "holder": target,
                                "requester": serde_json::Value::Null,
                            })
                            .to_string();
                            let _ = state.tx.send(update);
                        }
                    }
                }
            }

            "revoke_control" => {
                let mut sessions = manager.sessions.lock().await;
                if let Some(state) = sessions.get_mut(&session_id) {
                    if state.host_user_id == user_id {
                        state.control_holder = state.host_user_id;
                        state.pending_control_request = None;
                        let update = serde_json::json!({
                            "type": "control_update",
                            "holder": state.host_user_id,
                            "requester": serde_json::Value::Null,
                        })
                        .to_string();
                        let _ = state.tx.send(update);
                    }
                }
            }

            _ => {}
        }
    }

    send_task.abort();
    cleanup_participant(&manager, session_id, user_id, &tx, &pool).await;
    info!(session_id = %session_id, user_id = %user_id, "WS participant left");
}

async fn cleanup_participant(
    manager: &TerminalManager,
    session_id: Uuid,
    user_id: Uuid,
    tx: &tokio::sync::broadcast::Sender<String>,
    pool: &PgPool,
) {
    let is_host = {
        let mut sessions = manager.sessions.lock().await;
        if let Some(state) = sessions.get_mut(&session_id) {
            let host = state.host_user_id == user_id;
            if !host {
                state.participants.remove(&user_id);
                if state.control_holder == user_id {
                    state.control_holder = state.host_user_id;
                    let update = serde_json::json!({
                        "type": "control_update",
                        "holder": state.host_user_id,
                        "requester": serde_json::Value::Null,
                    })
                    .to_string();
                    let _ = state.tx.send(update);
                }
            }
            host
        } else {
            false
        }
    };

    if is_host {
        // Host disconnected: end the session entirely
        if let Err(e) = sqlx::query(
            "UPDATE terminal_sessions SET ended_at = now() WHERE id = $1 AND ended_at IS NULL",
        )
        .bind(session_id)
        .execute(pool)
        .await
        {
            error!(error = %e, session_id = %session_id, "Failed to mark session ended on host disconnect");
        }

        let mut sessions = manager.sessions.lock().await;
        if let Some(state) = sessions.remove(&session_id) {
            let _ = state.tx.send(r#"{"type":"session_ended"}"#.to_string());
        }

        info!(session_id = %session_id, "Session ended: host disconnected");
    } else {
        let left_msg = serde_json::json!({
            "type": "participant_left",
            "user_id": user_id,
        })
        .to_string();
        let _ = tx.send(left_msg);
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;
    use crate::auth::jwt::Claims;
    use crate::auth::{AuthClaims, AuthUser};
    use crate::permissions::PERM_CONNECT;
    use crate::sync_notifier::SyncNotifier;
    use crate::terminal_manager::TerminalManager;
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, member_with_role, seed_team, seed_user};
    use axum::extract::State;
    use axum::{Extension, Json};

    fn claims_for(user: uuid::Uuid) -> AuthClaims {
        AuthClaims(Claims {
            sub: user,
            exp: 0,
            iat: 0,
            kind: "access".to_string(),
            tier: "business".to_string(),
            trial_ends_at: None,
            trial_used: false,
            is_admin: false,
            is_banned: false,
            email_verified: true,
        })
    }

    // `CreateSessionRequest` derives only `Deserialize` — no `Default` — so every
    // field is enumerated explicitly here.
    fn session_request(
        vault_ids: Vec<uuid::Uuid>,
        visibility: &str,
        invitees: Vec<ParticipantKeyEntry>,
    ) -> CreateSessionRequest {
        CreateSessionRequest {
            vault_ids,
            connection_name: "box".to_string(),
            visibility: Some(visibility.to_string()),
            participant_keys: Vec::new(),
            session_key_bytes: None,
            allowed_roles: Vec::new(),
            invitees,
        }
    }

    fn vault_session_request(vault_ids: Vec<uuid::Uuid>) -> CreateSessionRequest {
        session_request(vault_ids, "vault", Vec::new())
    }

    fn direct_session_request(invitees: Vec<ParticipantKeyEntry>) -> CreateSessionRequest {
        session_request(Vec::new(), "direct", invitees)
    }

    #[tokio::test]
    async fn create_session_forbidden_for_non_member_of_vault() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let outsider = seed_user(&pool).await; // not a member of `team`

        let res = create_session(
            State(pool.clone()),
            Extension(AuthUser(outsider)),
            Extension(claims_for(outsider)),
            Extension(TerminalManager::new()),
            Extension(SyncNotifier::new()),
            Json(vault_session_request(vec![team])),
        )
        .await;

        // `Ok` is `(StatusCode, Json<CreateSessionResponse>)`, which isn't `Debug`
        // (`CreateSessionResponse` derives only `Serialize`) — `unwrap_err()`
        // doesn't compile here, so match on the `Err` variant directly.
        assert!(matches!(res, Err(axum::http::StatusCode::FORBIDDEN)));
    }

    #[tokio::test]
    async fn create_session_forbidden_without_start_permission() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        // Member of the vault but only CONNECT — not START_TERMINAL_SESSION.
        let caller = member_with_role(&pool, team, PERM_CONNECT).await;

        let res = create_session(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(claims_for(caller)),
            Extension(TerminalManager::new()),
            Extension(SyncNotifier::new()),
            Json(vault_session_request(vec![team])),
        )
        .await;

        assert!(matches!(res, Err(axum::http::StatusCode::FORBIDDEN)));
    }

    #[tokio::test]
    async fn create_session_direct_grants_invitee_and_populates_in_memory_state() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_member(&pool, team, host).await;
        add_member(&pool, team, mate).await;

        let manager = TerminalManager::new();
        let entry = ParticipantKeyEntry {
            user_id: mate,
            wrapped_key: "wrapped".to_string(),
        };

        let res = create_session(
            State(pool.clone()),
            Extension(AuthUser(host)),
            Extension(claims_for(host)),
            Extension(manager.clone()),
            Extension(SyncNotifier::new()),
            Json(direct_session_request(vec![entry])),
        )
        .await;

        let (status, Json(body)) = res.expect("direct session with an invitee must be created");
        assert_eq!(status, axum::http::StatusCode::CREATED);

        let sessions = manager.sessions.lock().await;
        let state = sessions
            .get(&body.session_id)
            .expect("session must be in memory");
        assert!(state.invitees.contains(&mate));
        drop(sessions);

        let grants: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2",
        )
        .bind(body.session_id)
        .bind(mate)
        .fetch_one(&pool)
        .await
        .unwrap();
        let keys: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_keys WHERE session_id = $1 AND user_id = $2",
        )
        .bind(body.session_id)
        .bind(mate)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((grants, keys), (1, 1));
    }

    #[tokio::test]
    async fn create_session_direct_rejects_empty_invitees() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;

        let res = create_session(
            State(pool.clone()),
            Extension(AuthUser(host)),
            Extension(claims_for(host)),
            Extension(TerminalManager::new()),
            Extension(SyncNotifier::new()),
            Json(direct_session_request(Vec::new())),
        )
        .await;

        assert!(matches!(res, Err(axum::http::StatusCode::BAD_REQUEST)));
    }

    #[tokio::test]
    async fn end_session_forbidden_for_non_host() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        // Seed a live terminal session hosted by `host`. `terminal_sessions` has
        // no `vault_ids` column (that lives in `terminal_session_vaults`); the
        // only NOT-NULL columns without a default are `host_user_id` and
        // `connection_name` — `visibility`/`allowed_roles`/`created_at` all
        // default. `end_session` only reads `host_user_id`, so no vault
        // association is needed for this test.
        let session_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO terminal_sessions (id, host_user_id, connection_name)
             VALUES ($1, $2, 'box')",
        )
        .bind(session_id)
        .bind(host)
        .execute(&pool)
        .await
        .expect("seed terminal session");

        let attacker = seed_user(&pool).await;

        let res = end_session(
            State(pool.clone()),
            Extension(AuthUser(attacker)),
            Extension(TerminalManager::new()),
            Extension(SyncNotifier::new()),
            axum::extract::Path(session_id),
        )
        .await;

        assert_eq!(res.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, seed_team, seed_user};

    async fn seed_session(pool: &PgPool, host: Uuid, visibility: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO terminal_sessions (host_user_id, connection_name, visibility) \
             VALUES ($1, 'web-prod', $2) RETURNING id",
        )
        .bind(host)
        .bind(visibility)
        .fetch_one(pool)
        .await
        .expect("insert session")
    }

    #[test]
    fn host_tier_session_limits_match_the_shipped_gate() {
        assert_eq!(host_tier_session_limit("business"), Some(20));
        assert_eq!(host_tier_session_limit("teams"), Some(5));
        assert_eq!(host_tier_session_limit("pro"), Some(1));
        assert_eq!(host_tier_session_limit("free"), None);
    }

    #[tokio::test]
    async fn shares_a_team_is_true_only_for_a_common_team() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let stranger = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_member(&pool, team, host).await;
        add_member(&pool, team, mate).await;

        assert!(shares_a_team(&pool, host, mate).await.unwrap());
        assert!(!shares_a_team(&pool, host, stranger).await.unwrap());
    }

    #[tokio::test]
    async fn grant_invitee_is_idempotent_and_inserts_both_rows() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_member(&pool, team, host).await;
        add_member(&pool, team, mate).await;
        let session_id = seed_session(&pool, host, "direct").await;

        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        for _ in 0..2 {
            grant_invitee(
                &pool, &notifier, &manager, session_id, host, mate, "wrapped",
            )
            .await
            .expect("grant");
        }

        let grants: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2",
        )
        .bind(session_id)
        .bind(mate)
        .fetch_one(&pool)
        .await
        .unwrap();
        let keys: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_keys WHERE session_id = $1 AND user_id = $2",
        )
        .bind(session_id)
        .bind(mate)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((grants, keys), (1, 1));

        let sessions = manager.sessions.lock().await;
        assert!(sessions.get(&session_id).unwrap().invitees.contains(&mate));
    }

    #[tokio::test]
    async fn grant_invitee_rejects_a_non_teammate() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let stranger = seed_user(&pool).await;
        let session_id = seed_session(&pool, host, "direct").await;

        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        let err = grant_invitee(
            &pool, &notifier, &manager, session_id, host, stranger, "wrapped",
        )
        .await
        .expect_err("stranger must be rejected");
        assert_eq!(err, StatusCode::FORBIDDEN);

        let grants: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_invitees WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(grants, 0);
    }

    #[tokio::test]
    async fn ws_authorizes_an_invitee_of_a_vaultless_session() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_member(&pool, team, host).await;
        add_member(&pool, team, mate).await;
        let session_id = seed_session(&pool, host, "direct").await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, session_id, host, mate, "wrapped")
            .await
            .unwrap();

        let invitees = manager.sessions.lock().await.get(&session_id).unwrap().invitees.clone();
        assert!(is_authorized_participant(&pool, mate, host, "direct", &[], &[], None, None, &invitees).await);
        let stranger = seed_user(&pool).await;
        assert!(!is_authorized_participant(&pool, stranger, host, "direct", &[], &[], None, None, &invitees).await);
    }

    #[tokio::test]
    async fn list_query_returns_a_direct_session_only_for_host_and_invitee() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let stranger = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_member(&pool, team, host).await;
        add_member(&pool, team, mate).await;
        let session_id = seed_session(&pool, host, "direct").await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, session_id, host, mate, "wrapped")
            .await
            .unwrap();

        let for_mate = visible_sessions(&pool, mate).await.unwrap();
        assert_eq!(for_mate.len(), 1);
        assert_eq!(for_mate[0].0, session_id);
        assert_eq!(for_mate[0].6, Some(host), "invited_by names the host");

        let for_host = visible_sessions(&pool, host).await.unwrap();
        assert_eq!(for_host.len(), 1);
        assert_eq!(for_host[0].6, None, "the host is not their own invitee");

        assert!(visible_sessions(&pool, stranger).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn end_session_recipients_include_invitees_of_a_vaultless_session() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_member(&pool, team, host).await;
        add_member(&pool, team, mate).await;
        let session_id = seed_session(&pool, host, "direct").await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, session_id, host, mate, "wrapped")
            .await
            .unwrap();

        let recipients = session_end_recipients(&pool, session_id, host).await.unwrap();
        assert_eq!(recipients, vec![mate]);
    }

    async fn test_notifier_and_manager(
        session_id: Uuid,
        host: Uuid,
    ) -> (crate::sync_notifier::SyncNotifier, TerminalManager) {
        let notifier = crate::sync_notifier::SyncNotifier::new();
        let manager = TerminalManager::new();
        let (tx, _) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);
        manager.sessions.lock().await.insert(
            session_id,
            crate::terminal_manager::SessionState {
                vault_ids: vec![],
                allowed_roles: vec![],
                invite_token: None,
                invitees: std::collections::HashSet::new(),
                host_user_id: host,
                host_public_key: String::new(),
                visibility: "direct".to_string(),
                vault_owner_id: None,
                participants: std::collections::HashMap::new(),
                control_holder: host,
                pending_control_request: None,
                tx,
                output_history: std::collections::VecDeque::new(),
            },
        );
        (notifier, manager)
    }
}
