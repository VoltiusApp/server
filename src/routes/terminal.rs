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

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    /// Vaults whose members can join (multi-vault support).
    /// Required for visibility="vault"; unused for visibility="invite_link".
    #[serde(default)]
    pub vault_ids: Vec<Uuid>,
    pub connection_name: String,
    /// "vault" (default) | "invite_link"
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
}

#[derive(Serialize)]
pub struct SessionKeyResponse {
    /// Set for vault sessions: wrapped with recipient's X25519 key.
    pub wrapped_key: Option<String>,
    /// Set for invite_link sessions: raw key bytes (base64), no E2EE.
    pub raw_key: Option<String>,
    pub host_public_key: String,
}

// ─── Create terminal session ──────────────────────────────────────────────────

pub async fn create_session(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(auth_claims): Extension<AuthClaims>,
    Extension(manager): Extension<TerminalManager>,
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
        // invite_link visibility: gate on the host's own JWT tier
        let session_limit: i64 = match auth_claims.0.tier.as_str() {
            "business" => 20,
            "teams"    => 5,
            "pro"      => 1,
            _          => return Err(StatusCode::PAYMENT_REQUIRED),
        };

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

    info!(session_id = %session_id, visibility = %visibility, vault_count = body.vault_ids.len(), "Terminal session created");
    Ok((StatusCode::CREATED, Json(CreateSessionResponse { session_id, invite_token })))
}

// ─── List active sessions (vault sessions the user is part of) ────────────────

pub async fn list_active_sessions(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(manager): Extension<TerminalManager>,
) -> Result<Json<Vec<ActiveSession>>, StatusCode> {
    // Show vault sessions where user is a member of one of the session's vaults
    // (respecting role filter if set).
    // Invite-link sessions are NOT listed here — they're accessible only via the link.
    // Host always sees their own sessions.
    let rows = sqlx::query_as::<_, (Uuid, String, Uuid, String, chrono::DateTime<Utc>, Vec<Uuid>)>(
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
            ) AS vault_ids
        FROM terminal_sessions ts
        WHERE ts.ended_at IS NULL
          AND ts.visibility = 'vault'
          AND (
            ts.host_user_id = $1
            OR EXISTS (
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
        ORDER BY ts.created_at DESC
        "#,
    )
    .bind(auth.0)
    .bind(crate::permissions::PERM_VIEW_TERMINAL_SESSIONS)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list active sessions");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let sessions_lock = manager.sessions.lock().await;
    let result = rows
        .into_iter()
        .filter(|(id, ..)| sessions_lock.contains_key(id))
        .map(|(id, connection_name, host_user_id, visibility, created_at, vault_ids)| {
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
            }
        })
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

// ─── End session ─────────────────────────────────────────────────────────────

pub async fn end_session(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(manager): Extension<TerminalManager>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let host_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT host_user_id FROM terminal_sessions WHERE id = $1 AND ended_at IS NULL",
    )
    .bind(session_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to get session host");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    if host_id != auth.0 {
        return Err(StatusCode::FORBIDDEN);
    }

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

    info!(session_id = %session_id, "Terminal session ended");
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
        sessions.get(&session_id).map(|s| (
            s.vault_ids.clone(),
            s.visibility.clone(),
            s.allowed_roles.clone(),
            s.invite_token.clone(),
            s.host_user_id,
            s.vault_owner_id,
        ))
    };

    let (vault_ids, visibility, allowed_roles, stored_token, host_user_id, vault_owner_id) = match session_info {
        Some(info) => info,
        None => {
            warn!(session_id = %session_id, user_id = %user_id, "WS: session not found");
            return;
        }
    };

    // Host is always allowed
    if user_id != host_user_id {
        let authorized = if visibility == "invite_link" {
            // Invite link: validate token
            invite_token.is_some() && invite_token.as_deref() == stored_token.as_deref()
        } else {
            // Vault session: user must be a member of one of the session's vaults,
            // satisfy the role filter (if any), and have JOIN_TERMINAL_SESSION permission.
            if vault_ids.is_empty() {
                false
            } else {
                let is_member = if allowed_roles.is_empty() {
                    sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = ANY($1) AND user_id = $2)",
                    )
                    .bind(&vault_ids)
                    .bind(user_id)
                    .fetch_one(&pool)
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
                    .bind(&vault_ids)
                    .bind(user_id)
                    .bind(&allowed_roles)
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(false)
                };
                is_member && crate::permissions::has_any_team_permission(
                    &pool, &vault_ids, user_id, crate::permissions::PERM_JOIN_TERMINAL_SESSION,
                )
                .await
                .unwrap_or(false)
            }
        };

        if !authorized {
            warn!(session_id = %session_id, user_id = %user_id, "WS: unauthorized user rejected");
            return;
        }
    }

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Participant cap: guests only (host is always allowed)
    if user_id != host_user_id {
        let effective_tier = if let Some(owner_id) = vault_owner_id {
            sqlx::query_scalar::<_, String>("SELECT subscription_tier FROM users WHERE id = $1")
                .bind(owner_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|_| "free".to_string())
        } else {
            sqlx::query_scalar::<_, String>("SELECT subscription_tier FROM users WHERE id = $1")
                .bind(host_user_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|_| "free".to_string())
        };

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
