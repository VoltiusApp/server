use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use chrono::{Duration, Utc};
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
    /// `None` for an unaccepted stranger invitee — a mis-aimed invite must not
    /// leak what it was for until the recipient accepts.
    pub connection_name: Option<String>,
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
    /// `invited_by`'s handle, resolved server-side from `users`. The knock UI
    /// renders this and nothing else: `list_active_sessions` deliberately
    /// redacts `participants` to empty for an unaccepted stranger.
    pub invited_by_handle: Option<String>,
    /// Everyone the host has individually invited (#66). Populated only when
    /// the caller is the host — a guest must not learn the guest list.
    pub invitee_ids: Vec<Uuid>,
}

#[derive(Serialize)]
pub struct SessionKeyResponse {
    /// Set for vault sessions: wrapped with recipient's X25519 key.
    pub wrapped_key: Option<String>,
    /// Set for invite_link sessions: raw key bytes (base64), no E2EE.
    pub raw_key: Option<String>,
    pub host_public_key: String,
}

/// True when the two users are members of at least one team in common. Shares
/// `TEAMMATE_PAIR_SQL` with `search_users_inner`: `u.id` there is bound here via
/// a one-row derived table so the same predicate text serves both call shapes.
pub(crate) async fn shares_a_team(pool: &PgPool, a: Uuid, b: Uuid) -> Result<bool, StatusCode> {
    let sql = format!(
        "SELECT {pair} FROM (SELECT $1::uuid AS id) u",
        pair = crate::routes::teams::TEAMMATE_PAIR_SQL,
    );
    sqlx::query_scalar::<_, bool>(&sql)
        .bind(b)
        .bind(a)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to check shared team membership");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GrantOutcome {
    Granted,
    /// The recipient blocked the sender or opted out. Reported as success and
    /// written as nothing: a sender must not be able to learn either fact, and a
    /// row that is never written cannot hold a guest seat.
    Suppressed,
}

/// Live block from `blocked_by` against `sender`.
async fn is_blocked(pool: &PgPool, blocked_by: Uuid, sender: Uuid) -> Result<bool, StatusCode> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM user_blocks \
          WHERE blocker_id = $1 AND blocked_id = $2 \
            AND (expires_at IS NULL OR expires_at > now()))",
    )
    .bind(blocked_by)
    .bind(sender)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to check user block");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Whether a stranger knock may be delivered: the recipient's opt-in and the
/// absence of a live block.
///
/// Both reads always run, and the two booleans are combined only after the fact.
/// Written as `!opted_in || is_blocked(..).await?` the block query was skipped
/// for an opted-out recipient, so the three outcomes (granted / opted-out /
/// blocked) each cost a different number of round trips — measurable as latency,
/// and a sender is promised they can learn neither fact.
async fn stranger_knock_allowed(
    pool: &PgPool,
    recipient: Uuid,
    sender: Uuid,
) -> Result<bool, StatusCode> {
    let opted_in = sqlx::query_scalar::<_, bool>(
        "SELECT allow_stranger_invites FROM users WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(recipient)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to read invite preference");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .unwrap_or(false);
    let blocked = is_blocked(pool, recipient, sender).await?;
    Ok(opted_in && !blocked)
}

/// Grants one named user access to a session: the durable row, the wrapped key,
/// the in-memory authorization set, and the push. The single grant path — both
/// `create_session` with visibility "direct" and the invitees endpoint call it.
///
/// A teammate is granted unconditionally, as before. A stranger is granted
/// only on the recipient's terms — their opt-out, their block list, and a
/// per-sender knock budget — and a refusal on those terms is reported back as
/// `Suppressed`, identical to success, so a blocked sender can never learn it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn grant_invitee(
    pool: &PgPool,
    notifier: &crate::sync_notifier::SyncNotifier,
    manager: &TerminalManager,
    knocks: &crate::rate_limit::KnockRateLimiter,
    session_id: Uuid,
    host_user_id: Uuid,
    user_id: Uuid,
    wrapped_key: &str,
) -> Result<GrantOutcome, StatusCode> {
    let is_teammate = user_id == host_user_id || shares_a_team(pool, host_user_id, user_id).await?;

    // A stranger knock is allowed, but on the recipient's terms: their opt-out,
    // their block list, and a per-sender budget. Teammates keep today's path
    // untouched, budget included.
    if !is_teammate {
        if !knocks.0.check(host_user_id).await {
            warn!(host = %host_user_id, "Knock rate limit exceeded");
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        if !stranger_knock_allowed(pool, user_id, host_user_id).await? {
            info!(target: "knock", sender = %host_user_id, recipient = %user_id, outcome = "suppressed", "Stranger knock suppressed");
            // No grant row, ever — that silence is the whole point. This is the
            // one place that writes here: it exists only so the host's own
            // invitee list can't tell a block/opt-out apart from a real grant.
            sqlx::query(
                "INSERT INTO suppressed_invites (session_id, user_id, invited_by) \
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(session_id)
            .bind(user_id)
            .bind(host_user_id)
            .execute(pool)
            .await
            .map_err(|e| {
                error!(error = %e, session_id = %session_id, "Failed to record suppressed invite");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            return Ok(GrantOutcome::Suppressed);
        }
        info!(target: "knock", sender = %host_user_id, recipient = %user_id, outcome = "granted", "Stranger knock");
    }

    let invitee_insert = sqlx::query(
        "INSERT INTO terminal_session_invitees (session_id, user_id, invited_by, accepted_at) \
         VALUES ($1, $2, $3, CASE WHEN $4 THEN now() ELSE NULL END) ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(host_user_id)
    .bind(is_teammate)
    .execute(pool)
    .await
    .map_err(|e| {
        error!(error = %e, session_id = %session_id, "Failed to insert session invitee");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Refreshed rather than skipped: a recipient whose X25519 keypair changed
    // after an earlier grant can no longer open the stored wrapping, and with
    // DO NOTHING every later invite was a silent no-op that left them stuck.
    sqlx::query(
        "INSERT INTO terminal_session_keys (session_id, user_id, wrapped_key) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (session_id, user_id) DO UPDATE SET wrapped_key = EXCLUDED.wrapped_key",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(wrapped_key)
    .execute(pool)
    .await
    .map_err(|e| {
        error!(error = %e, session_id = %session_id, "Failed to store invitee session key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some(state) = manager.sessions.lock().await.get_mut(&session_id) {
        state.invitees.insert(user_id);
    }

    // Only push on a genuinely new grant — the ON CONFLICT above means a repeat
    // invite of someone already granted must not re-knock them.
    if invitee_insert.rows_affected() > 0 {
        notifier.notify_session_shared(user_id, session_id, host_user_id);
    }
    Ok(GrantOutcome::Granted)
}

/// Tables keyed by `(session_id, user_id)` that ride along whenever
/// `terminal_session_invitees` is cleared for a grant: the wrapped key and the
/// suppressed-knock row. Both revoke paths delete from `terminal_session_invitees`
/// with their own shape (a plain pair delete here, a set-scoped delete with a
/// teammate check in the bulk path below) but must clear these two identically —
/// drive both from this list so a future table can't drift out of one of them.
const GRANT_SIDE_TABLES: &[&str] = &["terminal_session_keys", "suppressed_invites"];

/// Deletes `table`'s row for one `(session_id, user_id)` pair.
async fn delete_grant_side_row(
    pool: &PgPool,
    table: &str,
    session_id: Uuid,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("DELETE FROM {table} WHERE session_id = $1 AND user_id = $2"))
        .bind(session_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Deletes `table`'s rows for a batch of `(session_id, user_id)` pairs in one round trip.
async fn delete_grant_side_rows(
    pool: &PgPool,
    table: &str,
    session_ids: &[Uuid],
    user_ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    sqlx::query(&format!(
        "DELETE FROM {table} t \
          USING UNNEST($1::uuid[], $2::uuid[]) AS revoked(session_id, user_id) \
          WHERE t.session_id = revoked.session_id AND t.user_id = revoked.user_id"
    ))
    .bind(session_ids)
    .bind(user_ids)
    .execute(pool)
    .await?;
    Ok(())
}

/// Undoes `grant_invitee` for every grant `user_id` is no longer qualified for
/// after leaving a team — both grants they hold and grants they issued, since
/// the admission guard tests the inviter/invitee *pair*. Clears the durable
/// row, the wrapped key (`GET .../key` would otherwise still hand it out), the
/// suppressed-knock row (else the seat it fakes-occupies never frees up) and
/// the in-memory set the WebSocket actually reads.
///
/// Scope: this closes admission to *new* connections. The relay protocol has no
/// eviction message, so a participant already attached to the live socket stays
/// until they disconnect — deliberate, not an oversight.
// Kept as its own bulk-statement shape rather than looping `revoke_one_grant`
// per pair: the filtered `NOT EXISTS` DELETE below computes the whole revoked
// set in one round trip, and a departed member can hold or have issued many
// grants — looping would turn one statement into 3N and re-derive the same
// teammate check per row.
pub(crate) async fn revoke_grants_for_departed_member(
    pool: &PgPool,
    manager: &TerminalManager,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    let revoked: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "DELETE FROM terminal_session_invitees tsi \
          WHERE (tsi.user_id = $1 OR tsi.invited_by = $1) \
            AND NOT EXISTS ( \
              SELECT 1 FROM team_members a \
                JOIN team_members b ON a.team_id = b.team_id \
               WHERE a.user_id = tsi.invited_by AND b.user_id = tsi.user_id) \
          RETURNING tsi.session_id, tsi.user_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    if revoked.is_empty() {
        return Ok(());
    }

    let (session_ids, user_ids): (Vec<Uuid>, Vec<Uuid>) = revoked.iter().copied().unzip();
    for table in GRANT_SIDE_TABLES {
        delete_grant_side_rows(pool, table, &session_ids, &user_ids).await?;
    }

    let mut sessions = manager.sessions.lock().await;
    for (session_id, revoked_user) in revoked {
        if let Some(state) = sessions.get_mut(&session_id) {
            state.invitees.remove(&revoked_user);
        }
    }
    Ok(())
}

/// The single-pair form of `revoke_grants_for_departed_member`: durable row,
/// wrapped key, the suppressed-knock row, and the in-memory set the WebSocket
/// actually reads. All four, always — a DB-only revoke leaves live admission
/// open, and a stale `suppressed_invites` row occupies a guest seat that
/// `visible_sessions` reports back to the host as still-invited.
pub(crate) async fn revoke_one_grant(
    pool: &PgPool,
    manager: &TerminalManager,
    session_id: Uuid,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    for table in GRANT_SIDE_TABLES {
        delete_grant_side_row(pool, table, session_id, user_id).await?;
    }
    if let Some(state) = manager.sessions.lock().await.get_mut(&session_id) {
        state.invitees.remove(&user_id);
    }
    Ok(())
}

pub(crate) async fn decline_invite_inner(
    pool: &PgPool,
    manager: &TerminalManager,
    session_id: Uuid,
    user_id: Uuid,
    permanent: bool,
) -> Result<(), StatusCode> {
    let inviter: Option<Uuid> = sqlx::query_scalar(
        "SELECT invited_by FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to read invite before decline");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .flatten();

    revoke_one_grant(pool, manager, session_id, user_id)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to revoke declined invite");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Declining blocks by default: the abuse shape is one sender knocking
    // repeatedly at one target, and making the victim hunt for a setting after
    // each knock is the wrong default.
    if let Some(inviter) = inviter {
        let expires = if permanent {
            None
        } else {
            Some(Utc::now() + Duration::days(7))
        };
        sqlx::query(
            "INSERT INTO user_blocks (blocker_id, blocked_id, expires_at) VALUES ($1, $2, $3) \
             ON CONFLICT (blocker_id, blocked_id) DO UPDATE SET expires_at = EXCLUDED.expires_at, created_at = now()",
        )
        .bind(user_id)
        .bind(inviter)
        .bind(expires)
        .execute(pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to write block on decline");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }
    Ok(())
}

pub(crate) async fn uninvite_inner(
    pool: &PgPool,
    manager: &TerminalManager,
    session_id: Uuid,
    caller: Uuid,
    target: Uuid,
) -> Result<(), StatusCode> {
    require_active_session_host(pool, session_id, caller).await?;
    revoke_one_grant(pool, manager, session_id, target)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to un-invite");
            StatusCode::INTERNAL_SERVER_ERROR
        })
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
    Extension(knocks): Extension<crate::rate_limit::KnockRateLimiter>,
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
        Some(crate::session_grants::new_token_secret())
    } else {
        None
    };

    // Insert session record and its legacy join grant together: if the grant
    // insert fails, the session row must not survive carrying a token that
    // can never resolve.
    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to start session creation transaction");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to insert terminal session");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some(token) = &invite_token {
        crate::session_grants::insert_grant(
            &mut *tx, session_id, "legacy_token", token, None, auth.0, None,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to insert legacy join grant");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit session creation transaction");
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
        if let Err(e) = grant_invitee(
            &pool,
            &notifier,
            &manager,
            &knocks,
            session_id,
            auth.0,
            entry.user_id,
            &entry.wrapped_key,
        )
        .await
        {
            // A partially-granted session must not linger as "active": it would
            // count against the host's own concurrency limit forever, and the
            // client never learned its id to end it itself. Only drop the
            // in-memory entry once the row is confirmed ended — otherwise the
            // session would be both still-counted AND unreachable.
            match sqlx::query("UPDATE terminal_sessions SET ended_at = now() WHERE id = $1")
                .bind(session_id)
                .execute(&pool)
                .await
            {
                Ok(_) => {
                    manager.sessions.lock().await.remove(&session_id);
                }
                Err(update_err) => {
                    error!(
                        error = %update_err,
                        session_id = %session_id,
                        "Failed to end orphaned session after a failed grant; it remains live and reachable"
                    );
                }
            }
            return Err(e);
        }
    }

    info!(session_id = %session_id, visibility = %visibility, vault_count = body.vault_ids.len(), "Terminal session created");
    Ok((StatusCode::CREATED, Json(CreateSessionResponse { session_id, invite_token })))
}

// ─── List active sessions (vault sessions the user is part of) ────────────────

#[derive(sqlx::FromRow)]
struct VisibleSessionRow {
    id: Uuid,
    /// `None` for an unaccepted stranger invitee (see the CASE in `visible_sessions`).
    connection_name: Option<String>,
    host_user_id: Uuid,
    visibility: String,
    created_at: chrono::DateTime<Utc>,
    vault_ids: Vec<Uuid>,
    invited_by: Option<Uuid>,
    /// `invited_by`'s handle, read from `users`.
    invited_by_handle: Option<String>,
    invitee_ids: Vec<Uuid>,
}

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
            -- An unaccepted stranger invitee must not learn what they were
            -- invited to; the host and any teammate always see the name.
            -- The teammate arm deliberately comes before the invite-status
            -- check below, so a teammate sees the name even while their own
            -- individual invite row is still unaccepted.
            CASE
              WHEN ts.host_user_id = $1 THEN ts.connection_name
              -- Teammate pair test, inlined: TEAMMATE_PAIR_SQL (teams.rs) hardcodes
              -- `$2`/`u.id`, which collide with this query's own `$2` (a permission
              -- bitmask) and lack of a `u`-aliased row — see that constant's doc.
              WHEN EXISTS (SELECT 1 FROM team_members a JOIN team_members b ON a.team_id = b.team_id
                            WHERE a.user_id = $1 AND b.user_id = ts.host_user_id) THEN ts.connection_name
              WHEN EXISTS (SELECT 1 FROM terminal_session_invitees tsi2
                            WHERE tsi2.session_id = ts.id AND tsi2.user_id = $1
                              AND tsi2.accepted_at IS NULL) THEN NULL
              ELSE ts.connection_name
            END AS connection_name,
            ts.host_user_id,
            ts.visibility,
            ts.created_at,
            COALESCE(
                (SELECT array_agg(tsv.team_id) FROM terminal_session_vaults tsv WHERE tsv.session_id = ts.id),
                ARRAY[]::uuid[]
            ) AS vault_ids,
            (SELECT tsi.invited_by FROM terminal_session_invitees tsi
              WHERE tsi.session_id = ts.id AND tsi.user_id = $1) AS invited_by,
            -- The inviter's handle, for the caller's own grant only. A knock is
            -- the one surface a stranger reads before consenting, so its identity
            -- must come from `users` — same resolution the participant list uses,
            -- closing the impersonation vector a client-supplied name would open.
            (SELECT u.handle FROM terminal_session_invitees tsi
               JOIN users u ON u.id = tsi.invited_by
              WHERE tsi.session_id = ts.id AND tsi.user_id = $1) AS invited_by_handle,
            -- Suppressed knocks are unioned in here, and only here: the host must see
            -- a blocked/opted-out stranger exactly as an ordinary pending invite, or
            -- the missing id would tell them what the silent block exists to hide.
            CASE WHEN ts.host_user_id = $1 THEN
              COALESCE(
                (SELECT array_agg(uid) FROM (
                  SELECT tsi3.user_id AS uid FROM terminal_session_invitees tsi3 WHERE tsi3.session_id = ts.id
                  UNION
                  SELECT si.user_id FROM suppressed_invites si WHERE si.session_id = ts.id
                ) all_invitee_ids),
                ARRAY[]::uuid[]
              )
            ELSE ARRAY[]::uuid[] END AS invitee_ids
        FROM terminal_sessions ts
        WHERE ts.ended_at IS NULL
          AND (
            (ts.host_user_id = $1 AND ts.visibility IN ('vault', 'direct'))
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
        .filter(|row| sessions_lock.contains_key(&row.id))
        .map(|row| {
            let (mut participant_count, mut participants, host_public_key) = sessions_lock
                .get(&row.id)
                .map(|s| {
                    let ps: Vec<Participant> = s.participants.values().cloned().collect();
                    (ps.len() as i64, ps, s.host_public_key.clone())
                })
                .unwrap_or_default();
            // A redacted `connection_name` marks an unaccepted stranger, and the
            // rest of this row is just as identifying: participant display names
            // and a headcount say who is already in the room. D7 promises such a
            // recipient learns a handle and nothing else. `host_public_key` stays
            // — it is inert and plausibly needed before joining.
            if row.connection_name.is_none() {
                participants = Vec::new();
                participant_count = 0;
            }
            ActiveSession {
                id: row.id,
                connection_name: row.connection_name,
                host_user_id: row.host_user_id,
                host_public_key,
                visibility: row.visibility,
                created_at: row.created_at,
                participant_count,
                participants,
                vault_ids: row.vault_ids,
                invited_by: row.invited_by,
                invited_by_handle: row.invited_by_handle,
                invitee_ids: row.invitee_ids,
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

    // Invite link session: session must exist first (404), then the token
    // must resolve to a live grant (403) — preserves the pre-grant status
    // code contract for unknown/ended sessions vs. a bad credential.
    if let Some(token) = &query.invite_token {
        let row = sqlx::query_as::<_, (Option<String>, String)>(
            r#"
            SELECT ts.session_key_bytes, u.public_key
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

        if crate::session_grants::resolve_join_grant(&pool, session_id, token)
            .await
            .is_none()
        {
            return Err(StatusCode::FORBIDDEN);
        }

        let (session_key_bytes, host_public_key) = row;
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
pub(crate) async fn require_active_session_host(
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

/// Fan `session_ended` out to `session_end_recipients`. Callers with no
/// `Result` channel of their own (host disconnect, not `end_session`'s HTTP
/// response) can call this and just move on; the load failure is logged by
/// `session_end_recipients` itself.
async fn fan_out_session_ended(
    pool: &PgPool,
    notifier: &crate::sync_notifier::SyncNotifier,
    session_id: Uuid,
    host_user_id: Uuid,
) {
    let Ok(recipients) = session_end_recipients(pool, session_id, host_user_id).await else {
        return;
    };

    // Recipients must be loaded above, before these deletes: they clear the very
    // rows `session_end_recipients` reads invitees from, so deleting first
    // would fan the "session ended" push out to nobody.
    //
    // Every one of these holds per-invitee grant state whose `ON DELETE CASCADE`
    // a soft end (`ended_at = now()`) never fires, so each must be cleared
    // explicitly. The side tables come from `GRANT_SIDE_TABLES` rather than a
    // second hardcoded list — that is the whole point of the constant, and a
    // stale `suppressed_invites` row is exactly the social-graph record D9
    // refused to create.
    for table in std::iter::once(&"terminal_session_invitees").chain(GRANT_SIDE_TABLES) {
        if let Err(e) = sqlx::query(&format!("DELETE FROM {table} WHERE session_id = $1"))
            .bind(session_id)
            .execute(pool)
            .await
        {
            error!(error = %e, session_id = %session_id, table, "Failed to clear session grant rows");
        }
    }

    for recipient in recipients {
        notifier.notify_session_ended(recipient, session_id);
    }
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

    fan_out_session_ended(&pool, &notifier, session_id, auth.0).await;

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
    Extension(knocks): Extension<crate::rate_limit::KnockRateLimiter>,
    Path(session_id): Path<Uuid>,
    Json(body): Json<InviteToSessionRequest>,
) -> Result<StatusCode, StatusCode> {
    require_active_session_host(&pool, session_id, auth.0).await?;

    // Granted or Suppressed both return 204: the sender must not be able to
    // tell a block/opt-out apart from an ordinary successful invite.
    grant_invitee(
        &pool,
        &notifier,
        &manager,
        &knocks,
        session_id,
        auth.0,
        body.user_id,
        &body.wrapped_key,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct DeclineQuery {
    /// "permanent" writes a never-expiring block; anything else (including
    /// absent) blocks for 7 days — decline blocks by default, silently.
    pub block: Option<String>,
}

/// The invitee's own path — must be registered before `/invitees/:user_id`
/// so the literal "me" wins the match instead of failing to parse as a UUID.
pub async fn decline_invite(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(manager): Extension<TerminalManager>,
    Path(session_id): Path<Uuid>,
    Query(query): Query<DeclineQuery>,
) -> Result<StatusCode, StatusCode> {
    let permanent = query.block.as_deref() == Some("permanent");
    decline_invite_inner(&pool, &manager, session_id, auth.0, permanent).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The host withdrawing their own invite — not a block, so it must never
/// touch `user_blocks`.
pub async fn uninvite(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(manager): Extension<TerminalManager>,
    Path((session_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    uninvite_inner(&pool, &manager, session_id, auth.0, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── WebSocket handler ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: String,
    /// Accepted and discarded. Pre-0.26 clients still append
    /// `&display_name=<email>`; a struct without the field would make serde
    /// reject their upgrade. Never read this. Delete it in 0.27.
    #[allow(dead_code)]
    pub display_name: Option<String>,
    /// Required when joining invite_link sessions
    pub invite_token: Option<String>,
}

/// Resolves the name shown on participant lists. Reads `users.handle` by the
/// authenticated user id, so the value cannot be influenced by the caller.
/// Falls back to the user id — matching the previous behaviour for a caller
/// that sent nothing — rather than refusing an upgrade over a missing row.
pub(crate) async fn resolve_participant_handle(pool: &PgPool, user_id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| user_id.to_string())
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(session_id): Path<Uuid>,
    Query(query): Query<WsQuery>,
    State(pool): State<PgPool>,
    Extension(manager): Extension<TerminalManager>,
    Extension(notifier): Extension<crate::sync_notifier::SyncNotifier>,
) -> impl IntoResponse {
    let user_id = match validate_token(&query.token, "access") {
        Ok(claims) => claims.sub,
        Err(_) => {
            warn!(session_id = %session_id, "WS upgrade rejected: invalid token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let handle = resolve_participant_handle(&pool, user_id).await;

    ws.on_upgrade(move |socket| {
        handle_socket(
            socket,
            session_id,
            user_id,
            handle,
            query.invite_token,
            pool,
            manager,
            notifier,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn is_authorized_participant(
    pool: &PgPool,
    session_id: Uuid,
    user_id: Uuid,
    host_user_id: Uuid,
    visibility: &str,
    vault_ids: &[Uuid],
    allowed_roles: &[String],
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
        let Some(presented) = presented_token else {
            return false;
        };
        return crate::session_grants::resolve_join_grant(pool, session_id, presented)
            .await
            .is_some();
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

/// Stamps first admission. `accepted_at IS NULL` in the predicate makes a
/// re-join idempotent — the timestamp is "when they first said yes", and the
/// redaction above reads it.
pub(crate) async fn stamp_acceptance(pool: &PgPool, session_id: Uuid, user_id: Uuid) {
    if let Err(e) = sqlx::query(
        "UPDATE terminal_session_invitees SET accepted_at = now() \
          WHERE session_id = $1 AND user_id = $2 AND accepted_at IS NULL",
    )
    .bind(session_id)
    .bind(user_id)
    .execute(pool)
    .await
    {
        warn!(error = %e, session_id = %session_id, "Failed to stamp invitee acceptance");
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_socket(
    socket: WebSocket,
    session_id: Uuid,
    user_id: Uuid,
    handle: String,
    invite_token: Option<String>,
    pool: PgPool,
    manager: TerminalManager,
    notifier: crate::sync_notifier::SyncNotifier,
) {
    // Fetch session state from in-memory manager
    let session_info = {
        let sessions = manager.sessions.lock().await;
        sessions.get(&session_id).map(|s| {
            (
                s.vault_ids.clone(),
                s.visibility.clone(),
                s.allowed_roles.clone(),
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
        session_id,
        user_id,
        host_user_id,
        &visibility,
        &vault_ids,
        &allowed_roles,
        invite_token.as_deref(),
        &invitees,
    )
    .await;

    if !authorized {
        warn!(session_id = %session_id, user_id = %user_id, "WS: unauthorized user rejected");
        return;
    }

    stamp_acceptance(&pool, session_id, user_id).await;

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Participant cap: guests only (host is always allowed)
    if user_id != host_user_id {
        let tier_owner = vault_owner_id.unwrap_or(host_user_id);
        let effective_tier = crate::entitlement::effective_tier_for_user(&pool, tier_owner).await;

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

        state.participants.insert(user_id, Participant::new(user_id, handle.clone()));

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
        cleanup_participant(&manager, session_id, user_id, &tx, &pool, &notifier).await;
        return;
    }

    // Replay terminal history so the new joiner sees what happened before they joined.
    for msg in history_snapshot {
        if ws_sender.send(Message::Text(msg)).await.is_err() {
            cleanup_participant(&manager, session_id, user_id, &tx, &pool, &notifier).await;
            return;
        }
    }

    let joined_msg = serde_json::json!({
        "type": "participant_joined",
        "user_id": user_id,
        "handle": handle,
        // ALIAS for pre-0.26 clients. Delete in 0.27.
        "display_name": handle,
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
    cleanup_participant(&manager, session_id, user_id, &tx, &pool, &notifier).await;
    info!(session_id = %session_id, user_id = %user_id, "WS participant left");
}

async fn cleanup_participant(
    manager: &TerminalManager,
    session_id: Uuid,
    user_id: Uuid,
    tx: &tokio::sync::broadcast::Sender<String>,
    pool: &PgPool,
    notifier: &crate::sync_notifier::SyncNotifier,
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
        drop(sessions);

        fan_out_session_ended(pool, notifier, session_id, user_id).await;

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
    use crate::rate_limit::RateLimiter;
    use crate::sync_notifier::SyncNotifier;
    use crate::terminal_manager::TerminalManager;
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, default_knock_limiter as knocks, member_with_role, seed_team, seed_user};
    use axum::extract::State;
    use axum::{Extension, Json};
    use std::time::Duration;

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
            Extension(knocks()),
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
            Extension(knocks()),
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
            Extension(knocks()),
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
            Extension(knocks()),
            Json(direct_session_request(Vec::new())),
        )
        .await;

        assert!(matches!(res, Err(axum::http::StatusCode::BAD_REQUEST)));
    }

    #[tokio::test]
    async fn create_session_direct_tears_down_the_session_when_a_grant_fails() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let stranger = seed_user(&pool).await; // no shared team with `host`
        let team = seed_team(&pool, host).await;
        add_member(&pool, team, host).await;
        add_member(&pool, team, mate).await;

        let manager = TerminalManager::new();
        let entries = vec![
            ParticipantKeyEntry { user_id: mate, wrapped_key: "wrapped".to_string() },
            ParticipantKeyEntry { user_id: stranger, wrapped_key: "wrapped".to_string() },
        ];

        // Zero budget: the stranger knock is what fails this grant, since a
        // stranger is no longer forbidden outright.
        let exhausted = crate::rate_limit::KnockRateLimiter(RateLimiter::new(0, Duration::from_secs(3600)));
        let res = create_session(
            State(pool.clone()),
            Extension(AuthUser(host)),
            Extension(claims_for(host)),
            Extension(manager.clone()),
            Extension(SyncNotifier::new()),
            Extension(exhausted),
            Json(direct_session_request(entries)),
        )
        .await;

        assert!(matches!(res, Err(axum::http::StatusCode::TOO_MANY_REQUESTS)));

        // The session must not linger as "active": ended_at set, and gone from
        // in-memory state (or `SELECT COUNT ... WHERE ended_at IS NULL` would
        // keep counting it against the host's own concurrency limit forever).
        let ended_at: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
            "SELECT ended_at FROM terminal_sessions WHERE host_user_id = $1",
        )
        .bind(host)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(ended_at.is_some(), "the orphaned session must be ended, not left live");

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_sessions WHERE host_user_id = $1 AND ended_at IS NULL",
        )
        .bind(host)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active_count, 0);
        assert!(manager.sessions.lock().await.is_empty());
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

    #[tokio::test]
    async fn creating_an_invite_link_session_also_mints_a_legacy_grant() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;

        let res = create_session(
            State(pool.clone()),
            Extension(AuthUser(host)),
            Extension(claims_for(host)),
            Extension(TerminalManager::new()),
            Extension(SyncNotifier::new()),
            Extension(knocks()),
            Json(session_request(Vec::new(), "invite_link", Vec::new())),
        )
        .await
        .expect("invite_link session creates");

        let (_, Json(body)) = res;
        let token = body.invite_token.expect("invite_link sessions carry a token");

        let grant_kind: String = sqlx::query_scalar(
            "SELECT kind FROM terminal_session_grants WHERE session_id = $1",
        )
        .bind(body.session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(grant_kind, "legacy_token");

        assert!(
            crate::session_grants::resolve_join_grant(&pool, body.session_id, &token)
                .await
                .is_some(),
            "the token an old client already holds must keep resolving"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::RateLimiter;
    use crate::test_pool_or_skip;
    use crate::test_support::{
        add_member, default_knock_limiter as knocks, seed_session, seed_team, seed_user,
    };
    use std::time::Duration;

    fn harness() -> (crate::sync_notifier::SyncNotifier, TerminalManager) {
        (
            crate::sync_notifier::SyncNotifier::new(),
            TerminalManager::new(),
        )
    }

    async fn mk_stranger(pool: &PgPool) -> Uuid {
        seed_user(pool).await
    }

    /// A direct session with a host and a user who shares no team — a stranger.
    async fn direct_session_with_stranger(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
        let host = seed_user(pool).await;
        let stranger = mk_stranger(pool).await;
        let session_id = seed_session(pool, host, "direct").await;
        (host, stranger, session_id)
    }

    /// A direct session with a host and a user who shares a team — a teammate.
    async fn direct_session_with_teammate(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
        let host = seed_user(pool).await;
        let mate = seed_user(pool).await;
        let team = seed_team(pool, host).await;
        add_member(pool, team, host).await;
        add_member(pool, team, mate).await;
        let session_id = seed_session(pool, host, "direct").await;
        (host, mate, session_id)
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
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;

        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        for _ in 0..2 {
            grant_invitee(
                &pool,
                &notifier,
                &manager,
                &knocks(),
                session_id,
                host,
                mate,
                "wrapped",
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
    async fn grant_invitee_refreshes_a_stale_wrapped_key() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;

        // The recipient rotates their keypair between the two grants, so the
        // first wrapping can no longer be opened; the re-invite must replace it.
        grant_invitee(
            &pool,
            &notifier,
            &manager,
            &knocks(),
            session_id,
            host,
            mate,
            "wrapped-to-the-old-key",
        )
        .await
        .expect("first grant");
        grant_invitee(
            &pool,
            &notifier,
            &manager,
            &knocks(),
            session_id,
            host,
            mate,
            "wrapped-to-the-current-key",
        )
        .await
        .expect("second grant");

        let stored: Vec<String> = sqlx::query_scalar(
            "SELECT wrapped_key FROM terminal_session_keys WHERE session_id = $1 AND user_id = $2",
        )
        .bind(session_id)
        .bind(mate)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(stored, vec!["wrapped-to-the-current-key".to_string()]);
    }

    #[tokio::test]
    async fn grant_invitee_pushes_only_on_the_first_grant() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;

        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        let mut events = notifier.subscribe();
        for _ in 0..2 {
            grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
                .await
                .expect("grant");
        }

        let mut shared_count = 0;
        while let Ok(event) = events.try_recv() {
            if matches!(event, crate::sync_notifier::SyncEvent::SessionShared { recipient, .. } if recipient == mate) {
                shared_count += 1;
            }
        }
        assert_eq!(shared_count, 1, "a repeat grant of the same invitee must not re-push");
    }

    #[tokio::test]
    async fn grant_invitee_suppresses_a_knock_to_an_opted_out_stranger() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let stranger = seed_user(&pool).await;
        sqlx::query("UPDATE users SET allow_stranger_invites = FALSE WHERE id = $1")
            .bind(stranger)
            .execute(&pool)
            .await
            .unwrap();
        let session_id = seed_session(&pool, host, "direct").await;

        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        let outcome = grant_invitee(
            &pool,
            &notifier,
            &manager,
            &knocks(),
            session_id,
            host,
            stranger,
            "wrapped",
        )
        .await
        .expect("suppression must look exactly like success to the sender");
        assert_eq!(outcome, GrantOutcome::Suppressed);

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
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();

        let invitees = manager.sessions.lock().await.get(&session_id).unwrap().invitees.clone();
        assert!(is_authorized_participant(&pool, session_id, mate, host, "direct", &[], &[], None, &invitees).await);
        let stranger = seed_user(&pool).await;
        assert!(!is_authorized_participant(&pool, session_id, stranger, host, "direct", &[], &[], None, &invitees).await);
    }

    #[tokio::test]
    async fn list_query_excludes_an_invite_link_session_for_its_own_host() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        seed_session(&pool, host, "invite_link").await;

        let for_host = visible_sessions(&pool, host).await.unwrap();
        assert!(for_host.is_empty(), "invite_link sessions are reachable only via the link, never listed");
    }

    #[tokio::test]
    async fn list_query_returns_a_direct_session_only_for_host_and_invitee() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        let stranger = seed_user(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();

        let for_mate = visible_sessions(&pool, mate).await.unwrap();
        assert_eq!(for_mate.len(), 1);
        assert_eq!(for_mate[0].id, session_id);
        assert_eq!(for_mate[0].invited_by, Some(host), "invited_by names the host");

        let for_host = visible_sessions(&pool, host).await.unwrap();
        assert_eq!(for_host.len(), 1);
        assert_eq!(for_host[0].invited_by, None, "the host is not their own invitee");

        assert!(visible_sessions(&pool, stranger).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_query_reveals_invitee_ids_only_to_the_host() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();

        let for_host = visible_sessions(&pool, host).await.unwrap();
        assert_eq!(for_host[0].invitee_ids, vec![mate], "the host sees who they invited");

        let for_mate = visible_sessions(&pool, mate).await.unwrap();
        assert!(for_mate[0].invitee_ids.is_empty(), "an invitee must not learn the guest list");
    }

    #[tokio::test]
    async fn a_stranger_sees_no_session_name_until_accepted() {
        let pool = test_pool_or_skip!();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("INSERT INTO terminal_session_invitees (session_id, user_id, invited_by) VALUES ($1, $2, $3)")
            .bind(session_id).bind(stranger).bind(host).execute(&pool).await.unwrap();

        let rows = visible_sessions(&pool, stranger).await.unwrap();
        let row = rows.iter().find(|r| r.id == session_id).expect("the knock must be visible");
        assert!(row.connection_name.is_none(), "a mis-aimed invite leaks a handle, never a hostname");

        sqlx::query("UPDATE terminal_session_invitees SET accepted_at = now() WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(stranger).execute(&pool).await.unwrap();
        let rows = visible_sessions(&pool, stranger).await.unwrap();
        assert!(rows.iter().find(|r| r.id == session_id).unwrap().connection_name.is_some());
    }

    #[tokio::test]
    async fn a_teammate_and_the_host_always_see_the_name() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        sqlx::query("INSERT INTO terminal_session_invitees (session_id, user_id, invited_by) VALUES ($1, $2, $3)")
            .bind(session_id).bind(mate).bind(host).execute(&pool).await.unwrap();

        assert!(visible_sessions(&pool, mate).await.unwrap()
            .iter().find(|r| r.id == session_id).unwrap().connection_name.is_some());
        assert!(visible_sessions(&pool, host).await.unwrap()
            .iter().find(|r| r.id == session_id).unwrap().connection_name.is_some());
    }

    #[tokio::test]
    async fn admission_stamps_acceptance_once() {
        let pool = test_pool_or_skip!();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("INSERT INTO terminal_session_invitees (session_id, user_id, invited_by) VALUES ($1, $2, $3)")
            .bind(session_id).bind(stranger).bind(host).execute(&pool).await.unwrap();

        stamp_acceptance(&pool, session_id, stranger).await;
        let first: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT accepted_at FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(stranger).fetch_one(&pool).await.unwrap();
        assert!(first.is_some());

        stamp_acceptance(&pool, session_id, stranger).await;
        let second: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT accepted_at FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(stranger).fetch_one(&pool).await.unwrap();
        assert_eq!(first, second, "re-joining must not move the acceptance timestamp");
    }

    #[tokio::test]
    async fn end_session_recipients_include_invitees_of_a_vaultless_session() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();

        let recipients = session_end_recipients(&pool, session_id, host).await.unwrap();
        assert_eq!(recipients, vec![mate]);
    }

    #[tokio::test]
    async fn host_disconnect_on_a_vaultless_session_retracts_the_invitees_knock() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();

        // Subscribe after the grant so its `SessionShared` push isn't mistaken
        // for the `SessionEnded` push under test.
        let mut events = notifier.subscribe();
        let (tx, _) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);

        // Simulates the host's WebSocket closing (app quit) rather than a
        // "Stop sharing" click — the path that used to leave `mate` knocking
        // on a session that no longer exists.
        cleanup_participant(&manager, session_id, host, &tx, &pool, &notifier).await;

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("SessionEnded must be pushed within 1s of host disconnect")
            .expect("notifier channel must not close");
        match event {
            crate::sync_notifier::SyncEvent::SessionEnded { recipient, session_id: ended } => {
                assert_eq!(recipient, mate, "the invitee, not the host, is the recipient");
                assert_eq!(ended, session_id);
            }
            other => panic!("expected SessionEnded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn host_disconnect_marks_the_session_ended_in_the_db() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let session_id = seed_session(&pool, host, "direct").await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        let (tx, _) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);

        cleanup_participant(&manager, session_id, host, &tx, &pool, &notifier).await;

        let ended_at: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar("SELECT ended_at FROM terminal_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(ended_at.is_some(), "host disconnect must mark the session ended");
        assert!(manager.sessions.lock().await.get(&session_id).is_none());
    }

    #[tokio::test]
    async fn ending_a_session_clears_its_invitee_grants_but_still_notifies_them() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();

        let mut events = notifier.subscribe();
        fan_out_session_ended(&pool, &notifier, session_id, host).await;

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("SessionEnded must still be pushed after the grant row is deleted")
            .expect("notifier channel must not close");
        match event {
            crate::sync_notifier::SyncEvent::SessionEnded { recipient, session_id: ended } => {
                assert_eq!(recipient, mate);
                assert_eq!(ended, session_id);
            }
            other => panic!("expected SessionEnded, got {other:?}"),
        }

        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_invitees WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0, "ending the session must clear its invitee grants");

        let keys: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_keys WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(keys, 0, "the wrapped keys are grant state too and must go with them");
    }

    #[tokio::test]
    async fn a_guest_leaving_does_not_end_the_session_for_everyone() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        let other = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        add_member(&pool, team, host).await;
        add_member(&pool, team, mate).await;
        add_member(&pool, team, other).await;
        let session_id = seed_session(&pool, host, "direct").await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        // Two invitees: with only the leaver invited, a wrongly fanned-out end
        // would have no recipient left to push to and the assertion below would
        // pass vacuously.
        for invitee in [mate, other] {
            grant_invitee(
                &pool,
                &notifier,
                &manager,
                &knocks(),
                session_id,
                host,
                invitee,
                "wrapped",
            )
            .await
            .unwrap();
        }

        let mut events = notifier.subscribe();
        let (tx, _keep) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);

        // The guest's socket closes, not the host's.
        cleanup_participant(&manager, session_id, mate, &tx, &pool, &notifier).await;

        while let Ok(event) = events.try_recv() {
            assert!(
                !matches!(event, crate::sync_notifier::SyncEvent::SessionEnded { .. }),
                "one guest closing a tab must not end the session for everyone"
            );
        }
        let ended_at: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar("SELECT ended_at FROM terminal_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(ended_at.is_none(), "the session must still be live");
        assert!(manager.sessions.lock().await.contains_key(&session_id));
        let grants: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_invitees WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(grants, 2, "nobody's grant is revoked by a guest disconnecting");
    }

    #[tokio::test]
    async fn host_disconnect_also_clears_the_sessions_invitee_grants() {
        let pool = test_pool_or_skip!();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();
        let (tx, _) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);

        cleanup_participant(&manager, session_id, host, &tx, &pool, &notifier).await;

        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM terminal_session_invitees WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0, "a host disconnect runs the same cleanup helper");
    }

    async fn test_notifier_and_manager(
        session_id: Uuid,
        host: Uuid,
    ) -> (crate::sync_notifier::SyncNotifier, TerminalManager) {
        let notifier = crate::sync_notifier::SyncNotifier::new();
        let manager = TerminalManager::new();
        manager.insert_test_session(session_id, host).await;
        (notifier, manager)
    }

    #[tokio::test]
    async fn grant_invitee_accepts_a_stranger_and_leaves_acceptance_unset() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;

        let outcome = grant_invitee(
            &pool,
            &notifier,
            &manager,
            &knocks(),
            session_id,
            host,
            stranger,
            "wrapped",
        )
        .await
        .unwrap();
        assert_eq!(outcome, GrantOutcome::Granted);

        let accepted: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT accepted_at FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(stranger).fetch_one(&pool).await.unwrap();
        assert!(accepted.is_none(), "a stranger grant is unaccepted until they join");
    }

    #[tokio::test]
    async fn a_teammate_grant_is_accepted_on_creation() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;

        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();
        let accepted: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT accepted_at FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(mate).fetch_one(&pool).await.unwrap();
        assert!(accepted.is_some(), "the shipped teammate path must not change behaviour");
    }

    /// The three stranger outcomes must take the same path through the two
    /// consent reads, so that neither an opt-out nor a block is distinguishable
    /// from a grant — or from each other — by how much work the server did.
    #[tokio::test]
    async fn stranger_consent_reads_both_facts_for_every_outcome() {
        let pool = test_pool_or_skip!();
        let (host, stranger, _) = direct_session_with_stranger(&pool).await;
        assert!(stranger_knock_allowed(&pool, stranger, host).await.unwrap());

        sqlx::query("INSERT INTO user_blocks (blocker_id, blocked_id, expires_at) VALUES ($1, $2, now() + interval '7 days')")
            .bind(stranger).bind(host).execute(&pool).await.unwrap();
        assert!(!stranger_knock_allowed(&pool, stranger, host).await.unwrap());

        // Opted out *and* blocked: the block read still runs, since the opt-out
        // no longer short-circuits it.
        sqlx::query("UPDATE users SET allow_stranger_invites = FALSE WHERE id = $1")
            .bind(stranger).execute(&pool).await.unwrap();
        assert!(!stranger_knock_allowed(&pool, stranger, host).await.unwrap());

        sqlx::query("DELETE FROM user_blocks WHERE blocker_id = $1").bind(stranger).execute(&pool).await.unwrap();
        assert!(!stranger_knock_allowed(&pool, stranger, host).await.unwrap(), "opted out alone still refuses");
    }

    #[tokio::test]
    async fn a_block_suppresses_the_grant_without_reporting_failure() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("INSERT INTO user_blocks (blocker_id, blocked_id, expires_at) VALUES ($1, $2, now() + interval '7 days')")
            .bind(stranger).bind(host).execute(&pool).await.unwrap();

        let outcome = grant_invitee(
            &pool,
            &notifier,
            &manager,
            &knocks(),
            session_id,
            host,
            stranger,
            "wrapped",
        )
        .await
        .expect("a block must look exactly like success to the sender");
        assert_eq!(outcome, GrantOutcome::Suppressed);

        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2",
        )
        .bind(session_id)
        .bind(stranger)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows, 0,
            "no row means no phantom invite holding a guest seat"
        );
    }

    #[tokio::test]
    async fn a_suppressed_knock_still_appears_in_the_hosts_invitee_ids() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("UPDATE users SET allow_stranger_invites = FALSE WHERE id = $1")
            .bind(stranger)
            .execute(&pool)
            .await
            .unwrap();

        let outcome = grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "wrapped")
            .await
            .unwrap();
        assert_eq!(outcome, GrantOutcome::Suppressed);

        // The host's own view must be unable to tell this apart from a real
        // grant, or the missing id would leak the very thing the block hides.
        let for_host = visible_sessions(&pool, host).await.unwrap();
        assert_eq!(for_host[0].invitee_ids, vec![stranger], "a suppressed knock occupies a seat exactly like a real one");
    }

    #[tokio::test]
    async fn a_suppressed_stranger_cannot_see_the_session_themselves() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("UPDATE users SET allow_stranger_invites = FALSE WHERE id = $1")
            .bind(stranger)
            .execute(&pool)
            .await
            .unwrap();

        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "wrapped")
            .await
            .unwrap();

        assert!(
            visible_sessions(&pool, stranger).await.unwrap().is_empty(),
            "the suppressed row must never grant the recipient their own visibility"
        );
    }

    #[tokio::test]
    async fn a_suppressed_stranger_is_not_an_authorized_participant() {
        let pool = test_pool_or_skip!();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        let (notifier, manager) = test_notifier_and_manager(session_id, host).await;
        sqlx::query("INSERT INTO user_blocks (blocker_id, blocked_id, expires_at) VALUES ($1, $2, NULL)")
            .bind(stranger).bind(host).execute(&pool).await.unwrap();

        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "wrapped")
            .await
            .unwrap();

        let invitees = manager.sessions.lock().await.get(&session_id).unwrap().invitees.clone();
        assert!(
            !is_authorized_participant(&pool, session_id, stranger, host, "direct", &[], &[], None, &invitees).await,
            "the suppressed row must not admit the WebSocket"
        );
    }

    #[tokio::test]
    async fn an_expired_block_no_longer_suppresses() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("INSERT INTO user_blocks (blocker_id, blocked_id, expires_at) VALUES ($1, $2, now() - interval '1 day')")
            .bind(stranger).bind(host).execute(&pool).await.unwrap();

        assert_eq!(
            grant_invitee(
                &pool,
                &notifier,
                &manager,
                &knocks(),
                session_id,
                host,
                stranger,
                "wrapped"
            )
            .await
            .unwrap(),
            GrantOutcome::Granted,
        );
    }

    #[tokio::test]
    async fn opting_out_suppresses_the_grant() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("UPDATE users SET allow_stranger_invites = FALSE WHERE id = $1")
            .bind(stranger)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            grant_invitee(
                &pool,
                &notifier,
                &manager,
                &knocks(),
                session_id,
                host,
                stranger,
                "wrapped"
            )
            .await
            .unwrap(),
            GrantOutcome::Suppressed,
        );
    }

    #[tokio::test]
    async fn the_knock_rate_limit_trips_and_teammates_are_exempt() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let limiter =
            crate::rate_limit::KnockRateLimiter(RateLimiter::new(1, Duration::from_secs(3600)));
        let (host, stranger_a, session_id) = direct_session_with_stranger(&pool).await;
        let stranger_b = mk_stranger(&pool).await;

        grant_invitee(
            &pool, &notifier, &manager, &limiter, session_id, host, stranger_a, "w",
        )
        .await
        .unwrap();
        let err = grant_invitee(
            &pool, &notifier, &manager, &limiter, session_id, host, stranger_b, "w",
        )
        .await
        .unwrap_err();
        assert_eq!(err, StatusCode::TOO_MANY_REQUESTS);

        // A teammate invite must not consume or be refused by the stranger budget.
        let (host2, mate, session2) = direct_session_with_teammate(&pool).await;
        grant_invitee(
            &pool, &notifier, &manager, &limiter, session2, host2, mate, "w",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn declining_removes_the_row_the_key_and_live_admission() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "wrapped").await.unwrap();

        decline_invite_inner(&pool, &manager, session_id, stranger, false).await.unwrap();

        let invitees = manager.sessions.lock().await.get(&session_id).map(|s| s.invitees.clone()).unwrap_or_default();
        // Asserted through the admission function, not a row count: a DB-only
        // revoke left live WebSocket access open — the Critical from #66.
        assert!(!is_authorized_participant(&pool, session_id, stranger, host, "direct", &[], &[], None, &invitees).await);

        let keys: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM terminal_session_keys WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(stranger).fetch_one(&pool).await.unwrap();
        assert_eq!(keys, 0);
    }

    #[tokio::test]
    async fn declining_blocks_the_sender_for_seven_days_and_the_next_knock_writes_nothing() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "wrapped").await.unwrap();
        decline_invite_inner(&pool, &manager, session_id, stranger, false).await.unwrap();

        let expires: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT expires_at FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2")
            .bind(stranger).bind(host).fetch_one(&pool).await.unwrap();
        assert!(expires.is_some(), "a plain decline blocks temporarily, not forever");

        assert_eq!(
            grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "w").await.unwrap(),
            GrantOutcome::Suppressed,
        );
    }

    #[tokio::test]
    async fn declining_with_permanent_writes_a_never_expiring_block() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "wrapped").await.unwrap();
        decline_invite_inner(&pool, &manager, session_id, stranger, true).await.unwrap();

        let expires: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT expires_at FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2")
            .bind(stranger).bind(host).fetch_one(&pool).await.unwrap();
        assert!(expires.is_none());
    }

    #[tokio::test]
    async fn host_uninvite_frees_the_seat_and_is_host_only() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "wrapped").await.unwrap();

        assert_eq!(uninvite_inner(&pool, &manager, session_id, stranger, stranger).await.unwrap_err(), StatusCode::FORBIDDEN);
        uninvite_inner(&pool, &manager, session_id, host, stranger).await.unwrap();

        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM terminal_session_invitees WHERE session_id = $1").bind(session_id)
            .fetch_one(&pool).await.unwrap();
        assert_eq!(rows, 0, "a pending invite must not hold a Pro host's only guest seat");

        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_blocks WHERE blocker_id = $1").bind(stranger)
            .fetch_one(&pool).await.unwrap();
        assert_eq!(blocked, 0, "the host withdrawing is not the invitee blocking");
    }

    #[tokio::test]
    async fn host_uninvite_of_a_suppressed_entry_clears_it_from_invitee_ids() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("UPDATE users SET allow_stranger_invites = FALSE WHERE id = $1")
            .bind(stranger)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "w").await.unwrap(),
            GrantOutcome::Suppressed,
        );

        let before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM suppressed_invites WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(stranger).fetch_one(&pool).await.unwrap();
        assert_eq!(before, 1);

        uninvite_inner(&pool, &manager, session_id, host, stranger).await.unwrap();

        // A suppressed knock never wrote an invitee row, but it still occupies a
        // seat in the host's invitee_ids (see `visible_sessions`) — un-invite must
        // clear the suppressed_invites row too, or the seat leaks forever.
        let after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM suppressed_invites WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(stranger).fetch_one(&pool).await.unwrap();
        assert_eq!(after, 0);
    }

    #[tokio::test]
    async fn departed_member_revoke_clears_the_suppressed_row_too() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, mate, session_id) = direct_session_with_teammate(&pool).await;
        grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, mate, "wrapped")
            .await
            .unwrap();

        // A suppressed row can coexist with a real grant row for the same pair
        // (e.g. an earlier stranger knock, before host and mate shared a team) —
        // seed one directly rather than relying on `grant_invitee` to produce it.
        sqlx::query(
            "INSERT INTO suppressed_invites (session_id, user_id, invited_by) VALUES ($1, $2, $3)",
        )
        .bind(session_id)
        .bind(mate)
        .bind(host)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM team_members WHERE user_id = $1")
            .bind(mate)
            .execute(&pool)
            .await
            .unwrap();

        revoke_grants_for_departed_member(&pool, &manager, mate).await.unwrap();

        let invitees: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM terminal_session_invitees WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(mate).fetch_one(&pool).await.unwrap();
        assert_eq!(invitees, 0);

        let keys: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM terminal_session_keys WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(mate).fetch_one(&pool).await.unwrap();
        assert_eq!(keys, 0);

        let suppressed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM suppressed_invites WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(mate).fetch_one(&pool).await.unwrap();
        assert_eq!(suppressed, 0, "a departed member's suppressed row must not keep the seat occupied");
    }

    #[tokio::test]
    async fn a_knock_carries_the_inviters_handle_from_the_users_table() {
        let pool = test_pool_or_skip!();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("INSERT INTO terminal_session_invitees (session_id, user_id, invited_by) VALUES ($1, $2, $3)")
            .bind(session_id).bind(stranger).bind(host).execute(&pool).await.unwrap();
        let host_handle: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
            .bind(host).fetch_one(&pool).await.unwrap();

        let rows = visible_sessions(&pool, stranger).await.unwrap();
        let row = rows.iter().find(|r| r.id == session_id).expect("the knock must be visible");
        assert_eq!(
            row.invited_by_handle.as_deref(),
            Some(host_handle.as_str()),
            "the knock's identity is the server-owned handle, not anything the sender supplies",
        );

        // The host is nobody's invitee, so their own row carries no inviter.
        let for_host = visible_sessions(&pool, host).await.unwrap();
        assert!(for_host.iter().find(|r| r.id == session_id).unwrap().invited_by_handle.is_none());
    }

    #[tokio::test]
    async fn ending_a_session_clears_the_suppressed_rows_too() {
        let pool = test_pool_or_skip!();
        let (notifier, manager) = harness();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("UPDATE users SET allow_stranger_invites = FALSE WHERE id = $1")
            .bind(stranger)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            grant_invitee(&pool, &notifier, &manager, &knocks(), session_id, host, stranger, "w").await.unwrap(),
            GrantOutcome::Suppressed,
        );

        // A soft end never fires ON DELETE CASCADE, so a row saying "this
        // recipient blocked or opted out of this sender" would otherwise outlive
        // the session forever — the social-graph record D9 refused to create.
        sqlx::query("UPDATE terminal_sessions SET ended_at = now() WHERE id = $1")
            .bind(session_id)
            .execute(&pool)
            .await
            .unwrap();
        fan_out_session_ended(&pool, &notifier, session_id, host).await;

        let suppressed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM suppressed_invites WHERE session_id = $1")
            .bind(session_id).fetch_one(&pool).await.unwrap();
        assert_eq!(suppressed, 0);
    }

    #[tokio::test]
    async fn an_unaccepted_stranger_sees_no_participant_names() {
        let pool = test_pool_or_skip!();
        let (host, stranger, session_id) = direct_session_with_stranger(&pool).await;
        sqlx::query("INSERT INTO terminal_session_invitees (session_id, user_id, invited_by) VALUES ($1, $2, $3)")
            .bind(session_id).bind(stranger).bind(host).execute(&pool).await.unwrap();

        let manager = TerminalManager::new();
        manager.insert_test_session(session_id, host).await;
        manager.sessions.lock().await.get_mut(&session_id).unwrap().participants.insert(
            host,
            Participant::new(host, "real-hostname-owner".to_string()),
        );

        let Json(sessions) = list_active_sessions(
            State(pool.clone()),
            Extension(AuthUser(stranger)),
            Extension(manager.clone()),
        )
        .await
        .unwrap();
        let row = sessions.iter().find(|s| s.id == session_id).expect("the knock must be listed");
        assert!(row.connection_name.is_none());
        assert!(row.participants.is_empty(), "D7 leaks a handle, never who is already in the room");
        assert_eq!(row.participant_count, 0);

        // Accepting un-redacts the whole row, participants included.
        sqlx::query("UPDATE terminal_session_invitees SET accepted_at = now() WHERE session_id = $1 AND user_id = $2")
            .bind(session_id).bind(stranger).execute(&pool).await.unwrap();
        let Json(sessions) =
            list_active_sessions(State(pool), Extension(AuthUser(stranger)), Extension(manager))
                .await
                .unwrap();
        let row = sessions.iter().find(|s| s.id == session_id).unwrap();
        assert_eq!(row.participant_count, 1);
    }

    #[tokio::test]
    async fn the_participant_handle_comes_from_the_database_not_the_caller() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;
        // Handles are unique and never recycled, so a fixed literal collides
        // on a second run against a persistent test database.
        let handle = crate::test_support::unique_handle("merry-quartz");

        sqlx::query("UPDATE users SET handle = $1 WHERE id = $2")
            .bind(&handle)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();

        // The caller cannot influence this value: there is no argument for them to set.
        let resolved = resolve_participant_handle(&pool, user).await;
        assert_eq!(resolved, handle);
    }

    #[tokio::test]
    async fn an_unknown_user_resolves_to_its_id_rather_than_failing_the_upgrade() {
        let pool = test_pool_or_skip!();
        let ghost = Uuid::new_v4();
        assert_eq!(resolve_participant_handle(&pool, ghost).await, ghost.to_string());
    }

    #[test]
    fn a_participant_carries_its_handle_in_both_json_keys() {
        let id = Uuid::new_v4();
        let p = Participant::new(id, "merry-quartz-2597".to_string());
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["handle"], "merry-quartz-2597");
        // The alias pre-0.26 clients read. Deleted in 0.27.
        assert_eq!(json["display_name"], "merry-quartz-2597");
    }

    #[tokio::test]
    async fn a_guest_grant_authorizes_the_key_endpoint_and_the_ws_upgrade() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let guest = seed_user(&pool).await;
        let session = seed_session(&pool, host, "invite_link").await;
        let secret = format!("fake-grant-secret-{}", Uuid::new_v4());

        sqlx::query("UPDATE terminal_sessions SET session_key_bytes = 'fake-key-bytes' WHERE id = $1")
            .bind(session)
            .execute(&pool)
            .await
            .unwrap();
        crate::session_grants::insert_grant(
            &pool, session, "guest", &secret, None, host, Some(guest),
        )
        .await
        .unwrap();

        let key = get_my_session_key(
            State(pool.clone()),
            Extension(AuthUser(guest)),
            axum::extract::Path(session),
            axum::extract::Query(GetKeyQuery {
                invite_token: Some(secret.clone()),
            }),
        )
        .await
        .expect("a guest grant unlocks the raw key");
        assert!(key.0.raw_key.is_some());

        assert!(
            is_authorized_participant(
                &pool, session, guest, host, "invite_link", &[], &[],
                Some(secret.as_str()),
                &std::collections::HashSet::new(),
            )
            .await
        );
    }

    #[tokio::test]
    async fn a_revoked_guest_grant_stops_authorizing() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let guest = seed_user(&pool).await;
        let other_guest = seed_user(&pool).await;
        let session = seed_session(&pool, host, "invite_link").await;
        let revoked_secret = format!("fake-grant-secret-{}", Uuid::new_v4());
        let live_secret = format!("fake-grant-secret-{}", Uuid::new_v4());

        crate::session_grants::insert_grant(
            &pool, session, "guest", &revoked_secret, None, host, Some(guest),
        )
        .await
        .unwrap();
        crate::session_grants::insert_grant(
            &pool, session, "guest", &live_secret, None, host, Some(other_guest),
        )
        .await
        .unwrap();

        // Revoke by secret_hash, not by session: proves the per-guest grant
        // this design exists for, not "revoking the session locks everyone out".
        sqlx::query("UPDATE terminal_session_grants SET revoked_at = now() WHERE secret_hash = $1")
            .bind(crate::session_grants::hash_secret(&revoked_secret))
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            !is_authorized_participant(
                &pool, session, guest, host, "invite_link", &[], &[],
                Some(revoked_secret.as_str()),
                &std::collections::HashSet::new(),
            )
            .await,
            "revoking one guest's grant must lock that guest out"
        );
        assert!(
            is_authorized_participant(
                &pool, session, other_guest, host, "invite_link", &[], &[],
                Some(live_secret.as_str()),
                &std::collections::HashSet::new(),
            )
            .await,
            "a different guest's grant on the same session must keep working"
        );
    }
}
