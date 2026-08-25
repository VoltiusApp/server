//! Team join grants: server-side, revocable, expiring, multi-use objects that
//! admit a redeemer into a team as a member.
//!
//! Why a server-side object and not a self-contained token: a team vault is
//! end-to-end encrypted and its key is wrapped per member with X25519, so a
//! link can never carry vault *access* — only *membership*, with the key
//! following separately once an online key-holder wraps it. A self-contained
//! token would also be unrevocable, and a revoked-in-DB grant that still
//! authorised has bitten this project before.
//!
//! Resolution here is deliberately kind-specific: every lookup is scoped to
//! `team_join_grants` AND to a caller-supplied grant id. There is no
//! "find any grant by secret" helper, and none is shared with
//! [`crate::session_grants`] — a code minted for one purpose being redeemable
//! on another path is exactly the bug that produced that rule.

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use sqlx::PgPool;
use uuid::Uuid;

// Only the pure sha256 of a secret is shared with session grants. Sharing a
// hash function is not sharing a resolver: nothing in this module can reach a
// `terminal_session_grants` row, and nothing there can reach one of ours.
use crate::session_grants::hash_secret;

/// Ceiling on a grant's lifetime. A link is unattended credential material, so
/// it expires whether or not the creator remembers to revoke it.
pub const MAX_TTL_SECS: i64 = 30 * 24 * 3600;
pub const DEFAULT_TTL_SECS: i64 = 7 * 24 * 3600;
pub const MAX_USES_CEILING: i32 = 500;

/// Builtin roles a grant may confer. `owner` is absent on purpose: a link that
/// mints owners is a privilege-escalation primitive, and the creator gate
/// (PERM_INVITE_MEMBERS) is held by managers who are not owners themselves.
pub const GRANTABLE_ROLES: &[&str] = &["manager", "editor", "member", "connect-only"];

pub fn is_grantable_role(role: &str) -> bool {
    GRANTABLE_ROLES.contains(&role)
}

/// 256 bits of URL-safe randomness. Longer than the session-grant token
/// because this one travels in a shareable link with a multi-day life.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Clamp a requested TTL into `[60, MAX_TTL_SECS]`, defaulting when absent.
pub fn clamp_ttl(requested: Option<i64>) -> Duration {
    let secs = requested
        .unwrap_or(DEFAULT_TTL_SECS)
        .clamp(60, MAX_TTL_SECS);
    Duration::seconds(secs)
}

/// Clamp a requested use count into `[1, MAX_USES_CEILING]`, defaulting to 1.
pub fn clamp_max_uses(requested: Option<i32>) -> i32 {
    requested.unwrap_or(1).clamp(1, MAX_USES_CEILING)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GrantRow {
    pub id: Uuid,
    pub role: String,
    pub max_uses: i32,
    pub uses: i32,
    pub expires_at: DateTime<Utc>,
    pub created_by: Uuid,
}

pub async fn create(
    pool: &PgPool,
    team_id: Uuid,
    role: &str,
    max_uses: i32,
    ttl: Duration,
    created_by: Uuid,
) -> Result<(GrantRow, String), sqlx::Error> {
    let secret = generate_secret();
    let expires_at = Utc::now() + ttl;

    let (id, created_at_role): (Uuid, String) = sqlx::query_as(
        "INSERT INTO team_join_grants \
         (team_id, secret_hash, role, max_uses, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, role",
    )
    .bind(team_id)
    .bind(hash_secret(&secret))
    .bind(role)
    .bind(max_uses)
    .bind(expires_at)
    .bind(created_by)
    .fetch_one(pool)
    .await?;

    Ok((
        GrantRow {
            id,
            role: created_at_role,
            max_uses,
            uses: 0,
            expires_at,
            created_by,
        },
        secret,
    ))
}

/// Live grants only: revoked and expired rows are history, not offers.
pub async fn list_live(pool: &PgPool, team_id: Uuid) -> Result<Vec<GrantRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (Uuid, String, i32, i32, DateTime<Utc>, Uuid)>(
        "SELECT id, role, max_uses, uses, expires_at, created_by \
         FROM team_join_grants \
         WHERE team_id = $1 AND revoked_at IS NULL AND expires_at > now() \
         ORDER BY created_at DESC",
    )
    .bind(team_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, role, max_uses, uses, expires_at, created_by)| GrantRow {
            id,
            role,
            max_uses,
            uses,
            expires_at,
            created_by,
        })
        .collect())
}

/// Returns true when this call was the one that revoked it. Scoped to
/// `team_id` so a grant id alone can never be revoked from another team.
pub async fn revoke(pool: &PgPool, team_id: Uuid, grant_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE team_join_grants SET revoked_at = now() \
         WHERE id = $1 AND team_id = $2 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .bind(team_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// What a grant looks like to someone holding its secret, before they commit
/// to joining. Carries no member list, no key material and no account_id.
#[derive(Debug)]
pub struct GrantPreview {
    pub team_name: String,
    pub role: String,
    pub inviter_handle: Option<String>,
}

/// Why the live path refused. Kept distinct from "no such grant" so a holder
/// of a real secret gets an honest reason; a non-holder cannot reach these at
/// all, since every variant requires the secret hash to have matched.
#[derive(Debug, PartialEq, Eq)]
pub enum GrantRejection {
    /// Wrong id, wrong secret, or both. Deliberately indistinguishable.
    NotFound,
    Revoked,
    Expired,
    Exhausted,
}

/// Read-only resolution for preview. Revocation and expiry are re-checked here
/// and again at redemption inside the consuming transaction — nothing caches a
/// resolved grant between the two.
pub async fn preview(
    pool: &PgPool,
    grant_id: Uuid,
    presented: &str,
) -> Result<GrantPreview, GrantRejection> {
    let row = sqlx::query_as::<_, (String, String, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>, i32, i32)>(
        "SELECT t.name, g.role, u.handle, g.revoked_at, g.expires_at, g.uses, g.max_uses \
         FROM team_join_grants g \
         JOIN teams t ON t.id = g.team_id \
         LEFT JOIN users u ON u.id = g.created_by \
         WHERE g.id = $1 AND g.secret_hash = $2",
    )
    .bind(grant_id)
    .bind(hash_secret(presented))
    .fetch_optional(pool)
    .await
    .map_err(|_| GrantRejection::NotFound)?
    .ok_or(GrantRejection::NotFound)?;

    let (team_name, role, inviter_handle, revoked_at, expires_at, uses, max_uses) = row;

    if revoked_at.is_some() {
        return Err(GrantRejection::Revoked);
    }
    if expires_at <= Utc::now() {
        return Err(GrantRejection::Expired);
    }
    if uses >= max_uses {
        return Err(GrantRejection::Exhausted);
    }

    Ok(GrantPreview {
        team_name,
        role,
        inviter_handle,
    })
}

/// A grant that has been locked for redemption. `already_member` decides
/// whether the caller consumes a use or takes the no-op path.
pub struct LockedGrant {
    pub team_id: Uuid,
    pub team_name: String,
    pub role: String,
    pub created_by: Uuid,
    pub already_member: bool,
}

/// Lock the grant row and validate it, inside the caller's transaction.
///
/// `SELECT ... FOR UPDATE` is what makes the last use safe: two redemptions of
/// the same grant serialize on this lock, and the loser re-reads the row after
/// the winner commits, so it sees `uses = max_uses` and is refused. Reading
/// without the lock would let both pass the check and both consume.
pub async fn lock_for_redemption(
    tx: &mut sqlx::PgConnection,
    grant_id: Uuid,
    presented: &str,
    redeemer: Uuid,
) -> Result<LockedGrant, GrantRejection> {
    let row = sqlx::query_as::<_, (Uuid, String, String, Uuid, Option<DateTime<Utc>>, DateTime<Utc>, i32, i32, bool)>(
        "SELECT g.team_id, t.name, g.role, g.created_by, g.revoked_at, g.expires_at, g.uses, g.max_uses, \
                EXISTS(SELECT 1 FROM team_members m WHERE m.team_id = g.team_id AND m.user_id = $3) \
         FROM team_join_grants g \
         JOIN teams t ON t.id = g.team_id \
         WHERE g.id = $1 AND g.secret_hash = $2 \
         FOR UPDATE OF g",
    )
    .bind(grant_id)
    .bind(hash_secret(presented))
    .bind(redeemer)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| GrantRejection::NotFound)?
    .ok_or(GrantRejection::NotFound)?;

    let (team_id, team_name, role, created_by, revoked_at, expires_at, uses, max_uses, already_member) =
        row;

    // Checked on the live path, every time, against the freshly locked row —
    // not against anything a resolver or cache decided earlier.
    if revoked_at.is_some() {
        return Err(GrantRejection::Revoked);
    }
    if expires_at <= Utc::now() {
        return Err(GrantRejection::Expired);
    }
    // An existing member consumes nothing, so exhaustion does not apply to
    // them: their redemption is a no-op success, not an offer being taken.
    if !already_member && uses >= max_uses {
        return Err(GrantRejection::Exhausted);
    }

    Ok(LockedGrant {
        team_id,
        team_name,
        role,
        created_by,
        already_member,
    })
}

/// Consume one use of a locked grant. The conditions are re-stated in the
/// UPDATE itself so validity and consumption are one statement: there is no
/// window in which a grant is judged good and then incremented separately.
pub async fn consume_use(
    tx: &mut sqlx::PgConnection,
    grant_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE team_join_grants SET uses = uses + 1 \
         WHERE id = $1 AND revoked_at IS NULL AND expires_at > now() AND uses < max_uses",
    )
    .bind(grant_id)
    .execute(&mut *tx)
    .await?;

    Ok(result.rows_affected() > 0)
}
