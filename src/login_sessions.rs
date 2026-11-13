use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

pub const LIFETIME: Duration = Duration::days(90);

const LIVE: &str =
    "s.expires_at > now() AND s.token_version = (SELECT u.token_version FROM users u WHERE u.id = s.user_id)";

/// What a client says about itself when signing in. Shown to the user, never trusted.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct Device {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub client: Option<String>,
}

fn label(value: &Option<String>, max: usize) -> Option<String> {
    let cleaned: String = value
        .as_deref()?
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SessionInfo {
    pub id: Uuid,
    pub device_name: Option<String>,
    pub platform: Option<String>,
    pub client: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub current: bool,
}

/// Opens a session at the user's current token version, dropping the user's dead rows on the way.
pub async fn open(pool: &PgPool, user_id: Uuid, device: &Device) -> Result<Uuid, sqlx::Error> {
    sqlx::query(&format!(
        "DELETE FROM login_sessions s WHERE s.user_id = $1 AND NOT ({LIVE})"
    ))
    .bind(user_id)
    .execute(pool)
    .await?;
    sqlx::query_scalar(
        "INSERT INTO login_sessions (user_id, token_version, device_name, platform, client, expires_at)
         SELECT id, token_version, $2, $3, $4, now() + make_interval(days => $5) FROM users WHERE id = $1
         RETURNING id",
    )
    .bind(user_id)
    .bind(label(&device.name, 64))
    .bind(label(&device.platform, 32))
    .bind(label(&device.client, 16))
    .bind(LIFETIME.num_days() as i32)
    .fetch_one(pool)
    .await
}

pub async fn is_live(pool: &PgPool, user_id: Uuid, session_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM login_sessions s WHERE s.id = $1 AND s.user_id = $2 AND {LIVE})"
    ))
    .bind(session_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
}

pub async fn touch(pool: &PgPool, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE login_sessions SET last_seen_at = now() WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await
        .map(drop)
}

/// Moves the caller's own session to the token version it just bumped, so only the others die.
pub async fn keep<'e>(
    ex: impl sqlx::PgExecutor<'e>,
    user_id: Uuid,
    current: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let Some(session_id) = current else {
        return Ok(false);
    };
    let kept = sqlx::query(
        "UPDATE login_sessions s SET token_version = u.token_version
         FROM users u WHERE s.id = $1 AND s.user_id = $2 AND u.id = s.user_id AND s.expires_at > now()",
    )
    .bind(session_id)
    .bind(user_id)
    .execute(ex)
    .await?;
    Ok(kept.rows_affected() == 1)
}

pub async fn list(
    pool: &PgPool,
    user_id: Uuid,
    current: Option<Uuid>,
) -> Result<Vec<SessionInfo>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT s.id, s.device_name, s.platform, s.client, s.created_at, s.last_seen_at, (s.id = $2) IS TRUE AS current
         FROM login_sessions s WHERE s.user_id = $1 AND {LIVE}
         ORDER BY current DESC, s.last_seen_at DESC"
    ))
    .bind(user_id)
    .bind(current)
    .fetch_all(pool)
    .await
}

pub async fn end(pool: &PgPool, user_id: Uuid, session_id: Uuid) -> Result<bool, sqlx::Error> {
    let ended = sqlx::query("DELETE FROM login_sessions WHERE id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(ended.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_trimmed_capped_and_stripped_of_control_characters() {
        assert_eq!(
            label(&Some("  lap\u{7}top \n".into()), 64).as_deref(),
            Some("laptop")
        );
        assert_eq!(label(&Some("x".repeat(100)), 64).map(|s| s.len()), Some(64));
        assert_eq!(label(&Some("   ".into()), 64), None);
        assert_eq!(label(&None, 64), None);
    }
}
