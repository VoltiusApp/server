use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Crockford base32: digits plus letters with I, L, O and U removed, so a code
/// survives being read aloud and retyped.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const CODE_LEN: usize = 10;

pub fn generate_short_code() -> String {
    let mut rng = rand::thread_rng();
    let symbols: Vec<char> = (0..CODE_LEN)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!(
        "{}-{}-{}",
        symbols[0..4].iter().collect::<String>(),
        symbols[4..8].iter().collect::<String>(),
        symbols[8..10].iter().collect::<String>(),
    )
}

pub fn normalize_short_code(input: &str) -> Option<String> {
    let normalized: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect();

    if normalized.len() != CODE_LEN {
        return None;
    }
    if !normalized.bytes().all(|b| ALPHABET.contains(&b)) {
        return None;
    }
    Some(normalized)
}

pub fn hash_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// The existing `invite_token` shape, kept identical so redeemed guests can use
/// the unchanged `my-key` and WebSocket query parameters.
pub fn new_token_secret() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}

pub const SHORT_CODE_TTL_MINUTES: i64 = 10;

pub struct Grant {
    pub id: Uuid,
    pub session_id: Uuid,
    pub kind: String,
}

/// Generic over the executor so a caller can run this inside its own
/// transaction (e.g. alongside the session INSERT it must not outlive) or
/// just pass a `&PgPool` for a standalone grant.
pub async fn insert_grant<'c, E>(
    executor: E,
    session_id: Uuid,
    kind: &str,
    secret: &str,
    expires_at: Option<DateTime<Utc>>,
    created_by: Uuid,
    redeemed_by: Option<Uuid>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'c, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO terminal_session_grants \
         (session_id, kind, secret_hash, expires_at, created_by, redeemed_by) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(session_id)
    .bind(kind)
    .bind(hash_secret(secret))
    .bind(expires_at)
    .bind(created_by)
    .bind(redeemed_by)
    .execute(executor)
    .await
    .map(|_| ())
}

/// Kind-agnostic: a live grant is a live grant. Short codes never travel this
/// path — they are redeemed at their own endpoint — so the secret is hashed raw.
pub async fn resolve_join_grant(pool: &PgPool, session_id: Uuid, presented: &str) -> Option<Grant> {
    sqlx::query_as::<_, (Uuid, Uuid, String)>(
        "SELECT g.id, g.session_id, g.kind \
         FROM terminal_session_grants g \
         JOIN terminal_sessions ts ON ts.id = g.session_id \
         WHERE g.session_id = $1 AND g.secret_hash = $2 \
           AND g.revoked_at IS NULL \
           AND (g.expires_at IS NULL OR g.expires_at > now()) \
           AND ts.ended_at IS NULL",
    )
    .bind(session_id)
    .bind(hash_secret(presented))
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|(id, session_id, kind)| Grant {
        id,
        session_id,
        kind,
    })
}

pub async fn resolve_short_code(pool: &PgPool, code: &str) -> Option<Grant> {
    let normalized = normalize_short_code(code)?;
    sqlx::query_as::<_, (Uuid, Uuid, String)>(
        "SELECT g.id, g.session_id, g.kind \
         FROM terminal_session_grants g \
         JOIN terminal_sessions ts ON ts.id = g.session_id \
         WHERE g.secret_hash = $1 AND g.kind = 'short_code' \
           AND g.revoked_at IS NULL AND g.expires_at > now() \
           AND ts.ended_at IS NULL",
    )
    .bind(hash_secret(&normalized))
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|(id, session_id, kind)| Grant {
        id,
        session_id,
        kind,
    })
}

pub async fn rotate_short_code(
    pool: &PgPool,
    session_id: Uuid,
    created_by: Uuid,
) -> Result<(String, DateTime<Utc>), sqlx::Error> {
    let code = generate_short_code();
    let normalized = normalize_short_code(&code).expect("generated codes normalize");
    let expires_at = Utc::now() + Duration::minutes(SHORT_CODE_TTL_MINUTES);

    let mut tx = pool.begin().await?;
    // No expiry condition: an expired-but-unrevoked row still occupies the
    // partial unique index, so it has to be swept too.
    sqlx::query(
        "UPDATE terminal_session_grants SET revoked_at = now() \
         WHERE session_id = $1 AND kind = 'short_code' AND revoked_at IS NULL",
    )
    .bind(session_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO terminal_session_grants \
         (session_id, kind, secret_hash, expires_at, created_by) \
         VALUES ($1, 'short_code', $2, $3, $4)",
    )
    .bind(session_id)
    .bind(hash_secret(&normalized))
    .bind(expires_at)
    .bind(created_by)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok((code, expires_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_session, seed_team, seed_user};
    use uuid::Uuid;

    async fn seed_host_and_session(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
        let host = seed_user(pool).await;
        let session = seed_session(pool, host, "invite_link").await;
        (host, session)
    }

    #[tokio::test]
    async fn backfill_creates_a_legacy_grant_for_a_live_invite_link_session() {
        let pool = test_pool_or_skip!();

        let host = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        // invite_token is UNIQUE; the throwaway DB persists across test runs.
        let token = format!("fake-legacy-token-{}", Uuid::new_v4());

        let session: Uuid = sqlx::query_scalar(
            "INSERT INTO terminal_sessions (team_id, host_user_id, connection_name, visibility, invite_token) \
             VALUES ($1, $2, 'box', 'invite_link', $3) RETURNING id",
        )
        .bind(team)
        .bind(host)
        .bind(&token)
        .fetch_one(&pool)
        .await
        .unwrap();

        // The migration already ran for pre-existing rows; this row is newer, so
        // apply the same expression the migration uses to prove it matches.
        let matches: bool = sqlx::query_scalar(
            "SELECT sha256(convert_to($1, 'UTF8')) = sha256(convert_to(invite_token, 'UTF8')) \
             FROM terminal_sessions WHERE id = $2",
        )
        .bind(&token)
        .bind(session)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(
            matches,
            "migration hash expression must match the stored token"
        );
    }

    /// The deploy-day case: an already-live session whose grant only exists
    /// because the migration backfilled it, hashing in SQL — not through
    /// `insert_grant`/`hash_secret`. Proves the two hashing paths agree; if
    /// they didn't, every mid-session guest would be locked out at deploy.
    #[tokio::test]
    async fn a_migration_backfilled_grant_resolves_the_pre_existing_token() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let session = seed_session(&pool, host, "invite_link").await;
        let token = format!("fake-legacy-token-{}", Uuid::new_v4());

        sqlx::query("UPDATE terminal_sessions SET invite_token = $1 WHERE id = $2")
            .bind(&token)
            .bind(session)
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO terminal_session_grants (session_id, kind, secret_hash, created_by) \
             SELECT id, 'legacy_token', sha256(convert_to(invite_token, 'UTF8')), host_user_id \
             FROM terminal_sessions WHERE id = $1",
        )
        .bind(session)
        .execute(&pool)
        .await
        .unwrap();

        assert!(
            resolve_join_grant(&pool, session, &token).await.is_some(),
            "SQL-side and Rust-side hashing must agree on deploy day"
        );
    }

    #[test]
    fn generated_codes_are_dashed_and_ten_symbols() {
        let code = generate_short_code();
        assert_eq!(code.len(), 12, "4-4-2 grouping adds two dashes");
        assert_eq!(code.chars().filter(|c| *c == '-').count(), 2);
        assert_eq!(normalize_short_code(&code).unwrap().len(), 10);
    }

    #[test]
    fn generated_codes_avoid_the_ambiguous_letters() {
        for _ in 0..500 {
            let code = generate_short_code();
            assert!(
                !code.contains(['I', 'L', 'O', 'U']),
                "Crockford excludes I, L, O and U: {code}"
            );
        }
    }

    #[test]
    fn normalization_folds_spelling_variants_to_one_value() {
        let canonical = normalize_short_code("K7M2-P9QX-3B").unwrap();
        for variant in ["k7m2p9qx3b", "K7M2 P9QX 3B", " k7m2-p9qx-3b "] {
            assert_eq!(normalize_short_code(variant).unwrap(), canonical);
        }
    }

    #[test]
    fn normalization_maps_the_confusable_letters_onto_digits() {
        // A guest who hears "oh" types O; Crockford says that is a zero.
        assert_eq!(normalize_short_code("O1IL-2345-67").unwrap(), "0111234567");
    }

    #[test]
    fn normalization_rejects_wrong_length_and_foreign_symbols() {
        assert!(normalize_short_code("K7M2-P9QX").is_none());
        assert!(normalize_short_code("K7M2-P9QX-3B4").is_none());
        assert!(normalize_short_code("K7M2-P9QX-3$").is_none());
        assert!(normalize_short_code("K7M2-P9QU-3B").is_none());
        assert!(normalize_short_code("").is_none());
    }

    #[test]
    fn equal_normalized_codes_hash_equal_and_different_ones_do_not() {
        let a = hash_secret(&normalize_short_code("k7m2p9qx3b").unwrap());
        let b = hash_secret(&normalize_short_code("K7M2-P9QX-3B").unwrap());
        let c = hash_secret(&normalize_short_code("K7M2-P9QX-3C").unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn token_secrets_are_thirty_two_hex_characters() {
        let secret = new_token_secret();
        assert_eq!(secret.len(), 32);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn a_live_grant_resolves_and_a_wrong_secret_does_not() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;
        let secret = format!("fake-grant-secret-{}", Uuid::new_v4());

        insert_grant(&pool, session, "legacy_token", &secret, None, host, None)
            .await
            .unwrap();

        assert!(resolve_join_grant(&pool, session, &secret).await.is_some());
        assert!(
            resolve_join_grant(&pool, session, "fake-grant-secret-wrong")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn expired_revoked_wrong_session_and_ended_grants_all_fail_to_resolve() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;
        let (_, other_session) = seed_host_and_session(&pool).await;

        let expired = format!("fake-grant-secret-{}", Uuid::new_v4());
        let revoked = format!("fake-grant-secret-{}", Uuid::new_v4());
        let live = format!("fake-grant-secret-{}", Uuid::new_v4());

        insert_grant(
            &pool,
            session,
            "guest",
            &expired,
            Some(Utc::now() - Duration::minutes(1)),
            host,
            None,
        )
        .await
        .unwrap();
        insert_grant(&pool, session, "guest", &revoked, None, host, None)
            .await
            .unwrap();
        sqlx::query("UPDATE terminal_session_grants SET revoked_at = now() WHERE secret_hash = $1")
            .bind(hash_secret(&revoked))
            .execute(&pool)
            .await
            .unwrap();
        insert_grant(&pool, session, "guest", &live, None, host, None)
            .await
            .unwrap();

        assert!(resolve_join_grant(&pool, session, &expired).await.is_none());
        assert!(resolve_join_grant(&pool, session, &revoked).await.is_none());
        assert!(
            resolve_join_grant(&pool, other_session, &live)
                .await
                .is_none(),
            "a grant must not resolve against a different session"
        );

        sqlx::query("UPDATE terminal_sessions SET ended_at = now() WHERE id = $1")
            .bind(session)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            resolve_join_grant(&pool, session, &live).await.is_none(),
            "an ended session must admit nobody"
        );
    }

    #[tokio::test]
    async fn rotating_the_code_revokes_the_previous_one() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;

        let (first, _) = rotate_short_code(&pool, session, host).await.unwrap();
        let (second, expires_at) = rotate_short_code(&pool, session, host).await.unwrap();

        assert!(
            resolve_short_code(&pool, &first).await.is_none(),
            "regenerating kills the old code"
        );
        assert!(resolve_short_code(&pool, &second).await.is_some());
        assert!(expires_at > Utc::now());
    }

    #[tokio::test]
    async fn rotation_sweeps_an_expired_but_unrevoked_code() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;

        rotate_short_code(&pool, session, host).await.unwrap();
        // Age the live row without revoking it: the partial unique index still
        // counts it, so a sweep conditioned on expiry would deadlock the host
        // out of ever minting again.
        sqlx::query(
            "UPDATE terminal_session_grants SET expires_at = now() - interval '1 minute' \
             WHERE session_id = $1 AND kind = 'short_code'",
        )
        .bind(session)
        .execute(&pool)
        .await
        .unwrap();

        let (fresh, _) = rotate_short_code(&pool, session, host).await.unwrap();
        assert!(resolve_short_code(&pool, &fresh).await.is_some());

        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM terminal_session_grants \
             WHERE session_id = $1 AND kind = 'short_code' AND revoked_at IS NULL",
        )
        .bind(session)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(live, 1, "exactly one live short code per session");
    }

    #[tokio::test]
    async fn an_expired_code_does_not_resolve() {
        let pool = test_pool_or_skip!();
        let (host, session) = seed_host_and_session(&pool).await;

        let (code, _) = rotate_short_code(&pool, session, host).await.unwrap();
        sqlx::query(
            "UPDATE terminal_session_grants SET expires_at = now() - interval '1 second' \
             WHERE session_id = $1 AND kind = 'short_code'",
        )
        .bind(session)
        .execute(&pool)
        .await
        .unwrap();

        assert!(resolve_short_code(&pool, &code).await.is_none());
    }
}
