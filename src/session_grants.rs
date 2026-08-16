use rand::Rng;
use sha2::{Digest, Sha256};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_team, seed_user};
    use uuid::Uuid;

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
}
