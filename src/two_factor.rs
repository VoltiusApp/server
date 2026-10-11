//! Optional TOTP second factor: seed encryption, code checks, recovery codes.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, warn};
use uuid::Uuid;

use crate::routes::coded_error;

const STEP_SECONDS: i64 = 30;
const NONCE_LEN: usize = 24;
const MAX_FAILED_ATTEMPTS: i32 = 5;
const LOCK_MINUTES: i32 = 15;
pub const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Seals TOTP seeds with `TOTP_ENC_KEY`. Without the key the server offers no enrolment.
#[derive(Clone)]
pub struct SeedCipher(Option<Arc<XChaCha20Poly1305>>);

impl SeedCipher {
    pub fn from_env() -> Self {
        Self::parse(std::env::var("TOTP_ENC_KEY").ok().as_deref())
            .unwrap_or_else(|why| panic!("TOTP_ENC_KEY {why} (expected 32 bytes, base64)"))
    }

    fn parse(value: Option<&str>) -> Result<Self, &'static str> {
        let Some(encoded) = value.map(str::trim).filter(|v| !v.is_empty()) else {
            return Ok(Self(None));
        };
        let key = B64.decode(encoded).map_err(|_| "is not valid base64")?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| "is not 32 bytes long")?;
        Ok(Self(Some(Arc::new(cipher))))
    }

    pub fn available(&self) -> bool {
        self.0.is_some()
    }

    pub fn seal(&self, seed: &[u8]) -> Option<String> {
        let cipher = self.0.as_ref()?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut sealed = nonce.to_vec();
        sealed.extend(cipher.encrypt(&nonce, seed).ok()?);
        Some(B64.encode(sealed))
    }

    fn open(&self, sealed: &str) -> Option<Vec<u8>> {
        let cipher = self.0.as_ref()?;
        let bytes = B64.decode(sealed).ok()?;
        if bytes.len() <= NONCE_LEN {
            return None;
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        cipher.decrypt(XNonce::from_slice(nonce), ciphertext).ok()
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self::parse(Some(&B64.encode([7u8; 32]))).unwrap()
    }

    #[cfg(test)]
    pub fn absent() -> Self {
        Self(None)
    }
}

pub fn generate_seed() -> [u8; 20] {
    let mut seed = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

pub fn seed_base32(seed: &[u8]) -> String {
    BASE32_NOPAD.encode(seed)
}

pub fn otpauth_uri(seed: &[u8], email: &str) -> String {
    let label: String = email
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect();
    format!(
        "otpauth://totp/Voltius:{label}?secret={}&issuer=Voltius&algorithm=SHA1&digits=6&period={STEP_SECONDS}",
        seed_base32(seed)
    )
}

pub fn current_step() -> i64 {
    Utc::now().timestamp() / STEP_SECONDS
}

pub fn totp_at(seed: &[u8], step: i64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(seed).expect("hmac accepts any key length");
    mac.update(&(step as u64).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([digest[offset], digest[offset + 1], digest[offset + 2], digest[offset + 3]])
        & 0x7fff_ffff;
    format!("{:06}", binary % 1_000_000)
}

fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn matching_step(seed: &[u8], code: &str, now_step: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    (now_step - 1..=now_step + 1).find(|step| same_bytes(totp_at(seed, *step).as_bytes(), code.as_bytes()))
}

pub fn generate_recovery_codes() -> Vec<String> {
    let mut rng = rand::rngs::OsRng;
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let chars: Vec<char> = (0..16)
                .map(|_| RECOVERY_ALPHABET[(rng.next_u32() as usize) % RECOVERY_ALPHABET.len()] as char)
                .collect();
            chars.chunks(4).map(|group| group.iter().collect::<String>()).collect::<Vec<_>>().join("-")
        })
        .collect()
}

fn hash_recovery_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

#[derive(Deserialize, Default)]
pub struct SecondFactorProof {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub recovery_code: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Required,
    Invalid,
    Locked,
    Unavailable,
    AlreadyEnabled,
    NotEnabled,
    Status(StatusCode),
}

impl From<StatusCode> for Refusal {
    fn from(status: StatusCode) -> Self {
        Refusal::Status(status)
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Refusal::Required => coded_error(StatusCode::PRECONDITION_REQUIRED, "TWO_FACTOR_REQUIRED"),
            Refusal::Invalid => coded_error(StatusCode::UNAUTHORIZED, "TWO_FACTOR_INVALID"),
            Refusal::Locked => coded_error(StatusCode::TOO_MANY_REQUESTS, "TWO_FACTOR_LOCKED"),
            Refusal::Unavailable => coded_error(StatusCode::SERVICE_UNAVAILABLE, "TWO_FACTOR_UNAVAILABLE"),
            Refusal::AlreadyEnabled => coded_error(StatusCode::CONFLICT, "TWO_FACTOR_ALREADY_ENABLED"),
            Refusal::NotEnabled => coded_error(StatusCode::CONFLICT, "TWO_FACTOR_NOT_ENABLED"),
            Refusal::Status(status) => status.into_response(),
        }
    }
}

pub fn db_failure(err: sqlx::Error) -> Refusal {
    error!(error = %err, "Two-factor query failed");
    Refusal::Status(StatusCode::INTERNAL_SERVER_ERROR)
}

/// What a sign-in challenge may offer: a code needs the seed key, a recovery code never does.
pub fn methods(cipher: &SeedCipher) -> Vec<&'static str> {
    if cipher.available() {
        vec!["totp", "recovery"]
    } else {
        vec!["recovery"]
    }
}

pub async fn is_enabled(pool: &PgPool, user_id: Uuid) -> Result<bool, Refusal> {
    sqlx::query_scalar("SELECT totp_enabled_at IS NOT NULL FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(db_failure)
}

/// The step every sensitive change takes once the account has a second factor.
pub async fn verify_if_enabled(
    pool: &PgPool,
    cipher: &SeedCipher,
    user_id: Uuid,
    proof: &SecondFactorProof,
) -> Result<(), Refusal> {
    if is_enabled(pool, user_id).await? {
        verify(pool, cipher, user_id, proof).await?;
    }
    Ok(())
}

pub async fn verify(
    pool: &PgPool,
    cipher: &SeedCipher,
    user_id: Uuid,
    proof: &SecondFactorProof,
) -> Result<(), Refusal> {
    verify_at(pool, cipher, user_id, proof, current_step()).await
}

/// Checks the stored seed whether or not it is enabled yet, so enrolment confirms through the same path.
pub async fn verify_at(
    pool: &PgPool,
    cipher: &SeedCipher,
    user_id: Uuid,
    proof: &SecondFactorProof,
    now_step: i64,
) -> Result<(), Refusal> {
    // A client that predates the feature sends nothing: that is not a wrong guess.
    if proof.code.is_none() && proof.recovery_code.is_none() {
        return Err(Refusal::Required);
    }
    let mut tx = pool.begin().await.map_err(db_failure)?;
    let (sealed, last_step, locked): (Option<String>, Option<i64>, bool) = sqlx::query_as(
        "SELECT totp_secret, totp_last_step, COALESCE(totp_locked_until > now(), FALSE)
         FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_failure)?;

    if locked {
        return Err(Refusal::Locked);
    }

    let accepted_step = if let Some(recovery_code) = &proof.recovery_code {
        let spent = sqlx::query(
            "UPDATE user_recovery_codes SET used_at = now()
             WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
        )
        .bind(user_id)
        .bind(hash_recovery_code(recovery_code))
        .execute(&mut *tx)
        .await
        .map_err(db_failure)?;
        (spent.rows_affected() == 1).then_some(last_step)
    } else if let Some(code) = &proof.code {
        match sealed {
            Some(sealed) => {
                let seed = cipher.open(&sealed).ok_or(Refusal::Unavailable)?;
                matching_step(&seed, code, now_step)
                    .filter(|step| last_step.is_none_or(|last| *step > last))
                    .map(Some)
            }
            None => None,
        }
    } else {
        None
    };

    let outcome = match accepted_step {
        Some(step) => {
            sqlx::query("UPDATE users SET totp_failed_attempts = 0, totp_last_step = $2 WHERE id = $1")
                .bind(user_id)
                .bind(step)
                .execute(&mut *tx)
                .await
                .map_err(db_failure)?;
            Ok(())
        }
        None => {
            sqlx::query(
                "UPDATE users SET
                   totp_locked_until = CASE WHEN totp_failed_attempts + 1 >= $2
                     THEN now() + make_interval(mins => $3) ELSE totp_locked_until END,
                   totp_failed_attempts = CASE WHEN totp_failed_attempts + 1 >= $2
                     THEN 0 ELSE totp_failed_attempts + 1 END
                 WHERE id = $1",
            )
            .bind(user_id)
            .bind(MAX_FAILED_ATTEMPTS)
            .bind(LOCK_MINUTES)
            .execute(&mut *tx)
            .await
            .map_err(db_failure)?;
            warn!(user_id = %user_id, "Second factor rejected");
            Err(Refusal::Invalid)
        }
    };
    tx.commit().await.map_err(db_failure)?;
    outcome
}

pub async fn replace_recovery_codes(
    tx: &mut sqlx::PgConnection,
    user_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    let codes = generate_recovery_codes();
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let hashes: Vec<String> = codes.iter().map(|code| hash_recovery_code(code)).collect();
    sqlx::query("INSERT INTO user_recovery_codes (user_id, code_hash) SELECT $1, unnest($2::text[])")
        .bind(user_id)
        .bind(&hashes)
        .execute(&mut *tx)
        .await?;
    Ok(codes)
}

pub async fn clear(tx: &mut sqlx::PgConnection, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let cleared = sqlx::query(
        "UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL,
                totp_failed_attempts = 0, totp_locked_until = NULL, token_version = token_version + 1
         WHERE id = $1 AND totp_enabled_at IS NOT NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    Ok(cleared.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, SHA-1 rows, truncated to six digits.
    #[test]
    fn totp_matches_the_rfc_vectors() {
        let seed = b"12345678901234567890";
        for (time, code) in [(59, "287082"), (1_111_111_109, "081804"), (1_234_567_890, "005924"), (20_000_000_000, "353130")] {
            assert_eq!(totp_at(seed, time / STEP_SECONDS), code);
        }
    }

    #[test]
    fn a_code_matches_only_within_one_step() {
        let seed = generate_seed();
        for (offset, accepted) in [(-2, false), (-1, true), (0, true), (1, true), (2, false)] {
            let code = totp_at(&seed, 1000 + offset);
            assert_eq!(matching_step(&seed, &code, 1000).is_some(), accepted, "offset {offset}");
        }
        assert_eq!(matching_step(&seed, &format!(" {} ", totp_at(&seed, 1000)), 1000), Some(1000));
    }

    #[test]
    fn a_sealed_seed_opens_only_under_its_key() {
        let cipher = SeedCipher::for_tests();
        let seed = generate_seed();
        let sealed = cipher.seal(&seed).unwrap();

        assert_eq!(cipher.open(&sealed).as_deref(), Some(&seed[..]));
        assert_ne!(cipher.seal(&seed).unwrap(), sealed);
        let other = SeedCipher::parse(Some(&B64.encode([8u8; 32]))).unwrap();
        assert_eq!(other.open(&sealed), None);
        assert_eq!(SeedCipher::absent().seal(&seed), None);
    }

    #[test]
    fn a_malformed_key_is_refused_and_an_empty_one_means_off() {
        assert!(!SeedCipher::parse(None).unwrap().available());
        assert!(!SeedCipher::parse(Some("  ")).unwrap().available());
        assert!(SeedCipher::parse(Some("not base64!")).is_err());
        assert!(SeedCipher::parse(Some(&B64.encode([1u8; 16]))).is_err());
    }

    #[test]
    fn recovery_codes_hash_the_same_however_they_are_typed() {
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let code = &codes[0];
        assert_eq!(code.len(), 19);
        assert_eq!(hash_recovery_code(code), hash_recovery_code(&code.replace('-', " ").to_uppercase()));
        assert_ne!(hash_recovery_code(code), hash_recovery_code(&codes[1]));
    }

    #[test]
    fn the_otpauth_uri_escapes_the_address() {
        let uri = otpauth_uri(b"12345678901234567890", "a+b@example.com");
        assert!(uri.starts_with("otpauth://totp/Voltius:a%2Bb%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Voltius"));
    }
}
