//! Passkeys as a second factor: the relying party, browser ceremonies and the codes they hand back.

use std::sync::Arc;

use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{types::Json, PgConnection, PgPool};
use tracing::{error, warn};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::two_factor::{db_failure, Refusal};

const CEREMONY_MINUTES: i32 = 5;
const MAX_PASSKEYS: usize = 10;
const MAX_NAME_CHARS: usize = 64;
const LOWEST_LOOPBACK_PORT: u16 = 1024;
const MAX_STATE_CHARS: usize = 64;

struct RelyingParty {
    webauthn: Webauthn,
    portal: Url,
}

/// The relying party named by `WEBAUTHN_RP_ID`. Without it the server offers no passkeys.
#[derive(Clone)]
pub struct Passkeys(Option<Arc<RelyingParty>>);

/// Where the browser sends the code once the ceremony is done. `state` comes back with it,
/// so a client can tell its own ceremony from a link someone else forged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReturnTo {
    /// The page that ran the ceremony keeps the code: the portal's own sign-in.
    Inline,
    App {
        #[serde(default)]
        state: String,
    },
    Loopback {
        port: u16,
        #[serde(default)]
        state: String,
    },
}

pub enum Ceremony {
    SignIn { pending_token: String },
    StepUp,
    Register { name: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    SignIn,
    StepUp,
    Register,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Purpose::SignIn => "sign_in",
            Purpose::StepUp => "step_up",
            Purpose::Register => "register",
        }
    }

    fn parse(stored: &str) -> Option<Self> {
        [Purpose::SignIn, Purpose::StepUp, Purpose::Register].into_iter().find(|p| p.as_str() == stored)
    }
}

#[derive(Serialize)]
pub struct Handle {
    pub handle: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct Begun {
    pub purpose: Purpose,
    pub email: String,
    pub options: Value,
}

#[derive(Debug, Serialize)]
pub struct Finished {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PasskeyInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct OpenCeremony {
    id: Uuid,
    user_id: Uuid,
    purpose: String,
    return_to: Json<ReturnTo>,
    state: Option<Json<Value>>,
}

fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn clean_name(name: &str) -> String {
    let name: String = name.trim().chars().filter(|c| !c.is_control()).take(MAX_NAME_CHARS).collect();
    if name.is_empty() {
        "Passkey".to_string()
    } else {
        name
    }
}

fn ceremony_failure(err: impl std::fmt::Display) -> Refusal {
    error!(error = %err, "Passkey ceremony failed");
    Refusal::Status(StatusCode::INTERNAL_SERVER_ERROR)
}

fn malformed(err: impl std::fmt::Display) -> Refusal {
    warn!(error = %err, "Passkey response rejected");
    Refusal::Status(StatusCode::BAD_REQUEST)
}

async fn held(conn: &mut PgConnection, user_id: Uuid) -> Result<Vec<Passkey>, Refusal> {
    let rows: Vec<(Json<Passkey>,)> =
        sqlx::query_as("SELECT credential FROM user_passkeys WHERE user_id = $1 ORDER BY created_at")
            .bind(user_id)
            .fetch_all(conn)
            .await
            .map_err(db_failure)?;
    Ok(rows.into_iter().map(|(Json(passkey),)| passkey).collect())
}

async fn open_ceremony(conn: &mut PgConnection, handle: &str) -> Result<OpenCeremony, Refusal> {
    sqlx::query_as(
        "SELECT id, user_id, purpose, return_to, state FROM passkey_ceremonies
         WHERE handle_hash = $1 AND code_hash IS NULL AND expires_at > now() FOR UPDATE",
    )
    .bind(digest(handle))
    .fetch_optional(conn)
    .await
    .map_err(db_failure)?
    .ok_or(Refusal::Status(StatusCode::GONE))
}

impl ReturnTo {
    fn acceptable(&self) -> bool {
        let (port, state) = match self {
            ReturnTo::Inline => return true,
            ReturnTo::App { state } => (None, state),
            ReturnTo::Loopback { port, state } => (Some(*port), state),
        };
        port.is_none_or(|port| port >= LOWEST_LOOPBACK_PORT)
            && state.len() <= MAX_STATE_CHARS
            && state.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    fn deliver(self, code: String) -> Finished {
        let (target, state) = match self {
            ReturnTo::Inline => return Finished { code: Some(code), redirect: None },
            ReturnTo::App { state } => ("voltius://passkey".to_string(), state),
            ReturnTo::Loopback { port, state } => (format!("http://127.0.0.1:{port}/passkey"), state),
        };
        let state = if state.is_empty() { state } else { format!("&s={state}") };
        Finished { code: None, redirect: Some(format!("{target}?c={code}{state}")) }
    }
}

impl Passkeys {
    pub fn from_env() -> Self {
        Self::parse(std::env::var("WEBAUTHN_RP_ID").ok().as_deref(), &crate::email::app_url())
            .unwrap_or_else(|why| panic!("WEBAUTHN_RP_ID {why}"))
    }

    fn parse(rp_id: Option<&str>, portal: &str) -> Result<Self, String> {
        let Some(rp_id) = rp_id.map(str::trim).filter(|v| !v.is_empty()) else {
            return Ok(Self(None));
        };
        let portal = Url::parse(portal).map_err(|_| format!("needs VOLTIUS_APP_URL to be a URL, got {portal:?}"))?;
        let webauthn = WebauthnBuilder::new(rp_id, &portal)
            .map_err(|err| format!("does not cover VOLTIUS_APP_URL {portal}: {err}"))?
            .rp_name("Voltius")
            .build()
            .map_err(|err| format!("is not usable: {err}"))?;
        Ok(Self(Some(Arc::new(RelyingParty { webauthn, portal }))))
    }

    pub fn available(&self) -> bool {
        self.0.is_some()
    }

    fn party(&self) -> Result<&RelyingParty, Refusal> {
        self.0.as_deref().ok_or(Refusal::Unavailable)
    }

    pub async fn open(
        &self,
        pool: &PgPool,
        user_id: Uuid,
        ceremony: Ceremony,
        return_to: ReturnTo,
    ) -> Result<Handle, Refusal> {
        let party = self.party()?;
        if !return_to.acceptable() {
            return Err(StatusCode::BAD_REQUEST.into());
        }
        let mut conn = pool.acquire().await.map_err(db_failure)?;
        let count = held(&mut conn, user_id).await?.len();
        let (purpose, binding, name) = match ceremony {
            Ceremony::Register { .. } if count >= MAX_PASSKEYS => return Err(Refusal::PasskeyLimit),
            Ceremony::Register { name } => (Purpose::Register, None, Some(clean_name(&name))),
            _ if count == 0 => return Err(Refusal::NotEnabled),
            Ceremony::SignIn { pending_token } => (Purpose::SignIn, Some(digest(&pending_token)), None),
            Ceremony::StepUp => (Purpose::StepUp, None, None),
        };

        sqlx::query("DELETE FROM passkey_ceremonies WHERE expires_at < now()")
            .execute(&mut *conn)
            .await
            .map_err(db_failure)?;
        let handle = secret();
        sqlx::query(
            "INSERT INTO passkey_ceremonies (user_id, purpose, handle_hash, binding, return_to, name, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(mins => $7))",
        )
        .bind(user_id)
        .bind(purpose.as_str())
        .bind(digest(&handle))
        .bind(binding)
        .bind(Json(return_to))
        .bind(name)
        .bind(CEREMONY_MINUTES)
        .execute(&mut *conn)
        .await
        .map_err(db_failure)?;

        let mut url = party.portal.join("2fa/passkey").map_err(ceremony_failure)?;
        url.set_fragment(Some(&format!("h={handle}")));
        Ok(Handle { handle, url: url.into() })
    }

    pub async fn begin(&self, pool: &PgPool, handle: &str) -> Result<Begun, Refusal> {
        let party = self.party()?;
        let mut tx = pool.begin().await.map_err(db_failure)?;
        let ceremony = open_ceremony(&mut tx, handle).await?;
        let purpose = Purpose::parse(&ceremony.purpose).ok_or(Refusal::Status(StatusCode::GONE))?;
        let (email, locked): (String, bool) =
            sqlx::query_as("SELECT email, COALESCE(totp_locked_until > now(), FALSE) FROM users WHERE id = $1")
                .bind(ceremony.user_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_failure)?;
        let held = held(&mut tx, ceremony.user_id).await?;

        let (options, state) = if purpose == Purpose::Register {
            let exclude = held.iter().map(|passkey| passkey.cred_id().clone()).collect();
            let (options, state) = party
                .webauthn
                .start_passkey_registration(ceremony.user_id, &email, &email, Some(exclude))
                .map_err(ceremony_failure)?;
            (serde_json::to_value(options), serde_json::to_value(state))
        } else {
            if locked {
                return Err(Refusal::Locked);
            }
            let (options, state) = party.webauthn.start_passkey_authentication(&held).map_err(ceremony_failure)?;
            (serde_json::to_value(options), serde_json::to_value(state))
        };
        let options = options.map_err(ceremony_failure)?;

        sqlx::query("UPDATE passkey_ceremonies SET state = $2 WHERE id = $1")
            .bind(ceremony.id)
            .bind(Json(state.map_err(ceremony_failure)?))
            .execute(&mut *tx)
            .await
            .map_err(db_failure)?;
        tx.commit().await.map_err(db_failure)?;
        Ok(Begun { purpose, email, options })
    }

    pub async fn finish(&self, pool: &PgPool, handle: &str, response: Value) -> Result<Finished, Refusal> {
        let party = self.party()?;
        let mut tx = pool.begin().await.map_err(db_failure)?;
        let ceremony = open_ceremony(&mut tx, handle).await?;
        let Some(Json(state)) = ceremony.state else {
            return Err(Refusal::Status(StatusCode::GONE));
        };

        if ceremony.purpose == Purpose::Register.as_str() {
            let state: PasskeyRegistration = serde_json::from_value(state).map_err(ceremony_failure)?;
            let response: RegisterPublicKeyCredential = serde_json::from_value(response).map_err(malformed)?;
            let passkey = party.webauthn.finish_passkey_registration(&response, &state).map_err(malformed)?;
            sqlx::query("UPDATE passkey_ceremonies SET credential = $2 WHERE id = $1")
                .bind(ceremony.id)
                .bind(Json(passkey))
                .execute(&mut *tx)
                .await
                .map_err(db_failure)?;
        } else {
            let state: PasskeyAuthentication = serde_json::from_value(state).map_err(ceremony_failure)?;
            let response: PublicKeyCredential = serde_json::from_value(response).map_err(malformed)?;
            let result = party.webauthn.finish_passkey_authentication(&response, &state).map_err(|err| {
                warn!(user_id = %ceremony.user_id, error = %err, "Passkey assertion rejected");
                Refusal::Invalid
            })?;
            let credential_id = B64URL.encode(result.cred_id());
            let stored: Option<(Json<Passkey>,)> = sqlx::query_as(
                "SELECT credential FROM user_passkeys WHERE user_id = $1 AND credential_id = $2 FOR UPDATE",
            )
            .bind(ceremony.user_id)
            .bind(&credential_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_failure)?;
            let Some((Json(mut passkey),)) = stored else {
                return Err(Refusal::Invalid);
            };
            passkey.update_credential(&result);
            sqlx::query("UPDATE user_passkeys SET credential = $2, last_used_at = now() WHERE credential_id = $1")
                .bind(&credential_id)
                .bind(Json(passkey))
                .execute(&mut *tx)
                .await
                .map_err(db_failure)?;
        }

        let code = secret();
        sqlx::query("UPDATE passkey_ceremonies SET code_hash = $2, state = NULL WHERE id = $1")
            .bind(ceremony.id)
            .bind(digest(&code))
            .execute(&mut *tx)
            .await
            .map_err(db_failure)?;
        tx.commit().await.map_err(db_failure)?;
        Ok(ceremony.return_to.0.deliver(code))
    }
}

/// Spends the code of a finished assertion. A sign-in code only fits the pending token it was opened for.
pub async fn spend_code(
    conn: &mut PgConnection,
    user_id: Uuid,
    code: &str,
    pending_token: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let purpose = if pending_token.is_some() { Purpose::SignIn } else { Purpose::StepUp };
    let spent = sqlx::query(
        "UPDATE passkey_ceremonies SET consumed_at = now()
         WHERE user_id = $1 AND code_hash = $2 AND purpose = $3 AND binding IS NOT DISTINCT FROM $4
           AND consumed_at IS NULL AND expires_at > now()",
    )
    .bind(user_id)
    .bind(digest(code.trim()))
    .bind(purpose.as_str())
    .bind(pending_token.map(digest))
    .execute(conn)
    .await?;
    Ok(spent.rows_affected() == 1)
}

/// Turns the credential a finished registration left behind into one of the account's passkeys.
pub async fn activate(
    conn: &mut PgConnection,
    user_id: Uuid,
    code: &str,
) -> Result<Option<PasskeyInfo>, sqlx::Error> {
    let registered: Option<(Option<Json<Passkey>>, Option<String>)> = sqlx::query_as(
        "UPDATE passkey_ceremonies SET consumed_at = now()
         WHERE user_id = $1 AND code_hash = $2 AND purpose = 'register'
           AND consumed_at IS NULL AND expires_at > now()
         RETURNING credential, name",
    )
    .bind(user_id)
    .bind(digest(code.trim()))
    .fetch_optional(&mut *conn)
    .await?;
    let Some((Some(Json(passkey)), name)) = registered else {
        return Ok(None);
    };
    sqlx::query_as(
        "INSERT INTO user_passkeys (user_id, credential_id, credential, name) VALUES ($1, $2, $3, $4)
         RETURNING id, name, created_at, last_used_at",
    )
    .bind(user_id)
    .bind(B64URL.encode(passkey.cred_id()))
    .bind(Json(&passkey))
    .bind(name.unwrap_or_else(|| clean_name("")))
    .fetch_one(conn)
    .await
    .map(Some)
}

pub async fn list(pool: &PgPool, user_id: Uuid) -> Result<Vec<PasskeyInfo>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, name, created_at, last_used_at FROM user_passkeys WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn remove(conn: &mut PgConnection, user_id: Uuid, passkey_id: Uuid) -> Result<bool, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM user_passkeys WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(passkey_id)
        .execute(conn)
        .await?;
    Ok(removed.rows_affected() == 1)
}

#[cfg(test)]
impl Passkeys {
    pub const TEST_ORIGIN: &'static str = "https://app.voltius.test";

    pub fn for_tests() -> Self {
        Self::parse(Some("voltius.test"), Self::TEST_ORIGIN).unwrap()
    }

    pub fn absent() -> Self {
        Self(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relying_party_must_cover_the_portal() {
        assert!(!Passkeys::parse(None, "https://app.voltius.app").unwrap().available());
        assert!(!Passkeys::parse(Some(" "), "https://app.voltius.app").unwrap().available());
        assert!(Passkeys::parse(Some("voltius.app"), "https://app.voltius.app").unwrap().available());
        assert!(Passkeys::parse(Some("localhost"), "http://localhost:3000").unwrap().available());
        assert!(Passkeys::parse(Some("example.com"), "https://app.voltius.app").is_err());
        assert!(Passkeys::parse(Some("voltius.app"), "not a url").is_err());
    }

    #[test]
    fn the_code_goes_back_where_the_ceremony_was_opened_from() {
        let inline = ReturnTo::Inline.deliver("c0de".into());
        assert_eq!((inline.code.as_deref(), inline.redirect), (Some("c0de"), None));
        let app = ReturnTo::App { state: "n0nce".into() }.deliver("c0de".into());
        assert_eq!(app.redirect.as_deref(), Some("voltius://passkey?c=c0de&s=n0nce"));
        let loopback: ReturnTo = serde_json::from_str(r#"{"kind":"loopback","port":49152}"#).unwrap();
        assert_eq!(loopback, ReturnTo::Loopback { port: 49152, state: String::new() });
        let loopback = loopback.deliver("c0de".into());
        assert_eq!((loopback.code, loopback.redirect.as_deref()), (None, Some("http://127.0.0.1:49152/passkey?c=c0de")));
    }

    #[test]
    fn a_return_target_cannot_point_at_a_system_port_or_smuggle_a_query() {
        let loopback = |port, state: &str| ReturnTo::Loopback { port, state: state.to_string() };
        assert!(loopback(49152, "aZ0-_").acceptable());
        assert!(!loopback(80, "").acceptable());
        assert!(!loopback(49152, "a&c=other").acceptable());
        assert!(!ReturnTo::App { state: "x".repeat(MAX_STATE_CHARS + 1) }.acceptable());
        assert!(ReturnTo::Inline.acceptable());
    }

    #[test]
    fn a_passkey_name_is_trimmed_bounded_and_never_empty() {
        assert_eq!(clean_name("  Laptop \n"), "Laptop");
        assert_eq!(clean_name(" \t "), "Passkey");
        assert_eq!(clean_name(&"x".repeat(200)).chars().count(), MAX_NAME_CHARS);
    }
}
