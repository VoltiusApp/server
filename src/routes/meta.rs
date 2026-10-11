//! Public metadata endpoint.
//!
//! Lets clients (desktop, admin dashboard) discover server-wide flags
//! without authenticating: whether the server is self-hosted (i.e. has no
//! Lemon Squeezy configuration) and which operator switches are on.

use axum::{Extension, Json};
use serde::Serialize;

use crate::{features::Features, passkeys::Passkeys, routes::team_objects, self_host, two_factor::SeedCipher};

#[derive(Serialize)]
pub struct MetaResponse {
    pub self_hosted: bool,
    pub billing_enabled: bool,
    pub registration_enabled: bool,
    pub team_invites_enabled: bool,
    pub identity_picks: bool,
    pub handles_from_email: bool,
    /// A client must not upload a type missing from this list; a server that omits the field predates it.
    pub team_secret_types: Vec<&'static str>,
    /// Whether accounts can enrol a second factor here; absent on servers that predate it.
    pub two_factor: bool,
    /// Whether a passkey can be a second factor here: needs a relying party and the portal.
    pub passkeys: bool,
}

pub async fn get_meta(
    Extension(features): Extension<Features>,
    Extension(cipher): Extension<SeedCipher>,
    Extension(passkeys): Extension<Passkeys>,
) -> Json<MetaResponse> {
    let self_hosted = self_host::is_self_hosted();
    Json(MetaResponse {
        self_hosted,
        billing_enabled: !self_hosted,
        registration_enabled: features.registration,
        team_invites_enabled: features.team_invites,
        identity_picks: true,
        handles_from_email: features.handles_from_email,
        team_secret_types: team_objects::secret_types(),
        two_factor: cipher.available(),
        passkeys: passkeys.available(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meta_advertises_identity_picks() {
        let Json(meta) = get_meta(Extension(Features::open()), Extension(SeedCipher::for_tests()), Extension(Passkeys::for_tests())).await;
        let body = serde_json::to_value(&meta).unwrap();
        assert_eq!(body["identity_picks"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn meta_advertises_the_team_secret_types_it_accepts() {
        let Json(meta) = get_meta(Extension(Features::open()), Extension(SeedCipher::for_tests()), Extension(Passkeys::for_tests())).await;
        let body = serde_json::to_value(&meta).unwrap();
        let types = body["team_secret_types"].as_array().unwrap();
        assert!(types.contains(&serde_json::json!("connection_knock_sequence")));
        assert!(types.contains(&serde_json::json!("connection_password")));
    }

    #[tokio::test]
    async fn meta_reports_the_handle_switch() {
        let Json(meta) = get_meta(Extension(Features { handles_from_email: true, ..Features::open() }), Extension(SeedCipher::for_tests()), Extension(Passkeys::for_tests())).await;
        assert_eq!(serde_json::to_value(&meta).unwrap()["handles_from_email"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn meta_offers_two_factor_only_with_a_seed_key() {
        for (cipher, offered) in [(SeedCipher::for_tests(), true), (SeedCipher::absent(), false)] {
            let Json(meta) = get_meta(Extension(Features::open()), Extension(cipher), Extension(Passkeys::absent())).await;
            let body = serde_json::to_value(&meta).unwrap();
            assert_eq!(body["two_factor"], serde_json::json!(offered));
            assert_eq!(body["passkeys"], serde_json::json!(false));
        }
    }

    #[tokio::test]
    async fn meta_offers_passkeys_only_with_a_relying_party() {
        let Json(meta) =
            get_meta(Extension(Features::open()), Extension(SeedCipher::absent()), Extension(Passkeys::for_tests())).await;
        assert_eq!(serde_json::to_value(&meta).unwrap()["passkeys"], serde_json::json!(true));
    }
}
