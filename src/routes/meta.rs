//! Public metadata endpoint.
//!
//! Lets clients (desktop, admin dashboard) discover server-wide flags
//! without authenticating: whether the server is self-hosted (i.e. has no
//! Lemon Squeezy configuration) and which operator switches are on.

use axum::{Extension, Json};
use serde::Serialize;

use crate::{features::Features, routes::team_objects, self_host};

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
}

pub async fn get_meta(Extension(features): Extension<Features>) -> Json<MetaResponse> {
    let self_hosted = self_host::is_self_hosted();
    Json(MetaResponse {
        self_hosted,
        billing_enabled: !self_hosted,
        registration_enabled: features.registration,
        team_invites_enabled: features.team_invites,
        identity_picks: true,
        handles_from_email: features.handles_from_email,
        team_secret_types: team_objects::secret_types(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meta_advertises_identity_picks() {
        let Json(meta) = get_meta(Extension(Features::open())).await;
        let body = serde_json::to_value(&meta).unwrap();
        assert_eq!(body["identity_picks"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn meta_advertises_the_team_secret_types_it_accepts() {
        let Json(meta) = get_meta(Extension(Features::open())).await;
        let body = serde_json::to_value(&meta).unwrap();
        let types = body["team_secret_types"].as_array().unwrap();
        assert!(types.contains(&serde_json::json!("connection_knock_sequence")));
        assert!(types.contains(&serde_json::json!("connection_password")));
    }

    #[tokio::test]
    async fn meta_reports_the_handle_switch() {
        let Json(meta) = get_meta(Extension(Features { handles_from_email: true, ..Features::open() })).await;
        assert_eq!(serde_json::to_value(&meta).unwrap()["handles_from_email"], serde_json::json!(true));
    }
}
