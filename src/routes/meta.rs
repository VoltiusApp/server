//! Public metadata endpoint.
//!
//! Lets clients (desktop, admin dashboard) discover server-wide flags
//! without authenticating: whether the server is self-hosted (i.e. has no
//! Lemon Squeezy configuration) and which operator switches are on.

use axum::{Extension, Json};
use serde::Serialize;

use crate::{features::Features, self_host};

#[derive(Serialize)]
pub struct MetaResponse {
    pub self_hosted: bool,
    pub billing_enabled: bool,
    pub registration_enabled: bool,
    pub team_invites_enabled: bool,
    pub identity_picks: bool,
}

pub async fn get_meta(Extension(features): Extension<Features>) -> Json<MetaResponse> {
    let self_hosted = self_host::is_self_hosted();
    Json(MetaResponse {
        self_hosted,
        billing_enabled: !self_hosted,
        registration_enabled: features.registration,
        team_invites_enabled: features.team_invites,
        identity_picks: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn meta_advertises_identity_picks() {
        let Json(meta) = get_meta(Extension(Features {
            registration: true,
            team_invites: true,
        }))
        .await;
        let body = serde_json::to_value(&meta).unwrap();
        assert_eq!(body["identity_picks"], serde_json::json!(true));
    }
}
