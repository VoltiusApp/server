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
}

pub async fn get_meta(Extension(features): Extension<Features>) -> Json<MetaResponse> {
    let self_hosted = self_host::is_self_hosted();
    Json(MetaResponse {
        self_hosted,
        billing_enabled: !self_hosted,
        registration_enabled: features.registration,
        team_invites_enabled: features.team_invites,
    })
}
