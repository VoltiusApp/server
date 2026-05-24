//! Public metadata endpoint.
//!
//! Lets clients (desktop, admin dashboard) discover server-wide flags
//! without authenticating — currently just whether the server is
//! self-hosted (i.e. has no Lemon Squeezy configuration).

use axum::Json;
use serde::Serialize;

use crate::self_host;

#[derive(Serialize)]
pub struct MetaResponse {
    pub self_hosted: bool,
    pub billing_enabled: bool,
}

pub async fn get_meta() -> Json<MetaResponse> {
    let self_hosted = self_host::is_self_hosted();
    Json(MetaResponse {
        self_hosted,
        billing_enabled: !self_hosted,
    })
}
