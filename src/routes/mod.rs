pub mod admin;
pub mod audit;
pub mod auth;
pub mod billing;
pub mod client_version;
pub mod health;
pub mod invitations;
pub mod member_identity_picks;
pub mod member_names;
pub mod meta;
pub mod metrics;
pub mod presence;
pub mod resend_webhook;
pub mod session_codes;
pub mod sync;
pub mod team_grants;
pub mod team_sync;
pub mod team_objects;
pub mod team_object_prefs;
pub mod team_rule_sets;
pub mod teams;
pub mod terminal;
pub mod users;
pub mod waitlist;
pub mod webhooks;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// The one 403 a client must be able to tell apart from every other refusal:
/// "verify your email" is a step the user can actually take. Shared by the
/// checkout gate and the handle-claim gate so the two cannot drift.
pub(crate) fn email_not_verified_response() -> Response {
    coded_error(StatusCode::FORBIDDEN, "EMAIL_NOT_VERIFIED")
}

/// Mail to the address bounced or is suppressed: resending cannot help, changing it can.
pub(crate) fn email_undeliverable_response() -> Response {
    coded_error(StatusCode::UNPROCESSABLE_ENTITY, "EMAIL_UNDELIVERABLE")
}

fn coded_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": code }))).into_response()
}
