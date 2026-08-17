pub mod admin;
pub mod audit;
pub mod auth;
pub mod billing;
pub mod invitations;
pub mod meta;
pub mod presence;
pub mod session_codes;
pub mod sync;
pub mod team_sync;
pub mod team_objects;
pub mod team_object_prefs;
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
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "EMAIL_NOT_VERIFIED" })),
    )
        .into_response()
}
