//! Self-hosted mode detection.
//!
//! The server runs in self-hosted mode whenever `LEMONSQUEEZY_API_KEY` is unset.
//! In that mode all tier gates are bypassed, no trial countdown runs, and the
//! billing/webhook routes are inert. There is no separate `SELF_HOSTED` flag —
//! the absence of paid-mode configuration *is* the signal.

use axum::{
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    extract::Request,
    Json,
};

pub fn is_self_hosted() -> bool {
    std::env::var("LEMONSQUEEZY_API_KEY")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
}

/// Middleware: short-circuit billing/webhook routes when self-hosted.
pub async fn block_when_self_hosted(req: Request, next: Next) -> Response {
    if is_self_hosted() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "BILLING_DISABLED", "self_hosted": true })),
        )
            .into_response();
    }
    next.run(req).await
}
