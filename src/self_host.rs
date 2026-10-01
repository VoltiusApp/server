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

#[cfg(test)]
thread_local! {
    static TEST_SELF_HOSTED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub fn set_test_billing_mode(self_hosted: Option<bool>) -> Option<bool> {
    TEST_SELF_HOSTED.with(|c| c.replace(self_hosted))
}

pub fn is_self_hosted() -> bool {
    #[cfg(test)]
    return TEST_SELF_HOSTED.with(|c| c.get()).unwrap_or(true);
    #[cfg(not(test))]
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

#[cfg(test)]
mod tests {
    use crate::test_support::BillingMode;

    #[test]
    fn billing_mode_only_affects_its_own_thread() {
        let _hosted = BillingMode::hosted();
        assert!(!super::is_self_hosted());
        let other = std::thread::spawn(super::is_self_hosted).join().unwrap();
        assert!(
            other,
            "another test thread must keep the self-hosted default"
        );
    }
}
