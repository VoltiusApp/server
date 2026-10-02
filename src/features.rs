//! Operator switches for self-hosted deployments.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Features {
    pub registration: bool,
    pub team_invites: bool,
    pub handles_from_email: bool,
}

impl Features {
    pub fn from_env() -> Self {
        Self {
            registration: env_flag("REGISTRATION_ENABLED", true),
            team_invites: env_flag("TEAM_INVITES_ENABLED", true),
            handles_from_email: env_flag("HANDLES_FROM_EMAIL", false),
        }
    }

    #[cfg(test)]
    pub fn open() -> Self {
        Self { registration: true, team_invites: true, handles_from_email: false }
    }
}

fn env_flag(key: &str, default: bool) -> bool {
    parse_flag(std::env::var(key).ok().as_deref(), default)
        .unwrap_or_else(|v| panic!("{key}={v:?} is not a boolean (use true or false)"))
}

// A typo must not silently leave a feature the operator meant to close open.
fn parse_flag(value: Option<&str>, default: bool) -> Result<bool, String> {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") => Ok(default),
        Some("true") | Some("1") | Some("yes") | Some("on") => Ok(true),
        Some("false") | Some("0") | Some("no") | Some("off") => Ok(false),
        Some(other) => Err(other.to_string()),
    }
}

async fn deny_unless(enabled: bool, code: &'static str, req: Request, next: Next) -> Response {
    if enabled {
        return next.run(req).await;
    }
    (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": code }))).into_response()
}

pub async fn require_registration(
    Extension(features): Extension<Features>,
    req: Request,
    next: Next,
) -> Response {
    deny_unless(features.registration, "REGISTRATION_DISABLED", req, next).await
}

pub async fn require_team_invites(
    Extension(features): Extension<Features>,
    req: Request,
    next: Next,
) -> Response {
    deny_unless(features.team_invites, "TEAM_INVITES_DISABLED", req, next).await
}

pub async fn require_handle_self_service(
    Extension(features): Extension<Features>,
    req: Request,
    next: Next,
) -> Response {
    deny_unless(!features.handles_from_email, "HANDLE_MANAGED", req, next).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware::from_fn, routing::post, Router};
    use tower::ServiceExt;

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    async fn call(features: Features) -> (StatusCode, StatusCode) {
        let app = Router::new()
            .route("/register", post(ok_handler).layer(from_fn(require_registration)))
            .route("/invite", post(ok_handler).layer(from_fn(require_team_invites)))
            .layer(Extension(features));
        let mut statuses = Vec::new();
        for uri in ["/register", "/invite"] {
            let resp = app
                .clone()
                .oneshot(Request::post(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            statuses.push(resp.status());
        }
        (statuses[0], statuses[1])
    }

    #[test]
    fn unset_or_empty_takes_the_default() {
        assert_eq!(parse_flag(None, true), Ok(true));
        assert_eq!(parse_flag(Some(""), true), Ok(true));
        assert_eq!(parse_flag(None, false), Ok(false));
        assert_eq!(parse_flag(Some("  "), false), Ok(false));
        assert_eq!(parse_flag(Some(" TRUE "), false), Ok(true));
    }

    #[test]
    fn false_spellings_turn_it_off() {
        for v in ["false", "FALSE", "0", "no", "off"] {
            assert_eq!(parse_flag(Some(v), true), Ok(false), "{v}");
        }
    }

    #[test]
    fn unknown_value_is_rejected_not_defaulted() {
        assert_eq!(parse_flag(Some("disabled"), true), Err("disabled".to_string()));
    }

    #[tokio::test]
    async fn each_switch_closes_only_its_own_route() {
        let all = Features::open();
        assert_eq!(call(all).await, (StatusCode::OK, StatusCode::OK));
        assert_eq!(
            call(Features { registration: false, ..all }).await,
            (StatusCode::FORBIDDEN, StatusCode::OK)
        );
        assert_eq!(
            call(Features { team_invites: false, ..all }).await,
            (StatusCode::OK, StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn refusal_names_the_disabled_feature() {
        let app = Router::new()
            .route("/register", post(ok_handler))
            .layer(from_fn(require_registration))
            .layer(Extension(Features { registration: false, ..Features::open() }));
        let resp = app
            .oneshot(Request::post("/register").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({ "error": "REGISTRATION_DISABLED" }));
    }

    #[tokio::test]
    async fn handle_lock_names_itself_and_only_when_switched_on() {
        async fn status(features: Features) -> (StatusCode, serde_json::Value) {
            let app = Router::new()
                .route("/handle", post(ok_handler))
                .layer(from_fn(require_handle_self_service))
                .layer(Extension(features));
            let resp = app.oneshot(Request::post("/handle").body(Body::empty()).unwrap()).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
        }
        assert_eq!(status(Features::open()).await.0, StatusCode::OK);
        assert_eq!(
            status(Features { handles_from_email: true, ..Features::open() }).await,
            (StatusCode::FORBIDDEN, serde_json::json!({ "error": "HANDLE_MANAGED" }))
        );
    }
}
