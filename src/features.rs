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
}

impl Features {
    pub fn from_env() -> Self {
        Self {
            registration: env_flag("REGISTRATION_ENABLED"),
            team_invites: env_flag("TEAM_INVITES_ENABLED"),
        }
    }
}

fn env_flag(key: &str) -> bool {
    parse_flag(std::env::var(key).ok().as_deref())
        .unwrap_or_else(|v| panic!("{key}={v:?} is not a boolean (use true or false)"))
}

// A typo must not silently leave a feature the operator meant to close open.
fn parse_flag(value: Option<&str>) -> Result<bool, String> {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("true") | Some("1") | Some("yes") | Some("on") => Ok(true),
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
    fn unset_or_empty_keeps_the_feature_on() {
        assert_eq!(parse_flag(None), Ok(true));
        assert_eq!(parse_flag(Some("")), Ok(true));
        assert_eq!(parse_flag(Some(" TRUE ")), Ok(true));
    }

    #[test]
    fn false_spellings_turn_it_off() {
        for v in ["false", "FALSE", "0", "no", "off"] {
            assert_eq!(parse_flag(Some(v)), Ok(false), "{v}");
        }
    }

    #[test]
    fn unknown_value_is_rejected_not_defaulted() {
        assert_eq!(parse_flag(Some("disabled")), Err("disabled".to_string()));
    }

    #[tokio::test]
    async fn each_switch_closes_only_its_own_route() {
        let all = Features { registration: true, team_invites: true };
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
            .layer(Extension(Features { registration: false, team_invites: true }));
        let resp = app
            .oneshot(Request::post("/register").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({ "error": "REGISTRATION_DISABLED" }));
    }
}
