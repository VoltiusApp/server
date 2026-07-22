pub mod jwt;
pub mod password;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use jwt::Claims;

/// Thin wrapper so existing handlers keep using `auth.0` (UUID).
#[derive(Debug, Clone, Copy)]
pub struct AuthUser(pub Uuid);

/// Admin identity injected by require_admin_key.
#[derive(Debug, Clone)]
pub struct AdminEmail(pub String);

/// Full JWT claims — injected alongside AuthUser for tier-aware handlers.
#[derive(Debug, Clone)]
pub struct AuthClaims(pub Claims);

pub async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_owned();

    let header = match req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(value) => value,
        None => {
            warn!(path = %path, "Unauthorized request missing authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let token = match header.strip_prefix("Bearer ") {
        Some(token) => token,
        None => {
            warn!(path = %path, "Unauthorized request with malformed authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let claims = match jwt::validate_token(token, "access") {
        Ok(claims) => claims,
        Err(_) => {
            warn!(path = %path, "Unauthorized request with invalid access token");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    if claims.is_banned {
        let reason = "Your account has been suspended.".to_string();
        warn!(path = %path, user_id = %claims.sub, "Banned user attempted request");
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "banned", "reason": reason})),
        )
            .into_response());
    }

    req.extensions_mut().insert(AuthUser(claims.sub));
    req.extensions_mut().insert(AuthClaims(claims));
    Ok(next.run(req).await)
}

/// Middleware that gates a route to Pro-or-above users (including active trial).
pub async fn require_pro(
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = req.extensions().get::<AuthClaims>().cloned();
    match claims {
        Some(AuthClaims(c)) if c.is_pro_active() => Ok(next.run(req).await),
        Some(_) => {
            warn!(path = %req.uri().path(), "Pro feature accessed by free-tier user");
            Err(StatusCode::PAYMENT_REQUIRED)
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Middleware that authenticates admin API calls via a shared secret header.
/// Reads ADMIN_SECRET env var; injects AdminEmail from X-Admin-Email header.
pub async fn require_admin_key(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let secret = std::env::var("ADMIN_SECRET").unwrap_or_default();
    if secret.is_empty() {
        warn!("ADMIN_SECRET not set — rejecting admin request");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let provided = req
        .headers()
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != secret {
        warn!(path = %req.uri().path(), "Admin request with invalid X-Admin-Key");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let email = req
        .headers()
        .get("x-admin-email")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    req.extensions_mut().insert(AdminEmail(email));
    Ok(next.run(req).await)
}

/// Middleware that gates a route to Teams-or-above users.
pub async fn require_teams(
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = req.extensions().get::<AuthClaims>().cloned();
    match claims {
        Some(AuthClaims(c)) if c.is_teams_active() => Ok(next.run(req).await),
        Some(_) => {
            warn!(path = %req.uri().path(), "Teams feature accessed by non-teams user");
            Err(StatusCode::PAYMENT_REQUIRED)
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod authz_tests {
    //! Enforcement tests for the request-gating middlewares. `require_admin_key`
    //! is the *entire* authorization surface for `routes::admin` (those handlers
    //! carry no inline checks), and `require_pro` / `require_teams` / the banned
    //! branch of `auth_middleware` gate large swaths of the API. Each is driven
    //! through a throwaway `Router` via `oneshot`. These are pure (no DB), so they
    //! run without `TEST_DATABASE_URL`.
    use super::*;
    use crate::test_support::env_lock;
    use axum::{body::Body, http::Request, middleware::from_fn, routing::get, Extension, Router};
    use tower::ServiceExt;

    /// Newtype wrapper so the env-lock guard survives the test's `.await` points
    /// without tripping clippy's `await_holding_lock` (mirrors the teams.rs tests).
    #[allow(dead_code)]
    struct EnvLockGuard(std::sync::MutexGuard<'static, ()>);

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    async fn echo_admin(Extension(AdminEmail(email)): Extension<AdminEmail>) -> String {
        email
    }

    // A far-future expiry; the tier middlewares don't check exp, they read `tier`.
    fn claims(tier: &str, is_banned: bool) -> Claims {
        Claims {
            sub: Uuid::new_v4(),
            exp: 4_102_444_800,
            iat: 0,
            kind: "access".to_string(),
            tier: tier.to_string(),
            trial_ends_at: None,
            trial_used: false,
            is_admin: false,
            is_banned,
            email_verified: true,
        }
    }

    // ── require_admin_key (the admin.rs gate) ─────────────────────────────────

    #[tokio::test]
    async fn require_admin_key_rejects_missing_key() {
        let _guard = EnvLockGuard(env_lock());
        std::env::set_var("ADMIN_SECRET", "sekret");
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_admin_key));

        let resp = app
            .oneshot(Request::builder().uri("/x").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_admin_key_rejects_wrong_key() {
        let _guard = EnvLockGuard(env_lock());
        std::env::set_var("ADMIN_SECRET", "sekret");
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_admin_key));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("x-admin-key", "wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_admin_key_service_unavailable_without_secret() {
        let _guard = EnvLockGuard(env_lock());
        std::env::remove_var("ADMIN_SECRET");
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_admin_key));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("x-admin-key", "anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn require_admin_key_allows_correct_key_and_injects_email() {
        let _guard = EnvLockGuard(env_lock());
        std::env::set_var("ADMIN_SECRET", "sekret");
        let app = Router::new()
            .route("/x", get(echo_admin))
            .layer(from_fn(require_admin_key));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("x-admin-key", "sekret")
                    .header("x-admin-email", "admin@voltius.app")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"admin@voltius.app");
    }

    // ── require_pro ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn require_pro_payment_required_for_free() {
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_pro));

        let mut req = Request::builder().uri("/x").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AuthClaims(claims("free", false)));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn require_pro_allows_pro() {
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_pro));

        let mut req = Request::builder().uri("/x").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AuthClaims(claims("pro", false)));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_pro_unauthorized_without_claims() {
        // No auth_middleware upstream → no AuthClaims in extensions → 401, not 402.
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_pro));

        let resp = app
            .oneshot(Request::builder().uri("/x").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── require_teams ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn require_teams_payment_required_for_pro() {
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_teams));

        let mut req = Request::builder().uri("/x").body(Body::empty()).unwrap();
        // pro is above free but below teams — must still be rejected.
        req.extensions_mut().insert(AuthClaims(claims("pro", false)));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn require_teams_allows_business() {
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_teams));

        let mut req = Request::builder().uri("/x").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AuthClaims(claims("business", false)));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_teams_allows_teams_tier() {
        // Guards against a regression that drops the literal "teams" from the
        // is_teams_active match and 402s real Teams (non-business) subscribers.
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(require_teams));

        let mut req = Request::builder().uri("/x").body(Body::empty()).unwrap();
        req.extensions_mut().insert(AuthClaims(claims("teams", false)));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── auth_middleware (banned gate) ─────────────────────────────────────────

    #[tokio::test]
    async fn auth_middleware_rejects_missing_header() {
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(auth_middleware));

        let resp = app
            .oneshot(Request::builder().uri("/x").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_middleware_rejects_non_bearer_header() {
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(auth_middleware));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("authorization", "Token abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_middleware_rejects_invalid_token() {
        let _guard = EnvLockGuard(env_lock());
        std::env::set_var("JWT_SECRET", "ci-test-secret");
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(auth_middleware));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("authorization", "Bearer not.a.jwt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_middleware_forbids_banned_user() {
        let _guard = EnvLockGuard(env_lock());
        std::env::set_var("JWT_SECRET", "ci-test-secret");
        let token =
            jwt::create_access_token(Uuid::new_v4(), "pro", None, false, false, true, true).unwrap();
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(auth_middleware));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn auth_middleware_allows_valid_user() {
        let _guard = EnvLockGuard(env_lock());
        std::env::set_var("JWT_SECRET", "ci-test-secret");
        let token =
            jwt::create_access_token(Uuid::new_v4(), "pro", None, false, false, false, true)
                .unwrap();
        let app = Router::new()
            .route("/x", get(ok_handler))
            .layer(from_fn(auth_middleware));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }
}
