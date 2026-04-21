pub mod jwt;
pub mod password;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use tracing::warn;
use uuid::Uuid;

use jwt::Claims;

/// Thin wrapper so existing handlers keep using `auth.0` (UUID).
#[derive(Debug, Clone, Copy)]
pub struct AuthUser(pub Uuid);

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
