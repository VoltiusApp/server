use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, warn};

#[derive(Deserialize)]
pub struct MobileWaitlistRequest {
    pub email: String,
    pub platform: String,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Serialize)]
pub struct MobileWaitlistResponse {
    pub ok: bool,
}

pub async fn join_mobile_waitlist(
    State(pool): State<PgPool>,
    Json(body): Json<MobileWaitlistRequest>,
) -> Result<(StatusCode, Json<MobileWaitlistResponse>), StatusCode> {
    let email = body.email.trim().to_lowercase();
    let platform = body.platform.trim().to_lowercase();
    let source = body
        .source
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("landing-download");

    if !is_valid_email(&email) || !matches!(platform.as_str(), "android" | "ios") {
        warn!(platform = %platform, "Invalid mobile waitlist signup");
        return Err(StatusCode::BAD_REQUEST);
    }

    sqlx::query(
        r#"INSERT INTO mobile_waitlist_signups (email, platform, source)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(&email)
    .bind(&platform)
    .bind(source)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to join mobile waitlist");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((StatusCode::OK, Json(MobileWaitlistResponse { ok: true })))
}

fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };

    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
}
