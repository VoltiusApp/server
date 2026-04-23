use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;

#[derive(Deserialize)]
pub struct CheckoutRequest {
    pub plan: String,     // "pro" | "teams"
    pub seats: Option<u32>,
    pub interval: Option<String>, // "monthly" | "yearly", defaults to "monthly"
}

#[derive(Serialize)]
pub struct CheckoutResponse {
    pub checkout_url: String,
}

pub async fn create_checkout(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<CheckoutRequest>,
) -> Result<Json<CheckoutResponse>, StatusCode> {
    let store_slug = std::env::var("LEMONSQUEEZY_STORE_SLUG").unwrap_or_default();
    let yearly = body.interval.as_deref().unwrap_or("monthly") == "yearly";
    let variant_id = match (body.plan.as_str(), yearly) {
        ("pro", false)   => std::env::var("LS_VARIANT_PRO_MONTHLY").unwrap_or_default(),
        ("pro", true)    => std::env::var("LS_VARIANT_PRO_YEARLY").unwrap_or_default(),
        ("teams", false) => std::env::var("LS_VARIANT_TEAMS_MONTHLY").unwrap_or_default(),
        ("teams", true)  => std::env::var("LS_VARIANT_TEAMS_YEARLY").unwrap_or_default(),
        _                => return Err(StatusCode::BAD_REQUEST),
    };

    if store_slug.is_empty() || variant_id.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Teams requires at least 3 seats
    if body.plan == "teams" {
        let seats = body.seats.unwrap_or(0);
        if seats < 3 {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    let email = fetch_user_email(&pool, auth.0).await?;
    let mut url = format!(
        "https://{store_slug}.lemonsqueezy.com/checkout/buy/{variant_id}?checkout[email]={email}"
    );

    // Embed user_id so the webhook can match by UUID instead of email
    url.push_str(&format!("&checkout[custom][user_id]={}", auth.0));

    if let Some(seats) = body.seats {
        url.push_str(&format!("&checkout[quantity]={seats}"));
    }

    Ok(Json(CheckoutResponse { checkout_url: url }))
}

async fn fetch_user_email(pool: &PgPool, user_id: Uuid) -> Result<String, StatusCode> {
    sqlx::query_as::<_, (String,)>("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map(|r| r.0)
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Failed to fetch user email for checkout");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}
