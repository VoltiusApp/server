use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;

#[derive(Serialize)]
pub struct PortalResponse {
    pub portal_url: String,
}

#[derive(Deserialize)]
pub struct UpdateSeatsRequest {
    pub seats: u32,
}

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

    // Teams requires at least 3 seats; default to 3 if not specified
    if body.plan == "teams" {
        let seats = body.seats.unwrap_or(3);
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

pub async fn get_portal(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<PortalResponse>, StatusCode> {
    let row = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT ls_customer_id FROM users WHERE id = $1",
    )
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to fetch customer id");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let customer_id = row.0.ok_or(StatusCode::NOT_FOUND)?;
    let store_id = std::env::var("LEMONSQUEEZY_STORE_ID").unwrap_or_default();
    if store_id.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Lemon Squeezy customer portal URL
    let portal_url = format!(
        "https://app.lemonsqueezy.com/my-orders?customer_id={customer_id}&store_id={store_id}"
    );
    Ok(Json(PortalResponse { portal_url }))
}

pub async fn update_seats(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<UpdateSeatsRequest>,
) -> Result<StatusCode, StatusCode> {
    if body.seats < 3 {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    let row = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT ls_subscription_id FROM users WHERE id = $1",
    )
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to fetch subscription id");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let subscription_id = row.0.ok_or(StatusCode::NOT_FOUND)?;
    let api_key = std::env::var("LEMONSQUEEZY_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let client = reqwest::Client::new();
    let res = client
        .patch(format!(
            "https://api.lemonsqueezy.com/v1/subscriptions/{subscription_id}"
        ))
        .bearer_auth(&api_key)
        .header("Accept", "application/vnd.api+json")
        .header("Content-Type", "application/vnd.api+json")
        .json(&serde_json::json!({
            "data": {
                "type": "subscriptions",
                "id": subscription_id,
                "attributes": { "quantity": body.seats }
            }
        }))
        .send()
        .await
        .map_err(|e| {
            error!(error = %e, "LS seats update request failed");
            StatusCode::BAD_GATEWAY
        })?;

    if !res.status().is_success() {
        error!(status = %res.status(), "LS seats update failed");
        return Err(StatusCode::BAD_GATEWAY);
    }

    Ok(StatusCode::NO_CONTENT)
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
