use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;

#[derive(Serialize)]
pub struct SubscriptionInfoResponse {
    pub tier: String,
    pub seats: Option<i32>,
    pub used_seats: Option<i64>,
    pub trial_ends_at: Option<i64>,
    pub has_ls_subscription: bool,
}

#[derive(Serialize)]
pub struct PortalResponse {
    pub portal_url: String,
}

#[derive(Deserialize)]
pub struct UpdateSeatsRequest {
    pub seats: u32,
    #[serde(default)]
    pub invoice_immediately: Option<bool>,
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
    let store_id = std::env::var("LEMONSQUEEZY_STORE_ID").unwrap_or_default();
    let api_key = std::env::var("LEMONSQUEEZY_API_KEY").unwrap_or_default();
    let yearly = body.interval.as_deref().unwrap_or("monthly") == "yearly";
    let variant_id = match (body.plan.as_str(), yearly) {
        ("pro", false)   => std::env::var("LS_VARIANT_PRO_MONTHLY").unwrap_or_default(),
        ("pro", true)    => std::env::var("LS_VARIANT_PRO_YEARLY").unwrap_or_default(),
        ("teams", false) => std::env::var("LS_VARIANT_TEAMS_MONTHLY").unwrap_or_default(),
        ("teams", true)  => std::env::var("LS_VARIANT_TEAMS_YEARLY").unwrap_or_default(),
        _                => return Err(StatusCode::BAD_REQUEST),
    };

    if store_id.is_empty() || api_key.is_empty() || variant_id.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Teams requires at least 3 seats; default to 3 if not specified
    let seats = if body.plan == "teams" {
        let s = body.seats.unwrap_or(3);
        if s < 3 {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        Some(s)
    } else {
        None
    };

    let email = fetch_user_email(&pool, auth.0).await?;
    let test_mode = std::env::var("LS_TEST_MODE").as_deref() == Ok("true");

    let variant_id_num: u64 = variant_id.parse().map_err(|_| {
        error!("LS variant ID is not a valid number: {variant_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut checkout_data = serde_json::json!({
        "email": email,
        "custom": { "user_id": auth.0 }
    });

    if let Some(s) = seats {
        checkout_data["variant_quantities"] = serde_json::json!([{
            "variant_id": variant_id_num,
            "quantity": s
        }]);
    }

    let payload = serde_json::json!({
        "data": {
            "type": "checkouts",
            "attributes": {
                "checkout_data": checkout_data,
                "test_mode": test_mode,
            },
            "relationships": {
                "store": { "data": { "type": "stores", "id": store_id } },
                "variant": { "data": { "type": "variants", "id": variant_id } }
            }
        }
    });

    let client = reqwest::Client::new();
    let ls_res = client
        .post("https://api.lemonsqueezy.com/v1/checkouts")
        .bearer_auth(&api_key)
        .header("Accept", "application/vnd.api+json")
        .header("Content-Type", "application/vnd.api+json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            error!(error = %e, "LS checkout creation request failed");
            StatusCode::BAD_GATEWAY
        })?;

    if !ls_res.status().is_success() {
        error!(status = %ls_res.status(), "LS checkout creation failed");
        return Err(StatusCode::BAD_GATEWAY);
    }

    let ls_body: serde_json::Value = ls_res.json().await.map_err(|e| {
        error!(error = %e, "LS checkout response parse failed");
        StatusCode::BAD_GATEWAY
    })?;

    let checkout_url = ls_body["data"]["attributes"]["url"]
        .as_str()
        .ok_or_else(|| {
            error!("LS checkout response missing url");
            StatusCode::BAD_GATEWAY
        })?
        .to_string();

    Ok(Json(CheckoutResponse { checkout_url }))
}

pub async fn get_portal(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<PortalResponse>, StatusCode> {
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
    let ls_res = client
        .get(format!(
            "https://api.lemonsqueezy.com/v1/subscriptions/{subscription_id}"
        ))
        .bearer_auth(&api_key)
        .header("Accept", "application/vnd.api+json")
        .send()
        .await
        .map_err(|e| {
            error!(error = %e, "LS subscription fetch request failed");
            StatusCode::BAD_GATEWAY
        })?;

    if !ls_res.status().is_success() {
        error!(status = %ls_res.status(), "LS subscription fetch failed");
        return Err(StatusCode::BAD_GATEWAY);
    }

    let ls_body: serde_json::Value = ls_res.json().await.map_err(|e| {
        error!(error = %e, "LS subscription response parse failed");
        StatusCode::BAD_GATEWAY
    })?;

    let portal_url = ls_body["data"]["attributes"]["urls"]["customer_portal"]
        .as_str()
        .ok_or_else(|| {
            error!("LS subscription response missing customer_portal URL");
            StatusCode::BAD_GATEWAY
        })?
        .to_string();

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

    let mut attributes = serde_json::json!({ "quantity": body.seats });
    if body.invoice_immediately == Some(true) {
        attributes["invoice_immediately"] = serde_json::json!(true);
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
                "attributes": attributes,
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

    // Optimistically update seat_count so the subsequent add_member call doesn't
    // race the LS webhook (which updates it asynchronously).
    sqlx::query("UPDATE users SET seat_count = $1 WHERE id = $2")
        .bind(body.seats as i32)
        .bind(auth.0)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to optimistically update seat_count");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_subscription(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<SubscriptionInfoResponse>, StatusCode> {
    let row = sqlx::query_as::<_, (String, Option<chrono::DateTime<chrono::Utc>>, Option<i32>, Option<String>)>(
        "SELECT subscription_tier, trial_ends_at, seat_count, ls_subscription_id FROM users WHERE id = $1",
    )
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to fetch subscription info");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let tier = &row.0;
    let used_seats = if tier == "teams" || tier == "business" {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT tm.user_id)
             FROM team_members tm
             JOIN teams t ON tm.team_id = t.id
             WHERE t.owner_id = $1",
        )
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %auth.0, "Failed to count used seats");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        Some(count)
    } else {
        None
    };

    let tier = &row.0;
    let seats = if (tier == "teams" || tier == "business") && row.2.is_none() {
        Some(3)
    } else {
        row.2
    };

    Ok(Json(SubscriptionInfoResponse {
        tier: row.0,
        trial_ends_at: row.1.map(|t| t.timestamp()),
        seats,
        used_seats,
        has_ls_subscription: row.3.is_some(),
    }))
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
