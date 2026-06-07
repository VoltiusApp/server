use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::lemonsqueezy::{parse_ls_datetime, tier_from_variant_id};
use crate::self_host;

#[derive(Serialize)]
pub struct SubscriptionInfoResponse {
    pub tier: String,
    pub status: Option<String>,
    pub cancelled: bool,
    pub renews_at: Option<i64>,
    pub ends_at: Option<i64>,
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
    pub plan: String, // "pro" | "teams"
    pub seats: Option<u32>,
    pub interval: Option<String>, // "monthly" | "yearly", defaults to "monthly"
}

#[derive(Serialize)]
pub struct CheckoutResponse {
    pub checkout_url: String,
}

fn status_response(status: StatusCode) -> Response {
    status.into_response()
}

fn email_not_verified_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "EMAIL_NOT_VERIFIED" })),
    )
        .into_response()
}

#[derive(Debug, Clone)]
struct LemonSubscriptionState {
    subscription_id: String,
    customer_id: Option<String>,
    variant_id: Option<String>,
    tier: Option<&'static str>,
    status: Option<String>,
    cancelled: bool,
    renews_at: Option<chrono::DateTime<chrono::Utc>>,
    ends_at: Option<chrono::DateTime<chrono::Utc>>,
    seat_count: Option<i32>,
}

fn parse_ls_subscription(body: &serde_json::Value) -> Option<LemonSubscriptionState> {
    let data = &body["data"];
    let attrs = &data["attributes"];
    let subscription_id = data["id"].as_str()?.to_string();
    let variant_id = attrs["variant_id"].as_i64().map(|v| v.to_string());
    let customer_id = data["relationships"]["customer"]["data"]["id"]
        .as_str()
        .map(ToOwned::to_owned)
        .or_else(|| attrs["customer_id"].as_i64().map(|v| v.to_string()));
    let tier = variant_id.as_deref().and_then(tier_from_variant_id);
    let seat_count = attrs["first_subscription_item"]["quantity"]
        .as_i64()
        .and_then(|q| i32::try_from(q).ok());

    Some(LemonSubscriptionState {
        subscription_id,
        customer_id,
        variant_id,
        tier,
        status: attrs["status"].as_str().map(ToOwned::to_owned),
        cancelled: attrs["cancelled"].as_bool().unwrap_or(false),
        renews_at: parse_ls_datetime(attrs["renews_at"].as_str()),
        ends_at: parse_ls_datetime(attrs["ends_at"].as_str()),
        seat_count,
    })
}

fn subscription_tier_for_persistence(
    state: &LemonSubscriptionState,
) -> Result<&'static str, StatusCode> {
    state.tier.ok_or_else(|| {
        error!(
            subscription_id = %state.subscription_id,
            variant_id = ?state.variant_id,
            "LS subscription state has unknown variant tier"
        );
        StatusCode::BAD_GATEWAY
    })
}

async fn persist_subscription_state(
    pool: &PgPool,
    user_id: Uuid,
    state: &LemonSubscriptionState,
) -> Result<(), StatusCode> {
    let tier = subscription_tier_for_persistence(state)?;
    sqlx::query(
        "UPDATE users SET
            subscription_tier = $1,
            ls_customer_id = COALESCE($2, ls_customer_id),
            ls_subscription_id = $3,
            ls_subscription_status = $4,
            ls_variant_id = $5,
            subscription_cancelled = $6,
            subscription_renews_at = $7,
            subscription_ends_at = $8,
            seat_count = COALESCE($9, seat_count),
            trial_used = TRUE,
            trial_ends_at = NULL
         WHERE id = $10 AND admin_override = FALSE",
    )
    .bind(tier)
    .bind(&state.customer_id)
    .bind(&state.subscription_id)
    .bind(&state.status)
    .bind(&state.variant_id)
    .bind(state.cancelled)
    .bind(state.renews_at)
    .bind(state.ends_at)
    .bind(state.seat_count)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to persist subscription state");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(())
}

async fn mutate_ls_subscription(
    subscription_id: &str,
    method: reqwest::Method,
) -> Result<LemonSubscriptionState, StatusCode> {
    let api_key = std::env::var("LEMONSQUEEZY_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let client = reqwest::Client::new();
    let mut req = client
        .request(
            method.clone(),
            format!("https://api.lemonsqueezy.com/v1/subscriptions/{subscription_id}"),
        )
        .bearer_auth(&api_key)
        .header("Accept", "application/vnd.api+json")
        .header("Content-Type", "application/vnd.api+json");

    if method == reqwest::Method::PATCH {
        req = req.json(&serde_json::json!({
            "data": {
                "type": "subscriptions",
                "id": subscription_id,
                "attributes": { "cancelled": false }
            }
        }));
    }

    let res = req.send().await.map_err(|e| {
        error!(error = %e, "LS subscription mutation request failed");
        StatusCode::BAD_GATEWAY
    })?;

    if !res.status().is_success() {
        error!(status = %res.status(), "LS subscription mutation failed");
        return Err(StatusCode::BAD_GATEWAY);
    }

    let body: serde_json::Value = res.json().await.map_err(|e| {
        error!(error = %e, "LS subscription mutation response parse failed");
        StatusCode::BAD_GATEWAY
    })?;

    parse_ls_subscription(&body).ok_or_else(|| {
        error!("LS subscription mutation response missing subscription data");
        StatusCode::BAD_GATEWAY
    })
}

async fn fetch_current_subscription_id(pool: &PgPool, user_id: Uuid) -> Result<String, StatusCode> {
    let row = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT ls_subscription_id FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to fetch subscription id");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    row.0.ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_checkout(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(body): Json<CheckoutRequest>,
) -> Result<Json<CheckoutResponse>, Response> {
    if self_host::is_self_hosted() {
        return Err(status_response(StatusCode::SERVICE_UNAVAILABLE));
    }
    let (email, email_verified) = fetch_checkout_user(&pool, auth.0)
        .await
        .map_err(status_response)?;
    if !email_verified {
        return Err(email_not_verified_response());
    }

    let store_id = std::env::var("LEMONSQUEEZY_STORE_ID").unwrap_or_default();
    let api_key = std::env::var("LEMONSQUEEZY_API_KEY").unwrap_or_default();
    let yearly = body.interval.as_deref().unwrap_or("monthly") == "yearly";
    let variant_id = match (body.plan.as_str(), yearly) {
        ("pro", false) => std::env::var("LS_VARIANT_PRO_MONTHLY").unwrap_or_default(),
        ("pro", true) => std::env::var("LS_VARIANT_PRO_YEARLY").unwrap_or_default(),
        ("teams", false) => std::env::var("LS_VARIANT_TEAMS_MONTHLY").unwrap_or_default(),
        ("teams", true) => std::env::var("LS_VARIANT_TEAMS_YEARLY").unwrap_or_default(),
        _ => return Err(status_response(StatusCode::BAD_REQUEST)),
    };

    if store_id.is_empty() || api_key.is_empty() || variant_id.is_empty() {
        return Err(status_response(StatusCode::SERVICE_UNAVAILABLE));
    }

    // Teams requires at least 3 seats; default to 3 if not specified
    let seats = if body.plan == "teams" {
        let s = body.seats.unwrap_or(3);
        if s < 3 {
            return Err(status_response(StatusCode::UNPROCESSABLE_ENTITY));
        }
        Some(s)
    } else {
        None
    };

    let test_mode = std::env::var("LS_TEST_MODE").as_deref() == Ok("true");

    let variant_id_num: u64 = variant_id.parse().map_err(|_| {
        error!("LS variant ID is not a valid number: {variant_id}");
        status_response(StatusCode::INTERNAL_SERVER_ERROR)
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
            status_response(StatusCode::BAD_GATEWAY)
        })?;

    if !ls_res.status().is_success() {
        error!(status = %ls_res.status(), "LS checkout creation failed");
        return Err(status_response(StatusCode::BAD_GATEWAY));
    }

    let ls_body: serde_json::Value = ls_res.json().await.map_err(|e| {
        error!(error = %e, "LS checkout response parse failed");
        status_response(StatusCode::BAD_GATEWAY)
    })?;

    let checkout_url = ls_body["data"]["attributes"]["url"]
        .as_str()
        .ok_or_else(|| {
            error!("LS checkout response missing url");
            status_response(StatusCode::BAD_GATEWAY)
        })?
        .to_string();

    Ok(Json(CheckoutResponse { checkout_url }))
}

pub async fn get_portal(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<PortalResponse>, StatusCode> {
    if self_host::is_self_hosted() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let subscription_id = fetch_current_subscription_id(&pool, auth.0).await?;
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
    if self_host::is_self_hosted() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    if body.seats < 3 {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    let subscription_id = fetch_current_subscription_id(&pool, auth.0).await?;
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

pub async fn cancel_subscription(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<SubscriptionInfoResponse>, StatusCode> {
    if self_host::is_self_hosted() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let subscription_id = fetch_current_subscription_id(&pool, auth.0).await?;
    let state = mutate_ls_subscription(&subscription_id, reqwest::Method::DELETE).await?;
    persist_subscription_state(&pool, auth.0, &state).await?;
    get_subscription(State(pool), axum::Extension(auth)).await
}

pub async fn resume_subscription(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<SubscriptionInfoResponse>, StatusCode> {
    if self_host::is_self_hosted() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let subscription_id = fetch_current_subscription_id(&pool, auth.0).await?;
    let state = mutate_ls_subscription(&subscription_id, reqwest::Method::PATCH).await?;
    persist_subscription_state(&pool, auth.0, &state).await?;
    get_subscription(State(pool), axum::Extension(auth)).await
}

pub async fn get_subscription(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<SubscriptionInfoResponse>, StatusCode> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<i32>,
            Option<String>,
            Option<String>,
            bool,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT subscription_tier, trial_ends_at, seat_count, ls_subscription_id,
                ls_subscription_status, subscription_cancelled, subscription_renews_at,
                subscription_ends_at
         FROM users WHERE id = $1",
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
        status: row.4,
        cancelled: row.5,
        renews_at: row.6.map(|t| t.timestamp()),
        ends_at: row.7.map(|t| t.timestamp()),
        seats,
        used_seats,
        trial_ends_at: row.1.map(|t| t.timestamp()),
        has_ls_subscription: row.3.is_some(),
    }))
}

async fn fetch_checkout_user(pool: &PgPool, user_id: Uuid) -> Result<(String, bool), StatusCode> {
    sqlx::query_as::<_, (String, bool)>("SELECT email, email_verified FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!(error = %e, user_id = %user_id, "Failed to fetch user for checkout");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, response::IntoResponse};

    use super::*;

    /// Set the variant env vars and return the held env lock; keep the guard
    /// alive (`let _env = set_variant_env();`) so the test runs serially.
    fn set_variant_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::test_support::env_lock();
        std::env::set_var("LS_VARIANT_PRO_MONTHLY", "101");
        std::env::set_var("LS_VARIANT_PRO_YEARLY", "102");
        std::env::set_var("LS_VARIANT_TEAMS_MONTHLY", "201");
        std::env::set_var("LS_VARIANT_TEAMS_YEARLY", "202");
        guard
    }

    #[test]
    fn tier_from_variant_id_maps_configured_pro_variants() {
        let _env = set_variant_env();
        assert_eq!(tier_from_variant_id("101"), Some("pro"));
        assert_eq!(tier_from_variant_id("102"), Some("pro"));
    }

    #[test]
    fn tier_from_variant_id_maps_configured_teams_variants() {
        let _env = set_variant_env();
        assert_eq!(tier_from_variant_id("201"), Some("teams"));
        assert_eq!(tier_from_variant_id("202"), Some("teams"));
    }

    #[test]
    fn tier_from_variant_id_rejects_unknown_variant() {
        let _env = set_variant_env();
        assert_eq!(tier_from_variant_id("999"), None);
    }

    #[tokio::test]
    async fn email_not_verified_checkout_response_is_forbidden_json() {
        let response = email_not_verified_response().into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({ "error": "EMAIL_NOT_VERIFIED" }));
    }

    #[test]
    fn parse_ls_subscription_extracts_lifecycle_fields() {
        let _env = set_variant_env();
        let body = serde_json::json!({
            "data": {
                "id": "sub_123",
                "attributes": {
                    "customer_id": 55,
                    "variant_id": 101,
                    "status": "cancelled",
                    "cancelled": true,
                    "renews_at": "2026-06-01T00:00:00.000000Z",
                    "ends_at": "2026-06-01T00:00:00.000000Z",
                    "first_subscription_item": { "quantity": 1 },
                    "urls": {
                        "customer_portal": "https://example.test/billing",
                        "update_payment_method": "https://example.test/payment"
                    }
                },
                "relationships": {
                    "customer": { "data": { "id": "cus_123" } }
                }
            }
        });

        let parsed = parse_ls_subscription(&body).expect("subscription parses");
        assert_eq!(parsed.subscription_id, "sub_123");
        assert_eq!(parsed.customer_id.as_deref(), Some("cus_123"));
        assert_eq!(parsed.variant_id.as_deref(), Some("101"));
        assert_eq!(parsed.tier, Some("pro"));
        assert_eq!(parsed.status.as_deref(), Some("cancelled"));
        assert!(parsed.cancelled);
        assert_eq!(parsed.renews_at.unwrap().timestamp(), 1_780_272_000);
        assert_eq!(parsed.ends_at.unwrap().timestamp(), 1_780_272_000);
        assert_eq!(parsed.seat_count, Some(1));
    }

    #[test]
    fn persistence_rejects_subscription_state_without_known_tier() {
        let state = LemonSubscriptionState {
            subscription_id: "sub_123".to_string(),
            customer_id: None,
            variant_id: Some("999".to_string()),
            tier: None,
            status: Some("active".to_string()),
            cancelled: false,
            renews_at: None,
            ends_at: None,
            seat_count: Some(1),
        };

        assert_eq!(
            subscription_tier_for_persistence(&state),
            Err(StatusCode::BAD_GATEWAY)
        );
    }

    #[test]
    fn subscription_info_response_serializes_lifecycle_fields() {
        let response = SubscriptionInfoResponse {
            tier: "teams".to_string(),
            status: Some("active".to_string()),
            cancelled: false,
            renews_at: Some(1_780_272_000),
            ends_at: None,
            seats: Some(3),
            used_seats: Some(2),
            trial_ends_at: Some(1_777_680_000),
            has_ls_subscription: true,
        };

        let serialized = serde_json::to_value(response).expect("response serializes");

        assert_eq!(serialized["tier"], "teams");
        assert_eq!(serialized["status"], "active");
        assert_eq!(serialized["cancelled"], false);
        assert_eq!(serialized["renews_at"], 1_780_272_000);
        assert_eq!(serialized["ends_at"], serde_json::Value::Null);
        assert_eq!(serialized["seats"], 3);
        assert_eq!(serialized["used_seats"], 2);
        assert_eq!(serialized["trial_ends_at"], 1_777_680_000);
        assert_eq!(serialized["has_ls_subscription"], true);
    }
}
