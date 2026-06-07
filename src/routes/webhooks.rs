use crate::lemonsqueezy::{parse_ls_datetime, tier_from_variant_id};
use crate::sync_notifier::SyncNotifier;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    Extension,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;

fn verify_ls_signature(body: &[u8], signature_header: &str) -> bool {
    let secret = match std::env::var("LEMONSQUEEZY_SIGNING_SECRET") {
        Ok(s) => s,
        Err(_) => {
            error!("LEMONSQUEEZY_SIGNING_SECRET not set — rejecting webhook");
            return false;
        }
    };

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    let result = hex::encode(mac.finalize().into_bytes());
    result == signature_header
}

#[derive(Debug, Clone)]
struct WebhookSubscriptionState {
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

fn parse_webhook_subscription(payload: &serde_json::Value) -> Option<WebhookSubscriptionState> {
    let data = &payload["data"];
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

    Some(WebhookSubscriptionState {
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

fn configured_tier_for_subscription(
    event_name: &str,
    subscription: &WebhookSubscriptionState,
) -> Option<&'static str> {
    match subscription.tier {
        Some(tier) => Some(tier),
        None => {
            warn!(
                event = %event_name,
                ls_subscription_id = %subscription.subscription_id,
                variant_id = ?subscription.variant_id,
                "LemonSqueezy webhook variant is not configured; skipping tier update"
            );
            None
        }
    }
}

fn tier_for_subscription_update(subscription: &WebhookSubscriptionState) -> &'static str {
    subscription.tier.unwrap_or("free")
}

pub async fn lemonsqueezy_webhook(
    State(pool): State<PgPool>,
    Extension(notifier): Extension<SyncNotifier>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let signature = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_ls_signature(&body, signature) {
        warn!("LemonSqueezy webhook: invalid signature");
        return StatusCode::UNAUTHORIZED;
    }

    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "LemonSqueezy webhook: failed to parse body");
            return StatusCode::BAD_REQUEST;
        }
    };

    let event_name = payload["meta"]["event_name"].as_str().unwrap_or("unknown");

    info!(event = %event_name, "LemonSqueezy webhook received");

    match event_name {
        "subscription_created" => handle_subscription_created(&pool, &notifier, &payload).await,
        "subscription_updated" => handle_subscription_updated(&pool, &notifier, &payload).await,
        "subscription_cancelled" => handle_subscription_cancelled(&pool, &notifier, &payload).await,
        "subscription_expired" => handle_subscription_expired(&pool, &notifier, &payload).await,
        "subscription_trial_expired" => handle_trial_expired(&pool, &notifier, &payload).await,
        _ => {
            info!(event = %event_name, "LemonSqueezy webhook: unhandled event");
            StatusCode::OK
        }
    }
}

async fn handle_subscription_created(
    pool: &PgPool,
    notifier: &SyncNotifier,
    payload: &serde_json::Value,
) -> StatusCode {
    let attrs = &payload["data"]["attributes"];
    let customer_email = attrs["user_email"].as_str().unwrap_or("");
    let ls_customer_id = payload["data"]["relationships"]["customer"]["data"]["id"]
        .as_str()
        .unwrap_or("");
    let subscription = match parse_webhook_subscription(payload) {
        Some(s) => s,
        None => {
            error!("subscription_created missing subscription id");
            return StatusCode::BAD_REQUEST;
        }
    };
    let tier = match configured_tier_for_subscription("subscription_created", &subscription) {
        Some(tier) => tier,
        None => return StatusCode::OK,
    };

    // Prefer UUID match from checkout custom_data — survives email changes at checkout
    let user_id = payload["meta"]["custom_data"]["user_id"]
        .as_str()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());

    let result = if let Some(uid) = user_id {
        sqlx::query(
            "UPDATE users SET
                subscription_tier = $1,
                ls_customer_id = $2,
                ls_subscription_id = $3,
                seat_count = COALESCE($4, seat_count),
                ls_subscription_status = $5,
                ls_variant_id = $6,
                subscription_cancelled = $7,
                subscription_renews_at = $8,
                subscription_ends_at = $9,
                trial_used = TRUE,
                trial_ends_at = NULL
             WHERE id = $10",
        )
        .bind(tier)
        .bind(
            subscription
                .customer_id
                .as_deref()
                .unwrap_or(ls_customer_id),
        )
        .bind(&subscription.subscription_id)
        .bind(subscription.seat_count)
        .bind(&subscription.status)
        .bind(&subscription.variant_id)
        .bind(subscription.cancelled)
        .bind(subscription.renews_at)
        .bind(subscription.ends_at)
        .bind(uid)
        .execute(pool)
        .await
    } else {
        // Fallback: match by email (e.g. manual LS admin actions without custom_data)
        sqlx::query(
            "UPDATE users SET
                subscription_tier = $1,
                ls_customer_id = $2,
                ls_subscription_id = $3,
                seat_count = COALESCE($4, seat_count),
                ls_subscription_status = $5,
                ls_variant_id = $6,
                subscription_cancelled = $7,
                subscription_renews_at = $8,
                subscription_ends_at = $9,
                trial_used = TRUE,
                trial_ends_at = NULL
             WHERE email = $10",
        )
        .bind(tier)
        .bind(
            subscription
                .customer_id
                .as_deref()
                .unwrap_or(ls_customer_id),
        )
        .bind(&subscription.subscription_id)
        .bind(subscription.seat_count)
        .bind(&subscription.status)
        .bind(&subscription.variant_id)
        .bind(subscription.cancelled)
        .bind(subscription.renews_at)
        .bind(subscription.ends_at)
        .bind(customer_email)
        .execute(pool)
        .await
    };

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(email = %customer_email, tier = %tier, "Subscription created");
            // Notify client to refresh JWT so it picks up the new tier immediately
            if let Some(uid) = user_id {
                notifier.notify(uid, "token_invalidated".to_string());
            } else if let Ok(Some((uid,))) =
                sqlx::query_as::<_, (uuid::Uuid,)>("SELECT id FROM users WHERE email = $1")
                    .bind(customer_email)
                    .fetch_optional(pool)
                    .await
            {
                notifier.notify(uid, "token_invalidated".to_string());
            }
            StatusCode::OK
        }
        Ok(_) => {
            warn!(email = %customer_email, "subscription_created: no matching user");
            StatusCode::OK // return 200 so LS doesn't retry
        }
        Err(e) => {
            error!(error = %e, "subscription_created DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn handle_subscription_updated(
    pool: &PgPool,
    notifier: &SyncNotifier,
    payload: &serde_json::Value,
) -> StatusCode {
    let subscription = match parse_webhook_subscription(payload) {
        Some(s) => s,
        None => {
            error!("subscription_updated missing subscription id");
            return StatusCode::BAD_REQUEST;
        }
    };
    let ls_subscription_id = subscription.subscription_id.as_str();
    let tier = tier_for_subscription_update(&subscription);
    if subscription.tier.is_none() {
        warn!(
            ls_subscription_id = %ls_subscription_id,
            variant_id = ?subscription.variant_id,
            "subscription_updated variant is not configured; downgrading matching subscription to free"
        );
    }

    let result = sqlx::query_as::<_, (uuid::Uuid,)>(
        "UPDATE users SET
            subscription_tier = $1,
            seat_count = COALESCE($2, seat_count),
            ls_subscription_status = $3,
            ls_variant_id = $4,
            subscription_cancelled = $5,
            subscription_renews_at = $6,
            subscription_ends_at = $7
         WHERE ls_subscription_id = $8 AND admin_override = FALSE
         RETURNING id",
    )
    .bind(tier)
    .bind(subscription.seat_count)
    .bind(&subscription.status)
    .bind(&subscription.variant_id)
    .bind(subscription.cancelled)
    .bind(subscription.renews_at)
    .bind(subscription.ends_at)
    .bind(ls_subscription_id)
    .fetch_optional(pool)
    .await;

    match result {
        Ok(Some((uid,))) => {
            info!(ls_subscription_id = %ls_subscription_id, tier = %tier, "Subscription updated");
            notifier.notify(uid, "token_invalidated".to_string());
            StatusCode::OK
        }
        Ok(None) => {
            info!(ls_subscription_id = %ls_subscription_id, "subscription_updated: no matching user");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "subscription_updated DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn handle_subscription_cancelled(
    pool: &PgPool,
    notifier: &SyncNotifier,
    payload: &serde_json::Value,
) -> StatusCode {
    let subscription = match parse_webhook_subscription(payload) {
        Some(s) => s,
        None => {
            error!("subscription_cancelled missing subscription id");
            return StatusCode::BAD_REQUEST;
        }
    };

    let result = sqlx::query_as::<_, (uuid::Uuid,)>(
        "UPDATE users SET
            ls_subscription_status = $1,
            ls_variant_id = $2,
            subscription_cancelled = TRUE,
            subscription_renews_at = $3,
            subscription_ends_at = $4
         WHERE ls_subscription_id = $5 AND admin_override = FALSE
         RETURNING id",
    )
    .bind(&subscription.status)
    .bind(&subscription.variant_id)
    .bind(subscription.renews_at)
    .bind(subscription.ends_at)
    .bind(&subscription.subscription_id)
    .fetch_optional(pool)
    .await;

    match result {
        Ok(Some((uid,))) => {
            info!(ls_subscription_id = %subscription.subscription_id, "Subscription cancelled at period end");
            notifier.notify(uid, "token_invalidated".to_string());
            StatusCode::OK
        }
        Ok(None) => {
            info!(ls_subscription_id = %subscription.subscription_id, "subscription_cancelled: no matching user");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "subscription_cancelled DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn handle_subscription_expired(
    pool: &PgPool,
    notifier: &SyncNotifier,
    payload: &serde_json::Value,
) -> StatusCode {
    let ls_subscription_id = payload["data"]["id"].as_str().unwrap_or("");

    let old_tier_row = sqlx::query_as::<_, (uuid::Uuid, String)>(
        "SELECT id, subscription_tier FROM users WHERE ls_subscription_id = $1",
    )
    .bind(ls_subscription_id)
    .fetch_optional(pool)
    .await;

    let result = sqlx::query(
        "UPDATE users SET
            subscription_tier = 'free',
            ls_subscription_id = NULL,
            ls_subscription_status = NULL,
            ls_variant_id = NULL,
            subscription_cancelled = FALSE,
            subscription_renews_at = NULL,
            subscription_ends_at = COALESCE(subscription_ends_at, NOW()),
            trial_used = TRUE
         WHERE ls_subscription_id = $1 AND admin_override = FALSE",
    )
    .bind(ls_subscription_id)
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            if let Ok(Some((user_id, old_tier))) = old_tier_row {
                let _ = sqlx::query(
                    "INSERT INTO churn_events (user_id, from_tier, to_tier, reason) VALUES ($1, $2, 'free', 'subscription_expired')",
                )
                .bind(user_id)
                .bind(&old_tier)
                .execute(pool)
                .await;
                notifier.notify(user_id, "token_invalidated".to_string());
            }
            info!(ls_subscription_id = %ls_subscription_id, "Subscription expired — downgraded to free");
            StatusCode::OK
        }
        Ok(_) => {
            info!(ls_subscription_id = %ls_subscription_id, "subscription_expired: no matching user");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "subscription_expired DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn handle_trial_expired(
    pool: &PgPool,
    notifier: &SyncNotifier,
    payload: &serde_json::Value,
) -> StatusCode {
    let customer_email = payload["data"]["attributes"]["user_email"]
        .as_str()
        .unwrap_or("");

    let old_tier_row = sqlx::query_as::<_, (uuid::Uuid, String)>(
        "SELECT id, subscription_tier FROM users WHERE email = $1",
    )
    .bind(customer_email)
    .fetch_optional(pool)
    .await;

    let result = sqlx::query(
        "UPDATE users SET subscription_tier = 'free', trial_used = TRUE, trial_ends_at = NULL WHERE email = $1",
    )
    .bind(customer_email)
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            if let Ok(Some((user_id, old_tier))) = old_tier_row {
                let _ = sqlx::query(
                    "INSERT INTO churn_events (user_id, from_tier, to_tier, reason) VALUES ($1, $2, 'free', 'trial_expired')",
                )
                .bind(user_id)
                .bind(&old_tier)
                .execute(pool)
                .await;
                notifier.notify(user_id, "token_invalidated".to_string());
            }
            info!(email = %customer_email, "Trial expired — downgraded to free");
            StatusCode::OK
        }
        Ok(_) => {
            info!(email = %customer_email, "trial_expired: no matching user");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "subscription_trial_expired DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_webhook_subscription_maps_variant_and_lifecycle_fields() {
        let _env = crate::test_support::env_lock();
        std::env::set_var("LS_VARIANT_PRO_MONTHLY", "101");
        std::env::set_var("LS_VARIANT_PRO_YEARLY", "102");
        std::env::set_var("LS_VARIANT_TEAMS_MONTHLY", "201");
        std::env::set_var("LS_VARIANT_TEAMS_YEARLY", "202");

        let payload = json!({
            "data": {
                "id": "sub_123",
                "relationships": {
                    "customer": { "data": { "id": "cus_456" } }
                },
                "attributes": {
                    "variant_id": 201,
                    "status": "active",
                    "cancelled": true,
                    "renews_at": "2026-06-01T00:00:00Z",
                    "ends_at": "2026-07-01T00:00:00Z",
                    "first_subscription_item": { "quantity": 7 }
                }
            }
        });

        let subscription = parse_webhook_subscription(&payload).unwrap();

        assert_eq!(subscription.subscription_id, "sub_123");
        assert_eq!(subscription.customer_id.as_deref(), Some("cus_456"));
        assert_eq!(subscription.variant_id.as_deref(), Some("201"));
        assert_eq!(subscription.tier, Some("teams"));
        assert_eq!(subscription.status.as_deref(), Some("active"));
        assert!(subscription.cancelled);
        assert_eq!(subscription.seat_count, Some(7));
        assert_eq!(subscription.renews_at.unwrap().timestamp(), 1_780_272_000);
        assert_eq!(subscription.ends_at.unwrap().timestamp(), 1_782_864_000);

        std::env::remove_var("LS_VARIANT_PRO_MONTHLY");
        std::env::remove_var("LS_VARIANT_PRO_YEARLY");
        std::env::remove_var("LS_VARIANT_TEAMS_MONTHLY");
        std::env::remove_var("LS_VARIANT_TEAMS_YEARLY");
    }

    #[test]
    fn configured_tier_for_subscription_returns_none_for_unknown_variant() {
        let _env = crate::test_support::env_lock();
        std::env::set_var("LS_VARIANT_PRO_MONTHLY", "101");
        std::env::set_var("LS_VARIANT_TEAMS_MONTHLY", "201");

        let payload = json!({
            "data": {
                "id": "sub_unknown",
                "attributes": {
                    "variant_id": 999,
                    "first_subscription_item": { "quantity": 1 }
                }
            }
        });

        let subscription = parse_webhook_subscription(&payload).unwrap();

        assert_eq!(subscription.variant_id.as_deref(), Some("999"));
        assert_eq!(
            configured_tier_for_subscription("subscription_created", &subscription),
            None
        );

        std::env::remove_var("LS_VARIANT_PRO_MONTHLY");
        std::env::remove_var("LS_VARIANT_TEAMS_MONTHLY");
    }

    #[test]
    fn tier_for_subscription_update_fails_closed_for_unknown_variant() {
        let _env = crate::test_support::env_lock();
        std::env::set_var("LS_VARIANT_PRO_MONTHLY", "101");

        let payload = json!({
            "data": {
                "id": "sub_unknown",
                "attributes": {
                    "variant_id": 999,
                    "first_subscription_item": { "quantity": 3 }
                }
            }
        });

        let subscription = parse_webhook_subscription(&payload).unwrap();

        assert_eq!(tier_for_subscription_update(&subscription), "free");

        std::env::remove_var("LS_VARIANT_PRO_MONTHLY");
    }
}
