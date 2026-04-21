use axum::{body::Bytes, extract::State, http::{HeaderMap, StatusCode}};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;

fn verify_ls_signature(body: &[u8], signature_header: &str) -> bool {
    let secret = match std::env::var("LEMONSQUEEZY_SIGNING_SECRET") {
        Ok(s) => s,
        Err(_) => {
            warn!("LEMONSQUEEZY_SIGNING_SECRET not set — skipping webhook signature verification");
            return true; // dev mode: allow unsigned
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

pub async fn lemonsqueezy_webhook(
    State(pool): State<PgPool>,
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

    let event_name = payload["meta"]["event_name"]
        .as_str()
        .unwrap_or("unknown");

    info!(event = %event_name, "LemonSqueezy webhook received");

    match event_name {
        "subscription_created" => handle_subscription_created(&pool, &payload).await,
        "subscription_updated" => handle_subscription_updated(&pool, &payload).await,
        "subscription_cancelled" => handle_subscription_cancelled(&pool, &payload).await,
        "subscription_expired" => handle_subscription_expired(&pool, &payload).await,
        "subscription_trial_expired" => handle_trial_expired(&pool, &payload).await,
        _ => {
            info!(event = %event_name, "LemonSqueezy webhook: unhandled event");
            StatusCode::OK
        }
    }
}

async fn handle_subscription_created(pool: &PgPool, payload: &serde_json::Value) -> StatusCode {
    let attrs = &payload["data"]["attributes"];
    let customer_email = attrs["user_email"].as_str().unwrap_or("");
    let ls_customer_id = payload["data"]["relationships"]["customer"]["data"]["id"]
        .as_str()
        .unwrap_or("");
    let ls_subscription_id = payload["data"]["id"].as_str().unwrap_or("");

    // Tier derived from product metadata or variant name
    let tier = attrs["product_name"]
        .as_str()
        .map(|n| tier_from_product_name(n))
        .unwrap_or("pro");

    let result = sqlx::query(
        "UPDATE users SET
            subscription_tier = $1,
            ls_customer_id = $2,
            ls_subscription_id = $3,
            trial_used = TRUE,
            trial_ends_at = NULL
         WHERE email = $4",
    )
    .bind(tier)
    .bind(ls_customer_id)
    .bind(ls_subscription_id)
    .bind(customer_email)
    .execute(pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            info!(email = %customer_email, tier = %tier, "Subscription created");
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

async fn handle_subscription_updated(pool: &PgPool, payload: &serde_json::Value) -> StatusCode {
    let attrs = &payload["data"]["attributes"];
    let ls_subscription_id = payload["data"]["id"].as_str().unwrap_or("");
    let tier = attrs["product_name"]
        .as_str()
        .map(|n| tier_from_product_name(n))
        .unwrap_or("pro");

    let result = sqlx::query(
        "UPDATE users SET subscription_tier = $1 WHERE ls_subscription_id = $2",
    )
    .bind(tier)
    .bind(ls_subscription_id)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            info!(ls_subscription_id = %ls_subscription_id, tier = %tier, "Subscription updated");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "subscription_updated DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn handle_subscription_cancelled(pool: &PgPool, payload: &serde_json::Value) -> StatusCode {
    // Keep tier active until ends_at; a cron job or subscription_expired fires then.
    // For now just log — downgrade happens on subscription_expired.
    let ls_subscription_id = payload["data"]["id"].as_str().unwrap_or("");
    info!(ls_subscription_id = %ls_subscription_id, "Subscription cancelled — will downgrade on expiry");
    let _ = pool; // used when subscription_expired fires
    StatusCode::OK
}

async fn handle_subscription_expired(pool: &PgPool, payload: &serde_json::Value) -> StatusCode {
    let ls_subscription_id = payload["data"]["id"].as_str().unwrap_or("");

    let result = sqlx::query(
        "UPDATE users SET
            subscription_tier = 'free',
            ls_subscription_id = NULL,
            trial_used = TRUE
         WHERE ls_subscription_id = $1",
    )
    .bind(ls_subscription_id)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            info!(ls_subscription_id = %ls_subscription_id, "Subscription expired — downgraded to free");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "subscription_expired DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn handle_trial_expired(pool: &PgPool, payload: &serde_json::Value) -> StatusCode {
    let customer_email = payload["data"]["attributes"]["user_email"]
        .as_str()
        .unwrap_or("");

    let result = sqlx::query(
        "UPDATE users SET subscription_tier = 'free', trial_used = TRUE, trial_ends_at = NULL WHERE email = $1",
    )
    .bind(customer_email)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            info!(email = %customer_email, "Trial expired — downgraded to free");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "subscription_trial_expired DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn tier_from_product_name(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    if lower.contains("teams") || lower.contains("team") {
        "teams"
    } else if lower.contains("business") {
        "business"
    } else {
        "pro"
    }
}
