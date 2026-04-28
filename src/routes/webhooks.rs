use axum::{body::Bytes, extract::State, http::{HeaderMap, StatusCode}, Extension};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use tracing::{error, info, warn};
use crate::sync_notifier::SyncNotifier;

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

    let event_name = payload["meta"]["event_name"]
        .as_str()
        .unwrap_or("unknown");

    info!(event = %event_name, "LemonSqueezy webhook received");

    match event_name {
        "subscription_created" => handle_subscription_created(&pool, &notifier, &payload).await,
        "subscription_updated" => handle_subscription_updated(&pool, &notifier, &payload).await,
        "subscription_cancelled" => handle_subscription_cancelled(&pool, &payload).await,
        "subscription_expired" => handle_subscription_expired(&pool, &notifier, &payload).await,
        "subscription_trial_expired" => handle_trial_expired(&pool, &notifier, &payload).await,
        _ => {
            info!(event = %event_name, "LemonSqueezy webhook: unhandled event");
            StatusCode::OK
        }
    }
}

async fn handle_subscription_created(pool: &PgPool, notifier: &SyncNotifier, payload: &serde_json::Value) -> StatusCode {
    let attrs = &payload["data"]["attributes"];
    let customer_email = attrs["user_email"].as_str().unwrap_or("");
    let ls_customer_id = payload["data"]["relationships"]["customer"]["data"]["id"]
        .as_str()
        .unwrap_or("");
    let ls_subscription_id = payload["data"]["id"].as_str().unwrap_or("");
    let tier = attrs["product_name"]
        .as_str()
        .map(|n| tier_from_product_name(n))
        .unwrap_or("pro");

    // Prefer UUID match from checkout custom_data — survives email changes at checkout
    let user_id = payload["meta"]["custom_data"]["user_id"]
        .as_str()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());

    let seat_count = attrs["quantity"].as_i64().map(|q| q as i32);

    let result = if let Some(uid) = user_id {
        sqlx::query(
            "UPDATE users SET
                subscription_tier = $1,
                ls_customer_id = $2,
                ls_subscription_id = $3,
                seat_count = COALESCE($4, seat_count),
                trial_used = TRUE,
                trial_ends_at = NULL
             WHERE id = $5",
        )
        .bind(tier)
        .bind(ls_customer_id)
        .bind(ls_subscription_id)
        .bind(seat_count)
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
                trial_used = TRUE,
                trial_ends_at = NULL
             WHERE email = $5",
        )
        .bind(tier)
        .bind(ls_customer_id)
        .bind(ls_subscription_id)
        .bind(seat_count)
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
            } else if let Ok(Some((uid,))) = sqlx::query_as::<_, (uuid::Uuid,)>(
                "SELECT id FROM users WHERE email = $1",
            )
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

async fn handle_subscription_updated(pool: &PgPool, notifier: &SyncNotifier, payload: &serde_json::Value) -> StatusCode {
    let attrs = &payload["data"]["attributes"];
    let ls_subscription_id = payload["data"]["id"].as_str().unwrap_or("");
    let tier = attrs["product_name"]
        .as_str()
        .map(|n| tier_from_product_name(n))
        .unwrap_or("pro");

    let seat_count = attrs["quantity"].as_i64().map(|q| q as i32);

    // Fetch user_id before updating so we can notify them regardless of admin_override
    let user_row = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM users WHERE ls_subscription_id = $1",
    )
    .bind(ls_subscription_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let result = sqlx::query(
        "UPDATE users SET
            subscription_tier = $1,
            seat_count = COALESCE($2, seat_count)
         WHERE ls_subscription_id = $3 AND admin_override = FALSE",
    )
    .bind(tier)
    .bind(seat_count)
    .bind(ls_subscription_id)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            info!(ls_subscription_id = %ls_subscription_id, tier = %tier, "Subscription updated");
            if let Some((uid,)) = user_row {
                notifier.notify(uid, "token_invalidated".to_string());
            }
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

async fn handle_subscription_expired(pool: &PgPool, notifier: &SyncNotifier, payload: &serde_json::Value) -> StatusCode {
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

async fn handle_trial_expired(pool: &PgPool, notifier: &SyncNotifier, payload: &serde_json::Value) -> StatusCode {
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
