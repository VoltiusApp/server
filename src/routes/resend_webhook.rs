use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use sqlx::PgPool;
use tracing::{error, info, warn};

const TIMESTAMP_TOLERANCE_SECS: i64 = 300;

#[derive(Deserialize)]
struct ResendEvent {
    #[serde(rename = "type")]
    kind: String,
    data: ResendEventData,
}

#[derive(Deserialize)]
struct ResendEventData {
    #[serde(default)]
    to: Vec<String>,
    bounce: Option<Bounce>,
}

#[derive(Deserialize)]
struct Bounce {
    #[serde(rename = "type")]
    kind: String,
}

/// Svix scheme: HMAC-SHA256 over `{id}.{timestamp}.{body}`, keyed with the base64 after `whsec_`.
fn verify_svix_signature(secret: &str, headers: &HeaderMap, body: &[u8], now: i64) -> bool {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let (Some(id), Some(timestamp), Some(signatures)) = (
        header("svix-id"),
        header("svix-timestamp"),
        header("svix-signature"),
    ) else {
        return false;
    };
    let Ok(sent_at) = timestamp.parse::<i64>() else {
        return false;
    };
    if (now - sent_at).abs() > TIMESTAMP_TOLERANCE_SECS {
        return false;
    }
    let Ok(key) = STANDARD.decode(secret.trim_start_matches("whsec_")) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&key) else {
        return false;
    };
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);

    signatures
        .split(' ')
        .filter_map(|entry| entry.strip_prefix("v1,"))
        .filter_map(|sig| STANDARD.decode(sig).ok())
        .any(|sig| mac.clone().verify_slice(&sig).is_ok())
}

fn undeliverable_recipients(event: &ResendEvent) -> Vec<String> {
    let undeliverable = match event.kind.as_str() {
        "email.suppressed" => true,
        "email.bounced" => event
            .data
            .bounce
            .as_ref()
            .is_some_and(|b| b.kind == "Permanent"),
        _ => false,
    };
    if !undeliverable {
        return Vec::new();
    }
    event
        .data
        .to
        .iter()
        .map(|to| crate::email::normalize(to))
        .collect()
}

pub async fn resend_webhook(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Some(secret) = std::env::var("RESEND_WEBHOOK_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        error!("RESEND_WEBHOOK_SECRET not set — rejecting Resend webhook");
        return StatusCode::UNAUTHORIZED;
    };
    if !verify_svix_signature(&secret, &headers, &body, chrono::Utc::now().timestamp()) {
        warn!("Resend webhook signature verification failed");
        return StatusCode::UNAUTHORIZED;
    }
    let Ok(event) = serde_json::from_slice::<ResendEvent>(&body) else {
        warn!("Resend webhook payload did not parse");
        return StatusCode::BAD_REQUEST;
    };

    let recipients = undeliverable_recipients(&event);
    if recipients.is_empty() {
        return StatusCode::OK;
    }
    match mark_undeliverable(&pool, &recipients).await {
        Ok(marked) => {
            info!(event = %event.kind, marked, "Marked unverified addresses undeliverable");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "Failed to mark undeliverable addresses");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn mark_undeliverable(pool: &PgPool, emails: &[String]) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE users SET email_undeliverable_at = now()
         WHERE email = ANY($1) AND NOT email_verified AND email_undeliverable_at IS NULL",
    )
    .bind(emails)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // Test vector from the Svix verification docs.
    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const TIMESTAMP: i64 = 1614265330;
    const BODY: &[u8] = br#"{"test": 2432232314}"#;
    const SIGNATURE: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

    fn headers(signature: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("svix-id", HeaderValue::from_static(ID));
        h.insert(
            "svix-timestamp",
            HeaderValue::from_str(&TIMESTAMP.to_string()).unwrap(),
        );
        h.insert("svix-signature", HeaderValue::from_str(signature).unwrap());
        h
    }

    #[test]
    fn accepts_a_valid_signature_among_several() {
        let sigs = format!("v1,bm90LWl0 {SIGNATURE}");
        assert!(verify_svix_signature(
            SECRET,
            &headers(&sigs),
            BODY,
            TIMESTAMP + 10
        ));
    }

    #[test]
    fn rejects_a_tampered_body_or_stale_timestamp() {
        assert!(!verify_svix_signature(
            SECRET,
            &headers(SIGNATURE),
            br#"{"test": 1}"#,
            TIMESTAMP
        ));
        assert!(!verify_svix_signature(
            SECRET,
            &headers(SIGNATURE),
            BODY,
            TIMESTAMP + 301
        ));
        assert!(!verify_svix_signature(
            SECRET,
            &HeaderMap::new(),
            BODY,
            TIMESTAMP
        ));
    }

    fn event(json: serde_json::Value) -> ResendEvent {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn hard_bounces_and_suppressions_are_undeliverable() {
        let bounced = event(serde_json::json!({
            "type": "email.bounced",
            "data": { "to": ["Typo@Gmail.com"], "bounce": { "type": "Permanent", "subType": "General" } }
        }));
        assert_eq!(undeliverable_recipients(&bounced), vec!["typo@gmail.com"]);

        let suppressed = event(serde_json::json!({
            "type": "email.suppressed",
            "data": { "to": ["typo@gmail.com"], "suppressed": { "type": "OnAccountSuppressionList" } }
        }));
        assert_eq!(
            undeliverable_recipients(&suppressed),
            vec!["typo@gmail.com"]
        );
    }

    #[test]
    fn soft_bounces_and_other_events_are_ignored() {
        let transient = event(serde_json::json!({
            "type": "email.bounced",
            "data": { "to": ["a@b.test"], "bounce": { "type": "Transient" } }
        }));
        assert!(undeliverable_recipients(&transient).is_empty());

        let delivered =
            event(serde_json::json!({ "type": "email.delivered", "data": { "to": ["a@b.test"] } }));
        assert!(undeliverable_recipients(&delivered).is_empty());
    }

    #[tokio::test]
    async fn a_marked_address_shows_on_me_and_refuses_resends() {
        let pool = crate::test_pool_or_skip!();
        let unverified = crate::test_support::seed_user(&pool).await;
        let verified = crate::test_support::seed_user(&pool).await;
        sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
            .bind(verified)
            .execute(&pool)
            .await
            .unwrap();

        let emails = vec![
            format!("{unverified}@test.local"),
            format!("{verified}@test.local"),
        ];
        assert_eq!(mark_undeliverable(&pool, &emails).await.unwrap(), 1);
        assert_eq!(mark_undeliverable(&pool, &emails).await.unwrap(), 0);

        let me = crate::routes::auth::fetch_me_inner(&pool, unverified, false)
            .await
            .unwrap();
        assert!(me.email_undeliverable);

        let resend = crate::routes::auth::resend_verification_email(
            State(pool.clone()),
            axum::Extension(crate::auth::AuthUser(unverified)),
        )
        .await
        .unwrap();
        assert_eq!(resend.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
