use tracing::{error, info};

pub async fn check() {
    let license_key = std::env::var("LICENSE_KEY").unwrap_or_else(|_| {
        error!("LICENSE_KEY environment variable not set");
        panic!("LICENSE_KEY is required");
    });

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.lemonsqueezy.com/v1/licenses/validate")
        .form(&[("license_key", &license_key)])
        .send()
        .await
        .unwrap_or_else(|err| {
            error!(error = %err, "Failed to reach LemonSqueezy");
            panic!("License validation failed: could not reach license server");
        });

    let body: serde_json::Value = response.json().await.unwrap_or_else(|err| {
        error!(error = %err, "Failed to parse license response");
        panic!("License validation failed: invalid response");
    });

    if body["valid"].as_bool() != Some(true) {
        let msg = body["error"].as_str().unwrap_or("license is not valid");
        error!(error = %msg, "License check failed");
        panic!("License validation failed: {}", msg);
    }

    let customer = body["meta"]["customer_name"].as_str().unwrap_or("unknown");
    let product = body["meta"]["product_name"].as_str().unwrap_or("unknown");
    info!(customer = %customer, product = %product, "License valid");
}
