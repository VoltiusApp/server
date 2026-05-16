use std::time::Duration;

use tracing::error;

pub async fn send_team_invitation(
    to: &str,
    team_name: &str,
    inviter_email: &str,
    token: &str,
    app_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let api_key = std::env::var("RESEND_API_KEY").unwrap_or_default();
    let from = std::env::var("RESEND_FROM")
        .unwrap_or_else(|_| "Voltius <noreply@voltius.app>".to_string());

    if api_key.is_empty() {
        error!("RESEND_API_KEY not set; skipping invitation email to {to}");
        return Ok(());
    }

    let accept_url = format!("{app_url}/invite/{token}");
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;max-width:480px;margin:40px auto;color:#1a1a1a">
  <h2 style="margin-bottom:8px">You've been invited to <strong>{team_name}</strong></h2>
  <p style="color:#555;margin-bottom:24px">{inviter_email} invited you to join their team vault on Voltius.</p>
  <a href="{accept_url}"
     style="display:inline-block;padding:12px 24px;background:#6366f1;color:#fff;text-decoration:none;border-radius:8px;font-weight:600">
    Accept invitation
  </a>
  <p style="color:#999;font-size:12px;margin-top:32px">
    This invitation expires in 7 days. If you weren't expecting this, you can ignore it.
  </p>
</body>
</html>"#
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let res = client
        .post("https://api.resend.com/emails")
        .bearer_auth(&api_key)
        .json(&serde_json::json!({
            "from": from,
            "to": [to],
            "subject": format!("{inviter_email} invited you to {team_name} on Voltius"),
            "html": html,
        }))
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        error!(status = %status, body = %body, "Resend API error");
        return Err(format!("Resend returned {status}").into());
    }

    Ok(())
}

pub async fn send_verification_email(
    to: &str,
    token: &str,
    app_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let api_key = std::env::var("RESEND_API_KEY").unwrap_or_default();
    let from = std::env::var("RESEND_FROM")
        .unwrap_or_else(|_| "Voltius <noreply@voltius.app>".to_string());

    if api_key.is_empty() {
        return Ok(());
    }

    let verify_url = format!("{app_url}/verify-email?token={token}");
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;max-width:480px;margin:40px auto;color:#1a1a1a">
  <h2 style="margin-bottom:8px">Verify your Voltius email</h2>
  <p style="color:#555;margin-bottom:24px">Confirm this email address to finish securing your Voltius account.</p>
  <a href="{verify_url}"
     style="display:inline-block;padding:12px 24px;background:#6366f1;color:#fff;text-decoration:none;border-radius:8px;font-weight:600">
    Verify email
  </a>
  <p style="color:#999;font-size:12px;margin-top:32px">
    This verification link expires in 24 hours. If you didn't create a Voltius account, you can ignore this.
  </p>
</body>
</html>"#
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let res = client
        .post("https://api.resend.com/emails")
        .bearer_auth(&api_key)
        .json(&serde_json::json!({
            "from": from,
            "to": [to],
            "subject": "Verify your Voltius email",
            "html": html,
        }))
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        error!(status = %status, body = %body, "Resend API error");
        return Err(format!("Resend returned {status}").into());
    }

    Ok(())
}
