use std::time::Duration;

use tracing::error;

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn branded_email_html(
    preheader: &str,
    eyebrow: &str,
    title: &str,
    body: &str,
    cta_label: &str,
    cta_url: &str,
    footer_note: &str,
) -> String {
    let preheader = escape_html(preheader);
    let eyebrow = escape_html(eyebrow);
    let title = escape_html(title);
    let cta_label = escape_html(cta_label);
    let cta_url = escape_html(cta_url);
    let footer_note = escape_html(footer_note);
    let logo_url = escape_html(
        &std::env::var("RESEND_LOGO_URL")
            .unwrap_or_else(|_| "https://voltius.app/logo.png".to_string()),
    );
    let website_url = escape_html(
        &std::env::var("VOLTIUS_MARKETING_URL").unwrap_or_else(|_| "https://voltius.app".to_string()),
    );

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>{title}</title>
</head>
<body style="margin:0;padding:0;background:#0a0a0f;color:#f0f0f5;font-family:Inter,Geist,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;-webkit-font-smoothing:antialiased;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;line-height:1px;font-size:1px;">{preheader}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#0a0a0f;background-image:radial-gradient(circle at 50% 0%,rgba(6,182,212,0.20),transparent 34%),linear-gradient(180deg,#0d0d12 0%,#0a0a0f 70%);">
    <tr>
      <td align="center" style="padding:42px 16px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;">
          <tr>
            <td align="center" style="padding:0 0 22px;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td align="center" valign="middle">
                    <a href="{website_url}" style="display:block;text-decoration:none;"><img src="{logo_url}" width="40" height="40" alt="Voltius" style="display:block;width:40px;height:40px;border:0;outline:none;text-decoration:none;"></a>
                  </td>
                  <td style="padding-left:10px;font-size:16px;font-weight:700;letter-spacing:-0.02em;"><a href="{website_url}" style="color:#ffffff;text-decoration:none;">Voltius</a></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="border:1px solid #1e1e2e;border-radius:28px;background:#111118;overflow:hidden;box-shadow:0 28px 70px rgba(0,0,0,0.55),0 0 60px rgba(34,211,238,0.12);">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td style="height:6px;background:linear-gradient(90deg,#06b6d4,#22d3ee,#22c55e);"></td>
                </tr>
                <tr>
                  <td style="padding:40px 36px 34px;">
                    <div style="display:inline-block;margin-bottom:18px;padding:7px 11px;border:1px solid rgba(34,211,238,0.28);border-radius:999px;background:rgba(6,182,212,0.10);color:#22d3ee;font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:12px;line-height:1;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;">{eyebrow}</div>
                    <h1 style="margin:0;color:#ffffff;font-size:34px;line-height:1.08;font-weight:800;letter-spacing:-0.04em;">{title}</h1>
                    <div style="margin-top:18px;color:#a1a1aa;font-size:16px;line-height:1.7;">{body}</div>
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin-top:30px;">
                      <tr>
                        <td style="border-radius:14px;background:#06b6d4;box-shadow:0 0 28px rgba(6,182,212,0.34);">
                          <a href="{cta_url}" style="display:inline-block;padding:15px 22px;color:#020617;text-decoration:none;font-size:15px;font-weight:800;letter-spacing:-0.01em;border-radius:14px;">{cta_label}</a>
                        </td>
                      </tr>
                    </table>
                    <div style="margin-top:28px;padding:16px 18px;border:1px solid #1e1e2e;border-radius:18px;background:#0d0d12;color:#71717a;font-size:13px;line-height:1.6;">{footer_note}</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:24px 20px 0;color:#52525b;font-size:12px;line-height:1.6;">
              Fast by design. Private by default.<br>
              <a href="{website_url}" style="color:#71717a;text-decoration:none;">Visit voltius.app</a><br>
              If the button does not work, paste this link into your browser:<br>
              <a href="{cta_url}" style="color:#22d3ee;text-decoration:none;word-break:break-all;">{cta_url}</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"##
    )
}

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

    let accept_url = format!("{}/invite/{token}", app_url.trim_end_matches('/'));
    let escaped_team_name = escape_html(team_name);
    let escaped_inviter_email = escape_html(inviter_email);
    let html = branded_email_html(
        &format!("{inviter_email} invited you to {team_name} on Voltius."),
        "Team invite",
        &format!("Join {team_name} on Voltius"),
        &format!(
            r#"<p style="margin:0 0 14px;">{escaped_inviter_email} invited you to collaborate in <strong style="color:#ffffff;font-weight:700;">{escaped_team_name}</strong>.</p>
                    <p style="margin:0;">Accept the invite to access the team's encrypted vaults, shared SSH assets, and collaboration workspace.</p>"#
        ),
        "Accept invitation",
        &accept_url,
        "This invitation expires in 7 days. If you were not expecting this, you can safely ignore this email.",
    );
    let text = format!(
        "{inviter_email} invited you to join {team_name} on Voltius. Accept the invitation: {accept_url}\n\nThis invitation expires in 7 days."
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
            "text": text,
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

    let verify_url = format!("{}/verify-email?token={token}", app_url.trim_end_matches('/'));
    let html = branded_email_html(
        "Confirm this email address to finish securing your Voltius account.",
        "Email verification",
        "Verify your Voltius email",
        r#"<p style="margin:0 0 14px;">Confirm this email address to finish securing your Voltius account.</p>
                    <p style="margin:0;">This keeps your encrypted sync, vault access, and account recovery protected behind a verified inbox.</p>"#,
        "Verify email",
        &verify_url,
        "This verification link expires in 24 hours. If you did not create a Voltius account, you can safely ignore this email.",
    );
    let text = format!(
        "Verify your Voltius email: {verify_url}\n\nThis verification link expires in 24 hours."
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
            "text": text,
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
