use std::fmt;
use std::time::Duration;

use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{error, warn};

pub type SendResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Canonical form of an address, for both storage and lookup.
///
/// Addresses are stored normalized, so every write path must run its input
/// through this and every lookup must compare against it. A mixed-case row is
/// unreachable to a client that lowercases (mobile keyboards autocapitalize),
/// and it shadows invitations addressed to the same mailbox in lower case.
pub fn normalize(raw: &str) -> String {
    raw.trim().to_lowercase()
}

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

pub(crate) fn app_url() -> String {
    std::env::var("VOLTIUS_APP_URL").unwrap_or_else(|_| "https://app.voltius.app".to_string())
}

pub fn delivery_configured() -> bool {
    matches!(Transport::from_env(), Ok(Transport::Resend { .. } | Transport::Smtp(_)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Security {
    StartTls,
    Tls,
    None,
}

impl Security {
    fn default_port(self) -> u16 {
        match self {
            Security::StartTls => 587,
            Security::Tls => 465,
            Security::None => 25,
        }
    }
}

pub struct Smtp {
    host: String,
    port: u16,
    security: Security,
    credentials: Option<Credentials>,
    from: Mailbox,
    timeout: Duration,
}

pub enum Transport {
    Disabled,
    Resend { api_key: String, from: String },
    Smtp(Smtp),
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Disabled => f.write_str("disabled"),
            Transport::Resend { from, .. } => write!(f, "resend, from {from}"),
            Transport::Smtp(s) => write!(
                f,
                "smtp {}:{} ({:?}, {}), from {}",
                s.host,
                s.port,
                s.security,
                if s.credentials.is_some() { "authenticated" } else { "unauthenticated" },
                s.from,
            ),
        }
    }
}

impl Transport {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// `from_env` plus the checks that build TLS state, so they run once at startup rather than per request.
    pub fn validated_from_env() -> Result<Self, String> {
        let transport = Self::from_env()?;
        if let Transport::Smtp(smtp) = &transport {
            smtp.transport().map_err(|e| format!("SMTP_HOST={:?}: {e}", smtp.host))?;
        }
        Ok(transport)
    }

    fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let var = |key: &str| get(key).filter(|v| !v.is_empty());
        let provider = match var("EMAIL_PROVIDER") {
            Some(p) => p.to_ascii_lowercase(),
            None => match (var("RESEND_API_KEY").is_some(), var("SMTP_HOST").is_some()) {
                (true, true) => {
                    return Err("RESEND_API_KEY and SMTP_HOST are both set: pick one with EMAIL_PROVIDER=resend or EMAIL_PROVIDER=smtp".into())
                }
                (true, false) => "resend".into(),
                (false, true) => "smtp".into(),
                (false, false) => "disabled".into(),
            },
        };
        match provider.as_str() {
            "disabled" => Ok(Transport::Disabled),
            "resend" => Ok(Transport::Resend {
                api_key: var("RESEND_API_KEY").ok_or("EMAIL_PROVIDER=resend needs RESEND_API_KEY")?,
                from: var("RESEND_FROM").unwrap_or_else(|| "Voltius <noreply@voltius.app>".into()),
            }),
            "smtp" => Smtp::from_lookup(&var).map(Transport::Smtp),
            other => Err(format!("EMAIL_PROVIDER={other:?} is not one of resend, smtp, disabled")),
        }
    }

    async fn send(&self, to: &str, subject: &str, html: String, text: String) -> SendResult {
        match self {
            Transport::Disabled => {
                warn!(to, "Email delivery is disabled; not sending");
                Ok(())
            }
            Transport::Resend { api_key, from } => send_via_resend(api_key, from, to, subject, html, text).await,
            Transport::Smtp(smtp) => smtp.send(to, subject, html, text).await,
        }
    }
}

fn parse_positive<T: std::str::FromStr + Default + PartialEq>(key: &str, value: Option<String>) -> Result<Option<T>, String> {
    value
        .map(|v| v.parse::<T>().ok().filter(|n| *n != T::default()).ok_or(format!("{key}={v:?} is not a positive number")))
        .transpose()
}

impl Smtp {
    fn from_lookup(var: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let host = var("SMTP_HOST").ok_or("EMAIL_PROVIDER=smtp needs SMTP_HOST")?;
        let security = match var("SMTP_SECURITY").unwrap_or_default().to_ascii_lowercase().as_str() {
            "" | "starttls" => Security::StartTls,
            "tls" => Security::Tls,
            "none" => Security::None,
            other => return Err(format!("SMTP_SECURITY={other:?} is not one of starttls, tls, none")),
        };
        let port = parse_positive("SMTP_PORT", var("SMTP_PORT"))?.unwrap_or(security.default_port());
        let credentials = match (var("SMTP_USERNAME"), var("SMTP_PASSWORD")) {
            (Some(_), Some(_)) if security == Security::None => {
                return Err("SMTP_SECURITY=none would send SMTP_PASSWORD unencrypted: use starttls or tls, or drop the credentials for an open relay".into());
            }
            (Some(user), Some(password)) => Some(Credentials::new(user, password)),
            (None, None) => None,
            _ => return Err("SMTP_USERNAME and SMTP_PASSWORD must be set together".into()),
        };
        let from = var("SMTP_FROM").ok_or("EMAIL_PROVIDER=smtp needs SMTP_FROM, e.g. Voltius <voltius@example.com>")?;
        let from = from.parse::<Mailbox>().map_err(|e| format!("SMTP_FROM={from:?} is not an address: {e}"))?;
        let timeout = Duration::from_secs(parse_positive("SMTP_TIMEOUT_SECS", var("SMTP_TIMEOUT_SECS"))?.unwrap_or(30));
        Ok(Smtp { host, port, security, credentials, from, timeout })
    }

    fn transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, lettre::transport::smtp::Error> {
        let builder = match self.security {
            Security::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.host)?,
            Security::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&self.host)?,
            Security::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.host),
        }
        .port(self.port)
        .timeout(Some(self.timeout));
        Ok(match &self.credentials {
            Some(credentials) => builder.credentials(credentials.clone()),
            None => builder,
        }
        .build())
    }

    async fn send(&self, to: &str, subject: &str, html: String, text: String) -> SendResult {
        let message = Message::builder()
            .from(self.from.clone())
            .to(to.parse()?)
            .subject(subject)
            .multipart(MultiPart::alternative_plain_html(text, html))?;
        tokio::time::timeout(self.timeout, self.transport()?.send(message))
            .await
            .map_err(|_| format!("SMTP server {}:{} did not finish within {:?}", self.host, self.port, self.timeout))??;
        Ok(())
    }
}

async fn send_via_resend(api_key: &str, from: &str, to: &str, subject: &str, html: String, text: String) -> SendResult {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let res = client
        .post("https://api.resend.com/emails")
        .bearer_auth(api_key)
        .json(&serde_json::json!({
            "from": from,
            "to": [to],
            "subject": subject,
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

async fn send(to: &str, subject: &str, html: String, text: String) -> SendResult {
    Transport::from_env()?.send(to, subject, html, text).await
}

const TEST_EMAIL_BODY: &str = "Your Voltius server handed this message to its mail provider, so verification emails, team invitations and security notices will be sent the same way.";

pub async fn send_test_email(transport: &Transport, to: &str) -> SendResult {
    if let Transport::Disabled = transport {
        return Err("email delivery is disabled: set EMAIL_PROVIDER with RESEND_API_KEY or SMTP_HOST".into());
    }
    let url = app_url();
    let html = branded_email_html(
        "Your Voltius server can send email.",
        "Test email",
        "Email delivery works",
        &format!(r#"<p style="margin:0;">{TEST_EMAIL_BODY}</p>"#),
        "Open Voltius",
        &url,
        "Sent by the send-test-email command of voltius-server.",
    );
    transport.send(to, "Voltius test email", html, TEST_EMAIL_BODY.to_string()).await
}

pub async fn send_team_invitation(
    to: &str,
    team_name: &str,
    inviter_email: &str,
    token: &str,
) -> SendResult {
    let accept_url = format!("{}/invite/{token}", app_url().trim_end_matches('/'));
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

    send(
        to,
        &format!("{inviter_email} invited you to {team_name} on Voltius"),
        html,
        text,
    )
    .await
}

pub async fn send_verification_email(
    to: &str,
    token: &str,
) -> SendResult {
    let verify_url = format!("{}/verify-email?token={token}", app_url().trim_end_matches('/'));
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

    send(to, "Verify your Voltius email", html, text).await
}

pub async fn send_password_changed_email(
    to: &str,
) -> SendResult {
    let account_url = format!("{}/account", app_url().trim_end_matches('/'));
    let when = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let html = branded_email_html(
        "The master password of your Voltius account was just changed.",
        "Security notice",
        "Your master password was changed",
        &format!(
            r#"<p style="margin:0 0 14px;">The master password of your Voltius account was changed on {when}.</p>
                    <p style="margin:0;">If you did this, there is nothing else to do. If you did not, someone with access to one of your signed-in devices changed it: write to <a href="mailto:contact@voltius.app" style="color:#22d3ee;text-decoration:none;">contact@voltius.app</a> right away.</p>"#
        ),
        "Open your account",
        &account_url,
        "Every other device signed in to this account has been signed out and needs the new password.",
    );
    let text = format!(
        "The master password of your Voltius account was changed on {when}.\n\nIf you did this, there is nothing else to do. If you did not, write to contact@voltius.app right away.\n\nEvery other device signed in to this account has been signed out and needs the new password."
    );

    send(to, "Your Voltius master password was changed", html, text).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Instant;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    fn parse(pairs: &[(&str, &str)]) -> Result<Transport, String> {
        let env: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Transport::from_lookup(&|key| env.get(key).cloned())
    }

    fn smtp(pairs: &[(&str, &str)]) -> Smtp {
        let base = [("SMTP_HOST", "mail.example.com"), ("SMTP_FROM", "Voltius <voltius@example.com>")];
        match parse(&[&base[..], pairs].concat()) {
            Ok(Transport::Smtp(smtp)) => smtp,
            Ok(other) => panic!("expected smtp, got {other}"),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn resend_only_config_keeps_working() {
        let Ok(Transport::Resend { api_key, from }) = parse(&[("RESEND_API_KEY", "re_x")]) else { panic!() };
        assert_eq!((api_key.as_str(), from.as_str()), ("re_x", "Voltius <noreply@voltius.app>"));
        let Ok(Transport::Resend { from, .. }) = parse(&[("RESEND_API_KEY", "re_x"), ("RESEND_FROM", "A <a@b.c>")]) else { panic!() };
        assert_eq!(from, "A <a@b.c>");
    }

    #[test]
    fn nothing_set_or_explicitly_disabled_sends_nothing() {
        assert!(matches!(parse(&[]), Ok(Transport::Disabled)));
        assert!(matches!(parse(&[("RESEND_API_KEY", "")]), Ok(Transport::Disabled)));
        assert!(matches!(parse(&[("EMAIL_PROVIDER", "disabled"), ("RESEND_API_KEY", "re_x")]), Ok(Transport::Disabled)));
    }

    #[test]
    fn provider_is_inferred_from_smtp_host_and_ambiguity_is_refused() {
        assert!(matches!(parse(&[("SMTP_HOST", "h"), ("SMTP_FROM", "a@b.c")]), Ok(Transport::Smtp(_))));
        assert!(parse(&[("SMTP_HOST", "h"), ("RESEND_API_KEY", "re_x")]).is_err());
        assert!(matches!(
            parse(&[("EMAIL_PROVIDER", "SMTP"), ("SMTP_HOST", "h"), ("SMTP_FROM", "a@b.c"), ("RESEND_API_KEY", "re_x")]),
            Ok(Transport::Smtp(_))
        ));
    }

    #[test]
    fn smtp_security_picks_the_conventional_port() {
        for (security, mode, port) in [("", Security::StartTls, 587), ("starttls", Security::StartTls, 587), ("TLS", Security::Tls, 465), ("none", Security::None, 25)] {
            let s = smtp(&[("SMTP_SECURITY", security)]);
            assert_eq!((s.security, s.port), (mode, port), "{security:?}");
        }
        let s = smtp(&[("SMTP_PORT", "2525"), ("SMTP_TIMEOUT_SECS", "3")]);
        assert_eq!((s.port, s.timeout), (2525, Duration::from_secs(3)));
        assert_eq!(smtp(&[]).timeout, Duration::from_secs(30));
    }

    #[test]
    fn invalid_configurations_are_refused() {
        let base = [("SMTP_HOST", "h"), ("SMTP_FROM", "a@b.c")];
        let smtp_with = |extra: &[(&'static str, &'static str)]| [&base[..], extra].concat();
        for pairs in [
            vec![("EMAIL_PROVIDER", "sendgrid")],
            vec![("EMAIL_PROVIDER", "resend")],
            vec![("EMAIL_PROVIDER", "smtp")],
            vec![("SMTP_HOST", "h")],
            vec![("SMTP_HOST", "h"), ("SMTP_FROM", "not an address")],
            smtp_with(&[("SMTP_SECURITY", "ssl")]),
            smtp_with(&[("SMTP_PORT", "0")]),
            smtp_with(&[("SMTP_PORT", "70000")]),
            smtp_with(&[("SMTP_TIMEOUT_SECS", "0")]),
            smtp_with(&[("SMTP_USERNAME", "u")]),
            smtp_with(&[("SMTP_PASSWORD", "p")]),
            smtp_with(&[("SMTP_SECURITY", "none"), ("SMTP_USERNAME", "u"), ("SMTP_PASSWORD", "p")]),
        ] {
            assert!(parse(&pairs).is_err(), "{pairs:?} should be refused");
        }
    }

    #[test]
    fn credentials_never_reach_the_description_or_config_errors() {
        let s = smtp(&[("SMTP_USERNAME", "voltius@example.com"), ("SMTP_PASSWORD", "hunter2-secret")]);
        assert!(!Transport::Smtp(s).to_string().contains("hunter2"));
        let err = parse(&[("SMTP_HOST", "h"), ("SMTP_FROM", "a@b.c"), ("SMTP_SECURITY", "none"), ("SMTP_USERNAME", "u"), ("SMTP_PASSWORD", "hunter2-secret")])
            .err()
            .unwrap();
        assert!(!err.contains("hunter2"), "{err}");
        let resend = parse(&[("RESEND_API_KEY", "re_secret")]).unwrap();
        assert!(!resend.to_string().contains("re_secret"));
    }

    #[test]
    fn startup_validation_builds_tls_for_every_mode() {
        for security in ["starttls", "tls", "none"] {
            assert!(smtp(&[("SMTP_SECURITY", security)]).transport().is_ok(), "{security}");
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Mock {
        Accept,
        RejectAuth,
        Silent,
    }

    async fn mock_smtp(mode: Mock) -> (u16, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut transcript = String::new();
            if mode == Mock::Silent {
                tokio::time::sleep(Duration::from_secs(60)).await;
                return transcript;
            }
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            write.write_all(b"220 mock ESMTP\r\n").await.unwrap();
            let mut in_data = false;
            while let Ok(Some(line)) = lines.next_line().await {
                transcript.push_str(&line);
                transcript.push('\n');
                if in_data {
                    if line == "." {
                        in_data = false;
                        write.write_all(b"250 2.0.0 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let verb = line.split(' ').next().unwrap_or_default().to_ascii_uppercase();
                let reply: &[u8] = match verb.as_str() {
                    "EHLO" => b"250-mock\r\n250 AUTH PLAIN LOGIN\r\n",
                    "AUTH" if mode == Mock::RejectAuth => b"535 5.7.8 Authentication credentials invalid\r\n",
                    "AUTH" => b"235 2.7.0 ok\r\n",
                    "DATA" => {
                        in_data = true;
                        b"354 go ahead\r\n"
                    }
                    "QUIT" => {
                        let _ = write.write_all(b"221 bye\r\n").await;
                        break;
                    }
                    _ => b"250 ok\r\n",
                };
                write.write_all(reply).await.unwrap();
            }
            transcript
        });
        (port, handle)
    }

    fn local(port: u16, security: Security, credentials: Option<(&str, &str)>) -> Smtp {
        Smtp {
            host: "127.0.0.1".into(),
            port,
            security,
            credentials: credentials.map(|(u, p)| Credentials::new(u.into(), p.into())),
            from: "Voltius <voltius@example.com>".parse().unwrap(),
            timeout: Duration::from_secs(1),
        }
    }

    impl Smtp {
        async fn probe(&self) -> SendResult {
            self.send("alice@example.org", "s", "h".into(), "t".into()).await
        }
    }

    #[tokio::test]
    async fn smtp_submits_a_text_and_html_message() {
        let (port, server) = mock_smtp(Mock::Accept).await;
        local(port, Security::None, None)
            .send("alice@example.org", "Hello there", "<p>html body</p>".into(), "text body".into())
            .await
            .unwrap();
        let transcript = server.await.unwrap();
        for expected in ["MAIL FROM:<voltius@example.com>", "RCPT TO:<alice@example.org>", "Subject: Hello there", "text/plain", "text/html"] {
            assert!(transcript.contains(expected), "missing {expected:?} in\n{transcript}");
        }
    }

    #[tokio::test]
    async fn smtp_authenticates_with_the_configured_credentials() {
        let (port, server) = mock_smtp(Mock::Accept).await;
        local(port, Security::None, Some(("voltius@example.com", "pw")))
            .probe()
            .await
            .unwrap();
        assert!(server.await.unwrap().contains("AUTH PLAIN"));
    }

    #[tokio::test]
    async fn smtp_auth_failure_is_an_error_without_the_password() {
        let (port, server) = mock_smtp(Mock::RejectAuth).await;
        let err = local(port, Security::None, Some(("voltius@example.com", "hunter2-secret")))
            .probe()
            .await
            .unwrap_err()
            .to_string();
        assert!(!err.contains("hunter2"), "{err}");
        assert!(!server.await.unwrap().contains("MAIL FROM"));
    }

    #[tokio::test]
    async fn smtp_times_out_on_a_server_that_never_answers() {
        let (port, server) = mock_smtp(Mock::Silent).await;
        let started = Instant::now();
        let result = local(port, Security::None, None).probe().await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
        server.abort();
    }

    #[tokio::test]
    async fn smtp_refused_connection_is_an_error() {
        let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        assert!(local(port, Security::None, None).probe().await.is_err());
    }

    #[tokio::test]
    async fn starttls_is_required_not_opportunistic() {
        let (port, server) = mock_smtp(Mock::Accept).await;
        let result = local(port, Security::StartTls, Some(("u", "hunter2-secret")))
            .probe()
            .await;
        assert!(result.is_err());
        let transcript = server.await.unwrap();
        assert!(!transcript.contains("AUTH") && !transcript.contains("MAIL FROM"), "{transcript}");
    }

    #[tokio::test]
    async fn implicit_tls_does_not_fall_back_to_plaintext() {
        let (port, server) = mock_smtp(Mock::Accept).await;
        let result = local(port, Security::Tls, Some(("u", "hunter2-secret")))
            .probe()
            .await;
        assert!(result.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn disabled_transport_refuses_the_test_email() {
        assert!(send_test_email(&Transport::Disabled, "alice@example.org").await.is_err());
    }

    #[tokio::test]
    async fn every_email_kind_goes_through_the_configured_smtp_server() {
        let _env = crate::test_support::EnvLockGuard(crate::test_support::env_lock());
        let vars = ["EMAIL_PROVIDER", "SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_FROM", "RESEND_API_KEY"];
        let saved: Vec<_> = vars.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        let mut subjects = Vec::new();
        for kind in 0..3 {
            let (port, server) = mock_smtp(Mock::Accept).await;
            for (k, v) in [("EMAIL_PROVIDER", "smtp"), ("SMTP_HOST", "127.0.0.1"), ("SMTP_SECURITY", "none"), ("SMTP_FROM", "voltius@example.com")] {
                std::env::set_var(k, v);
            }
            std::env::set_var("SMTP_PORT", port.to_string());
            std::env::remove_var("RESEND_API_KEY");
            assert!(delivery_configured());
            match kind {
                0 => send_verification_email("alice@example.org", "tok").await,
                1 => send_team_invitation("alice@example.org", "Ops", "bob@example.org", "tok").await,
                _ => send_password_changed_email("alice@example.org").await,
            }
            .unwrap();
            let transcript = server.await.unwrap();
            subjects.push(transcript.lines().find(|l| l.starts_with("Subject:")).unwrap_or_default().to_string());
        }
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        assert_eq!(subjects.len(), 3);
        assert!(subjects.iter().all(|s| !s.is_empty()), "{subjects:?}");
    }
}
