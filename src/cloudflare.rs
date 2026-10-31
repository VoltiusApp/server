use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const DEFAULT_RTC_BASE: &str = "https://rtc.live.cloudflare.com";
const MAX_QUERY_WINDOW_DAYS: i64 = 31;
const USAGE_GROUP_LIMIT: usize = 10000;

const USAGE_QUERY: &str = "query($accountId: string!, $from: Time!, $to: Time!) { viewer { accounts(filter: {accountTag: $accountId}) { callsTurnUsageAdaptiveGroups(limit: 10000, filter: {datetime_geq: $from, datetime_lt: $to}) { dimensions { customIdentifier } sum { egressBytes } } } } }";

#[derive(Clone)]
pub struct CfConfig {
    pub account_id: String,
    pub turn_key_id: String,
    pub turn_key_token: String,
    pub analytics_token: String,
}

impl CfConfig {
    pub fn from_env() -> Option<CfConfig> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Some(CfConfig {
            account_id: get("CF_ACCOUNT_ID")?,
            turn_key_id: get("CF_TURN_KEY_ID")?,
            turn_key_token: get("CF_TURN_KEY_TOKEN")?,
            analytics_token: get("CF_ANALYTICS_TOKEN")?,
        })
    }
}

#[derive(Debug)]
pub enum CfError {
    Http(reqwest::Error),
    Status(u16),
    Malformed(String),
}

impl fmt::Display for CfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CfError::Http(e) => write!(f, "cloudflare request failed: {e}"),
            CfError::Status(s) => write!(f, "cloudflare returned status {s}"),
            CfError::Malformed(m) => write!(f, "cloudflare response malformed: {m}"),
        }
    }
}

impl std::error::Error for CfError {}

impl From<reqwest::Error> for CfError {
    fn from(e: reqwest::Error) -> Self {
        CfError::Http(e)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IceServers {
    pub ice_servers: Vec<IceServer>,
    pub username: String,
}

#[derive(Deserialize)]
struct IceServersWire {
    #[serde(rename = "iceServers")]
    ice_servers: Vec<IceServer>,
}

fn client() -> Result<reqwest::Client, CfError> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?)
}

fn env_base(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
        .trim_end_matches('/')
        .to_string()
}

pub async fn generate_ice_servers(
    cfg: &CfConfig,
    ttl_secs: u64,
    custom_identifier: &str,
) -> Result<IceServers, CfError> {
    generate_ice_servers_at(
        &env_base("CF_RTC_BASE", DEFAULT_RTC_BASE),
        cfg,
        ttl_secs,
        custom_identifier,
    )
    .await
}

pub async fn revoke_credential(cfg: &CfConfig, username: &str) -> Result<(), CfError> {
    revoke_credential_at(&env_base("CF_RTC_BASE", DEFAULT_RTC_BASE), cfg, username).await
}

pub async fn turn_usage(
    cfg: &CfConfig,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<(String, u64)>, CfError> {
    turn_usage_at(&env_base("CF_API_BASE", DEFAULT_API_BASE), cfg, since, until).await
}

async fn generate_ice_servers_at(
    rtc_base: &str,
    cfg: &CfConfig,
    ttl_secs: u64,
    custom_identifier: &str,
) -> Result<IceServers, CfError> {
    let url = format!(
        "{rtc_base}/v1/turn/keys/{}/credentials/generate-ice-servers",
        cfg.turn_key_id
    );
    let resp = client()?
        .post(url)
        .bearer_auth(&cfg.turn_key_token)
        .json(&json!({ "ttl": ttl_secs, "customIdentifier": custom_identifier }))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(CfError::Status(resp.status().as_u16()));
    }
    let wire: IceServersWire = resp
        .json()
        .await
        .map_err(|e| CfError::Malformed(e.to_string()))?;
    let username = wire
        .ice_servers
        .iter()
        .find_map(|s| s.username.clone())
        .ok_or_else(|| CfError::Malformed("no TURN username in iceServers".into()))?;
    Ok(IceServers {
        ice_servers: wire.ice_servers,
        username,
    })
}

async fn revoke_credential_at(
    rtc_base: &str,
    cfg: &CfConfig,
    username: &str,
) -> Result<(), CfError> {
    let mut url = url::Url::parse(rtc_base).map_err(|e| CfError::Malformed(e.to_string()))?;
    url.path_segments_mut()
        .map_err(|_| CfError::Malformed("base url cannot have path".into()))?
        .pop_if_empty()
        .extend(["v1", "turn", "keys", &cfg.turn_key_id, "credentials", username, "revoke"]);
    let resp = client()?
        .post(url)
        .bearer_auth(&cfg.turn_key_token)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(CfError::Status(resp.status().as_u16()));
    }
    Ok(())
}

#[derive(Deserialize)]
struct GqlResponse {
    data: Option<GqlData>,
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct GqlData {
    viewer: GqlViewer,
}

#[derive(Deserialize)]
struct GqlViewer {
    accounts: Vec<GqlAccount>,
}

#[derive(Deserialize)]
struct GqlAccount {
    #[serde(rename = "callsTurnUsageAdaptiveGroups")]
    groups: Vec<GqlGroup>,
}

#[derive(Deserialize)]
struct GqlGroup {
    dimensions: GqlDimensions,
    sum: GqlSum,
}

#[derive(Deserialize)]
struct GqlDimensions {
    #[serde(rename = "customIdentifier")]
    custom_identifier: Option<String>,
}

#[derive(Deserialize)]
struct GqlSum {
    #[serde(rename = "egressBytes")]
    egress_bytes: u64,
}

async fn turn_usage_at(
    api_base: &str,
    cfg: &CfConfig,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<(String, u64)>, CfError> {
    let client = client()?;
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    let mut from = since;
    while from < until {
        let to = (from + ChronoDuration::days(MAX_QUERY_WINDOW_DAYS)).min(until);
        let resp = client
            .post(format!("{api_base}/graphql"))
            .bearer_auth(&cfg.analytics_token)
            .json(&json!({
                "query": USAGE_QUERY,
                "variables": {
                    "accountId": cfg.account_id,
                    "from": from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    "to": to.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                },
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(CfError::Status(resp.status().as_u16()));
        }
        let body: GqlResponse = resp
            .json()
            .await
            .map_err(|e| CfError::Malformed(e.to_string()))?;
        if body.errors.as_ref().is_some_and(|e| !e.is_empty()) {
            return Err(CfError::Malformed(format!("graphql errors: {:?}", body.errors)));
        }
        let account = body
            .data
            .and_then(|d| d.viewer.accounts.into_iter().next())
            .ok_or_else(|| CfError::Malformed("no account in response".into()))?;
        if account.groups.len() >= USAGE_GROUP_LIMIT {
            return Err(CfError::Malformed("usage truncated".into()));
        }
        for g in account.groups {
            if let Some(id) = g.dimensions.custom_identifier {
                *totals.entry(id).or_default() += g.sum.egress_bytes;
            }
        }
        from = to;
    }
    Ok(totals.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<(String, Option<String>, Value)>>>;

    #[derive(Clone)]
    struct Mock {
        seen: Seen,
        status: u16,
        reply: Value,
    }

    async fn record(
        State(m): State<Mock>,
        uri: axum::http::Uri,
        headers: HeaderMap,
        body: Option<Json<Value>>,
    ) -> (StatusCode, Json<Value>) {
        let auth = headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_string());
        m.seen.lock().unwrap().push((
            uri.path().to_string(),
            auth,
            body.map(|b| b.0).unwrap_or(Value::Null),
        ));
        (StatusCode::from_u16(m.status).unwrap(), Json(m.reply.clone()))
    }

    async fn serve(status: u16, reply: Value) -> (String, Seen) {
        let seen: Seen = Default::default();
        let app = Router::new()
            .fallback(post(record))
            .with_state(Mock {
                seen: seen.clone(),
                status,
                reply,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, seen)
    }

    fn cfg() -> CfConfig {
        CfConfig {
            account_id: "acct".into(),
            turn_key_id: "key1".into(),
            turn_key_token: "turn-secret".into(),
            analytics_token: "analytics-secret".into(),
        }
    }

    fn real_ice_response() -> Value {
        json!({"iceServers": [
            {"urls": ["stun:stun.cloudflare.com:3478"]},
            {"urls": ["turn:turn.cloudflare.com:3478?transport=udp", "turns:turn.cloudflare.com:443?transport=tcp"],
             "username": "u123", "credential": "c456"}
        ]})
    }

    #[tokio::test]
    async fn generate_sends_bearer_path_and_body_and_parses() {
        let (base, seen) = serve(201, real_ice_response()).await;
        let out = generate_ice_servers_at(&base, &cfg(), 3600, "opaque-id")
            .await
            .unwrap();
        assert_eq!(out.username, "u123");
        assert_eq!(out.ice_servers.len(), 2);
        assert_eq!(out.ice_servers[0].username, None);
        assert_eq!(out.ice_servers[1].credential.as_deref(), Some("c456"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].0, "/v1/turn/keys/key1/credentials/generate-ice-servers");
        assert_eq!(seen[0].1.as_deref(), Some("Bearer turn-secret"));
        assert_eq!(seen[0].2, json!({"ttl": 3600, "customIdentifier": "opaque-id"}));
    }

    #[tokio::test]
    async fn generate_errors_on_non_2xx_and_missing_username() {
        let (base, _) = serve(500, json!({})).await;
        assert!(matches!(
            generate_ice_servers_at(&base, &cfg(), 3600, "x").await,
            Err(CfError::Status(500))
        ));
        let (base, _) = serve(201, json!({"iceServers": [{"urls": ["stun:a"]}]})).await;
        assert!(matches!(
            generate_ice_servers_at(&base, &cfg(), 3600, "x").await,
            Err(CfError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn revoke_posts_to_username_path() {
        let (base, seen) = serve(204, Value::Null).await;
        revoke_credential_at(&base, &cfg(), "u123").await.unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen[0].0, "/v1/turn/keys/key1/credentials/u123/revoke");
            assert_eq!(seen[0].1.as_deref(), Some("Bearer turn-secret"));
        }
        let (base, _) = serve(404, Value::Null).await;
        assert!(matches!(
            revoke_credential_at(&base, &cfg(), "u").await,
            Err(CfError::Status(404))
        ));
    }

    fn usage_reply() -> Value {
        json!({"data": {"viewer": {"accounts": [{"callsTurnUsageAdaptiveGroups": [
            {"dimensions": {"customIdentifier": "a"}, "sum": {"egressBytes": 100}},
            {"dimensions": {"customIdentifier": "b"}, "sum": {"egressBytes": 7}},
            {"dimensions": {"customIdentifier": null}, "sum": {"egressBytes": 9}}
        ]}]}}, "errors": null})
    }

    #[tokio::test]
    async fn usage_single_window_shape_and_parse() {
        let (base, seen) = serve(200, usage_reply()).await;
        let until = Utc::now();
        let out = turn_usage_at(&base, &cfg(), until - ChronoDuration::days(31), until)
            .await
            .unwrap();
        assert_eq!(out, vec![("a".to_string(), 100), ("b".to_string(), 7)]);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "/graphql");
        assert_eq!(seen[0].1.as_deref(), Some("Bearer analytics-secret"));
        assert_eq!(seen[0].2["variables"]["accountId"], "acct");
    }

    #[tokio::test]
    async fn usage_splits_long_ranges_and_sums() {
        let (base, seen) = serve(200, usage_reply()).await;
        let until = DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
        let since = until - ChronoDuration::days(70);
        let out = turn_usage_at(&base, &cfg(), since, until).await.unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 3);
            let fmt = |d: DateTime<Utc>| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            assert_eq!(seen[0].2["variables"]["from"], fmt(since));
            assert_eq!(seen[2].2["variables"]["to"], fmt(until));
            for w in seen.windows(2) {
                assert_eq!(w[0].2["variables"]["to"], w[1].2["variables"]["from"]);
            }
            assert!(seen[0].2["query"].as_str().unwrap().contains("datetime_lt: $to"));
        }
        assert_eq!(out, vec![("a".to_string(), 300), ("b".to_string(), 21)]);
    }

    #[tokio::test]
    async fn usage_errors_when_truncated_at_limit() {
        let groups: Vec<Value> = (0..USAGE_GROUP_LIMIT)
            .map(|i| json!({"dimensions": {"customIdentifier": format!("id{i}")}, "sum": {"egressBytes": 1}}))
            .collect();
        let reply = json!({"data": {"viewer": {"accounts": [{"callsTurnUsageAdaptiveGroups": groups}]}}, "errors": null});
        let (base, _) = serve(200, reply).await;
        let until = Utc::now();
        assert!(matches!(
            turn_usage_at(&base, &cfg(), until - ChronoDuration::days(1), until).await,
            Err(CfError::Malformed(m)) if m == "usage truncated"
        ));
    }

    #[tokio::test]
    async fn revoke_percent_encodes_username() {
        let (base, seen) = serve(204, Value::Null).await;
        revoke_credential_at(&base, &cfg(), "a/b?c#d").await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].0, "/v1/turn/keys/key1/credentials/a%2Fb%3Fc%23d/revoke");
    }

    #[tokio::test]
    async fn usage_errors_on_non_2xx_and_graphql_errors() {
        let (base, _) = serve(502, json!({})).await;
        let until = Utc::now();
        let since = until - ChronoDuration::days(1);
        assert!(matches!(
            turn_usage_at(&base, &cfg(), since, until).await,
            Err(CfError::Status(502))
        ));
        let (base, _) = serve(200, json!({"data": null, "errors": [{"message": "quota"}]})).await;
        assert!(matches!(
            turn_usage_at(&base, &cfg(), since, until).await,
            Err(CfError::Malformed(_))
        ));
    }
}
