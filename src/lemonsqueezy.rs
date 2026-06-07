//! Lemon Squeezy metrics: real MRR, paying-subscriber count, revenue,
//! failed payments, refunds, recent orders.
//!
//! Pulls live from the LS API, caches in-process. A background task refreshes
//! every 5 minutes. The admin overview reads from the cache, so page loads
//! never block on LS.

use chrono::{DateTime, Datelike, Duration, TimeZone, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Clone, Default)]
pub struct LsCache {
    inner: Arc<RwLock<LsCacheInner>>,
}

#[derive(Default)]
struct LsCacheInner {
    metrics: Option<LsMetrics>,
    refreshed_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    refreshing: bool,
    variants: HashMap<String, VariantInfo>,
}

#[derive(Clone)]
struct VariantInfo {
    /// monthly equivalent price in cents
    monthly_cents: i64,
    /// "month" or "year"
    interval: String,
}

#[derive(Clone, Serialize, Debug)]
pub struct LsMetrics {
    pub mrr_cents: i64,
    pub mrr_monthly_cents: i64,
    pub mrr_annual_cents: i64,
    pub paying_count: i64,
    pub on_trial_count: i64,
    pub past_due_count: i64,
    pub cancelled_active_count: i64,
    pub revenue_this_month_cents: i64,
    pub refunds_30d_cents: i64,
    pub failed_payments_30d: i64,
    pub recent_orders: Vec<LsRecentOrder>,
    pub currency: String,
}

#[derive(Clone, Serialize, Debug)]
pub struct LsRecentOrder {
    pub id: String,
    pub email: Option<String>,
    pub status: String,
    pub total_cents: i64,
    pub currency: String,
    pub created_at: DateTime<Utc>,
    pub refunded: bool,
}

#[derive(Serialize)]
pub struct LsSummaryResponse {
    pub metrics: Option<LsMetrics>,
    pub refreshed_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub refreshing: bool,
}

impl LsCache {
    pub async fn summary(&self) -> LsSummaryResponse {
        let r = self.inner.read().await;
        LsSummaryResponse {
            metrics: r.metrics.clone(),
            refreshed_at: r.refreshed_at,
            last_error: r.last_error.clone(),
            refreshing: r.refreshing,
        }
    }

    pub async fn refresh(&self) -> Result<(), String> {
        {
            let mut w = self.inner.write().await;
            if w.refreshing {
                return Ok(());
            }
            w.refreshing = true;
        }

        let api_key = std::env::var("LEMONSQUEEZY_API_KEY").unwrap_or_default();
        let store_id = std::env::var("LEMONSQUEEZY_STORE_ID").unwrap_or_default();
        if api_key.is_empty() || store_id.is_empty() {
            let msg = "LEMONSQUEEZY_API_KEY or LEMONSQUEEZY_STORE_ID not set".to_string();
            let mut w = self.inner.write().await;
            w.refreshing = false;
            w.last_error = Some(msg.clone());
            return Err(msg);
        }

        let result = self.compute_metrics(&api_key, &store_id).await;

        let mut w = self.inner.write().await;
        w.refreshing = false;
        match result {
            Ok(m) => {
                info!(
                    mrr = m.mrr_cents,
                    paying = m.paying_count,
                    "LS metrics refreshed"
                );
                w.metrics = Some(m);
                w.refreshed_at = Some(Utc::now());
                w.last_error = None;
                Ok(())
            }
            Err(e) => {
                error!(error = %e, "LS metrics refresh failed");
                w.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    async fn compute_metrics(&self, api_key: &str, store_id: &str) -> Result<LsMetrics, String> {
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(20))
            .build()
            .map_err(|e| format!("http client build: {e}"))?;

        // ── 1. Active-ish subscriptions ──────────────────────────────────────
        // We pull every subscription for the store and bucket by status. MRR
        // counts active + on_trial + past_due (still entitled, still billed).
        let subs = fetch_all_pages(
            &client,
            api_key,
            "https://api.lemonsqueezy.com/v1/subscriptions",
            &[("filter[store_id]", store_id)],
        )
        .await?;

        let mut paying_count: i64 = 0;
        let mut on_trial_count: i64 = 0;
        let mut past_due_count: i64 = 0;
        let mut cancelled_active_count: i64 = 0;
        let mut mrr_cents: i64 = 0;
        let mut mrr_monthly_cents: i64 = 0;
        let mut mrr_annual_cents: i64 = 0;

        // Distinct variant IDs we need pricing for.
        let mut needed_variants: Vec<String> = Vec::new();
        for sub in &subs {
            let status = sub["attributes"]["status"].as_str().unwrap_or("");
            if matches!(status, "active" | "on_trial" | "past_due") {
                if let Some(v) = variant_id(sub) {
                    if !needed_variants.contains(&v) {
                        needed_variants.push(v);
                    }
                }
            }
        }

        // Populate variant cache for any missing IDs.
        self.ensure_variants(&client, api_key, &needed_variants).await?;

        let variants_snapshot: HashMap<String, VariantInfo> = {
            let r = self.inner.read().await;
            r.variants.clone()
        };

        for sub in &subs {
            let attrs = &sub["attributes"];
            let status = attrs["status"].as_str().unwrap_or("");
            let cancelled = attrs["cancelled"].as_bool().unwrap_or(false);

            match status {
                "active" => {
                    paying_count += 1;
                    if cancelled {
                        cancelled_active_count += 1;
                    }
                }
                "on_trial" => on_trial_count += 1,
                "past_due" => past_due_count += 1,
                _ => continue, // expired, cancelled (terminal), unpaid → skip MRR
            }

            let Some(vid) = variant_id(sub) else {
                continue;
            };
            let Some(info) = variants_snapshot.get(&vid) else {
                warn!(variant = %vid, "no variant info for active subscription");
                continue;
            };

            mrr_cents += info.monthly_cents;
            if info.interval == "year" {
                mrr_annual_cents += info.monthly_cents;
            } else {
                mrr_monthly_cents += info.monthly_cents;
            }
        }

        // ── 2. Orders for revenue + recent feed + refunds ────────────────────
        // LS rejects sort on /orders ("Sort parameter created_at is not
        // allowed"), so we fetch all pages (capped) and sort in Rust. For
        // stores with long history this fetches more than needed; revisit if
        // it becomes a perf issue.
        let mut orders = fetch_all_pages_capped(
            &client,
            api_key,
            "https://api.lemonsqueezy.com/v1/orders",
            &[("filter[store_id]", store_id)],
            20,
        )
        .await?;
        orders.sort_by_key(|o| {
            std::cmp::Reverse(parse_ls_datetime(o["attributes"]["created_at"].as_str()))
        });

        let month_start = start_of_current_month();
        let cutoff_30d = Utc::now() - Duration::days(30);

        let mut revenue_this_month_cents: i64 = 0;
        let mut refunds_30d_cents: i64 = 0;
        let mut currency = String::from("USD");
        let mut recent_orders: Vec<LsRecentOrder> = Vec::new();

        for order in &orders {
            let attrs = &order["attributes"];
            let created_at = parse_ls_datetime(attrs["created_at"].as_str()).unwrap_or_else(Utc::now);
            let status = attrs["status"].as_str().unwrap_or("").to_string();
            let total = attrs["total"].as_i64().unwrap_or(0);
            let refunded = attrs["refunded"].as_bool().unwrap_or(false);
            let cur = attrs["currency"].as_str().unwrap_or("USD").to_string();
            currency = cur.clone();

            // Revenue this month: any paid order in the current calendar month.
            if status == "paid" && created_at >= month_start {
                revenue_this_month_cents += total;
            }

            // Refunds in last 30d.
            if refunded {
                let refunded_at =
                    parse_ls_datetime(attrs["refunded_at"].as_str()).unwrap_or(created_at);
                if refunded_at >= cutoff_30d {
                    refunds_30d_cents += total;
                }
            }

            if recent_orders.len() < 10 {
                recent_orders.push(LsRecentOrder {
                    id: order["id"].as_str().unwrap_or("").to_string(),
                    email: attrs["user_email"].as_str().map(String::from),
                    status,
                    total_cents: total,
                    currency: cur,
                    created_at,
                    refunded,
                });
            }
        }

        // ── 3. Failed subscription invoices in last 30d ──────────────────────
        // Same sort-not-allowed story applies; fetch all & filter in Rust.
        let invoices = fetch_all_pages_capped(
            &client,
            api_key,
            "https://api.lemonsqueezy.com/v1/subscription-invoices",
            &[("filter[store_id]", store_id)],
            20,
        )
        .await?;
        let mut failed_payments_30d: i64 = 0;
        for inv in &invoices {
            let attrs = &inv["attributes"];
            let created_at = parse_ls_datetime(attrs["created_at"].as_str()).unwrap_or_else(Utc::now);
            if created_at < cutoff_30d {
                continue;
            }
            if attrs["status"].as_str() == Some("failed") {
                failed_payments_30d += 1;
            }
        }

        Ok(LsMetrics {
            mrr_cents,
            mrr_monthly_cents,
            mrr_annual_cents,
            paying_count,
            on_trial_count,
            past_due_count,
            cancelled_active_count,
            revenue_this_month_cents,
            refunds_30d_cents,
            failed_payments_30d,
            recent_orders,
            currency,
        })
    }

    async fn ensure_variants(
        &self,
        client: &reqwest::Client,
        api_key: &str,
        ids: &[String],
    ) -> Result<(), String> {
        let missing: Vec<String> = {
            let r = self.inner.read().await;
            ids.iter()
                .filter(|id| !r.variants.contains_key(*id))
                .cloned()
                .collect()
        };

        for id in &missing {
            let url = format!("https://api.lemonsqueezy.com/v1/variants/{id}");
            let res = client
                .get(&url)
                .bearer_auth(api_key)
                .header("Accept", "application/vnd.api+json")
                .send()
                .await
                .map_err(|e| format!("variant {id} GET: {e}"))?;
            if !res.status().is_success() {
                return Err(format!("variant {id} GET -> {}", res.status()));
            }
            let body: Value = res
                .json()
                .await
                .map_err(|e| format!("variant {id} parse: {e}"))?;
            let attrs = &body["data"]["attributes"];
            let price_cents = attrs["price"].as_i64().unwrap_or(0);
            let interval = attrs["interval"].as_str().unwrap_or("month").to_string();
            let interval_count = attrs["interval_count"].as_i64().unwrap_or(1).max(1);

            let monthly_cents = match interval.as_str() {
                "year" => price_cents / (12 * interval_count),
                "month" => price_cents / interval_count,
                "week" => (price_cents * 52) / (12 * interval_count),
                "day" => (price_cents * 365) / (12 * interval_count),
                _ => price_cents,
            };

            let info = VariantInfo {
                monthly_cents,
                interval,
            };
            let mut w = self.inner.write().await;
            w.variants.insert(id.clone(), info);
        }
        Ok(())
    }
}

/// Spawn a background task that refreshes the cache every 5 minutes.
/// First refresh starts immediately.
pub fn spawn_refresher(cache: LsCache) {
    tokio::spawn(async move {
        loop {
            let _ = cache.refresh().await;
            tokio::time::sleep(StdDuration::from_secs(300)).await;
        }
    });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn variant_id(sub: &Value) -> Option<String> {
    sub["attributes"]["variant_id"]
        .as_i64()
        .map(|i| i.to_string())
        .or_else(|| sub["attributes"]["variant_id"].as_str().map(String::from))
}

/// Parse an RFC 3339 / ISO-8601 timestamp into UTC. Shared by the metrics
/// cache and by billing/webhook subscription parsing.
pub fn parse_ls_datetime(s: Option<&str>) -> Option<DateTime<Utc>> {
    let s = s?;
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Map a Lemon Squeezy variant id to our internal tier, reading the configured
/// `LS_VARIANT_*` env vars. Returns `None` for unconfigured/unknown variants.
pub fn tier_from_variant_id(variant_id: &str) -> Option<&'static str> {
    let pro_monthly = std::env::var("LS_VARIANT_PRO_MONTHLY").ok();
    let pro_yearly = std::env::var("LS_VARIANT_PRO_YEARLY").ok();
    let teams_monthly = std::env::var("LS_VARIANT_TEAMS_MONTHLY").ok();
    let teams_yearly = std::env::var("LS_VARIANT_TEAMS_YEARLY").ok();

    if pro_monthly.as_deref() == Some(variant_id) || pro_yearly.as_deref() == Some(variant_id) {
        Some("pro")
    } else if teams_monthly.as_deref() == Some(variant_id)
        || teams_yearly.as_deref() == Some(variant_id)
    {
        Some("teams")
    } else {
        None
    }
}

fn start_of_current_month() -> DateTime<Utc> {
    let now = Utc::now();
    Utc.with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .unwrap_or(now)
}

async fn ls_get_page(
    client: &reqwest::Client,
    api_key: &str,
    base_url: &str,
    extra_query: &[(&str, &str)],
    page: u64,
) -> Result<Value, String> {
    let page_str = page.to_string();
    let mut query: Vec<(&str, &str)> = extra_query.to_vec();
    query.push(("page[size]", "100"));
    query.push(("page[number]", &page_str));

    let res = client
        .get(base_url)
        .bearer_auth(api_key)
        .header("Accept", "application/vnd.api+json")
        .query(&query)
        .send()
        .await
        .map_err(|e| format!("GET {base_url}: {e}"))?;

    let status = res.status();
    if !status.is_success() {
        let body = res.text().await.unwrap_or_default();
        let snippet = body.chars().take(500).collect::<String>();
        return Err(format!("GET {base_url} -> {status}: {snippet}"));
    }
    res.json::<Value>()
        .await
        .map_err(|e| format!("parse {base_url}: {e}"))
}

async fn fetch_all_pages(
    client: &reqwest::Client,
    api_key: &str,
    base_url: &str,
    extra_query: &[(&str, &str)],
) -> Result<Vec<Value>, String> {
    let mut all = Vec::new();
    let mut page = 1u64;
    loop {
        let body = ls_get_page(client, api_key, base_url, extra_query, page).await?;
        if let Some(data) = body["data"].as_array() {
            all.extend(data.clone());
        }
        let last_page = body["meta"]["page"]["last_page"].as_u64().unwrap_or(1);
        if page >= last_page {
            break;
        }
        page += 1;
        if page > 200 {
            warn!(url = %base_url, "fetch_all_pages: bailing after 200 pages");
            break;
        }
    }
    Ok(all)
}

/// Fetch all pages up to a hard cap. Used when LS doesn't support sort and we
/// have to filter in Rust.
async fn fetch_all_pages_capped(
    client: &reqwest::Client,
    api_key: &str,
    base_url: &str,
    extra_query: &[(&str, &str)],
    max_pages: u64,
) -> Result<Vec<Value>, String> {
    let mut all = Vec::new();
    let mut page = 1u64;
    loop {
        let body = ls_get_page(client, api_key, base_url, extra_query, page).await?;
        if let Some(data) = body["data"].as_array() {
            all.extend(data.clone());
        }
        let last_page = body["meta"]["page"]["last_page"].as_u64().unwrap_or(1);
        if page >= last_page {
            break;
        }
        page += 1;
        if page > max_pages {
            warn!(
                url = %base_url,
                cap = max_pages,
                "fetch_all_pages_capped: bailing at cap"
            );
            break;
        }
    }
    Ok(all)
}
