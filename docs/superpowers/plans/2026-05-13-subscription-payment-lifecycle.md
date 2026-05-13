# Subscription Payment Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a SaaS-quality Pro subscription lifecycle with upgrade, cancel-at-period-end, resume, and correct local account state across Lemon Squeezy, server, portal, and desktop.

**Architecture:** The server owns all billing mutations and mirrors Lemon Squeezy subscription lifecycle fields into `users`. Lemon Squeezy remains the payment source of truth; webhooks reconcile local state and invalidate client tokens. The web portal exposes app-owned Pro cancel/resume UX while the desktop account section mirrors important state and links users to the portal.

**Tech Stack:** Rust, Axum, SQLx/Postgres, Lemon Squeezy REST API, Next.js 16 portal, React 19 desktop UI, Zustand subscription store.

---

## File Structure

- Create `migrations/020_subscription_lifecycle_fields.sql`: adds Lemon Squeezy lifecycle mirror columns to `users`.
- Modify `src/routes/billing.rs`: extends subscription response, adds cancel/resume endpoints, parses Lemon Squeezy subscription objects, persists refreshed state.
- Modify `src/routes/webhooks.rs`: switches tier mapping to variant IDs, stores lifecycle fields on subscription webhooks, handles cancellation state instead of logging only.
- Modify `src/main.rs`: registers cancel/resume billing routes.
- Modify `/home/kiki/projects/web/portal/lib/api.ts`: adds response fields and cancel/resume API clients.
- Modify `/home/kiki/projects/web/portal/app/account/page.tsx`: adds Pro active/cancelling UX and cancel/resume actions.
- Modify `/home/kiki/projects/voltius/src/stores/subscriptionStore.ts`: reads richer subscription state from the server for desktop display.
- Modify `/home/kiki/projects/voltius/src/components/settings/sections/AccountSection.tsx`: shows renewal/cancellation state and directs deeper billing actions to portal.

## Task 1: Add Database Lifecycle Fields

**Files:**
- Create: `migrations/020_subscription_lifecycle_fields.sql`

- [ ] **Step 1: Create migration**

Create `migrations/020_subscription_lifecycle_fields.sql` with exactly:

```sql
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS ls_subscription_status TEXT NULL,
    ADD COLUMN IF NOT EXISTS ls_variant_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS subscription_cancelled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS subscription_renews_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS subscription_ends_at TIMESTAMPTZ NULL;
```

- [ ] **Step 2: Validate SQLx migration syntax**

Run: `cargo check`

Expected: command completes without Rust compile errors. SQL migrations are not applied by `cargo check`, but this catches accidental repo-wide compile breakage before code changes.

- [ ] **Step 3: Commit**

```bash
git add migrations/020_subscription_lifecycle_fields.sql
git commit -m "feat: add subscription lifecycle fields"
```

## Task 2: Add Testable Billing Parsing Helpers

**Files:**
- Modify: `src/routes/billing.rs`

- [ ] **Step 1: Write failing unit tests**

Append this test module to the bottom of `src/routes/billing.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn set_variant_env() {
        std::env::set_var("LS_VARIANT_PRO_MONTHLY", "101");
        std::env::set_var("LS_VARIANT_PRO_YEARLY", "102");
        std::env::set_var("LS_VARIANT_TEAMS_MONTHLY", "201");
        std::env::set_var("LS_VARIANT_TEAMS_YEARLY", "202");
    }

    #[test]
    fn tier_from_variant_id_maps_configured_pro_variants() {
        set_variant_env();
        assert_eq!(tier_from_variant_id("101"), Some("pro"));
        assert_eq!(tier_from_variant_id("102"), Some("pro"));
    }

    #[test]
    fn tier_from_variant_id_maps_configured_teams_variants() {
        set_variant_env();
        assert_eq!(tier_from_variant_id("201"), Some("teams"));
        assert_eq!(tier_from_variant_id("202"), Some("teams"));
    }

    #[test]
    fn tier_from_variant_id_rejects_unknown_variant() {
        set_variant_env();
        assert_eq!(tier_from_variant_id("999"), None);
    }

    #[test]
    fn parse_ls_subscription_extracts_lifecycle_fields() {
        set_variant_env();
        let body = serde_json::json!({
            "data": {
                "id": "sub_123",
                "attributes": {
                    "customer_id": 55,
                    "variant_id": 101,
                    "status": "cancelled",
                    "cancelled": true,
                    "renews_at": "2026-06-01T00:00:00.000000Z",
                    "ends_at": "2026-06-01T00:00:00.000000Z",
                    "first_subscription_item": { "quantity": 1 },
                    "urls": {
                        "customer_portal": "https://example.test/billing",
                        "update_payment_method": "https://example.test/payment"
                    }
                },
                "relationships": {
                    "customer": { "data": { "id": "cus_123" } }
                }
            }
        });

        let parsed = parse_ls_subscription(&body).expect("subscription parses");
        assert_eq!(parsed.subscription_id, "sub_123");
        assert_eq!(parsed.customer_id.as_deref(), Some("cus_123"));
        assert_eq!(parsed.variant_id.as_deref(), Some("101"));
        assert_eq!(parsed.tier.as_deref(), Some("pro"));
        assert_eq!(parsed.status.as_deref(), Some("cancelled"));
        assert!(parsed.cancelled);
        assert_eq!(parsed.renews_at.unwrap().timestamp(), 1_780_272_000);
        assert_eq!(parsed.ends_at.unwrap().timestamp(), 1_780_272_000);
        assert_eq!(parsed.seat_count, Some(1));
        assert_eq!(parsed.portal_url.as_deref(), Some("https://example.test/billing"));
        assert_eq!(parsed.update_payment_url.as_deref(), Some("https://example.test/payment"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test routes::billing::tests::tier_from_variant_id_maps_configured_pro_variants routes::billing::tests::parse_ls_subscription_extracts_lifecycle_fields`

Expected: FAIL because `tier_from_variant_id`, `parse_ls_subscription`, and the parsed struct do not exist yet.

- [ ] **Step 3: Add helper types and functions**

Insert this below `CheckoutResponse` in `src/routes/billing.rs`:

```rust
#[derive(Debug, Clone)]
struct LemonSubscriptionState {
    subscription_id: String,
    customer_id: Option<String>,
    variant_id: Option<String>,
    tier: Option<&'static str>,
    status: Option<String>,
    cancelled: bool,
    renews_at: Option<chrono::DateTime<chrono::Utc>>,
    ends_at: Option<chrono::DateTime<chrono::Utc>>,
    seat_count: Option<i32>,
    portal_url: Option<String>,
    update_payment_url: Option<String>,
}

fn tier_from_variant_id(variant_id: &str) -> Option<&'static str> {
    let pro_monthly = std::env::var("LS_VARIANT_PRO_MONTHLY").ok();
    let pro_yearly = std::env::var("LS_VARIANT_PRO_YEARLY").ok();
    let teams_monthly = std::env::var("LS_VARIANT_TEAMS_MONTHLY").ok();
    let teams_yearly = std::env::var("LS_VARIANT_TEAMS_YEARLY").ok();

    if pro_monthly.as_deref() == Some(variant_id) || pro_yearly.as_deref() == Some(variant_id) {
        Some("pro")
    } else if teams_monthly.as_deref() == Some(variant_id) || teams_yearly.as_deref() == Some(variant_id) {
        Some("teams")
    } else {
        None
    }
}

fn parse_ls_datetime(value: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn parse_ls_subscription(body: &serde_json::Value) -> Option<LemonSubscriptionState> {
    let data = &body["data"];
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

    Some(LemonSubscriptionState {
        subscription_id,
        customer_id,
        variant_id,
        tier,
        status: attrs["status"].as_str().map(ToOwned::to_owned),
        cancelled: attrs["cancelled"].as_bool().unwrap_or(false),
        renews_at: parse_ls_datetime(attrs["renews_at"].as_str()),
        ends_at: parse_ls_datetime(attrs["ends_at"].as_str()),
        seat_count,
        portal_url: attrs["urls"]["customer_portal"].as_str().map(ToOwned::to_owned),
        update_payment_url: attrs["urls"]["update_payment_method"].as_str().map(ToOwned::to_owned),
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test routes::billing::tests`

Expected: PASS for all four billing helper tests.

- [ ] **Step 5: Commit**

```bash
git add src/routes/billing.rs
git commit -m "test: cover lemon squeezy subscription parsing"
```

## Task 3: Extend Server Subscription State Response

**Files:**
- Modify: `src/routes/billing.rs`

- [ ] **Step 1: Update response struct**

Replace `SubscriptionInfoResponse` with:

```rust
#[derive(Serialize)]
pub struct SubscriptionInfoResponse {
    pub tier: String,
    pub status: Option<String>,
    pub cancelled: bool,
    pub renews_at: Option<i64>,
    pub ends_at: Option<i64>,
    pub seats: Option<i32>,
    pub used_seats: Option<i64>,
    pub trial_ends_at: Option<i64>,
    pub has_ls_subscription: bool,
}
```

- [ ] **Step 2: Update `get_subscription` query and response**

Replace the query tuple and SQL in `get_subscription` with:

```rust
let row = sqlx::query_as::<_, (
    String,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<i32>,
    Option<String>,
    Option<String>,
    bool,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
)>(
    "SELECT subscription_tier, trial_ends_at, seat_count, ls_subscription_id,
            ls_subscription_status, subscription_cancelled, subscription_renews_at,
            subscription_ends_at
     FROM users WHERE id = $1",
)
```

Replace the final `Ok(Json(...))` body with:

```rust
Ok(Json(SubscriptionInfoResponse {
    tier: row.0,
    status: row.4,
    cancelled: row.5,
    renews_at: row.6.map(|t| t.timestamp()),
    ends_at: row.7.map(|t| t.timestamp()),
    trial_ends_at: row.1.map(|t| t.timestamp()),
    seats,
    used_seats,
    has_ls_subscription: row.3.is_some(),
}))
```

- [ ] **Step 3: Run server checks**

Run: `cargo check`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/routes/billing.rs
git commit -m "feat: expose subscription lifecycle state"
```

## Task 4: Persist Lemon Squeezy State From Webhooks

**Files:**
- Modify: `src/routes/webhooks.rs`

- [ ] **Step 1: Add local parsing helpers**

Insert below `verify_ls_signature`:

```rust
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

fn tier_from_variant_id(variant_id: &str) -> Option<&'static str> {
    let pro_monthly = std::env::var("LS_VARIANT_PRO_MONTHLY").ok();
    let pro_yearly = std::env::var("LS_VARIANT_PRO_YEARLY").ok();
    let teams_monthly = std::env::var("LS_VARIANT_TEAMS_MONTHLY").ok();
    let teams_yearly = std::env::var("LS_VARIANT_TEAMS_YEARLY").ok();

    if pro_monthly.as_deref() == Some(variant_id) || pro_yearly.as_deref() == Some(variant_id) {
        Some("pro")
    } else if teams_monthly.as_deref() == Some(variant_id) || teams_yearly.as_deref() == Some(variant_id) {
        Some("teams")
    } else {
        None
    }
}

fn parse_ls_datetime(value: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    value
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
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
```

- [ ] **Step 2: Replace product-name tier inference in created/updated handlers**

In `handle_subscription_created`, replace the `tier` binding with:

```rust
let subscription = match parse_webhook_subscription(payload) {
    Some(s) => s,
    None => {
        error!("subscription_created missing subscription id");
        return StatusCode::BAD_REQUEST;
    }
};
let tier = subscription.tier.unwrap_or("pro");
```

In `handle_subscription_updated`, replace the `ls_subscription_id` and `tier` bindings with:

```rust
let subscription = match parse_webhook_subscription(payload) {
    Some(s) => s,
    None => {
        error!("subscription_updated missing subscription id");
        return StatusCode::BAD_REQUEST;
    }
};
let ls_subscription_id = subscription.subscription_id.as_str();
let tier = subscription.tier.unwrap_or("pro");
```

- [ ] **Step 3: Persist lifecycle fields on `subscription_created`**

Update both `UPDATE users SET` statements in `handle_subscription_created` to include:

```sql
ls_subscription_status = $5,
ls_variant_id = $6,
subscription_cancelled = $7,
subscription_renews_at = $8,
subscription_ends_at = $9,
```

For the UUID-matched query, bind in this order:

```rust
.bind(tier)
.bind(subscription.customer_id.as_deref().unwrap_or(ls_customer_id))
.bind(&subscription.subscription_id)
.bind(subscription.seat_count)
.bind(&subscription.status)
.bind(&subscription.variant_id)
.bind(subscription.cancelled)
.bind(subscription.renews_at)
.bind(subscription.ends_at)
.bind(uid)
```

For the email fallback query, use the same first nine binds and bind `customer_email` last.

- [ ] **Step 4: Persist lifecycle fields on `subscription_updated`**

Replace the `UPDATE users SET` SQL in `handle_subscription_updated` with:

```rust
let result = sqlx::query(
    "UPDATE users SET
        subscription_tier = $1,
        seat_count = COALESCE($2, seat_count),
        ls_subscription_status = $3,
        ls_variant_id = $4,
        subscription_cancelled = $5,
        subscription_renews_at = $6,
        subscription_ends_at = $7
     WHERE ls_subscription_id = $8 AND admin_override = FALSE",
)
.bind(tier)
.bind(subscription.seat_count)
.bind(&subscription.status)
.bind(&subscription.variant_id)
.bind(subscription.cancelled)
.bind(subscription.renews_at)
.bind(subscription.ends_at)
.bind(ls_subscription_id)
.execute(pool)
.await;
```

- [ ] **Step 5: Handle `subscription_cancelled` as state update**

Replace `handle_subscription_cancelled` with:

```rust
async fn handle_subscription_cancelled(pool: &PgPool, payload: &serde_json::Value) -> StatusCode {
    let subscription = match parse_webhook_subscription(payload) {
        Some(s) => s,
        None => {
            error!("subscription_cancelled missing subscription id");
            return StatusCode::BAD_REQUEST;
        }
    };

    let result = sqlx::query(
        "UPDATE users SET
            ls_subscription_status = $1,
            ls_variant_id = $2,
            subscription_cancelled = TRUE,
            subscription_renews_at = $3,
            subscription_ends_at = $4
         WHERE ls_subscription_id = $5 AND admin_override = FALSE",
    )
    .bind(&subscription.status)
    .bind(&subscription.variant_id)
    .bind(subscription.renews_at)
    .bind(subscription.ends_at)
    .bind(&subscription.subscription_id)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            info!(ls_subscription_id = %subscription.subscription_id, "Subscription cancelled at period end");
            StatusCode::OK
        }
        Err(e) => {
            error!(error = %e, "subscription_cancelled DB error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
```

- [ ] **Step 6: Clear lifecycle fields on expiration**

In `handle_subscription_expired`, replace the `UPDATE users SET` SQL with:

```sql
UPDATE users SET
    subscription_tier = 'free',
    ls_subscription_id = NULL,
    ls_subscription_status = NULL,
    ls_variant_id = NULL,
    subscription_cancelled = FALSE,
    subscription_renews_at = NULL,
    subscription_ends_at = COALESCE(subscription_ends_at, NOW()),
    trial_used = TRUE
WHERE ls_subscription_id = $1 AND admin_override = FALSE
```

- [ ] **Step 7: Remove obsolete product-name mapper**

Delete `fn tier_from_product_name(name: &str) -> &'static str` from `src/routes/webhooks.rs`.

- [ ] **Step 8: Run checks**

Run: `cargo check`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/routes/webhooks.rs
git commit -m "feat: mirror lemon squeezy subscription lifecycle"
```

## Task 5: Add Cancel And Resume Billing Endpoints

**Files:**
- Modify: `src/routes/billing.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Add persistence helper**

Insert below `parse_ls_subscription` in `src/routes/billing.rs`:

```rust
async fn persist_subscription_state(
    pool: &PgPool,
    user_id: Uuid,
    state: &LemonSubscriptionState,
) -> Result<(), StatusCode> {
    let tier = state.tier.unwrap_or("pro");
    sqlx::query(
        "UPDATE users SET
            subscription_tier = $1,
            ls_customer_id = COALESCE($2, ls_customer_id),
            ls_subscription_id = $3,
            ls_subscription_status = $4,
            ls_variant_id = $5,
            subscription_cancelled = $6,
            subscription_renews_at = $7,
            subscription_ends_at = $8,
            seat_count = COALESCE($9, seat_count),
            trial_used = TRUE,
            trial_ends_at = NULL
         WHERE id = $10 AND admin_override = FALSE",
    )
    .bind(tier)
    .bind(&state.customer_id)
    .bind(&state.subscription_id)
    .bind(&state.status)
    .bind(&state.variant_id)
    .bind(state.cancelled)
    .bind(state.renews_at)
    .bind(state.ends_at)
    .bind(state.seat_count)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to persist subscription state");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(())
}
```

- [ ] **Step 2: Add Lemon Squeezy mutation helper**

Insert below `persist_subscription_state`:

```rust
async fn mutate_ls_subscription(subscription_id: &str, method: reqwest::Method) -> Result<LemonSubscriptionState, StatusCode> {
    let api_key = std::env::var("LEMONSQUEEZY_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let client = reqwest::Client::new();
    let mut req = client
        .request(method.clone(), format!("https://api.lemonsqueezy.com/v1/subscriptions/{subscription_id}"))
        .bearer_auth(&api_key)
        .header("Accept", "application/vnd.api+json")
        .header("Content-Type", "application/vnd.api+json");

    if method == reqwest::Method::PATCH {
        req = req.json(&serde_json::json!({
            "data": {
                "type": "subscriptions",
                "id": subscription_id,
                "attributes": { "cancelled": false }
            }
        }));
    }

    let res = req.send().await.map_err(|e| {
        error!(error = %e, "LS subscription mutation request failed");
        StatusCode::BAD_GATEWAY
    })?;

    if !res.status().is_success() {
        error!(status = %res.status(), "LS subscription mutation failed");
        return Err(StatusCode::BAD_GATEWAY);
    }

    let body: serde_json::Value = res.json().await.map_err(|e| {
        error!(error = %e, "LS subscription mutation response parse failed");
        StatusCode::BAD_GATEWAY
    })?;

    parse_ls_subscription(&body).ok_or_else(|| {
        error!("LS subscription mutation response missing subscription data");
        StatusCode::BAD_GATEWAY
    })
}
```

- [ ] **Step 3: Add current subscription lookup helper**

Insert below `mutate_ls_subscription`:

```rust
async fn fetch_current_subscription_id(pool: &PgPool, user_id: Uuid) -> Result<String, StatusCode> {
    let row = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT ls_subscription_id FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %user_id, "Failed to fetch subscription id");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    row.0.ok_or(StatusCode::NOT_FOUND)
}
```

- [ ] **Step 4: Add cancel/resume handlers**

Insert before `get_subscription`:

```rust
pub async fn cancel_subscription(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<SubscriptionInfoResponse>, StatusCode> {
    let subscription_id = fetch_current_subscription_id(&pool, auth.0).await?;
    let state = mutate_ls_subscription(&subscription_id, reqwest::Method::DELETE).await?;
    persist_subscription_state(&pool, auth.0, &state).await?;
    get_subscription(State(pool), axum::Extension(auth)).await
}

pub async fn resume_subscription(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<SubscriptionInfoResponse>, StatusCode> {
    let subscription_id = fetch_current_subscription_id(&pool, auth.0).await?;
    let state = mutate_ls_subscription(&subscription_id, reqwest::Method::PATCH).await?;
    persist_subscription_state(&pool, auth.0, &state).await?;
    get_subscription(State(pool), axum::Extension(auth)).await
}
```

- [ ] **Step 5: Reuse lookup helper in existing portal/seats code**

In `get_portal` and `update_seats`, replace each inline query that fetches `ls_subscription_id` with:

```rust
let subscription_id = fetch_current_subscription_id(&pool, auth.0).await?;
```

- [ ] **Step 6: Register routes**

In `src/main.rs`, add these routes after `/v1/billing/subscription`:

```rust
.route("/v1/billing/subscription/cancel", post(routes::billing::cancel_subscription))
.route("/v1/billing/subscription/resume", post(routes::billing::resume_subscription))
```

- [ ] **Step 7: Run checks**

Run: `cargo check`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/routes/billing.rs src/main.rs
git commit -m "feat: add subscription cancel and resume endpoints"
```

## Task 6: Update Web Portal API Client And UX

**Files:**
- Modify: `/home/kiki/projects/web/portal/lib/api.ts`
- Modify: `/home/kiki/projects/web/portal/app/account/page.tsx`

- [ ] **Step 1: Update API types and functions**

In `/home/kiki/projects/web/portal/lib/api.ts`, replace `SubscriptionInfo` with:

```ts
export interface SubscriptionInfo {
  tier: string;
  status: string | null;
  cancelled: boolean;
  renews_at: number | null;
  ends_at: number | null;
  seats: number | null;
  used_seats: number | null;
  trial_ends_at: number | null;
  has_ls_subscription: boolean;
}
```

Append these functions after `getSubscription`:

```ts
export function cancelSubscription(token: string): Promise<SubscriptionInfo> {
  return request<SubscriptionInfo>("/v1/billing/subscription/cancel", { method: "POST" }, token);
}

export function resumeSubscription(token: string): Promise<SubscriptionInfo> {
  return request<SubscriptionInfo>("/v1/billing/subscription/resume", { method: "POST" }, token);
}
```

- [ ] **Step 2: Import new API functions**

In `/home/kiki/projects/web/portal/app/account/page.tsx`, change the import to:

```ts
import { getCheckoutUrl, getPortalUrl, updateSeats, refreshJwt, getSubscription, cancelSubscription, resumeSubscription } from "../../lib/api";
```

- [ ] **Step 3: Add lifecycle state**

After `const [seats, setSeats] = useState<number | null>(null);`, add:

```ts
const [subscriptionStatus, setSubscriptionStatus] = useState<string | null>(null);
const [subscriptionCancelled, setSubscriptionCancelled] = useState(false);
const [renewsAt, setRenewsAt] = useState<number | null>(null);
const [endsAt, setEndsAt] = useState<number | null>(null);
const [subscriptionActionLoading, setSubscriptionActionLoading] = useState<"cancel" | "resume" | null>(null);
```

In the `getSubscription` success block, after `setSeats(sub.seats);`, add:

```ts
setSubscriptionStatus(sub.status);
setSubscriptionCancelled(sub.cancelled);
setRenewsAt(sub.renews_at);
setEndsAt(sub.ends_at);
```

- [ ] **Step 4: Add refresh helper and handlers**

Add these functions after `handleManage`:

```ts
function applySubscription(sub: Awaited<ReturnType<typeof getSubscription>>) {
  setHasLsSubscription(sub.has_ls_subscription);
  setSeats(sub.seats);
  if (sub.seats !== null) setTeamsSeats(sub.seats);
  setTier(sub.tier);
  setSubscriptionStatus(sub.status);
  setSubscriptionCancelled(sub.cancelled);
  setRenewsAt(sub.renews_at);
  setEndsAt(sub.ends_at);
  sessionStorage.setItem("tier", sub.tier);
  if (sub.trial_ends_at != null) {
    sessionStorage.setItem("trial_ends_at", String(sub.trial_ends_at));
  } else {
    sessionStorage.removeItem("trial_ends_at");
  }
}

async function handleCancelSubscription() {
  if (!token) return;
  const confirmed = window.confirm("Cancel Pro at the end of the current billing period? You will keep Pro access until the cancellation date.");
  if (!confirmed) return;
  setSubscriptionActionLoading("cancel");
  setError("");
  try {
    applySubscription(await cancelSubscription(token));
  } catch (err) {
    setError(err instanceof Error ? err.message : "Failed to cancel subscription.");
  } finally {
    setSubscriptionActionLoading(null);
  }
}

async function handleResumeSubscription() {
  if (!token) return;
  setSubscriptionActionLoading("resume");
  setError("");
  try {
    applySubscription(await resumeSubscription(token));
  } catch (err) {
    setError(err instanceof Error ? err.message : "Failed to resume subscription.");
  } finally {
    setSubscriptionActionLoading(null);
  }
}
```

In the existing subscription fetch success block, replace the repeated setters with:

```ts
applySubscription(sub);
```

- [ ] **Step 5: Pass lifecycle props to `PlanCard`**

Add these props to the `PlanCard` call:

```tsx
subscriptionStatus={subscriptionStatus}
subscriptionCancelled={subscriptionCancelled}
renewsAt={renewsAt}
endsAt={endsAt}
subscriptionActionLoading={subscriptionActionLoading}
onCancelSubscription={handleCancelSubscription}
onResumeSubscription={handleResumeSubscription}
```

Add matching fields to `PlanCard` parameter destructuring and type:

```ts
subscriptionStatus: string | null;
subscriptionCancelled: boolean;
renewsAt: number | null;
endsAt: number | null;
subscriptionActionLoading: "cancel" | "resume" | null;
onCancelSubscription: () => void;
onResumeSubscription: () => void;
```

- [ ] **Step 6: Add date formatter**

Add above `PlanCard`:

```ts
function formatBillingDate(timestamp: number | null): string | null {
  if (timestamp == null) return null;
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" }).format(new Date(timestamp * 1000));
}
```

- [ ] **Step 7: Replace active Pro controls**

Inside `PlanCard`, after `const loading = checkoutLoading || portalLoading;`, add:

```ts
const renewalDate = formatBillingDate(renewsAt);
const cancellationDate = formatBillingDate(endsAt ?? renewsAt);
const showProLifecycle = plan.id === "pro" && isActive && hasLsSubscription && !onTrial;
```

In the `isActive` branch, replace the non-trial fragment with:

```tsx
<>
  <button
    disabled
    className="w-full py-2.5 rounded-xl text-sm font-semibold border border-cyan-500/30 text-cyan-400 opacity-70 cursor-default"
  >
    Current plan
  </button>
  {showProLifecycle && (
    <div className="rounded-xl border border-[#1e1e2e] bg-[#0a0a0f] p-3 text-xs text-zinc-500 leading-relaxed">
      {subscriptionCancelled ? (
        <p>Cancels on {cancellationDate ?? "the period end"}. You keep Pro until then.</p>
      ) : (
        <p>{subscriptionStatus === "active" && renewalDate ? `Renews on ${renewalDate}.` : "Your Pro subscription is active."}</p>
      )}
    </div>
  )}
  {showProLifecycle && subscriptionCancelled ? (
    <button
      onClick={onResumeSubscription}
      disabled={subscriptionActionLoading !== null}
      className="w-full py-2.5 rounded-xl text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 text-black transition-all duration-200 disabled:opacity-50"
    >
      {subscriptionActionLoading === "resume" ? "Resuming…" : "Resume subscription"}
    </button>
  ) : showProLifecycle ? (
    <button
      onClick={onCancelSubscription}
      disabled={subscriptionActionLoading !== null}
      className="w-full py-2.5 rounded-xl text-sm font-semibold border border-[#1e1e2e] hover:border-red-500/50 text-zinc-400 hover:text-red-300 transition-colors disabled:opacity-50"
    >
      {subscriptionActionLoading === "cancel" ? "Cancelling…" : "Cancel subscription"}
    </button>
  ) : null}
  {activePlanId !== "free" && (
    <button
      onClick={onManage}
      disabled={portalLoading}
      className="text-xs text-center text-zinc-600 hover:text-zinc-400 transition-colors disabled:opacity-50"
    >
      {portalLoading ? "Opening…" : "Manage billing →"}
    </button>
  )}
</>
```

- [ ] **Step 8: Run portal checks**

Run from `/home/kiki/projects/web/portal`: `pnpm lint && pnpm build`

Expected: PASS.

- [ ] **Step 9: Commit in web repo**

```bash
git add portal/lib/api.ts portal/app/account/page.tsx
git commit -m "feat: add pro subscription lifecycle controls"
```

## Task 7: Mirror Lifecycle State In Desktop Settings

**Files:**
- Modify: `/home/kiki/projects/voltius/src/stores/subscriptionStore.ts`
- Modify: `/home/kiki/projects/voltius/src/components/settings/sections/AccountSection.tsx`

- [ ] **Step 1: Extend desktop subscription state**

In `SubscriptionState`, add:

```ts
subscriptionStatus: string | null;
subscriptionCancelled: boolean;
renewsAt: Date | null;
endsAt: Date | null;
```

In the initial state object, add:

```ts
subscriptionStatus: null,
subscriptionCancelled: false,
renewsAt: null,
endsAt: null,
```

In every non-server or invalid-token reset `set(...)`, include:

```ts
subscriptionStatus: null, subscriptionCancelled: false, renewsAt: null, endsAt: null
```

- [ ] **Step 2: Parse richer server response**

In the Teams fetch block, change the parsed data type to:

```ts
const data = await res.json() as {
  used_seats?: number | null;
  seats?: number | null;
  status?: string | null;
  cancelled?: boolean;
  renews_at?: number | null;
  ends_at?: number | null;
};
```

Change the `set` call to:

```ts
set({
  usedSeats: data.used_seats ?? null,
  totalSeats: data.seats ?? null,
  subscriptionStatus: data.status ?? null,
  subscriptionCancelled: data.cancelled ?? false,
  renewsAt: data.renews_at ? new Date(data.renews_at * 1000) : null,
  endsAt: data.ends_at ? new Date(data.ends_at * 1000) : null,
});
```

After the existing `set({ tier, trialEndsAt, ... })`, add a non-fatal fetch for all Pro users by changing `if (isTeams) {` to:

```ts
if (isPro) {
```

- [ ] **Step 3: Add desktop date formatter**

In `AccountSection.tsx`, add above `PlansSection`:

```ts
function formatPlanDate(date: Date | null): string | null {
  if (!date) return null;
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" }).format(date);
}
```

- [ ] **Step 4: Show Pro lifecycle copy**

In `PlansSection`, change the store destructuring to:

```ts
const { tier, trialEndsAt, isTrialActive, isPro, isTeams, isBusiness, usedSeats, totalSeats, subscriptionStatus, subscriptionCancelled, renewsAt, endsAt } = useSubscriptionStore();
```

After `const badgeColor = isPro ? "#f59e0b" : "var(--t-text-muted)";`, add:

```ts
const renewalDate = formatPlanDate(renewsAt);
const cancellationDate = formatPlanDate(endsAt ?? renewsAt);
```

After the header row ending at `</div>` around line 554, add:

```tsx
{isPaidPro && (
  <div className="rounded-md px-3 py-2 bg-[var(--t-bg-input)] text-xs text-[var(--t-text-muted)]">
    {subscriptionCancelled ? (
      <span>Cancels on {cancellationDate ?? "the period end"}. You keep Pro until then.</span>
    ) : subscriptionStatus === "active" && renewalDate ? (
      <span>Renews on {renewalDate}.</span>
    ) : (
      <span>Your Pro subscription is active.</span>
    )}
  </div>
)}
```

- [ ] **Step 5: Run desktop checks**

Run from `/home/kiki/projects/voltius`: `pnpm build`

Expected: PASS.

- [ ] **Step 6: Commit in desktop repo**

```bash
git add src/stores/subscriptionStore.ts src/components/settings/sections/AccountSection.tsx
git commit -m "feat: show subscription lifecycle in settings"
```

## Task 8: Final Verification

**Files:**
- Verify only; no planned edits.

- [ ] **Step 1: Run server verification**

Run from `/home/kiki/projects/server`: `cargo test && cargo check`

Expected: PASS.

- [ ] **Step 2: Run portal verification**

Run from `/home/kiki/projects/web/portal`: `pnpm lint && pnpm build`

Expected: PASS.

- [ ] **Step 3: Run desktop verification**

Run from `/home/kiki/projects/voltius`: `pnpm build`

Expected: PASS.

- [ ] **Step 4: Manual Lemon Squeezy test-mode checklist**

Verify these flows against the test-mode store:

- Free or trial account opens Pro checkout and becomes Pro after `subscription_created`.
- Pro account can cancel and still keeps Pro access with `Cancels on <date>` shown.
- Pending-cancel Pro account can resume and returns to `Renews on <date>`.
- Simulated `subscription_expired` downgrades to Free and Pro-gated sync rejects access.
- Portal-side cancellation updates Voltius after webhook delivery.
- Desktop Account settings shows active or cancelling state after token invalidation/refresh.

- [ ] **Step 5: Final commit for plan/doc updates if not already committed**

```bash
git status --short
git add docs/superpowers/specs/2026-05-13-subscription-payment-lifecycle-design.md docs/superpowers/plans/2026-05-13-subscription-payment-lifecycle.md
git commit -m "docs: plan subscription lifecycle implementation"
```

Only run this commit if the docs are intended to be committed in the server repo and no prior docs commit exists.

## Self-Review Notes

- Spec coverage: Pro upgrade remains existing checkout plus improved webhook handling; cancel/resume endpoints are covered in Task 5; webhook reconciliation is covered in Task 4; portal UX is covered in Task 6; desktop mirroring is covered in Task 7; verification is covered in Task 8.
- Placeholder scan: no task uses unspecified edge handling; each code-changing step includes exact code or exact replacement text.
- Type consistency: server response fields use snake_case for JSON compatibility; portal and desktop consume those snake_case fields; Rust lifecycle fields use `chrono::DateTime<Utc>` internally and unix timestamps in API responses.
