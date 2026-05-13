# Subscription Payment Lifecycle Design

Date: 2026-05-13

## Goal

Make Voltius subscription management feel like a mature SaaS product. Users must be able to upgrade to Pro, cancel, and resume without account-state drift between Lemon Squeezy, the server, the web portal, and the desktop app.

This phase focuses on Pro. Teams plan changes and seat-management improvements remain out of scope until Pro billing is reliable.

## Product Policy

Voltius uses a hybrid billing model:

- Voltius owns common subscription actions: upgrade to Pro, cancel at period end, and resume a pending cancellation.
- Lemon Squeezy remains the payment authority for checkout, card handling, invoices, tax, proration, and hosted account-management edge cases.
- The Lemon Squeezy customer portal remains available for payment method updates, invoices, tax details, and unusual account changes.

Billing fairness policy:

- Upgrades are immediate.
- Downgrades and cancellations take effect at the end of the current billing period.
- Users keep paid Pro access until `ends_at` when cancelling.
- Voltius should not promise refunds in app copy for cancellation, because this phase uses end-of-period cancellation rather than immediate downgrade/refund handling.

## Current Gaps

The existing implementation mostly opens checkout or the Lemon Squeezy portal and relies on webhooks. The main correctness gaps are:

- No first-class Pro cancel or resume endpoints.
- `subscription_cancelled` only logs and does not mirror pending-cancel state locally.
- Subscription state exposed to clients lacks Lemon Squeezy lifecycle fields such as `status`, `cancelled`, `renews_at`, and `ends_at`.
- Webhook tier mapping infers from `product_name`, which is fragile compared with configured variant IDs.
- Desktop and portal UI cannot clearly distinguish active Pro from pending-cancel Pro.

## Architecture

The server is the only system that mutates billing state. Web and desktop clients call Voltius billing endpoints. The server calls Lemon Squeezy and then mirrors the relevant subscription state into the database.

Lemon Squeezy remains the payment source of truth. Voltius stores a normalized mirror used for authorization and UI state:

- Current tier.
- Lemon Squeezy customer ID.
- Lemon Squeezy subscription ID.
- Lemon Squeezy variant ID.
- Lemon Squeezy subscription status.
- Whether the subscription is cancelled.
- Renewal date.
- End date.
- Seat count when applicable.
- Trial fields already used by the app.

Webhooks are the primary reconciliation path. Direct API calls can refresh local state from the Lemon Squeezy response for responsive UX, but webhook payloads must still be accepted as authoritative updates. If local state and webhook state disagree, the most recent Lemon Squeezy subscription payload wins.

## User Flows

### Free Or Trial To Pro

The user clicks upgrade. Voltius opens Lemon Squeezy checkout. After payment, Lemon Squeezy sends `subscription_created`. The server updates the user to Pro, stores Lemon Squeezy IDs, clears trial state, stores variant/status/date fields, and invalidates the client token so the app refreshes immediately.

### Active Pro To Cancelled At Period End

The user clicks `Cancel subscription` in Voltius and confirms. The server calls Lemon Squeezy to cancel the current subscription at period end. Pro features remain active locally. The UI shows cancellation state with copy such as `Cancels on <date>. You keep Pro until then.`

### Pending-Cancel Pro To Active Pro

The user clicks `Resume subscription`. The server resumes the Lemon Squeezy subscription. The UI returns to active copy such as `Renews on <date>`.

### Expired Subscription To Free

When Lemon Squeezy emits `subscription_expired`, the server downgrades the user to Free, clears active subscription access, records churn, and invalidates the token. Cloud/pro feature checks then consistently reflect Free across desktop and web.

### Teams

Teams plan changes are not part of this phase. Existing Teams checkout, portal links, or coming-soon UI can remain unchanged.

## API Design

Add these server endpoints:

- `POST /v1/billing/subscription/cancel`: cancel the current Lemon Squeezy subscription at period end and return refreshed subscription state.
- `POST /v1/billing/subscription/resume`: resume a pending-cancel subscription and return refreshed subscription state.

Extend this existing endpoint:

- `GET /v1/billing/subscription`: return richer subscription state for portal and desktop UI.

The subscription response should include:

- `tier`
- `status`
- `cancelled`
- `renews_at`
- `ends_at`
- `trial_ends_at`
- `seats`
- `used_seats`
- `has_ls_subscription`

Keep this existing endpoint:

- `POST /v1/billing/portal`: opens Lemon Squeezy billing management for payment methods, invoices, tax details, and edge cases.

## Webhook Design

Webhook handling must be idempotent and variant-driven.

Required changes:

- Map Lemon Squeezy `variant_id` to Voltius tiers using configured environment variables, not `product_name`.
- On `subscription_created`, store tier, customer ID, subscription ID, variant ID, status, cancellation flag, renewal date, end date, seat count if present, and clear trial state.
- On `subscription_updated`, update status, cancellation flag, renewal date, end date, variant ID, tier, and seat count if present.
- On `subscription_cancelled`, store pending-cancel state instead of only logging.
- On `subscription_expired`, downgrade to Free, clear active subscription access, record churn, and invalidate the token.
- On `subscription_trial_expired`, keep existing trial expiry behavior.

All state-changing subscription webhooks should notify the affected user with `token_invalidated` so clients refresh their JWT and subscription store.

## Database Design

Add database columns to `users` for the mirrored Lemon Squeezy lifecycle fields:

- `ls_subscription_status text null`
- `ls_variant_id text null`
- `subscription_cancelled boolean not null default false`
- `subscription_renews_at timestamptz null`
- `subscription_ends_at timestamptz null`

Existing fields remain:

- `subscription_tier`
- `trial_ends_at`
- `trial_used`
- `ls_customer_id`
- `ls_subscription_id`
- `seat_count`
- `admin_override`

When a subscription expires, `subscription_tier` becomes `free`, `subscription_cancelled` becomes `false`, `subscription_renews_at` becomes `null`, `subscription_ends_at` is kept as the historical expiry date, and `ls_subscription_id` is cleared so the account no longer has an active paid subscription. `ls_customer_id` can remain for future checkouts or operator lookup.

## Client UX

The web portal plan card should show one clear state:

- Free.
- Trial.
- Pro active.
- Pro cancelling.
- Pro expired/free.

Pro active copy:

- `Renews on <date>`.
- Actions: `Cancel subscription`, `Manage billing`.

Pro cancelling copy:

- `Cancels on <date>. You keep Pro until then.`
- Actions: `Resume subscription`, `Manage billing`.

Cancel must use a confirmation dialog before calling the API. The copy should avoid refund promises.

The desktop app should mirror important state in Account settings: current plan, renewal or cancellation date, and a portal link. Deep billing actions can happen in the web portal for this phase.

## Error Handling

If Lemon Squeezy API credentials are missing, billing mutation endpoints return `503`.

If the user has no Lemon Squeezy subscription, cancel/resume return `404`.

If Lemon Squeezy rejects or fails the request, endpoints return `502` and local state is not downgraded optimistically.

If an admin override is active, webhooks must not overwrite `subscription_tier`, but they may still store Lemon Squeezy mirror fields if needed for operator visibility. Token invalidation should still happen when visible account state may have changed.

## Verification

Automated verification should cover:

- Variant ID to tier mapping for Pro monthly/yearly and existing configured variants.
- `subscription_created` stores all required state and invalidates tokens.
- `subscription_updated` handles plan/status/date changes idempotently.
- `subscription_cancelled` records pending cancellation without removing Pro access.
- `subscription_expired` downgrades to Free and records churn.
- Cancel API success, no-subscription, missing config, Lemon Squeezy failure, and admin-override cases.
- Resume API success, no-subscription, missing config, Lemon Squeezy failure, and non-cancelled subscription cases.

Manual Lemon Squeezy test-mode verification should cover:

- Free or trial to Pro checkout.
- Pro cancellation at period end.
- Resume before period end.
- Simulated `subscription_expired` webhook.
- Portal-side cancellation and resume.
- Failed payment or status update webhook.
- Desktop refresh after token invalidation.

## Out Of Scope

- Teams upgrade/downgrade lifecycle.
- Seat-proration policy redesign.
- Immediate downgrade refunds.
- Local invoice history.
- Full billing ledger or admin reconciliation dashboard.
