use axum::{extract::State, http::StatusCode, response::Response, Extension, Json};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;

use crate::auth::AuthUser;
use crate::entitlement::effective_tier;
use crate::routes::{coded_error, email_not_verified_response};
use crate::sync_notifier::SyncNotifier;

/// Plan and trial offers a new account starts with.
pub(crate) struct InitialPlan {
    pub tier: &'static str,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub pro_trial_available: bool,
    pub teams_trial_available: bool,
}

pub(crate) fn initial_plan(self_hosted: bool, trial_blocked: bool, supports_activation: bool, now: DateTime<Utc>) -> InitialPlan {
    if self_hosted {
        InitialPlan { tier: "business", trial_ends_at: None, pro_trial_available: false, teams_trial_available: false }
    } else if trial_blocked {
        InitialPlan { tier: "free", trial_ends_at: None, pro_trial_available: false, teams_trial_available: false }
    } else if supports_activation {
        InitialPlan { tier: "free", trial_ends_at: None, pro_trial_available: true, teams_trial_available: true }
    } else {
        InitialPlan { tier: "pro", trial_ends_at: Some(now + Duration::days(14)), pro_trial_available: false, teams_trial_available: true }
    }
}

/// Relaunch statement; must stay identical to the UPDATE in migrations/075_trial_activation.sql.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const RELAUNCH_SQL: &str = "UPDATE users SET pro_trial_available = TRUE, teams_trial_available = TRUE WHERE deleted_at IS NULL AND is_banned = FALSE AND ls_subscription_id IS NULL AND admin_override = FALSE";

#[derive(Deserialize)]
pub struct ActivateTrialRequest {
    pub plan: String,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ActivateTrialResponse {
    pub plan: String,
    pub trial_ends_at: i64,
}

fn tier_rank(tier: &str) -> u8 {
    match tier {
        "pro" => 1,
        "teams" => 2,
        "business" => 3,
        _ => 0,
    }
}

type ActivationRow = (bool, String, Option<DateTime<Utc>>, bool, Option<String>, bool, bool);

/// Starts the card-free 14-day trial of `pro` or `teams`.
pub async fn activate_trial(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Json(body): Json<ActivateTrialRequest>,
) -> Result<Json<ActivateTrialResponse>, Response> {
    let (plan, promo) = match body.plan.as_str() {
        "pro" => ("pro", "pro_redeem"),
        "teams" => ("teams", "teams_promo"),
        _ => return Err(coded_error(StatusCode::BAD_REQUEST, "INVALID_PLAN")),
    };
    let unavailable = || coded_error(StatusCode::CONFLICT, "TRIAL_UNAVAILABLE");
    let internal = |e: sqlx::Error| {
        error!("trial activation failed: {e}");
        coded_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
    };

    let row: ActivationRow = sqlx::query_as(
        "SELECT email_verified, subscription_tier, trial_ends_at, admin_override, ls_subscription_id, \
         pro_trial_available, teams_trial_available FROM users WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(internal)?;
    let (verified, stored_tier, stored_ends, admin_override, ls_sub, pro_flag, teams_flag) = row;
    if !verified {
        return Err(email_not_verified_response());
    }
    let flag = if plan == "pro" { pro_flag } else { teams_flag };
    let effective = effective_tier(&stored_tier, stored_ends, ls_sub.is_some(), admin_override, Utc::now());
    if !flag || ls_sub.is_some() || admin_override || tier_rank(effective) >= tier_rank(plan) {
        return Err(unavailable());
    }

    // Eligibility is re-checked in the WHERE so a concurrent second call affects 0 rows.
    let sql = if plan == "pro" {
        "UPDATE users SET subscription_tier = 'pro', trial_ends_at = now() + interval '14 days', pro_trial_available = FALSE \
         WHERE id = $1 AND pro_trial_available AND email_verified AND ls_subscription_id IS NULL AND admin_override = FALSE \
         AND subscription_tier = $2 AND trial_ends_at IS NOT DISTINCT FROM $3 RETURNING trial_ends_at"
    } else {
        "UPDATE users SET subscription_tier = 'teams', trial_ends_at = now() + interval '14 days', seat_count = 10, \
         teams_trial_available = FALSE, pro_trial_available = FALSE \
         WHERE id = $1 AND teams_trial_available AND email_verified AND ls_subscription_id IS NULL AND admin_override = FALSE \
         AND subscription_tier = $2 AND trial_ends_at IS NOT DISTINCT FROM $3 RETURNING trial_ends_at"
    };
    let ends: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(sql)
        .bind(auth.0)
        .bind(&stored_tier)
        .bind(stored_ends)
        .fetch_optional(&pool)
        .await
        .map_err(internal)?;
    let Some(Some(ends)) = ends else {
        return Err(unavailable());
    };

    let source: String = body.source.as_deref().unwrap_or("unknown").chars().take(64).collect();
    if let Err(e) = sqlx::query(
        "INSERT INTO promo_events (user_id, promo, event, source) VALUES ($1, $2, 'activated', $3)",
    )
    .bind(auth.0)
    .bind(promo)
    .bind(source)
    .execute(&pool)
    .await
    {
        error!("promo event insert failed: {e}");
    }

    notifier.notify(auth.0, "token_invalidated".to_string());
    let (bg_pool, bg_notifier) = (pool.clone(), notifier.clone());
    tokio::spawn(async move {
        crate::team_plan::reconcile_all_teams(&bg_pool, &bg_notifier).await;
    });

    Ok(Json(ActivateTrialResponse { plan: plan.to_string(), trial_ends_at: ends.timestamp() }))
}

#[derive(Serialize)]
pub struct SeenPromo {
    pub promo: String,
    pub source: String,
    pub occurrence: Option<i64>,
    pub at: i64,
}

#[derive(Serialize)]
pub struct PlanEnded {
    pub kind: String,
    pub at: i64,
}

#[derive(Serialize)]
pub struct TeamEnded {
    pub team_id: uuid::Uuid,
    pub team_name: String,
    pub at: i64,
}

#[derive(Serialize)]
pub struct PaymentIssue {
    pub status: String,
    pub renews_at: Option<i64>,
}

#[derive(Serialize)]
pub struct PromoState {
    pub pro_trial_available: bool,
    pub teams_trial_available: bool,
    pub email_verified: bool,
    pub seen: Vec<SeenPromo>,
    pub plan_ended: Option<PlanEnded>,
    pub team_ended: Option<TeamEnded>,
    pub payment_issue: Option<PaymentIssue>,
}

#[derive(Deserialize)]
pub struct PromoEventRequest {
    pub promo: String,
    pub event: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub occurrence: Option<i64>,
}

fn default_source() -> String {
    "launch".to_string()
}

type OwnerPlanRow = (uuid::Uuid, String, String, Option<DateTime<Utc>>, bool, Option<String>, DateTime<Utc>);
type SeenRow = (String, String, Option<DateTime<Utc>>, DateTime<Utc>);

type PromoUserRow = (bool, bool, bool, Option<DateTime<Utc>>, Option<String>, Option<String>, Option<DateTime<Utc>>);

/// Everything the client needs to decide which promo to show.
pub async fn get_promos(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
) -> Result<Json<PromoState>, Response> {
    let internal = |e: sqlx::Error| {
        error!("promo state failed: {e}");
        coded_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
    };

    let (pro, teams, verified, ended_at, ended_kind, ls_status, renews): PromoUserRow = sqlx::query_as(
        "SELECT pro_trial_available, teams_trial_available, email_verified, last_plan_ended_at, last_plan_ended_kind, \
         ls_subscription_status, subscription_renews_at FROM users WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(auth.0)
    .fetch_one(&pool)
    .await
    .map_err(internal)?;

    let seen_rows: Vec<SeenRow> = sqlx::query_as(
        "SELECT promo, source, occurrence, created_at FROM promo_events WHERE user_id = $1 AND event = 'shown' ORDER BY created_at",
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(internal)?;

    let owners: Vec<OwnerPlanRow> = sqlx::query_as(
        "SELECT t.id, t.name, o.subscription_tier, o.trial_ends_at, o.admin_override, o.ls_subscription_id, o.last_plan_ended_at \
         FROM team_members m JOIN teams t ON t.id = m.team_id JOIN users o ON o.id = t.owner_id \
         WHERE m.user_id = $1 AND t.owner_id <> $1 AND o.last_plan_ended_kind = 'teams_trial' AND o.last_plan_ended_at IS NOT NULL \
         ORDER BY o.last_plan_ended_at DESC",
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(internal)?;
    let now = Utc::now();
    let team_ended = owners
        .into_iter()
        .find(|(_, _, tier, ends, admin, sub, _)| {
            !matches!(effective_tier(tier, *ends, sub.is_some(), *admin, now), "teams" | "business")
        })
        .map(|(team_id, team_name, _, _, _, _, at)| TeamEnded { team_id, team_name, at: at.timestamp() });

    let plan_ended = match (ended_at, ended_kind) {
        (Some(at), Some(kind)) => Some(PlanEnded { kind, at: at.timestamp() }),
        _ => None,
    };
    let payment_issue = ls_status
        .filter(|s| s == "past_due" || s == "unpaid")
        .map(|status| PaymentIssue { status, renews_at: renews.map(|r| r.timestamp()) });

    Ok(Json(PromoState {
        pro_trial_available: pro,
        teams_trial_available: teams,
        email_verified: verified,
        seen: seen_rows
            .into_iter()
            .map(|(promo, source, occ, at)| SeenPromo { promo, source, occurrence: occ.map(|o| o.timestamp()), at: at.timestamp() })
            .collect(),
        plan_ended,
        team_ended,
        payment_issue,
    }))
}

/// Records a promo interaction; `shown` is idempotent per promo and occurrence.
pub async fn post_promo_event(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Json(body): Json<PromoEventRequest>,
) -> Result<StatusCode, Response> {
    let invalid = || coded_error(StatusCode::BAD_REQUEST, "INVALID_PROMO_EVENT");
    if !matches!(body.promo.as_str(), "pro_redeem" | "teams_promo" | "plan_ended")
        || !matches!(body.event.as_str(), "shown" | "dismissed" | "clicked" | "activated")
    {
        return Err(invalid());
    }
    let occurrence = match body.occurrence {
        Some(secs) => Some(DateTime::<Utc>::from_timestamp(secs, 0).ok_or_else(invalid)?),
        None => None,
    };
    let source: String = body.source.chars().take(64).collect();
    sqlx::query(
        "INSERT INTO promo_events (user_id, promo, event, source, occurrence) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(auth.0)
    .bind(&body.promo)
    .bind(&body.event)
    .bind(source)
    .bind(occurrence)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("promo event insert failed: {e}");
        coded_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
    })?;
    Ok(StatusCode::NO_CONTENT)
}

/// Downgrade lapsed trials to `free`: a non-free tier whose `trial_ends_at` has
/// passed, with no paid subscription and no admin override, has consumed its
/// trial and reverts. Records the end for the plan-ended promo and clears the
/// trial seat cap on teams trials. Paid accounts carry `trial_ends_at = NULL`.
pub async fn expire_lapsed_trials(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        r#"UPDATE users SET
               subscription_tier = 'free',
               trial_used = TRUE,
               last_plan_ended_at = trial_ends_at,
               last_plan_ended_kind = CASE WHEN subscription_tier = 'teams' THEN 'teams_trial' ELSE 'pro_trial' END,
               seat_count = CASE WHEN subscription_tier = 'teams' THEN NULL ELSE seat_count END,
               trial_ends_at = NULL
           WHERE subscription_tier <> 'free'
             AND trial_ends_at IS NOT NULL
             AND trial_ends_at <= now()
             AND ls_subscription_id IS NULL
             AND admin_override = FALSE"#,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::seed_user;
    use axum::{extract::State, http::StatusCode, response::Response, Extension, Json};

    async fn flags(pool: &sqlx::PgPool, id: uuid::Uuid) -> (bool, bool) {
        sqlx::query_as::<_, (bool, bool)>(
            "SELECT pro_trial_available, teams_trial_available FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn relaunch_marks_only_unpaid_accounts() {
        let pool = crate::test_pool_or_skip!();
        let free = seed_user(&pool).await;
        let paid = seed_user(&pool).await;
        let admin = seed_user(&pool).await;
        let banned = seed_user(&pool).await;
        sqlx::query("UPDATE users SET ls_subscription_id = 'sub_1' WHERE id = $1")
            .bind(paid)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET admin_override = TRUE WHERE id = $1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET is_banned = TRUE WHERE id = $1")
            .bind(banned)
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(&format!("{RELAUNCH_SQL} AND id = ANY($1)"))
            .bind(vec![free, paid, admin, banned])
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(flags(&pool, free).await, (true, true));
        assert_eq!(flags(&pool, paid).await, (false, false));
        assert_eq!(flags(&pool, admin).await, (false, false));
        assert_eq!(flags(&pool, banned).await, (false, false));
    }

    #[test]
    fn initial_plan_self_hosted() {
        let p = initial_plan(true, true, true, chrono::Utc::now());
        assert_eq!((p.tier, p.trial_ends_at, p.pro_trial_available, p.teams_trial_available), ("business", None, false, false));
    }

    #[test]
    fn initial_plan_fingerprint_blocked() {
        let p = initial_plan(false, true, true, chrono::Utc::now());
        assert_eq!((p.tier, p.trial_ends_at, p.pro_trial_available, p.teams_trial_available), ("free", None, false, false));
    }

    #[test]
    fn initial_plan_legacy_client() {
        let now = chrono::Utc::now();
        let p = initial_plan(false, false, false, now);
        assert_eq!(p.tier, "pro");
        assert_eq!(p.trial_ends_at, Some(now + chrono::Duration::days(14)));
        assert!(!p.pro_trial_available);
        assert!(p.teams_trial_available);
    }

    #[test]
    fn initial_plan_activation_client() {
        let p = initial_plan(false, false, true, chrono::Utc::now());
        assert_eq!((p.tier, p.trial_ends_at, p.pro_trial_available, p.teams_trial_available), ("free", None, true, true));
    }

    #[test]
    fn relaunch_sql_matches_migration() {
        assert!(include_str!("../migrations/075_trial_activation.sql").contains(RELAUNCH_SQL));
    }

    async fn verified_user(pool: &sqlx::PgPool) -> uuid::Uuid {
        let u = seed_user(pool).await;
        sqlx::query("UPDATE users SET email_verified = TRUE, pro_trial_available = TRUE, teams_trial_available = TRUE WHERE id = $1")
            .bind(u)
            .execute(pool)
            .await
            .unwrap();
        u
    }

    async fn activate(
        pool: &sqlx::PgPool,
        u: uuid::Uuid,
        plan: &str,
    ) -> Result<Json<ActivateTrialResponse>, Response> {
        activate_trial(
            State(pool.clone()),
            Extension(AuthUser(u)),
            Extension(SyncNotifier::new()),
            Json(ActivateTrialRequest { plan: plan.to_string(), source: Some("test".to_string()) }),
        )
        .await
    }

    async fn err_body(res: Result<Json<ActivateTrialResponse>, Response>) -> (StatusCode, String) {
        let r = res.err().expect("expected error");
        let status = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn activates_pro_trial() {
        let pool = crate::test_pool_or_skip!();
        let _billing = crate::test_support::BillingMode::hosted();
        let u = verified_user(&pool).await;
        let Json(resp) = activate(&pool, u, "pro").await.ok().unwrap();
        assert_eq!(resp.plan, "pro");
        let want = (Utc::now() + Duration::days(14)).timestamp();
        assert!((resp.trial_ends_at - want).abs() < 60);
        let (tier, ends, pro, teams): (String, Option<DateTime<Utc>>, bool, bool) = sqlx::query_as(
            "SELECT subscription_tier, trial_ends_at, pro_trial_available, teams_trial_available FROM users WHERE id = $1",
        )
        .bind(u)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(tier, "pro");
        assert_eq!(ends.unwrap().timestamp(), resp.trial_ends_at);
        assert!(!pro);
        assert!(teams);
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM promo_events WHERE user_id = $1 AND promo = 'pro_redeem' AND event = 'activated' AND source = 'test'")
            .bind(u)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn activates_teams_trial_with_ten_seats() {
        let pool = crate::test_pool_or_skip!();
        let _billing = crate::test_support::BillingMode::hosted();
        let u = verified_user(&pool).await;
        let Json(resp) = activate(&pool, u, "teams").await.ok().unwrap();
        assert_eq!(resp.plan, "teams");
        let (tier, seats, pro, teams): (String, Option<i32>, bool, bool) = sqlx::query_as(
            "SELECT subscription_tier, seat_count, pro_trial_available, teams_trial_available FROM users WHERE id = $1",
        )
        .bind(u)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((tier.as_str(), seats, pro, teams), ("teams", Some(10), false, false));
        assert_eq!(crate::routes::teams::owner_seat_cap(&pool, u).await, Ok(Some(10)));
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM promo_events WHERE user_id = $1 AND promo = 'teams_promo' AND event = 'activated'")
            .bind(u)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn activation_requires_verified_email() {
        let pool = crate::test_pool_or_skip!();
        let _billing = crate::test_support::BillingMode::hosted();
        let u = seed_user(&pool).await;
        sqlx::query("UPDATE users SET pro_trial_available = TRUE WHERE id = $1").bind(u).execute(&pool).await.unwrap();
        let (status, body) = err_body(activate(&pool, u, "pro").await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, r#"{"error":"EMAIL_NOT_VERIFIED"}"#);
    }

    #[tokio::test]
    async fn second_activation_conflicts() {
        let pool = crate::test_pool_or_skip!();
        let _billing = crate::test_support::BillingMode::hosted();
        let u = verified_user(&pool).await;
        let _ = activate(&pool, u, "pro").await.ok().unwrap();
        let before: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT trial_ends_at FROM users WHERE id = $1").bind(u).fetch_one(&pool).await.unwrap();
        let (status, body) = err_body(activate(&pool, u, "pro").await).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, r#"{"error":"TRIAL_UNAVAILABLE"}"#);
        let after: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT trial_ends_at FROM users WHERE id = $1").bind(u).fetch_one(&pool).await.unwrap();
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn activation_conflicts_during_running_trial() {
        let pool = crate::test_pool_or_skip!();
        let _billing = crate::test_support::BillingMode::hosted();
        let u = verified_user(&pool).await;
        crate::test_support::set_user_tier(&pool, u, "pro").await;
        crate::test_support::set_user_trial(&pool, u, 5).await;
        let (status, _) = err_body(activate(&pool, u, "pro").await).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let Json(resp) = activate(&pool, u, "teams").await.ok().unwrap();
        assert_eq!(resp.plan, "teams");
    }

    #[tokio::test]
    async fn activation_refused_for_paid_or_comped() {
        let pool = crate::test_pool_or_skip!();
        let _billing = crate::test_support::BillingMode::hosted();
        let paid = verified_user(&pool).await;
        sqlx::query("UPDATE users SET ls_subscription_id = 'sub_1' WHERE id = $1").bind(paid).execute(&pool).await.unwrap();
        let comped = verified_user(&pool).await;
        sqlx::query("UPDATE users SET admin_override = TRUE WHERE id = $1").bind(comped).execute(&pool).await.unwrap();
        for u in [paid, comped] {
            let (status, body) = err_body(activate(&pool, u, "teams").await).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body, r#"{"error":"TRIAL_UNAVAILABLE"}"#);
            let tier: String = sqlx::query_scalar("SELECT subscription_tier FROM users WHERE id = $1").bind(u).fetch_one(&pool).await.unwrap();
            assert_eq!(tier, "free");
        }
    }

    #[tokio::test]
    async fn activation_blocked_when_self_hosted() {
        use tower::ServiceExt;
        let _billing = crate::test_support::BillingMode::self_hosted();
        let app: axum::Router = axum::Router::new()
            .route("/t", axum::routing::post(activate_trial))
            .route_layer(axum::middleware::from_fn(crate::self_host::block_when_self_hosted))
            .with_state(PgPool::connect_lazy("postgres://u@127.0.0.1/x").unwrap());
        let res = app
            .oneshot(axum::http::Request::post("/t").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8(bytes.to_vec()).unwrap().contains("BILLING_DISABLED"));
    }

    #[tokio::test]
    async fn invalid_plan_rejected() {
        let pool = crate::test_pool_or_skip!();
        let _billing = crate::test_support::BillingMode::hosted();
        let u = verified_user(&pool).await;
        let (status, body) = err_body(activate(&pool, u, "business").await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"INVALID_PLAN"}"#);
    }

    async fn promos(pool: &sqlx::PgPool, u: uuid::Uuid) -> PromoState {
        let Json(s) = get_promos(State(pool.clone()), Extension(AuthUser(u))).await.ok().unwrap();
        s
    }

    async fn post_event(
        pool: &sqlx::PgPool,
        u: uuid::Uuid,
        promo: &str,
        event: &str,
        occurrence: Option<i64>,
    ) -> Result<StatusCode, Response> {
        post_promo_event(
            State(pool.clone()),
            Extension(AuthUser(u)),
            Json(PromoEventRequest {
                promo: promo.to_string(),
                event: event.to_string(),
                source: "launch".to_string(),
                occurrence,
            }),
        )
        .await
    }

    #[tokio::test]
    async fn promo_state_reports_flags_and_seen() {
        let pool = crate::test_pool_or_skip!();
        let u = verified_user(&pool).await;
        sqlx::query("INSERT INTO promo_events (user_id, promo, event, source) VALUES ($1, 'pro_redeem', 'shown', 'banner'), ($1, 'pro_redeem', 'dismissed', 'banner')")
            .bind(u)
            .execute(&pool)
            .await
            .unwrap();
        let s = promos(&pool, u).await;
        assert!(s.pro_trial_available && s.teams_trial_available && s.email_verified);
        assert_eq!(s.seen.len(), 1);
        assert_eq!((s.seen[0].promo.as_str(), s.seen[0].source.as_str()), ("pro_redeem", "banner"));
        assert!(s.plan_ended.is_none() && s.team_ended.is_none() && s.payment_issue.is_none());
    }

    #[tokio::test]
    async fn shown_event_is_idempotent() {
        let pool = crate::test_pool_or_skip!();
        let u = verified_user(&pool).await;
        for _ in 0..2 {
            assert_eq!(post_event(&pool, u, "teams_promo", "shown", None).await.ok().unwrap(), StatusCode::NO_CONTENT);
        }
        for _ in 0..2 {
            post_event(&pool, u, "plan_ended", "shown", Some(1_700_000_000)).await.ok().unwrap();
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM promo_events WHERE user_id = $1 AND promo = 'teams_promo' AND event = 'shown'")
            .bind(u)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let s = promos(&pool, u).await;
        assert_eq!(s.seen.len(), 2);
        let pe = s.seen.iter().find(|p| p.promo == "plan_ended").unwrap();
        assert_eq!(pe.occurrence, Some(1_700_000_000));
    }

    #[tokio::test]
    async fn invalid_promo_event_rejected() {
        let pool = crate::test_pool_or_skip!();
        let u = verified_user(&pool).await;
        for (p, e) in [("bogus", "shown"), ("pro_redeem", "bogus")] {
            let r = post_event(&pool, u, p, e, None).await.expect_err("expected error");
            assert_eq!(r.status(), StatusCode::BAD_REQUEST);
            let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
            assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), r#"{"error":"INVALID_PROMO_EVENT"}"#);
        }
    }

    #[tokio::test]
    async fn plan_ended_reported_from_columns() {
        let pool = crate::test_pool_or_skip!();
        let u = verified_user(&pool).await;
        assert!(promos(&pool, u).await.plan_ended.is_none());
        sqlx::query("UPDATE users SET last_plan_ended_at = to_timestamp(1700000000), last_plan_ended_kind = 'pro_trial' WHERE id = $1")
            .bind(u)
            .execute(&pool)
            .await
            .unwrap();
        let pe = promos(&pool, u).await.plan_ended.unwrap();
        assert_eq!((pe.kind.as_str(), pe.at), ("pro_trial", 1_700_000_000));
    }

    #[tokio::test]
    async fn team_ended_reported_to_members() {
        let pool = crate::test_pool_or_skip!();
        let owner = verified_user(&pool).await;
        let member = verified_user(&pool).await;
        let team = crate::test_support::seed_team(&pool, owner).await;
        crate::test_support::add_member(&pool, team, owner).await;
        crate::test_support::add_member(&pool, team, member).await;
        sqlx::query("UPDATE users SET last_plan_ended_at = to_timestamp(1700000000), last_plan_ended_kind = 'teams_trial' WHERE id = $1")
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        let te = promos(&pool, member).await.team_ended.unwrap();
        assert_eq!((te.team_id, te.team_name.as_str(), te.at), (team, "test-team", 1_700_000_000));
        assert!(promos(&pool, owner).await.team_ended.is_none());
        crate::test_support::set_user_tier(&pool, owner, "teams").await;
        assert!(promos(&pool, member).await.team_ended.is_none());
    }

    #[tokio::test]
    async fn payment_issue_reported_for_past_due() {
        let pool = crate::test_pool_or_skip!();
        let u = verified_user(&pool).await;
        crate::test_support::set_user_ls_status(&pool, u, "past_due").await;
        let pi = promos(&pool, u).await.payment_issue.unwrap();
        assert_eq!(pi.status, "past_due");
        crate::test_support::set_user_ls_status(&pool, u, "active").await;
        assert!(promos(&pool, u).await.payment_issue.is_none());
    }

    async fn expire_row(pool: &sqlx::PgPool, id: uuid::Uuid) -> (String, bool, Option<i32>, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>, Option<String>) {
        sqlx::query_as(
            "SELECT subscription_tier, trial_used, seat_count, trial_ends_at, last_plan_ended_at, last_plan_ended_kind FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn seed_lapsed(pool: &sqlx::PgPool, tier: &str, seats: Option<i32>) -> (uuid::Uuid, chrono::DateTime<chrono::Utc>) {
        let u = seed_user(pool).await;
        let ended = chrono::Utc::now() - chrono::Duration::days(2);
        sqlx::query("UPDATE users SET subscription_tier = $1, seat_count = $2, trial_ends_at = $3 WHERE id = $4")
            .bind(tier)
            .bind(seats)
            .bind(ended)
            .bind(u)
            .execute(pool)
            .await
            .unwrap();
        (u, ended)
    }

    #[tokio::test]
    async fn sweep_records_pro_trial_end() {
        let pool = crate::test_pool_or_skip!();
        let (u, ended) = seed_lapsed(&pool, "pro", None).await;
        expire_lapsed_trials(&pool).await.unwrap();
        let (tier, used, _, te, at, kind) = expire_row(&pool, u).await;
        assert_eq!((tier.as_str(), used, te), ("free", true, None));
        assert_eq!(at.unwrap().timestamp_micros(), ended.timestamp_micros());
        assert_eq!(kind.as_deref(), Some("pro_trial"));
    }

    #[tokio::test]
    async fn sweep_records_teams_trial_end_and_clears_seats() {
        let pool = crate::test_pool_or_skip!();
        let (u, ended) = seed_lapsed(&pool, "teams", Some(10)).await;
        expire_lapsed_trials(&pool).await.unwrap();
        let (tier, used, seats, te, at, kind) = expire_row(&pool, u).await;
        assert_eq!((tier.as_str(), used, seats, te), ("free", true, None, None));
        assert_eq!(at.unwrap().timestamp_micros(), ended.timestamp_micros());
        assert_eq!(kind.as_deref(), Some("teams_trial"));
    }

    #[tokio::test]
    async fn sweep_ignores_paid_and_comped() {
        let pool = crate::test_pool_or_skip!();
        let (paid, _) = seed_lapsed(&pool, "pro", None).await;
        let (comped, _) = seed_lapsed(&pool, "teams", Some(10)).await;
        sqlx::query("UPDATE users SET ls_subscription_id = $1 WHERE id = $2")
            .bind(format!("sub_{paid}"))
            .bind(paid)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET admin_override = TRUE WHERE id = $1")
            .bind(comped)
            .execute(&pool)
            .await
            .unwrap();
        expire_lapsed_trials(&pool).await.unwrap();
        for (u, tier) in [(paid, "pro"), (comped, "teams")] {
            let (t, used, _, te, at, kind) = expire_row(&pool, u).await;
            assert_eq!(t, tier);
            assert!(!used);
            assert!(te.is_some());
            assert!(at.is_none() && kind.is_none());
        }
    }
}
