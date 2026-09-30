use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::entitlement::effective_tier;
use crate::self_host;

pub const OWNER_PLAN_COLUMNS: &str =
    "u.subscription_tier, u.trial_ends_at, u.admin_override, u.ls_subscription_id";

pub type OwnerPlanRow = (String, Option<DateTime<Utc>>, bool, Option<String>);

pub fn plan_for_owner(
    stored: &str,
    trial_ends_at: Option<DateTime<Utc>>,
    has_paid_sub: bool,
    admin_override: bool,
) -> String {
    if self_host::is_self_hosted() {
        return "business".to_string();
    }
    effective_tier(
        stored,
        trial_ends_at,
        has_paid_sub,
        admin_override,
        Utc::now(),
    )
    .to_string()
}

pub fn plan_from_row(row: &OwnerPlanRow) -> String {
    plan_for_owner(&row.0, row.1, row.3.is_some(), row.2)
}

pub async fn team_plan(pool: &PgPool, team_id: Uuid) -> Result<String, StatusCode> {
    let row = sqlx::query_as::<_, OwnerPlanRow>(&format!(
        "SELECT {OWNER_PLAN_COLUMNS} FROM teams t JOIN users u ON u.id = t.owner_id WHERE t.id = $1"
    ))
    .bind(team_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to read team plan");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;
    Ok(plan_from_row(&row))
}

pub async fn require_granular(
    pool: &PgPool,
    team_id: Uuid,
    narrowing: bool,
) -> Result<(), StatusCode> {
    if narrowing || team_plan(pool, team_id).await? == "business" {
        Ok(())
    } else {
        Err(StatusCode::PAYMENT_REQUIRED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::BillingMode;
    use chrono::Duration;

    #[test]
    fn self_hosted_is_business_whatever_the_stored_tier() {
        let _env = BillingMode::self_hosted();
        assert_eq!(plan_for_owner("free", None, false, false), "business");
    }

    #[test]
    fn hosted_reports_the_effective_tier() {
        let _env = BillingMode::hosted();
        assert_eq!(plan_for_owner("business", None, true, false), "business");
        assert_eq!(plan_for_owner("teams", None, true, false), "teams");
        let lapsed = Some(Utc::now() - Duration::days(1));
        assert_eq!(plan_for_owner("business", lapsed, false, false), "free");
    }
}
