use axum::http::StatusCode;
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::entitlement::{effective_tier_of, TierRow, OWNER_PLAN_COLUMNS};
use crate::self_host;

pub fn plan_from_row(row: &TierRow) -> String {
    if self_host::is_self_hosted() {
        return "business".to_string();
    }
    effective_tier_of(row)
}

pub async fn team_plan(pool: &PgPool, team_id: Uuid) -> Result<String, StatusCode> {
    if self_host::is_self_hosted() {
        return Ok("business".to_string());
    }
    let row = sqlx::query_as::<_, TierRow>(&format!(
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

pub async fn team_locked(pool: &PgPool, team_id: Uuid) -> Result<bool, StatusCode> {
    Ok(team_plan(pool, team_id).await? != "business")
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

pub fn narrows_masks(previous: (i64, i64), next: (i64, i64)) -> bool {
    next.0 & !previous.0 == 0 && next.1 & !previous.1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::BillingMode;
    use chrono::{Duration, Utc};

    #[test]
    fn self_hosted_is_business_whatever_the_stored_tier() {
        let _env = BillingMode::self_hosted();
        assert_eq!(
            plan_from_row(&("free".into(), None, false, None)),
            "business"
        );
    }

    #[test]
    fn hosted_reports_the_effective_tier() {
        let _env = BillingMode::hosted();
        assert_eq!(
            plan_from_row(&("business".into(), None, false, Some("s".into()))),
            "business"
        );
        assert_eq!(
            plan_from_row(&("teams".into(), None, false, Some("s".into()))),
            "teams"
        );
        let lapsed = Some(Utc::now() - Duration::days(1));
        assert_eq!(
            plan_from_row(&("business".into(), lapsed, false, None)),
            "free"
        );
    }

    #[test]
    fn narrowing_masks_only_drop_bits() {
        assert!(narrows_masks((0b101, 0b010), (0b001, 0)));
        assert!(narrows_masks((0, 0), (0, 0)));
        assert!(!narrows_masks((0b001, 0), (0b011, 0)));
        assert!(!narrows_masks((0, 0b01), (0, 0b11)));
        assert!(!narrows_masks((0b01, 0), (0, 0b01)));
    }
}
