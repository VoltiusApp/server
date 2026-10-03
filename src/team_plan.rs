use axum::http::StatusCode;
use sqlx::PgPool;
use tracing::{error, info};
use uuid::Uuid;

use crate::entitlement::{effective_tier_of, TierRow, OWNER_PLAN_COLUMNS};
use crate::object_authz::member_rows;
use crate::routes::teams::notify_team_members_changed;
use crate::self_host;
use crate::sync_notifier::SyncNotifier;

const OWNER_PLAN_FROM: &str = "FROM teams t JOIN users u ON u.id = t.owner_id";

pub fn plan_from_row(row: &TierRow) -> String {
    if self_host::is_self_hosted() {
        return "business".to_string();
    }
    effective_tier_of(row)
}

pub fn locked_from_row(row: &TierRow) -> bool {
    plan_from_row(row) != "business"
}

async fn owner_plan_row(pool: &PgPool, team_id: Uuid) -> Result<TierRow, StatusCode> {
    sqlx::query_as::<_, TierRow>(&format!(
        "SELECT {OWNER_PLAN_COLUMNS} {OWNER_PLAN_FROM} WHERE t.id = $1"
    ))
    .bind(team_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to read team plan");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)
}

pub async fn team_locked(pool: &PgPool, team_id: Uuid) -> Result<bool, StatusCode> {
    if self_host::is_self_hosted() {
        return Ok(false);
    }
    Ok(locked_from_row(&owner_plan_row(pool, team_id).await?))
}

pub async fn reconcile_team_plan(
    pool: &PgPool,
    notifier: &SyncNotifier,
    team_id: Uuid,
) -> Result<(), StatusCode> {
    let db = |e: sqlx::Error| {
        error!(error = %e, team_id = %team_id, "Failed to reconcile team plan");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let mut tx = pool.begin().await.map_err(db)?;
    let row = sqlx::query_as::<_, (bool, String, Option<chrono::DateTime<chrono::Utc>>, bool, Option<String>)>(&format!(
        "SELECT t.granular_locked, {OWNER_PLAN_COLUMNS} {OWNER_PLAN_FROM} WHERE t.id = $1 FOR UPDATE OF t"
    ))
    .bind(team_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    let Some((stored, tier, trial_ends_at, admin_override, ls_sub)) = row else {
        return Ok(());
    };
    let locked_now = locked_from_row(&(tier, trial_ends_at, admin_override, ls_sub));
    if stored == locked_now {
        return Ok(());
    }
    let members = member_rows(pool, team_id, None).await?;
    sqlx::query("UPDATE teams SET granular_locked = $2 WHERE id = $1")
        .bind(team_id)
        .bind(locked_now)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    info!(team_id = %team_id, locked = locked_now, "Team plan transition reconciled");
    notify_team_members_changed(pool, notifier, team_id).await;
    if !locked_now {
        for m in &members {
            notifier.notify_vault_key_changed(m.user_id);
        }
    }
    Ok(())
}

pub async fn reconcile_all_teams(pool: &PgPool, notifier: &SyncNotifier) {
    if self_host::is_self_hosted() {
        return;
    }
    let rows = sqlx::query_as::<_, (Uuid, bool, String, Option<chrono::DateTime<chrono::Utc>>, bool, Option<String>)>(&format!(
        "SELECT t.id, t.granular_locked, {OWNER_PLAN_COLUMNS} {OWNER_PLAN_FROM}"
    ))
    .fetch_all(pool)
    .await;
    let rows = match rows {
        Ok(r) => r,
        Err(e) => return error!(error = %e, "Failed to list teams for plan reconcile"),
    };
    for (team_id, stored, tier, trial_ends_at, admin_override, ls_sub) in rows {
        let locked_now = locked_from_row(&(tier, trial_ends_at, admin_override, ls_sub));
        if locked_now != stored {
            if let Err(status) = reconcile_team_plan(pool, notifier, team_id).await {
                error!(team_id = %team_id, %status, "Team plan reconcile failed");
            }
        }
    }
}

pub async fn require_granular(
    pool: &PgPool,
    team_id: Uuid,
    narrowing: bool,
) -> Result<(), StatusCode> {
    if narrowing || !team_locked(pool, team_id).await? {
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

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::permissions::{PERM_CONNECT, PERM_VIEW};
    use crate::sync_notifier::{SyncEvent, SyncNotifier};
    use crate::test_support::*;

    async fn stored_lock(pool: &PgPool, team: Uuid) -> bool {
        sqlx::query_scalar("SELECT granular_locked FROM teams WHERE id = $1")
            .bind(team)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_repeat_downgrade_reconcile_is_silent() {
        let _mode = BillingMode::hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "teams").await;
        let team = seed_team_with_roles(&pool, owner).await;
        member_with_role(&pool, team, PERM_CONNECT).await;
        let notifier = SyncNotifier::new();
        reconcile_team_plan(&pool, &notifier, team).await.unwrap();
        let mut rx = notifier.subscribe();
        reconcile_team_plan(&pool, &notifier, team).await.unwrap();
        assert!(rx.try_recv().is_err());
        assert!(stored_lock(&pool, team).await);
    }

    #[tokio::test]
    async fn upgrade_clears_the_lock_and_tells_members_to_refetch_keys() {
        let _mode = BillingMode::hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "teams").await;
        let team = seed_team_with_roles(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_VIEW | PERM_CONNECT).await;
        let notifier = SyncNotifier::new();
        reconcile_team_plan(&pool, &notifier, team).await.unwrap();
        set_user_tier(&pool, owner, "business").await;
        let mut rx = notifier.subscribe();
        reconcile_team_plan(&pool, &notifier, team).await.unwrap();
        assert!(!stored_lock(&pool, team).await);
        let mut key_changed = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let SyncEvent::VaultKeyChanged { user_id } = ev {
                key_changed.push(user_id);
            }
        }
        assert!(key_changed.contains(&member));
    }

    #[tokio::test]
    async fn self_hosted_reconcile_leaves_teams_untouched() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        sqlx::query("UPDATE teams SET granular_locked = TRUE WHERE id = $1")
            .bind(team)
            .execute(&pool)
            .await
            .unwrap();
        reconcile_all_teams(&pool, &SyncNotifier::new()).await;
        assert!(stored_lock(&pool, team).await);
    }
}
