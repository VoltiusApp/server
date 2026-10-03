use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use sqlx::PgPool;
use tracing::{error, warn};
use uuid::Uuid;

use crate::object_authz::{db_error, holds_vault_key_gate, live_rule_set_ids, member_contexts, rule_entries};
use crate::routes::teams::{notify_team_members_changed, request_team_rotation};
use crate::sync_notifier::SyncNotifier;

// A member holds the current epoch's key once they fetched their wrap or wrapped one for someone.
const CURRENT_KEY_HOLDERS: &str = r#"
    WITH cur AS (
        SELECT t.id AS team_id, COALESCE(MAX(e.key_version), 1) AS epoch
        FROM teams t LEFT JOIN team_key_epochs e ON e.team_id = t.id
        WHERE $1::uuid IS NULL OR t.id = $1
        GROUP BY t.id
    )
    SELECT DISTINCT cur.team_id, h.user_id
    FROM cur
    JOIN team_vault_keys k ON k.team_id = cur.team_id AND k.key_version = cur.epoch
    CROSS JOIN LATERAL (VALUES (CASE WHEN k.fetched_at IS NOT NULL THEN k.user_id END), (k.wrapped_by)) h(user_id)
    WHERE h.user_id IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM team_rotation_requests r
                      WHERE r.team_id = cur.team_id AND r.requested_at_epoch >= cur.epoch)
"#;

pub async fn queue_exposed_key_rotations(pool: &PgPool, notifier: &SyncNotifier, only: Option<Uuid>) {
    let rows = match sqlx::query_as::<_, (Uuid, Uuid)>(CURRENT_KEY_HOLDERS).bind(only).fetch_all(pool).await {
        Ok(rows) => rows,
        Err(e) => return error!(error = %e, "Failed to list team vault key holders"),
    };
    let mut holders: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
    for (team_id, user_id) in rows {
        holders.entry(team_id).or_default().insert(user_id);
    }
    for (team_id, holders) in holders {
        match rotate_if_exposed(pool, team_id, &holders).await {
            Ok(true) => {
                warn!(team_id = %team_id, "A member holding the team vault key lost access; rotation queued");
                notify_team_members_changed(pool, notifier, team_id).await;
            }
            Ok(false) => {}
            Err(status) => error!(team_id = %team_id, %status, "Team vault key exposure check failed"),
        }
    }
}

async fn rotate_if_exposed(pool: &PgPool, team_id: Uuid, holders: &HashSet<Uuid>) -> Result<bool, StatusCode> {
    let entries = rule_entries(pool, team_id, None).await?;
    let live = live_rule_set_ids(pool, team_id).await?;
    let exposed = member_contexts(pool, team_id, None)
        .await?
        .into_iter()
        .filter(|m| holders.contains(&m.user_id))
        .any(|m| !holds_vault_key_gate(m, entries.clone(), &live));
    if exposed {
        let mut conn = pool.acquire().await.map_err(|e| db_error(e, "acquire for rotation request"))?;
        request_team_rotation(&mut conn, team_id).await?;
    }
    Ok(exposed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{PERM_CONNECT, PERM_VIEW};
    use crate::test_support::*;

    async fn sweep(pool: &PgPool, team: Uuid) -> i64 {
        queue_exposed_key_rotations(pool, &SyncNotifier::new(), Some(team)).await;
        rotation_request_count(pool, team).await
    }

    async fn team_with_member(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
        let owner = seed_user(pool).await;
        let team = seed_team_with_roles(pool, owner).await;
        let member = seed_user(pool).await;
        add_member(pool, team, member).await;
        (team, owner, member)
    }

    #[tokio::test]
    async fn a_member_who_fetched_the_key_and_lost_the_gate_queues_one_rotation() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let (team, owner, member) = team_with_member(&pool).await;
        seed_vault_key(&pool, team, member, owner, 1, true).await;

        assert_eq!(sweep(&pool, team).await, 1);
        assert_eq!(sweep(&pool, team).await, 1);
    }

    #[tokio::test]
    async fn a_wrap_the_member_never_fetched_does_not_rotate() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let (team, owner, member) = team_with_member(&pool).await;
        seed_vault_key(&pool, team, member, owner, 1, false).await;

        assert_eq!(sweep(&pool, team).await, 0);
    }

    #[tokio::test]
    async fn wrapping_the_key_for_someone_counts_as_holding_it() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let (team, owner, member) = team_with_member(&pool).await;
        seed_vault_key(&pool, team, owner, member, 1, false).await;

        assert_eq!(sweep(&pool, team).await, 1);
    }

    #[tokio::test]
    async fn a_holder_who_still_passes_the_gate_does_not_rotate() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT).await;
        seed_vault_key(&pool, team, member, owner, 1, true).await;
        seed_vault_key(&pool, team, owner, owner, 1, true).await;

        assert_eq!(sweep(&pool, team).await, 0);
    }

    #[tokio::test]
    async fn a_rule_set_edit_that_drops_the_only_granted_host_rotates() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        let member = member_with_role(&pool, team, 0).await;
        seed_vault_key(&pool, team, member, owner, 1, true).await;
        seed_team_object(&pool, team, owner, "host-1", "connection").await;
        let grant = seed_rule_set(&pool, team, owner, &[("member", Some(member), PERM_CONNECT | PERM_VIEW, 0)]).await;
        point_object(&pool, team, "host-1", Some(grant)).await;
        assert_eq!(sweep(&pool, team).await, 0);

        sqlx::query("UPDATE team_rule_set_entries SET allow_mask = $2 WHERE rule_set_id = $1")
            .bind(grant)
            .bind(PERM_VIEW)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(sweep(&pool, team).await, 1);
    }

    #[tokio::test]
    async fn a_role_edit_that_drops_view_rotates() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT).await;
        seed_vault_key(&pool, team, member, owner, 1, true).await;
        assert_eq!(sweep(&pool, team).await, 0);

        sqlx::query(
            "UPDATE team_roles SET permissions = $2 WHERE team_id = $1 AND id IN \
             (SELECT role_id FROM team_member_roles WHERE team_id = $1 AND user_id = $3)",
        )
        .bind(team)
        .bind(PERM_CONNECT)
        .bind(member)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(sweep(&pool, team).await, 1);
    }

    #[tokio::test]
    async fn a_holder_of_only_an_older_epoch_does_not_rotate() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let (team, owner, member) = team_with_member(&pool).await;
        seed_vault_key(&pool, team, member, owner, 1, true).await;
        sqlx::query("INSERT INTO team_key_epochs (team_id, key_version, created_by) VALUES ($1, 2, $2)")
            .bind(team)
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        seed_vault_key(&pool, team, member, owner, 2, false).await;
        seed_vault_key(&pool, team, owner, owner, 2, true).await;

        assert_eq!(sweep(&pool, team).await, 0);
    }

    #[tokio::test]
    async fn a_plan_lapse_rotates_out_a_member_whose_gate_came_from_a_custom_role() {
        let _mode = BillingMode::hosted();
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        set_user_tier(&pool, owner, "teams").await;
        let team = seed_team_with_roles(&pool, owner).await;
        let member = member_with_role(&pool, team, PERM_CONNECT).await;
        seed_vault_key(&pool, team, member, owner, 1, true).await;

        assert_eq!(sweep(&pool, team).await, 1);
    }

    #[tokio::test]
    async fn queuing_a_rotation_tells_the_team() {
        let _mode = BillingMode::self_hosted();
        let pool = crate::test_pool_or_skip!();
        let (team, owner, member) = team_with_member(&pool).await;
        seed_vault_key(&pool, team, member, owner, 1, true).await;
        let notifier = SyncNotifier::new();
        let mut rx = notifier.subscribe();

        queue_exposed_key_rotations(&pool, &notifier, Some(team)).await;
        assert!(rx.try_recv().is_ok());
    }
}
