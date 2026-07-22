use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::sync_notifier::SyncNotifier;
use crate::UsageMap;

#[derive(Debug, Deserialize)]
pub struct ConnectionUsageRequest {
    pub connection_id: String,
    pub in_use: bool,
}

#[derive(Debug, Serialize)]
pub struct ConnectionUsageEntry {
    pub connection_id: String,
    pub user_ids: Vec<Uuid>,
}

/// Returns the user IDs of teammates currently broadcasting "in use" for connections
/// the caller has access to.
pub async fn get_connection_usage(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(usage_map): Extension<UsageMap>,
) -> Result<Json<Vec<ConnectionUsageEntry>>, StatusCode> {
    // Connections the caller can see (their own teams' team-vault connections).
    let accessible: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT tvo.object_id
           FROM team_vault_objects tvo
           JOIN team_members tm ON tm.team_id = tvo.team_id
           WHERE tm.user_id = $1
             AND tvo.object_type = 'connection'
             AND tvo.deleted_at IS NULL"#,
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to list accessible connections for presence snapshot");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if accessible.is_empty() {
        return Ok(Json(Vec::new()));
    }

    let accessible_set: std::collections::HashSet<&str> =
        accessible.iter().map(String::as_str).collect();

    // Teammates of the caller (across any shared team).
    let teammates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT tm2.user_id \
         FROM team_members tm1 \
         JOIN team_members tm2 ON tm1.team_id = tm2.team_id \
         WHERE tm1.user_id = $1 AND tm2.user_id != $1",
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to list teammates for presence snapshot");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Build connection_id -> [user_ids] by intersecting each teammate's usage set
    // with the accessible-connections set.
    let mut grouped: HashMap<String, Vec<Uuid>> = HashMap::new();
    for teammate in teammates {
        if let Some(entry) = usage_map.get(&teammate) {
            for conn_id in entry.value().iter() {
                if accessible_set.contains(conn_id.as_str()) {
                    grouped
                        .entry(conn_id.clone())
                        .or_default()
                        .push(teammate);
                }
            }
        }
    }

    let response: Vec<ConnectionUsageEntry> = grouped
        .into_iter()
        .map(|(connection_id, user_ids)| ConnectionUsageEntry {
            connection_id,
            user_ids,
        })
        .collect();

    Ok(Json(response))
}

/// Caller announces they started or stopped using a connection.
/// Server validates the caller has access to the connection, mutates UsageMap,
/// and fans out a ConnectionUsageChanged event to teammates with access.
pub async fn post_connection_usage(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(usage_map): Extension<UsageMap>,
    Extension(notifier): Extension<SyncNotifier>,
    Json(body): Json<ConnectionUsageRequest>,
) -> Result<StatusCode, StatusCode> {
    // Find all teams that own this connection. If empty, this isn't a team-vault
    // connection (or doesn't exist) — reject. The caller must be a member of at
    // least one of those teams.
    let owning_teams: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT DISTINCT team_id
           FROM team_vault_objects
           WHERE object_id = $1
             AND object_type = 'connection'
             AND deleted_at IS NULL"#,
    )
    .bind(&body.connection_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, connection_id = %body.connection_id, "Failed to look up connection owning teams");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if owning_teams.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Verify the caller is a member of at least one owning team.
    let caller_is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM team_members WHERE user_id = $1 AND team_id = ANY($2))",
    )
    .bind(auth.0)
    .bind(&owning_teams)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to check team membership for usage broadcast");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !caller_is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    // Mutate the in-memory map. If the resulting set is empty, drop the entry.
    if body.in_use {
        usage_map
            .entry(auth.0)
            .or_default()
            .insert(body.connection_id.clone());
    } else {
        let mut should_remove = false;
        if let Some(entry) = usage_map.get(&auth.0) {
            entry.value().remove(&body.connection_id);
            should_remove = entry.value().is_empty();
        }
        if should_remove {
            usage_map.remove(&auth.0);
        }
    }

    // Fan out to teammates that share at least one owning team (and aren't the caller).
    let recipients: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_id FROM team_members WHERE team_id = ANY($1) AND user_id != $2",
    )
    .bind(&owning_teams)
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, user_id = %auth.0, "Failed to list usage fan-out recipients");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    for recipient in recipients {
        notifier.notify_connection_usage_changed(
            recipient,
            auth.0,
            body.connection_id.clone(),
            body.in_use,
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod authz_tests {
    use super::*;
    use crate::auth::AuthUser;
    use crate::sync_notifier::SyncNotifier;
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, seed_team, seed_team_object, seed_user};
    use crate::UsageMap;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::{Extension, Json};
    use dashmap::DashMap;
    use std::sync::Arc;

    fn empty_usage() -> UsageMap {
        Arc::new(DashMap::new())
    }

    #[tokio::test]
    async fn post_usage_not_found_for_unknown_connection() {
        let pool = test_pool_or_skip!();
        let user = seed_user(&pool).await;

        let res = post_connection_usage(
            State(pool.clone()),
            Extension(AuthUser(user)),
            Extension(empty_usage()),
            Extension(SyncNotifier::new()),
            Json(ConnectionUsageRequest { connection_id: "ghost".into(), in_use: true }),
        ).await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn post_usage_forbidden_for_non_member() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        seed_team_object(&pool, team, owner, "conn-1", "connection").await;
        let outsider = seed_user(&pool).await; // not a member of `team`

        let res = post_connection_usage(
            State(pool.clone()),
            Extension(AuthUser(outsider)),
            Extension(empty_usage()),
            Extension(SyncNotifier::new()),
            Json(ConnectionUsageRequest { connection_id: "conn-1".into(), in_use: true }),
        ).await;

        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_usage_member_sets_and_clears_usage_map() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        seed_team_object(&pool, team, owner, "conn-2", "connection").await;
        let member = seed_user(&pool).await;
        add_member(&pool, team, member).await;
        let usage = empty_usage();

        let set = post_connection_usage(
            State(pool.clone()),
            Extension(AuthUser(member)),
            Extension(usage.clone()),
            Extension(SyncNotifier::new()),
            Json(ConnectionUsageRequest { connection_id: "conn-2".into(), in_use: true }),
        ).await.unwrap();
        assert_eq!(set, StatusCode::NO_CONTENT);
        assert!(usage.get(&member).map(|e| e.value().contains("conn-2")).unwrap_or(false));

        // in_use=false removes the entry (and drops the now-empty set).
        post_connection_usage(
            State(pool.clone()),
            Extension(AuthUser(member)),
            Extension(usage.clone()),
            Extension(SyncNotifier::new()),
            Json(ConnectionUsageRequest { connection_id: "conn-2".into(), in_use: false }),
        ).await.unwrap();
        assert!(usage.get(&member).is_none());
    }

    #[tokio::test]
    async fn get_usage_empty_when_no_accessible_connections() {
        let pool = test_pool_or_skip!();
        let lonely = seed_user(&pool).await; // in no team

        let res = get_connection_usage(
            State(pool.clone()),
            Extension(AuthUser(lonely)),
            Extension(empty_usage()),
        ).await.unwrap().0;

        assert!(res.is_empty());
    }

    #[tokio::test]
    async fn get_usage_reports_teammate_on_accessible_connection() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        seed_team_object(&pool, team, owner, "conn-3", "connection").await;
        let me = seed_user(&pool).await;
        let mate = seed_user(&pool).await;
        add_member(&pool, team, me).await;
        add_member(&pool, team, mate).await;

        // Teammate is broadcasting conn-3; I am NOT (self must be excluded).
        let usage: UsageMap = Arc::new(DashMap::new());
        usage.entry(mate).or_default().insert("conn-3".to_string());
        usage.entry(me).or_default().insert("conn-3".to_string());
        // An inaccessible connection the teammate also broadcasts must be filtered out.
        usage.entry(mate).or_default().insert("conn-not-mine".to_string());

        let res = get_connection_usage(
            State(pool.clone()),
            Extension(AuthUser(me)),
            Extension(usage),
        ).await.unwrap().0;

        assert_eq!(res.len(), 1, "only conn-3 is accessible");
        assert_eq!(res[0].connection_id, "conn-3");
        assert_eq!(res[0].user_ids, vec![mate], "self excluded, only teammate listed");
    }
}
