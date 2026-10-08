use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockPolicy {
    pub max_minutes: i32,
    pub force_vault: bool,
}

impl LockPolicy {
    pub fn from_columns(max_minutes: Option<i32>, force_vault: bool) -> Option<Self> {
        max_minutes.map(|max_minutes| Self { max_minutes, force_vault })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthUser;
    use crate::routes::teams::list_teams;
    use crate::test_support::{seed_team_with_roles, seed_user};
    use axum::{extract::State, Extension, Json};
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn listed(pool: &PgPool, team: Uuid, user: Uuid) -> Option<LockPolicy> {
        let Json(teams) = list_teams(State(pool.clone()), Extension(AuthUser(user))).await.unwrap();
        teams.into_iter().find(|t| t.id == team).unwrap().lock_policy
    }

    #[tokio::test]
    async fn list_teams_carries_the_stored_policy() {
        let pool = crate::test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team_with_roles(&pool, owner).await;
        assert_eq!(listed(&pool, team, owner).await, None);

        sqlx::query("UPDATE teams SET lock_max_minutes = 15, lock_force_vault = TRUE WHERE id = $1")
            .bind(team).execute(&pool).await.unwrap();

        assert_eq!(listed(&pool, team, owner).await, Some(LockPolicy { max_minutes: 15, force_vault: true }));
    }
}
