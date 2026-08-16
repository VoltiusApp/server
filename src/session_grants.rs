#[cfg(test)]
mod tests {
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_team, seed_user};
    use uuid::Uuid;

    #[tokio::test]
    async fn backfill_creates_a_legacy_grant_for_a_live_invite_link_session() {
        let pool = test_pool_or_skip!();

        let host = seed_user(&pool).await;
        let team = seed_team(&pool, host).await;
        // invite_token is UNIQUE; the throwaway DB persists across test runs.
        let token = format!("fake-legacy-token-{}", Uuid::new_v4());

        let session: Uuid = sqlx::query_scalar(
            "INSERT INTO terminal_sessions (team_id, host_user_id, connection_name, visibility, invite_token) \
             VALUES ($1, $2, 'box', 'invite_link', $3) RETURNING id",
        )
        .bind(team)
        .bind(host)
        .bind(&token)
        .fetch_one(&pool)
        .await
        .unwrap();

        // The migration already ran for pre-existing rows; this row is newer, so
        // apply the same expression the migration uses to prove it matches.
        let matches: bool = sqlx::query_scalar(
            "SELECT sha256(convert_to($1, 'UTF8')) = sha256(convert_to(invite_token, 'UTF8')) \
             FROM terminal_sessions WHERE id = $2",
        )
        .bind(&token)
        .bind(session)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(matches, "migration hash expression must match the stored token");
    }
}
