use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::permissions::{has_team_permission, PERM_MANAGE_MEMBERS};
use crate::routes::audit::write_audit_event;
use crate::routes::teams::notify_team_members_changed;
use crate::sync_notifier::SyncNotifier;

const MAX_MEMBER_NAME_CHARS: usize = 64;

// Cf category; std has no table for it.
fn is_format_char(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

pub(crate) fn validate_member_name(raw: Option<&str>) -> Result<Option<String>, StatusCode> {
    let Some(name) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if name.chars().count() > MAX_MEMBER_NAME_CHARS
        || name.chars().any(|c| c.is_control() || is_format_char(c))
    {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    Ok(Some(name.to_string()))
}

pub(crate) async fn require_can_name_members(
    pool: &PgPool,
    team_id: Uuid,
    actor: Uuid,
) -> Result<(), StatusCode> {
    if has_team_permission(pool, team_id, actor, PERM_MANAGE_MEMBERS).await? {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[allow(dead_code)]
pub(crate) async fn invite_member_name(
    pool: &PgPool,
    team_id: Uuid,
    actor: Uuid,
    raw: Option<&str>,
) -> Result<Option<String>, StatusCode> {
    let name = validate_member_name(raw)?;
    if name.is_some() {
        require_can_name_members(pool, team_id, actor).await?;
    }
    Ok(name)
}

pub(crate) async fn store_member_name(
    conn: &mut sqlx::PgConnection,
    team_id: Uuid,
    user_id: Uuid,
    name: Option<&str>,
    updated_by: Option<Uuid>,
) -> Result<Option<String>, StatusCode> {
    let db_err = |e: sqlx::Error| {
        error!(error = %e, "Failed to store member name");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT name FROM team_member_names WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_err)?;

    match name {
        Some(name) => sqlx::query(
            "INSERT INTO team_member_names (team_id, user_id, name, updated_by)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (team_id, user_id) DO UPDATE
               SET name = EXCLUDED.name, updated_by = EXCLUDED.updated_by, updated_at = now()",
        )
        .bind(team_id)
        .bind(user_id)
        .bind(name)
        .bind(updated_by),
        None => sqlx::query("DELETE FROM team_member_names WHERE team_id = $1 AND user_id = $2")
            .bind(team_id)
            .bind(user_id),
    }
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;

    Ok(previous)
}

#[derive(Deserialize)]
pub struct SetMemberNameRequest {
    pub name: Option<String>,
}

pub async fn set_member_name(
    State(pool): State<PgPool>,
    Extension(auth): Extension<AuthUser>,
    Extension(notifier): Extension<SyncNotifier>,
    Path((team_id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<SetMemberNameRequest>,
) -> Result<StatusCode, StatusCode> {
    let name = validate_member_name(body.name.as_deref())?;
    require_can_name_members(&pool, team_id, auth.0).await?;

    let target_handle: Option<String> = sqlx::query_scalar(
        "SELECT u.handle FROM team_members tm JOIN users u ON u.id = tm.user_id
         WHERE tm.team_id = $1 AND tm.user_id = $2",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to check member before naming");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let Some(target_handle) = target_handle else {
        return Err(StatusCode::NOT_FOUND);
    };

    let mut conn = pool.acquire().await.map_err(|e| {
        error!(error = %e, "Failed to acquire connection for member name");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let previous = store_member_name(&mut conn, team_id, user_id, name.as_deref(), Some(auth.0)).await?;
    drop(conn);

    if previous != name {
        tokio::spawn(write_audit_event(
            pool.clone(),
            team_id,
            auth.0,
            "member.renamed",
            Some("user"),
            Some(user_id.to_string()),
            Some(target_handle),
            Some(json!({ "old": previous, "new": name })),
        ));
        notify_team_members_changed(&pool, &notifier, team_id).await;
    }
    Ok(StatusCode::NO_CONTENT)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_clears() {
        assert_eq!(validate_member_name(None), Ok(None));
        assert_eq!(validate_member_name(Some("")), Ok(None));
        assert_eq!(validate_member_name(Some("   \t ")), Ok(None));
    }

    #[test]
    fn trims_and_keeps_unicode() {
        assert_eq!(
            validate_member_name(Some("  Jan Novák 🚀 ")),
            Ok(Some("Jan Novák 🚀".to_string()))
        );
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        let sixty_four = "á".repeat(64);
        assert_eq!(validate_member_name(Some(&sixty_four)), Ok(Some(sixty_four.clone())));
        let sixty_five = "á".repeat(65);
        assert_eq!(validate_member_name(Some(&sixty_five)), Err(StatusCode::UNPROCESSABLE_ENTITY));
    }

    #[test]
    fn rejects_control_and_format_characters() {
        for bad in ["Jan\u{0007}", "Jan\nNovak", "\u{202E}kavoN naJ", "Jan\u{200B}", "Jan\u{FEFF}", "Jan\u{2066}x"] {
            assert_eq!(validate_member_name(Some(bad)), Err(StatusCode::UNPROCESSABLE_ENTITY), "{bad:?}");
        }
    }
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::permissions::{PERM_INVITE_MEMBERS, PERM_MANAGE_MEMBERS};
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, member_with_role, seed_team, seed_user};

    async fn stored(pool: &PgPool, team: Uuid, user: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT name FROM team_member_names WHERE team_id = $1 AND user_id = $2")
            .bind(team)
            .bind(user)
            .fetch_optional(pool)
            .await
            .unwrap()
    }

    async fn put(pool: &PgPool, actor: Uuid, team: Uuid, target: Uuid, name: Option<&str>) -> Result<StatusCode, StatusCode> {
        set_member_name(
            State(pool.clone()),
            Extension(AuthUser(actor)),
            Extension(SyncNotifier::new()),
            Path((team, target)),
            Json(SetMemberNameRequest { name: name.map(str::to_string) }),
        )
        .await
    }

    #[tokio::test]
    async fn manager_sets_renames_and_clears() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let target = seed_user(&pool).await;
        add_member(&pool, team, target).await;

        assert_eq!(put(&pool, admin, team, target, Some("Jan Novák")).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(stored(&pool, team, target).await.as_deref(), Some("Jan Novák"));
        assert_eq!(put(&pool, admin, team, target, Some("Jan Nováková")).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(stored(&pool, team, target).await.as_deref(), Some("Jan Nováková"));
        assert_eq!(put(&pool, admin, team, target, Some("  ")).await, Ok(StatusCode::NO_CONTENT));
        assert_eq!(stored(&pool, team, target).await, None);
    }

    #[tokio::test]
    async fn admin_may_name_themselves() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        assert_eq!(put(&pool, admin, team, admin, Some("IT Desk")).await, Ok(StatusCode::NO_CONTENT));
    }

    #[tokio::test]
    async fn invite_only_and_plain_members_are_refused() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let inviter = member_with_role(&pool, team, PERM_INVITE_MEMBERS).await;
        let plain = member_with_role(&pool, team, 0).await;
        let target = seed_user(&pool).await;
        add_member(&pool, team, target).await;

        assert_eq!(put(&pool, inviter, team, target, Some("X")).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(put(&pool, plain, team, target, Some("X")).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(put(&pool, target, team, target, Some("Me")).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(stored(&pool, team, target).await, None);
    }

    #[tokio::test]
    async fn non_member_target_is_not_found() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let stranger = seed_user(&pool).await;
        assert_eq!(put(&pool, admin, team, stranger, Some("X")).await, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rename_writes_one_audit_event_with_old_and_new() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let target = seed_user(&pool).await;
        add_member(&pool, team, target).await;

        put(&pool, admin, team, target, Some("Jan")).await.unwrap();
        put(&pool, admin, team, target, Some("Jan")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT metadata FROM audit_logs WHERE team_id = $1 AND action = 'member.renamed' AND target_id = $2",
        )
        .bind(team)
        .bind(target.to_string())
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1, "an unchanged name must not write a second event");
        assert_eq!(rows[0], serde_json::json!({ "old": null, "new": "Jan" }));
    }
}
