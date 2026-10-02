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
use crate::permissions::PERM_MANAGE_MEMBERS;
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
    crate::permissions::require_all_team_permissions(pool, team_id, actor, &[PERM_MANAGE_MEMBERS]).await
}

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

    let db_err = |e: sqlx::Error| {
        error!(error = %e, "Failed to store member name");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let mut tx = pool.begin().await.map_err(db_err)?;
    let target_handle: Option<String> = sqlx::query_scalar(
        "SELECT u.handle FROM team_members tm JOIN users u ON u.id = tm.user_id
         WHERE tm.team_id = $1 AND tm.user_id = $2 FOR UPDATE OF tm",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(target_handle) = target_handle else {
        return Err(StatusCode::NOT_FOUND);
    };

    let previous = store_member_name(&mut tx, team_id, user_id, name.as_deref(), Some(auth.0)).await?;
    tx.commit().await.map_err(db_err)?;

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

    use crate::routes::teams::{add_member as add_member_route, invite_member, AddMemberRequest, InviteMemberRequest};
    use crate::test_support::{seed_builtin_roles, set_user_tier};

    async fn invite_email(pool: &PgPool, actor: Uuid, team: Uuid, email: &str, name: Option<&str>) -> Result<(), StatusCode> {
        invite_member(
            State(pool.clone()),
            Extension(AuthUser(actor)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(InviteMemberRequest { email: email.into(), role: None, name: name.map(str::to_string) }),
        )
        .await
        .map(|_| ())
    }

    async fn pending_name(pool: &PgPool, team: Uuid, email: &str) -> Option<String> {
        sqlx::query_scalar("SELECT member_name FROM pending_invitations WHERE team_id = $1 AND email = $2")
            .bind(team)
            .bind(email)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn team_for_invites(pool: &PgPool) -> (Uuid, Uuid) {
        let owner = seed_user(pool).await;
        set_user_tier(pool, owner, "business").await;
        let team = seed_team(pool, owner).await;
        seed_builtin_roles(pool, team).await;
        (owner, team)
    }

    #[tokio::test]
    async fn invite_with_name_needs_manage_members() {
        let pool = test_pool_or_skip!();
        let (_, team) = team_for_invites(&pool).await;
        let inviter = member_with_role(&pool, team, PERM_INVITE_MEMBERS).await;
        let email = format!("{}@corp.test", Uuid::new_v4());

        assert_eq!(invite_email(&pool, inviter, team, &email, Some("Jan")).await, Err(StatusCode::FORBIDDEN));
        assert_eq!(invite_email(&pool, inviter, team, &email, None).await, Ok(()));
        assert_eq!(pending_name(&pool, team, &email).await, None);
    }

    #[tokio::test]
    async fn invite_stores_name_and_reinvite_without_name_keeps_it() {
        let pool = test_pool_or_skip!();
        let (_, team) = team_for_invites(&pool).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS | PERM_INVITE_MEMBERS).await;
        let email = format!("{}@corp.test", Uuid::new_v4());

        invite_email(&pool, admin, team, &email, Some("Jan Novák")).await.unwrap();
        assert_eq!(pending_name(&pool, team, &email).await.as_deref(), Some("Jan Novák"));
        invite_email(&pool, admin, team, &email, None).await.unwrap();
        assert_eq!(pending_name(&pool, team, &email).await.as_deref(), Some("Jan Novák"));
        invite_email(&pool, admin, team, &email, Some("Jan N.")).await.unwrap();
        assert_eq!(pending_name(&pool, team, &email).await.as_deref(), Some("Jan N."));
    }

    #[tokio::test]
    async fn add_member_by_id_carries_the_name_into_membership() {
        let pool = test_pool_or_skip!();
        let (_, team) = team_for_invites(&pool).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS | PERM_INVITE_MEMBERS).await;
        let invitee = seed_user(&pool).await;

        let _ = add_member_route(
            State(pool.clone()),
            Extension(AuthUser(admin)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(AddMemberRequest { email: None, user_id: Some(invitee), role: None, name: Some("Eva".into()) }),
        )
        .await
        .expect("invite");

        let id: Uuid = sqlx::query_scalar("SELECT id FROM pending_invitations WHERE team_id = $1 AND user_id = $2")
            .bind(team)
            .bind(invitee)
            .fetch_one(&pool)
            .await
            .unwrap();
        crate::routes::invitations::accept_my_pending_invitation(
            State(pool.clone()),
            Extension(AuthUser(invitee)),
            Extension(SyncNotifier::new()),
            Path(id),
        )
        .await
        .expect("accept");

        assert_eq!(stored(&pool, team, invitee).await.as_deref(), Some("Eva"));
    }

    #[tokio::test]
    async fn rejoin_keeps_old_name_unless_the_invite_names_them() {
        let pool = test_pool_or_skip!();
        let (owner, team) = team_for_invites(&pool).await;
        let user = seed_user(&pool).await;
        let mut conn = pool.acquire().await.unwrap();

        crate::routes::invitations::admit_member(&mut conn, team, user, Some(owner), "member", Some("Jan")).await.unwrap();
        sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team).bind(user).execute(&pool).await.unwrap();
        assert_eq!(stored(&pool, team, user).await.as_deref(), Some("Jan"), "name survives departure");

        crate::routes::invitations::admit_member(&mut conn, team, user, Some(owner), "member", None).await.unwrap();
        assert_eq!(stored(&pool, team, user).await.as_deref(), Some("Jan"));

        crate::routes::invitations::admit_member(&mut conn, team, user, Some(owner), "member", Some("Jan Nováková")).await.unwrap();
        assert_eq!(stored(&pool, team, user).await.as_deref(), Some("Jan Nováková"));
    }

    use crate::PresenceMap;

    #[tokio::test]
    async fn members_list_returns_the_name() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let target = seed_user(&pool).await;
        add_member(&pool, team, target).await;
        put(&pool, admin, team, target, Some("Jan")).await.unwrap();

        let presence: PresenceMap = std::sync::Arc::new(dashmap::DashMap::new());
        let Json(rows) = crate::routes::teams::list_members(
            State(pool.clone()), Extension(AuthUser(admin)), Extension(presence), Path(team),
        )
        .await
        .unwrap();
        let json = serde_json::to_value(&rows).unwrap();
        let row = json.as_array().unwrap().iter().find(|r| r["user_id"] == target.to_string()).unwrap();
        assert_eq!(row["member_name"], "Jan");
        let other = json.as_array().unwrap().iter().find(|r| r["user_id"] == admin.to_string()).unwrap();
        assert!(other["member_name"].is_null());
    }

    #[tokio::test]
    async fn audit_names_an_actor_who_has_left() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS | crate::permissions::PERM_VIEW_AUDIT_LOG).await;
        let leaver = seed_user(&pool).await;
        add_member(&pool, team, leaver).await;
        put(&pool, admin, team, leaver, Some("Ex Employee")).await.unwrap();
        write_audit_event(pool.clone(), team, leaver, "vault.deleted", None, None, None, None).await;
        sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team).bind(leaver).execute(&pool).await.unwrap();

        let name: Option<String> = sqlx::query_scalar(&format!(
            "SELECT {} FROM audit_logs al {} WHERE al.team_id = $1 AND al.actor_id = $2",
            "mn.name", crate::routes::audit::AUDIT_ACTOR_JOINS
        ))
        .bind(team)
        .bind(leaver)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(name.as_deref(), Some("Ex Employee"));
    }

    #[test]
    fn member_names_are_read_only_by_team_scoped_modules() {
        let allowed = [
            "src/main.rs",
            "src/routes/mod.rs",
            "src/routes/member_names.rs",
            "src/routes/teams.rs",
            "src/routes/audit.rs",
            "src/routes/invitations.rs",
            "src/routes/auth.rs",
        ];
        let mut offenders = Vec::new();
        let mut stack = vec![std::path::PathBuf::from("src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    let rel = path.to_string_lossy().replace('\\', "/");
                    if (text.contains("team_member_names") || text.contains("member_name"))
                        && !allowed.contains(&rel.as_str())
                        && rel != "src/models/team.rs"
                    {
                        offenders.push(rel);
                    }
                }
            }
        }
        assert!(offenders.is_empty(), "member names must stay out of session/presence/search code: {offenders:?}");
    }

    #[tokio::test]
    async fn reinvite_without_a_name_does_not_revive_the_first_invites_name() {
        let pool = test_pool_or_skip!();
        let (_, team) = team_for_invites(&pool).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS | PERM_INVITE_MEMBERS).await;
        let user = seed_user(&pool).await;
        let email = crate::test_support::test_user_email(user);

        async fn accept(pool: &PgPool, team: Uuid, email: &str, user: Uuid) {
            let token: String = sqlx::query_scalar("SELECT token FROM pending_invitations WHERE team_id = $1 AND email = $2")
                .bind(team).bind(email).fetch_one(pool).await.unwrap();
            crate::routes::invitations::accept_invitation(
                State(pool.clone()), Extension(AuthUser(user)), Extension(SyncNotifier::new()), Path(token),
            )
            .await
            .expect("accept");
        }

        invite_email(&pool, admin, team, &email, Some("First")).await.unwrap();
        accept(&pool, team, &email, user).await;
        assert_eq!(stored(&pool, team, user).await.as_deref(), Some("First"));
        put(&pool, admin, team, user, Some("Renamed")).await.unwrap();
        sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
            .bind(team).bind(user).execute(&pool).await.unwrap();

        invite_email(&pool, admin, team, &email, None).await.unwrap();
        assert_eq!(pending_name(&pool, team, &email).await, None);
        accept(&pool, team, &email, user).await;
        assert_eq!(stored(&pool, team, user).await.as_deref(), Some("Renamed"));
    }

    #[tokio::test]
    async fn user_search_never_returns_member_names() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS).await;
        let target = seed_user(&pool).await;
        add_member(&pool, team, target).await;
        put(&pool, admin, team, target, Some("Secret Alias")).await.unwrap();
        let handle: String = sqlx::query_scalar("SELECT handle FROM users WHERE id = $1")
            .bind(target).fetch_one(&pool).await.unwrap();

        let found = crate::routes::teams::search_users_inner(&pool, admin, &handle).await.unwrap();
        let json = serde_json::to_value(&found).unwrap();
        let row = json.as_array().unwrap().iter().find(|r| r["user_id"] == target.to_string()).expect("found");
        assert!(row.get("member_name").is_none());
        assert_eq!(row["handle"], handle.as_str());
        assert_eq!(row["display_name"], handle.as_str());
        assert!(!json.to_string().contains("Secret Alias"));
    }

    #[tokio::test]
    async fn invite_audit_carries_the_name_on_every_path() {
        let pool = test_pool_or_skip!();
        let (_, team) = team_for_invites(&pool).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS | PERM_INVITE_MEMBERS).await;
        let existing = seed_user(&pool).await;
        invite_email(&pool, admin, team, &format!("{}@corp.test", Uuid::new_v4()), Some("ByEmail")).await.unwrap();
        invite_email(&pool, admin, team, &crate::test_support::test_user_email(existing), Some("ByKnownEmail")).await.unwrap();
        let by_id = seed_user(&pool).await;
        let _ = add_member_route(
            State(pool.clone()),
            Extension(AuthUser(admin)),
            Extension(SyncNotifier::new()),
            Path(team),
            Json(AddMemberRequest { email: None, user_id: Some(by_id), role: None, name: Some("ById".into()) }),
        )
        .await
        .expect("invite");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let mut names: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT metadata->>'name' FROM audit_logs WHERE team_id = $1 AND action = 'member.invited'",
        )
        .bind(team)
        .fetch_all(&pool)
        .await
        .unwrap();
        names.sort();
        assert_eq!(names, [Some("ByEmail".into()), Some("ById".into()), Some("ByKnownEmail".into())]);
    }

    #[tokio::test]
    async fn pending_list_returns_the_member_name() {
        let pool = test_pool_or_skip!();
        let (_, team) = team_for_invites(&pool).await;
        let admin = member_with_role(&pool, team, PERM_MANAGE_MEMBERS | PERM_INVITE_MEMBERS).await;
        invite_email(&pool, admin, team, &format!("{}@corp.test", Uuid::new_v4()), Some("Pat")).await.unwrap();
        let Json(rows) = crate::routes::teams::list_pending_invitations(State(pool.clone()), Extension(AuthUser(admin)), Path(team))
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(&rows).unwrap()[0]["member_name"], "Pat");
    }
}
