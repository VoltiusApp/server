use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::routes::audit::write_audit_event;
use crate::routes::teams::notify_team_members_changed;
use crate::sync_notifier::SyncNotifier;

// ─── Get invitation details (public — no auth required) ───────────────────────

#[derive(Serialize)]
pub struct InvitationDetails {
    pub team_name: String,
    pub inviter_display_name: String,
    pub role: String,
    pub expires_at: i64,
}

pub async fn get_invitation(
    State(pool): State<PgPool>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<Json<InvitationDetails>, StatusCode> {
    let row = sqlx::query_as::<_, (String, Option<String>, String, chrono::DateTime<chrono::Utc>)>(
        r#"SELECT t.name, u.handle, pi.role, pi.expires_at
           FROM pending_invitations pi
           JOIN teams t ON t.id = pi.team_id
           LEFT JOIN users u ON u.id = pi.invited_by
           WHERE pi.token = $1
             AND pi.accepted_at IS NULL
             AND pi.expires_at > now()"#,
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch invitation");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(InvitationDetails {
        team_name: row.0,
        inviter_display_name: row.1.unwrap_or_else(|| "A teammate".to_string()),
        role: row.2,
        expires_at: row.3.timestamp(),
    }))
}

// ─── Admitting a member ───────────────────────────────────────────────────────

/// The membership row plus its builtin role, written the same way by all three
/// acceptance paths: the link token, the in-app pending invite, and the
/// auto-accept at registration.
///
/// `invited_by` is carried across from the invitation. Leaving it NULL is what
/// made `TeamMember.invited_by_display_name` blank on the roster for every
/// accepted invite. The upsert only fills a NULL, so re-accepting can never
/// rewrite who actually brought a member in.
pub(crate) async fn admit_member(
    conn: &mut sqlx::PgConnection,
    team_id: Uuid,
    user_id: Uuid,
    invited_by: Option<Uuid>,
    role: &str,
) -> Result<(), StatusCode> {
    sqlx::query(
        "INSERT INTO team_members (team_id, user_id, invited_by) VALUES ($1, $2, $3)
         ON CONFLICT (team_id, user_id)
         DO UPDATE SET invited_by = COALESCE(team_members.invited_by, EXCLUDED.invited_by)",
    )
    .bind(team_id)
    .bind(user_id)
    .bind(invited_by)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to add member on invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query(
        r#"INSERT INTO team_member_roles (team_id, user_id, role_id)
           SELECT $1, $2, tr.id FROM team_roles tr
           WHERE tr.team_id = $1 AND tr.name = $3 AND tr.is_builtin = TRUE
           ON CONFLICT DO NOTHING"#,
    )
    .bind(team_id)
    .bind(user_id)
    .bind(role)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to assign role on invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(())
}

// ─── Accept invitation (authed) ───────────────────────────────────────────────

pub async fn accept_invitation(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<StatusCode, StatusCode> {
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, String, Option<Uuid>)>(
        r#"SELECT pi.id, pi.team_id, pi.email, pi.role, pi.invited_by
           FROM pending_invitations pi
           WHERE pi.token = $1
             AND pi.accepted_at IS NULL
             AND pi.expires_at > now()"#,
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch invitation for acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!("Invitation not found or expired: {token}");
        StatusCode::NOT_FOUND
    })?;

    let (invitation_id, team_id, invited_email, role, invited_by) = row;

    let user_email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch accepting user email");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if user_email.to_lowercase() != invited_email.to_lowercase() {
        warn!(
            user_id = %auth.0,
            user_email = %user_email,
            invited_email = %invited_email,
            "Email mismatch on invitation acceptance"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin transaction for invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    admit_member(&mut tx, team_id, auth.0, invited_by, &role).await?;

    // Mark invitation accepted
    sqlx::query("UPDATE pending_invitations SET accepted_at = now() WHERE id = $1")
        .bind(invitation_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to mark invitation accepted");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(user_id = %auth.0, team_id = %team_id, role = %role, "Invitation accepted");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.joined",
        Some("user"),
        Some(auth.0.to_string()),
        Some(user_email.clone()),
        Some(json!({ "role": role, "via": "invitation" })),
    ));
    notifier.notify_membership_changed(auth.0);
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── List my pending invitations (in-app consent flow) ────────────────────────

#[derive(Serialize)]
pub struct MyPendingInvitation {
    pub id: Uuid,
    pub team_id: Uuid,
    pub team_name: String,
    pub inviter_display_name: Option<String>,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_my_pending_invitations(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> Result<Json<Vec<MyPendingInvitation>>, StatusCode> {
    let rows = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>, String, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>(
        r#"SELECT pi.id, pi.team_id, t.name, u.handle, pi.role, pi.created_at, pi.expires_at
           FROM pending_invitations pi
           JOIN teams t ON t.id = pi.team_id
           LEFT JOIN users u ON u.id = pi.invited_by
           WHERE pi.user_id = $1
             AND pi.accepted_at IS NULL
             AND pi.expires_at > now()
           ORDER BY pi.created_at DESC"#,
    )
    .bind(auth.0)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to list pending invitations for user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, team_id, team_name, inviter_display_name, role, created_at, expires_at)| {
                MyPendingInvitation { id, team_id, team_name, inviter_display_name, role, created_at, expires_at }
            })
            .collect(),
    ))
}

// ─── Accept my pending invitation ─────────────────────────────────────────────

pub async fn accept_my_pending_invitation(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(invitation_id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let row = sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(
        r#"SELECT team_id, role, invited_by FROM pending_invitations
           WHERE id = $1 AND user_id = $2
             AND accepted_at IS NULL AND expires_at > now()"#,
    )
    .bind(invitation_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch pending invitation for acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!(invitation_id = %invitation_id, user_id = %auth.0, "Pending invitation not found");
        StatusCode::NOT_FOUND
    })?;

    let (team_id, role, invited_by) = row;

    let mut tx = pool.begin().await.map_err(|e| {
        error!(error = %e, "Failed to begin transaction for invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    admit_member(&mut tx, team_id, auth.0, invited_by, &role).await?;

    sqlx::query("UPDATE pending_invitations SET accepted_at = now() WHERE id = $1")
        .bind(invitation_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to mark invitation accepted");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tx.commit().await.map_err(|e| {
        error!(error = %e, "Failed to commit invitation acceptance");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user_email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
        .bind(auth.0)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();

    info!(user_id = %auth.0, team_id = %team_id, role = %role, "Pending invitation accepted in-app");
    tokio::spawn(write_audit_event(
        pool.clone(),
        team_id,
        auth.0,
        "member.joined",
        Some("user"),
        Some(auth.0.to_string()),
        user_email,
        Some(json!({ "role": role, "via": "in_app_invite" })),
    ));
    notifier.notify_membership_changed(auth.0);
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Decline my pending invitation ────────────────────────────────────────────

pub async fn decline_my_pending_invitation(
    State(pool): State<PgPool>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    axum::Extension(notifier): axum::Extension<SyncNotifier>,
    axum::extract::Path(invitation_id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let team_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT team_id FROM pending_invitations WHERE id = $1 AND user_id = $2 AND accepted_at IS NULL",
    )
    .bind(invitation_id)
    .bind(auth.0)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(error = %e, "Failed to fetch pending invitation for decline");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        warn!(invitation_id = %invitation_id, user_id = %auth.0, "Pending invitation not found for decline");
        StatusCode::NOT_FOUND
    })?;

    sqlx::query("DELETE FROM pending_invitations WHERE id = $1")
        .bind(invitation_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to delete declined invitation");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(user_id = %auth.0, team_id = %team_id, "Pending invitation declined");
    // Notify my own other devices, or they keep offering Accept/Decline for an
    // invitation that no longer exists. Accept gets this via
    // notify_membership_changed; decline changes no membership, so it needs the
    // invitation-scoped event explicitly.
    notifier.notify_pending_invitations_changed(auth.0);
    // Notify team so the inviter's pending list refreshes
    notify_team_members_changed(&pool, &notifier, team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod authz_tests {
    //! Per-user boundary enforcement for the invitation handlers. These handlers
    //! don't gate on team permission bits — they enforce that you can only accept an
    //! invite addressed to *your* email, and only accept/decline/list invitations
    //! bound to *your* user_id. Requires `TEST_DATABASE_URL`; otherwise each skips.
    use super::*;
    use crate::auth::AuthUser;
    use crate::sync_notifier::{SyncEvent, SyncNotifier};
    use crate::test_pool_or_skip;
    use crate::test_support::{
        add_member, seed_invitation, seed_team, seed_user, test_user_email,
    };
    use axum::extract::{Path, State};
    use axum::Extension;

    async fn is_member(pool: &PgPool, team: Uuid, user: Uuid) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)",
        )
        .bind(team)
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn accept_invitation_forbidden_on_email_mismatch() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = seed_user(&pool).await;
        // Invitation addressed to a different email than the caller owns.
        let (_id, token) =
            seed_invitation(&pool, team, "someone-else@test.local", "member", None).await;

        let res = accept_invitation(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(token),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::FORBIDDEN);
        assert!(!is_member(&pool, team, caller).await);
    }

    #[tokio::test]
    async fn accept_invitation_not_found_for_bad_token() {
        let pool = test_pool_or_skip!();
        let caller = seed_user(&pool).await;

        let res = accept_invitation(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path("no-such-token".to_string()),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn accept_invitation_ok_on_email_match() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = seed_user(&pool).await;
        let (_id, token) =
            seed_invitation(&pool, team, &test_user_email(caller), "member", None).await;

        let res = accept_invitation(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(token),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert!(is_member(&pool, team, caller).await);
    }

    #[tokio::test]
    async fn accept_invitation_email_match_is_case_insensitive() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let caller = seed_user(&pool).await;
        // Invite addressed to the caller's email but in a different case — the
        // handler lowercases both sides, so acceptance must still succeed.
        let (_id, token) =
            seed_invitation(&pool, team, &test_user_email(caller).to_uppercase(), "member", None)
                .await;

        let res = accept_invitation(
            State(pool.clone()),
            Extension(AuthUser(caller)),
            Extension(SyncNotifier::new()),
            Path(token),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert!(is_member(&pool, team, caller).await);
    }

    #[tokio::test]
    async fn accept_my_pending_invitation_not_found_for_other_user() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let recipient = seed_user(&pool).await;
        let intruder = seed_user(&pool).await;
        // Invitation bound to `recipient`; `intruder` must not be able to accept it.
        let (invitation_id, _token) =
            seed_invitation(&pool, team, &test_user_email(recipient), "member", Some(recipient))
                .await;

        let res = accept_my_pending_invitation(
            State(pool.clone()),
            Extension(AuthUser(intruder)),
            Extension(SyncNotifier::new()),
            Path(invitation_id),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
        assert!(!is_member(&pool, team, intruder).await);
    }

    #[tokio::test]
    async fn accept_my_pending_invitation_ok_for_owner() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let recipient = seed_user(&pool).await;
        let (invitation_id, _token) =
            seed_invitation(&pool, team, &test_user_email(recipient), "member", Some(recipient))
                .await;

        let res = accept_my_pending_invitation(
            State(pool.clone()),
            Extension(AuthUser(recipient)),
            Extension(SyncNotifier::new()),
            Path(invitation_id),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        assert!(is_member(&pool, team, recipient).await);
    }

    #[tokio::test]
    async fn decline_my_pending_invitation_not_found_for_other_user() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let recipient = seed_user(&pool).await;
        let intruder = seed_user(&pool).await;
        let (invitation_id, _token) =
            seed_invitation(&pool, team, &test_user_email(recipient), "member", Some(recipient))
                .await;

        let res = decline_my_pending_invitation(
            State(pool.clone()),
            Extension(AuthUser(intruder)),
            Extension(SyncNotifier::new()),
            Path(invitation_id),
        )
        .await;

        assert_eq!(res.unwrap_err(), StatusCode::NOT_FOUND);
        // Still present — not deleted by a stranger.
        let still_there = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pending_invitations WHERE id = $1)",
        )
        .bind(invitation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(still_there);
    }

    #[tokio::test]
    async fn decline_my_pending_invitation_ok_for_owner() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let recipient = seed_user(&pool).await;
        let (invitation_id, _token) =
            seed_invitation(&pool, team, &test_user_email(recipient), "member", Some(recipient))
                .await;

        let res = decline_my_pending_invitation(
            State(pool.clone()),
            Extension(AuthUser(recipient)),
            Extension(SyncNotifier::new()),
            Path(invitation_id),
        )
        .await;

        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);
        let gone = sqlx::query_scalar::<_, bool>(
            "SELECT NOT EXISTS(SELECT 1 FROM pending_invitations WHERE id = $1)",
        )
        .bind(invitation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(gone);
    }

    /// A live two-account run caught this: declining on one client left the
    /// invitation sitting in the notification inbox of the decliner's *other*
    /// client, still offering Accept for a row that no longer exists. Accept
    /// reaches those devices through MembershipChanged; decline changes no
    /// membership, so it must send the invitation-scoped event itself.
    #[tokio::test]
    async fn decline_my_pending_invitation_notifies_my_other_devices() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let recipient = seed_user(&pool).await;
        let (invitation_id, _token) =
            seed_invitation(&pool, team, &test_user_email(recipient), "member", Some(recipient))
                .await;

        let notifier = SyncNotifier::new();
        let mut rx = notifier.subscribe();

        let res = decline_my_pending_invitation(
            State(pool.clone()),
            Extension(AuthUser(recipient)),
            Extension(notifier),
            Path(invitation_id),
        )
        .await;
        assert_eq!(res.unwrap(), StatusCode::NO_CONTENT);

        let want = format!("pending_invitations_changed:{recipient}");
        let mut saw = false;
        while let Ok(ev) = rx.try_recv() {
            if let SyncEvent::BlobPushed { user_id, device_id } = ev {
                if user_id == recipient && device_id == want {
                    saw = true;
                    break;
                }
            }
        }
        assert!(saw, "decline must push {want} to the decliner's own devices");
    }

    #[tokio::test]
    async fn list_my_pending_invitations_scoped_to_caller() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let mine = seed_user(&pool).await;
        let other = seed_user(&pool).await;
        add_member(&pool, team, mine).await;
        add_member(&pool, team, other).await;
        let (my_invitation, _t1) =
            seed_invitation(&pool, team, &test_user_email(mine), "member", Some(mine)).await;
        let (_their_invitation, _t2) =
            seed_invitation(&pool, team, &test_user_email(other), "member", Some(other)).await;

        let res = list_my_pending_invitations(State(pool.clone()), Extension(AuthUser(mine)))
            .await
            .unwrap();

        let ids: Vec<Uuid> = res.0.iter().map(|i| i.id).collect();
        assert_eq!(ids, vec![my_invitation]);
    }

    #[tokio::test]
    async fn get_invitation_not_found_for_bad_token() {
        let pool = test_pool_or_skip!();
        let res = get_invitation(State(pool.clone()), Path("no-such-token".to_string())).await;
        // `Json<InvitationDetails>` (the Ok payload) has no Debug impl, so match.
        match res {
            Err(status) => assert_eq!(status, StatusCode::NOT_FOUND),
            Ok(_) => panic!("expected NOT_FOUND, got Ok"),
        }
    }
}

#[cfg(test)]
mod admit_tests {
    //! `invited_by` on the membership row: it is what the roster reads back as
    //! `TeamMember.invited_by_display_name`, and every accept path used to leave
    //! it NULL. Requires `TEST_DATABASE_URL`; otherwise each skips.
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{seed_team, seed_user};

    async fn inviter_of(pool: &PgPool, team: Uuid, user: Uuid) -> Option<Uuid> {
        sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT invited_by FROM team_members WHERE team_id = $1 AND user_id = $2",
        )
        .bind(team)
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("read membership")
    }

    #[tokio::test]
    async fn admitting_records_the_inviter_and_the_roster_can_read_the_handle() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let invitee = seed_user(&pool).await;

        let mut conn = pool.acquire().await.unwrap();
        admit_member(&mut conn, team, invitee, Some(owner), "member")
            .await
            .unwrap();
        drop(conn);

        assert_eq!(inviter_of(&pool, team, invitee).await, Some(owner));

        // The join the roster query performs — a NULL here is exactly what made
        // `invited_by_display_name` blank on an accepted invite.
        let handle: Option<String> = sqlx::query_scalar(
            "SELECT inv.handle FROM team_members tm
             LEFT JOIN users inv ON inv.id = tm.invited_by
             WHERE tm.team_id = $1 AND tm.user_id = $2",
        )
        .bind(team)
        .bind(invitee)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(handle.is_some(), "the roster must resolve the inviter");
    }

    #[tokio::test]
    async fn re_admitting_backfills_a_null_but_never_rewrites_a_known_inviter() {
        let pool = test_pool_or_skip!();
        let owner = seed_user(&pool).await;
        let other = seed_user(&pool).await;
        let team = seed_team(&pool, owner).await;
        let invitee = seed_user(&pool).await;

        let mut conn = pool.acquire().await.unwrap();
        // A link-only invite carries no inviter; a later accept fills it in.
        admit_member(&mut conn, team, invitee, None, "member")
            .await
            .unwrap();
        assert_eq!(inviter_of(&pool, team, invitee).await, None);

        admit_member(&mut conn, team, invitee, Some(owner), "member")
            .await
            .unwrap();
        assert_eq!(inviter_of(&pool, team, invitee).await, Some(owner));

        // …and a second invitation cannot claim credit for a member already in.
        admit_member(&mut conn, team, invitee, Some(other), "member")
            .await
            .unwrap();
        assert_eq!(inviter_of(&pool, team, invitee).await, Some(owner));
    }
}
