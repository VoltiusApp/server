use axum::http::StatusCode;
use sqlx::{PgExecutor, PgPool};
use tracing::{error, warn};
use uuid::Uuid;

use crate::permissions::effective_permissions;

/// What a role carries, or what a member may hand out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authority {
    pub permissions: i64,
    pub owner: bool,
}

impl Authority {
    pub const OWNER: Self = Self { permissions: 0, owner: true };

    pub const fn role(permissions: i64) -> Self {
        Self { permissions, owner: false }
    }

    /// Granting or revoking `other` needs every bit it carries, and the Owner role needs an Owner.
    /// Raw bits on purpose: one inert alone can come alive beside another role the target holds.
    pub fn covers(self, other: Authority) -> bool {
        self.owner || (!other.owner && other.permissions & !self.permissions == 0)
    }
}

pub async fn holds_owner_role<'e>(
    executor: impl PgExecutor<'e>,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<bool, StatusCode> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS( \
             SELECT 1 FROM team_member_roles tmr \
             JOIN team_roles tr ON tr.id = tmr.role_id \
             WHERE tmr.team_id = $1 AND tmr.user_id = $2 \
               AND tr.is_builtin AND tr.name = 'owner')",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_one(executor)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, user_id = %user_id, "Failed to check owner role");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

pub async fn member_authority(pool: &PgPool, team_id: Uuid, user_id: Uuid) -> Result<Authority, StatusCode> {
    Ok(Authority {
        permissions: effective_permissions(pool, team_id, user_id).await?,
        owner: holds_owner_role(pool, team_id, user_id).await?,
    })
}

pub struct TeamRoleAuthority {
    pub authority: Authority,
    pub is_builtin: bool,
}

pub async fn role_authority(pool: &PgPool, team_id: Uuid, role_id: Uuid) -> Result<TeamRoleAuthority, StatusCode> {
    role_lookup(pool, team_id, Some(role_id), None).await
}

async fn builtin_role_authority(pool: &PgPool, team_id: Uuid, name: &str) -> Result<TeamRoleAuthority, StatusCode> {
    role_lookup(pool, team_id, None, Some(name)).await.map_err(|status| match status {
        StatusCode::NOT_FOUND => StatusCode::BAD_REQUEST,
        other => other,
    })
}

async fn role_lookup(
    pool: &PgPool,
    team_id: Uuid,
    role_id: Option<Uuid>,
    builtin_name: Option<&str>,
) -> Result<TeamRoleAuthority, StatusCode> {
    let (permissions, is_builtin, owner) = sqlx::query_as::<_, (i64, bool, bool)>(
        "SELECT permissions, is_builtin, is_builtin AND name = 'owner' FROM team_roles \
         WHERE team_id = $1 AND (id = $2 OR ($2 IS NULL AND is_builtin AND name = $3))",
    )
    .bind(team_id)
    .bind(role_id)
    .bind(builtin_name)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!(error = %e, team_id = %team_id, "Failed to read role");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;
    Ok(TeamRoleAuthority { authority: Authority { permissions, owner }, is_builtin })
}

pub async fn require_covers(pool: &PgPool, team_id: Uuid, actor: Uuid, target: Authority) -> Result<(), StatusCode> {
    let held = member_authority(pool, team_id, actor).await?;
    if held.covers(target) {
        return Ok(());
    }
    warn!(team_id = %team_id, actor = %actor, ?held, ?target, "Refused to confer authority the actor does not hold");
    Err(StatusCode::FORBIDDEN)
}

/// Gate for every path that admits someone under a builtin role by name: 400 for an unknown name.
pub async fn require_may_confer_builtin(pool: &PgPool, team_id: Uuid, actor: Uuid, name: &str) -> Result<(), StatusCode> {
    let role = builtin_role_authority(pool, team_id, name).await?;
    require_covers(pool, team_id, actor, role.authority).await
}

/// Locks the team row and returns its billing owner; every ownership change runs under this lock.
pub async fn lock_billing_owner(conn: &mut sqlx::PgConnection, team_id: Uuid) -> Result<Uuid, StatusCode> {
    sqlx::query_scalar::<_, Uuid>("SELECT owner_id FROM teams WHERE id = $1 FOR UPDATE")
        .bind(team_id)
        .fetch_optional(conn)
        .await
        .map_err(|e| {
            error!(error = %e, team_id = %team_id, "Failed to lock team");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{with_dependencies, ALL_PERMISSIONS, BUILTIN_ROLES, PERM_ADMINISTRATOR, PERM_CONNECT, PERM_VIEW_SECRETS};

    fn builtin(name: &str) -> Authority {
        let (_, permissions, _) = BUILTIN_ROLES.iter().find(|(n, _, _)| *n == name).unwrap();
        Authority { permissions: with_dependencies(*permissions), owner: name == "owner" }
    }

    #[test]
    fn only_an_owner_covers_the_owner_role() {
        let owner_role = builtin("owner");
        assert!(builtin("owner").covers(owner_role));
        let all_bits_non_owner = Authority { permissions: ALL_PERMISSIONS, owner: false };
        assert!(!all_bits_non_owner.covers(owner_role));
        for name in ["manager", "editor", "member", "connect-only"] {
            assert!(!builtin(name).covers(owner_role), "{name}");
        }
    }

    #[test]
    fn builtin_roles_cover_exactly_the_roles_at_or_below_them() {
        let ranked = ["owner", "manager", "editor", "member", "connect-only"];
        for (i, actor) in ranked.iter().enumerate() {
            for (j, target) in ranked.iter().enumerate() {
                assert_eq!(builtin(actor).covers(builtin(target)), i <= j, "{actor} over {target}");
            }
        }
    }

    fn sample_masks() -> impl Iterator<Item = i64> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..400).map(move |_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x as i64) & ALL_PERMISSIONS
        })
    }

    #[test]
    fn covers_is_reflexive_and_transitive_over_held_authority() {
        let held: Vec<Authority> = sample_masks()
            .zip([false, true].into_iter().cycle())
            .map(|(p, owner)| Authority { permissions: with_dependencies(p), owner })
            .collect();
        for a in &held {
            assert!(a.covers(*a));
        }
        for a in held.iter().take(60) {
            for b in held.iter().take(60) {
                for c in held.iter().take(60) {
                    if a.covers(*b) && b.covers(*c) {
                        assert!(a.covers(*c), "{a:?} {b:?} {c:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn covers_never_lets_a_bit_through_that_the_actor_lacks() {
        for actor in sample_masks() {
            for bit in 0..=18 {
                let p = 1i64 << bit;
                let held = Authority { permissions: with_dependencies(actor), owner: false };
                assert_eq!(held.covers(Authority::role(p)), held.permissions & p != 0, "{actor:#x} bit {bit}");
            }
        }
    }

    #[test]
    fn an_administrator_custom_role_cannot_be_handed_out_by_a_manager() {
        assert!(!builtin("manager").covers(Authority::role(PERM_ADMINISTRATOR)));
        assert!(!builtin("manager").covers(Authority::role(ALL_PERMISSIONS)));
    }

    #[test]
    fn a_secret_bit_inert_alone_still_needs_cover() {
        assert!(!Authority::role(PERM_CONNECT).covers(Authority::role(PERM_VIEW_SECRETS)));
    }
}
