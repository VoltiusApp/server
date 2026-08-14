use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum SyncEvent {
    /// Another device pushed a blob for this user.
    BlobPushed { user_id: Uuid, device_id: String },
    /// The user's team membership changed (added to or removed from a team).
    MembershipChanged { user_id: Uuid },
    /// A teammate's online/offline status changed. `recipient` is who should receive it.
    PresenceChanged {
        recipient: Uuid,
        subject: Uuid,
        online: bool,
    },
    /// A teammate started or stopped using a connection (terminal session in a team vault).
    ConnectionUsageChanged {
        recipient: Uuid,
        subject: Uuid,
        connection_id: String,
        in_use: bool,
    },
    /// A team session was shared into a vault this recipient belongs to.
    SessionShared {
        recipient: Uuid,
        session_id: Uuid,
        host_user_id: Uuid,
    },
    /// A team session this recipient could see has ended.
    SessionEnded { recipient: Uuid, session_id: Uuid },
}

#[derive(Clone)]
pub struct SyncNotifier(Arc<Inner>);

struct Inner {
    tx: broadcast::Sender<SyncEvent>,
}

impl SyncNotifier {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(512);
        Self(Arc::new(Inner { tx }))
    }

    pub fn notify(&self, user_id: Uuid, pusher_device_id: String) {
        let _ = self.0.tx.send(SyncEvent::BlobPushed {
            user_id,
            device_id: pusher_device_id,
        });
    }

    pub fn notify_membership_changed(&self, user_id: Uuid) {
        let _ = self.0.tx.send(SyncEvent::MembershipChanged { user_id });
    }

    pub fn notify_presence_changed(&self, recipient: Uuid, subject: Uuid, online: bool) {
        let _ = self.0.tx.send(SyncEvent::PresenceChanged {
            recipient,
            subject,
            online,
        });
    }

    pub fn notify_connection_usage_changed(
        &self,
        recipient: Uuid,
        subject: Uuid,
        connection_id: String,
        in_use: bool,
    ) {
        let _ = self.0.tx.send(SyncEvent::ConnectionUsageChanged {
            recipient,
            subject,
            connection_id,
            in_use,
        });
    }

    pub fn notify_session_shared(&self, recipient: Uuid, session_id: Uuid, host_user_id: Uuid) {
        let _ = self.0.tx.send(SyncEvent::SessionShared {
            recipient,
            session_id,
            host_user_id,
        });
    }

    pub fn notify_session_ended(&self, recipient: Uuid, session_id: Uuid) {
        let _ = self.0.tx.send(SyncEvent::SessionEnded {
            recipient,
            session_id,
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.0.tx.subscribe()
    }
}

pub fn team_vault_notification_payload(team_id: Uuid) -> String {
    format!("team:{}", team_id)
}

/// Runs `make` once per distinct member of the given teams, excluding the actor.
pub async fn notify_team_members(
    pool: &PgPool,
    team_ids: &[Uuid],
    actor_user_id: Uuid,
    mut make: impl FnMut(Uuid),
) {
    let member_ids: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT user_id FROM team_members WHERE team_id = ANY($1) AND user_id != $2",
    )
    .bind(team_ids)
    .bind(actor_user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for member_id in member_ids {
        make(member_id);
    }
}

pub async fn notify_team_vault_changed(
    pool: &PgPool,
    notifier: &SyncNotifier,
    team_id: Uuid,
    actor_user_id: Uuid,
) {
    let payload = team_vault_notification_payload(team_id);
    notify_team_members(pool, &[team_id], actor_user_id, |member_id| {
        notifier.notify(member_id, payload.clone());
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pool_or_skip;
    use crate::test_support::{add_member, seed_team, seed_user};

    #[tokio::test]
    async fn team_member_fanout_excludes_the_actor_and_dedupes_across_teams() {
        let pool = test_pool_or_skip!();
        let host = seed_user(&pool).await;
        let member = seed_user(&pool).await;

        let team_a = seed_team(&pool, host).await;
        let team_b = seed_team(&pool, host).await;
        for team in [team_a, team_b] {
            add_member(&pool, team, host).await;
            add_member(&pool, team, member).await;
        }

        let mut recipients: Vec<Uuid> = Vec::new();
        notify_team_members(&pool, &[team_a, team_b], host, |r| recipients.push(r)).await;

        assert_eq!(
            recipients,
            vec![member],
            "actor excluded, member not duplicated across two teams"
        );
    }
}
