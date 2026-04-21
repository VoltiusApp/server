use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Broadcast (user_id, pusher_device_id) whenever a device uploads a blob.
/// SSE handlers subscribe and forward only their user's events to connected clients.
#[derive(Clone)]
pub struct SyncNotifier(Arc<Inner>);

struct Inner {
    tx: broadcast::Sender<(Uuid, String)>,
}

impl SyncNotifier {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(512);
        Self(Arc::new(Inner { tx }))
    }

    /// Notify all SSE subscribers that `pusher_device_id` uploaded a new blob for `user_id`.
    pub fn notify(&self, user_id: Uuid, pusher_device_id: String) {
        let _ = self.0.tx.send((user_id, pusher_device_id));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(Uuid, String)> {
        self.0.tx.subscribe()
    }
}
