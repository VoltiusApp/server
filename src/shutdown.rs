use std::future::Future;
use std::time::Duration;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tokio_util::task::{task_tracker::TrackedFuture, TaskTracker};
use tracing::{error, info, warn};

#[derive(Clone, Default)]
pub struct Drain {
    token: CancellationToken,
    sockets: TaskTracker,
}

impl Drain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stopping(&self) -> WaitForCancellationFutureOwned {
        self.token.clone().cancelled_owned()
    }

    // Upgraded sockets leave hyper's connection tracking, so they are waited on here.
    pub fn track<F: Future>(&self, socket: F) -> TrackedFuture<F> {
        self.sockets.track_future(socket)
    }

    pub fn begin(&self) {
        self.token.cancel();
    }

    pub async fn serve(self, server: impl Future<Output = std::io::Result<()>>, grace: Duration) {
        tokio::spawn({
            let drain = self.clone();
            async move {
                stop_signal().await;
                info!(
                    grace_secs = grace.as_secs(),
                    "Stop signal received, draining connections"
                );
                drain.begin();
            }
        });

        let drained = async {
            if let Err(error) = server.await {
                error!(%error, "Server exited with an error");
            }
            self.begin();
            self.sockets.close();
            self.sockets.wait().await;
        };
        let deadline = async {
            self.token.cancelled().await;
            tokio::time::sleep(grace).await;
        };
        tokio::select! {
            () = drained => info!("Server drained"),
            () = deadline => warn!(open_sockets = self.sockets.len(), "Drain deadline reached, exiting"),
        }
    }
}

async fn stop_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(error) => {
                error!(%error, "Could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waits_for_tracked_sockets_once_the_server_returns() {
        let drain = Drain::new();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let socket = tokio::spawn(drain.track(async move {
            let _ = released.await;
        }));
        let serving = tokio::spawn(
            drain
                .clone()
                .serve(async { Ok(()) }, Duration::from_secs(30)),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!serving.is_finished(), "must wait for the open socket");
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .unwrap()
            .unwrap();
        socket.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_on_stuck_sockets_after_the_grace_period() {
        let drain = Drain::new();
        let _stuck = tokio::spawn(drain.track(std::future::pending::<()>()));
        let mut serving = tokio::spawn(
            drain
                .clone()
                .serve(async { Ok(()) }, Duration::from_secs(8)),
        );

        assert!(tokio::time::timeout(Duration::from_secs(7), &mut serving)
            .await
            .is_err());
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn stopping_resolves_when_the_drain_begins() {
        let drain = Drain::new();
        let stopping = drain.stopping();
        drain.begin();
        tokio::time::timeout(Duration::from_secs(1), stopping)
            .await
            .unwrap();
    }
}
