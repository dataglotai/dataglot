//! Ctrl-C handling for `dataglot query` and `dataglot shell`.
//!
//! Once [`CtrlC::listen`] runs, Ctrl-C no longer kills the process. Each
//! press bumps a counter instead, and the CLI decides what it means: cancel
//! the running statement, throw away a half-typed one, or exit with 130.
//! Without a handler a Ctrl-C would also leave a query running on the
//! server, since nothing would send it a cancel request.

use tokio::sync::watch;

/// Exit code for a run that was stopped with Ctrl-C, as in psql and most
/// shells (128 + SIGINT).
pub const INTERRUPTED: u8 = 130;

/// Counts Ctrl-C presses. Cheap to clone; every clone sees the same count.
#[derive(Clone)]
pub struct CtrlC {
    presses: watch::Receiver<u64>,
}

impl CtrlC {
    /// Take over Ctrl-C for the rest of the process.
    ///
    /// Only call this once nothing blocks on the terminal any more: after
    /// the handler is installed a Ctrl-C can't interrupt a blocking read.
    #[must_use]
    pub fn listen() -> Self {
        let (tx, presses) = watch::channel(0);
        tokio::spawn(async move {
            let mut count = 0;
            while tokio::signal::ctrl_c().await.is_ok() {
                count += 1;
                if tx.send(count).is_err() {
                    break;
                }
            }
        });
        Self { presses }
    }

    /// A `CtrlC` that never fires, for callers that don't handle Ctrl-C.
    #[must_use]
    pub fn never() -> Self {
        let (_, presses) = watch::channel(0);
        Self { presses }
    }

    /// Presses so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        *self.presses.borrow()
    }

    /// Resolve once more than `seen` presses have happened. Pending forever
    /// for [`Self::never`].
    pub async fn after(&self, seen: u64) {
        let mut presses = self.presses.clone();
        if presses.wait_for(|count| *count > seen).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// A `CtrlC` the test presses through the returned sender.
    #[cfg(test)]
    pub(crate) fn manual() -> (watch::Sender<u64>, Self) {
        let (tx, presses) = watch::channel(0);
        (tx, Self { presses })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn after_waits_for_a_press_past_seen() {
        let (tx, ctrl_c) = CtrlC::manual();
        assert_eq!(ctrl_c.count(), 0);
        let waiting = tokio::spawn({
            let ctrl_c = ctrl_c.clone();
            async move { ctrl_c.after(0).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "no press yet");
        tx.send(1).expect("send");
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("resolves after a press")
            .expect("task");
        assert_eq!(ctrl_c.count(), 1);
        // A press that already happened counts.
        tokio::time::timeout(Duration::from_secs(1), ctrl_c.after(0))
            .await
            .expect("already past 0");
    }

    #[tokio::test]
    async fn never_never_fires() {
        let ctrl_c = CtrlC::never();
        assert_eq!(ctrl_c.count(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), ctrl_c.after(0))
                .await
                .is_err()
        );
    }
}
