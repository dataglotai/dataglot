//! `BindingChange` event stream + the LISTEN/NOTIFY pump.
//!
//! Spec: the phase-1 `catalog-service` plan (subscribe
//! section) and the phase-1 `catalog-provider-cache` plan
//! (the consumer side).
//!
//! The catalog service emits a `catalog_binding_changed`
//! notification on every INSERT / UPDATE / DELETE against the
//! `catalog_binding` table. The payload is a JSON object with
//! `org_id`, `name`, and `kind` ("upserted" | "deleted"). The
//! Phase 1 task 09 cache subscribes to this stream and evicts
//! by key on every event.
//!
//! # Self-loop
//!
//! `upsert_binding()` writes fire the trigger too, so a single
//! caller's upsert produces a self-loop notification. This is
//! intentional per the spec's "Open questions" decision — the
//! cache rebuild on its own write is the same shape as the
//! cache rebuild from an external write, and skipping it would
//! require correlating event sources across the IPC boundary.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// One `catalog_binding` row change observed via LISTEN/NOTIFY.
///
/// Payload is decoded from the JSON `pg_notify` message emitted
/// by the catalog-service trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingChange {
    /// Org the changed binding belongs to.
    pub org_id: String,
    /// Catalog name whose binding moved.
    pub name: String,
    /// Whether the change was an insert/update or a delete.
    pub kind: BindingChangeKind,
}

/// Distinguishes the two write shapes the trigger emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingChangeKind {
    /// INSERT or UPDATE on the row.
    Upserted,
    /// DELETE on the row.
    Deleted,
}

/// Async stream of [`BindingChange`] events — the read side of the
/// control-plane change feed. Backend-agnostic: the Postgres store
/// ([`crate::CatalogService`]) builds it from a dedicated LISTEN/NOTIFY
/// pump, the embedded store ([`crate::EmbeddedMetaStore`]) from an
/// in-process broadcast — both box into this one type so
/// [`crate::MetaStore::subscribe`] has a single return.
///
/// The stream stays open until its backend closes it or the caller
/// drops it. For the Postgres backend the owning `tokio_postgres::Client`
/// rides inside the boxed stream, so dropping the `BindingChangeStream`
/// closes the LISTEN connection (which ends the pump task).
pub struct BindingChangeStream {
    inner: Pin<Box<dyn Stream<Item = BindingChange> + Send>>,
}

impl BindingChangeStream {
    /// Box any change stream into the public type. Used by the embedded
    /// store (wrapping a broadcast receiver) and, via [`Self::from_pg`],
    /// the Postgres store.
    pub(crate) fn from_stream(s: impl Stream<Item = BindingChange> + Send + 'static) -> Self {
        Self { inner: Box::pin(s) }
    }

    /// Postgres constructor: an mpsc receiver fed by the LISTEN pump,
    /// plus the owning client. The client rides along inside the stream
    /// so the connection lives exactly as long as the stream.
    pub(crate) fn from_pg(
        rx: mpsc::UnboundedReceiver<BindingChange>,
        client: tokio_postgres::Client,
    ) -> Self {
        Self::from_stream(PgListenStream {
            rx,
            _client: client,
        })
    }
}

/// The Postgres LISTEN pump's receiver + the client whose lifetime keeps
/// its connection open. Boxed inside a [`BindingChangeStream`]; dropping
/// the outer stream drops this, closing the connection.
struct PgListenStream {
    rx: mpsc::UnboundedReceiver<BindingChange>,
    _client: tokio_postgres::Client,
}

impl Stream for PgListenStream {
    type Item = BindingChange;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Stream for BindingChangeStream {
    type Item = BindingChange;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl std::fmt::Debug for BindingChangeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindingChangeStream")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_change_kind_serde_lowercase() {
        // Wire shape pinned — the Postgres trigger emits
        // `"upserted"` / `"deleted"` (snake_case), this must
        // round-trip.
        for (kind, expected) in [
            (BindingChangeKind::Upserted, r#""upserted""#),
            (BindingChangeKind::Deleted, r#""deleted""#),
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, expected);
            let parsed: BindingChangeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn binding_change_serde_round_trip() {
        // Pin the full payload shape against what the
        // Postgres trigger emits via json_build_object.
        let change = BindingChange {
            org_id: "default".into(),
            name: "pg_demo".into(),
            kind: BindingChangeKind::Upserted,
        };
        let json = serde_json::to_string(&change).unwrap();
        let parsed: BindingChange = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, change);
    }

    /// The public `BindingChangeStream` boxes any inner change stream
    /// (`from_stream`) and forwards items through its `Stream::poll_next`
    ///. The embedded store wraps a broadcast receiver this way;
    /// pin the forwarding + the `Debug` shape without a Postgres backend.
    #[tokio::test]
    async fn boxed_stream_forwards_items_and_debugs() {
        use futures::StreamExt;

        let changes = vec![
            BindingChange {
                org_id: "o".into(),
                name: "a".into(),
                kind: BindingChangeKind::Upserted,
            },
            BindingChange {
                org_id: "o".into(),
                name: "b".into(),
                kind: BindingChangeKind::Deleted,
            },
        ];
        let mut stream = BindingChangeStream::from_stream(futures::stream::iter(changes.clone()));

        // Debug is intentionally opaque (finish_non_exhaustive) — it must
        // still name the type and never expose the inner boxed stream.
        assert!(format!("{stream:?}").contains("BindingChangeStream"));

        // poll_next forwards every item from the inner stream, in order.
        let got: Vec<BindingChange> = stream.by_ref().collect().await;
        assert_eq!(got, changes);

        // Exhausted inner stream terminates the boxed stream.
        assert!(stream.next().await.is_none());
    }
}
