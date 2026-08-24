//! Error types for Dataglot.
//!
//! Uses `thiserror` for typed errors per hard rule 8.

use std::sync::Arc;

use arrow_schema::ArrowError;
use datafusion::error::DataFusionError;
use thiserror::Error;

/// Result type alias for Dataglot operations.
pub type Result<T> = std::result::Result<T, DataglotError>;

/// Core error type for Dataglot.
#[derive(Error, Debug)]
pub enum DataglotError {
    /// Error from `DataFusion` operations.
    #[error("DataFusion error: {0}")]
    DataFusion(#[from] DataFusionError),

    /// Error from Arrow operations.
    #[error("Arrow error: {0}")]
    Arrow(#[from] ArrowError),

    /// Error during federation/pushdown operations.
    #[error("Federation error: {0}")]
    Federation(String),

    /// Error during catalog resolution.
    #[error("Catalog error: {0}")]
    Catalog(String),

    /// Error during plan serialization.
    #[error("Plan serialization error: {0}")]
    PlanSerialization(String),

    /// Error from policy enforcement.
    #[error("Policy error: {0}")]
    Policy(String),

    /// Error from pg wire protocol.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Connection error to remote data source.
    #[error("Connection error: {0}")]
    Connection(String),

    /// A concurrent writer modified a warehouse table between the time this
    /// operation read its base version and the time it tried to commit —
    /// optimistic-concurrency conflict on a copy-on-write write path. The
    /// caller should re-read and retry. Distinct from [`Self::Catalog`] so
    /// callers can detect (and retry) conflicts without string-matching.
    #[error("Concurrent modification: {0}")]
    ConcurrentModification(String),

    /// Internal error (should not happen in normal operation).
    #[error("Internal error: {0}")]
    Internal(String),
}

impl DataglotError {
    /// Create a federation error.
    #[must_use]
    pub fn federation(msg: impl Into<String>) -> Self {
        Self::Federation(msg.into())
    }

    /// Create a catalog error.
    #[must_use]
    pub fn catalog(msg: impl Into<String>) -> Self {
        Self::Catalog(msg.into())
    }

    /// Create a plan serialization error.
    #[must_use]
    pub fn plan_serialization(msg: impl Into<String>) -> Self {
        Self::PlanSerialization(msg.into())
    }

    /// Create a policy error.
    #[must_use]
    pub fn policy(msg: impl Into<String>) -> Self {
        Self::Policy(msg.into())
    }

    /// Create a protocol error.
    #[must_use]
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Create a configuration error.
    #[must_use]
    pub fn configuration(msg: impl Into<String>) -> Self {
        Self::Configuration(msg.into())
    }

    /// Create a connection error.
    #[must_use]
    pub fn connection(msg: impl Into<String>) -> Self {
        Self::Connection(msg.into())
    }

    /// Create an internal error.
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Create a concurrent-modification (optimistic-concurrency conflict) error.
    #[must_use]
    pub fn concurrent_modification(msg: impl Into<String>) -> Self {
        Self::ConcurrentModification(msg.into())
    }

    /// Whether this is a [`Self::ConcurrentModification`] conflict — the
    /// signal a caller uses to decide whether to re-read and retry.
    #[must_use]
    pub fn is_concurrent_modification(&self) -> bool {
        matches!(self, Self::ConcurrentModification(_))
    }
}

// Enable DataglotError to be used in DataFusion contexts
impl From<DataglotError> for DataFusionError {
    fn from(err: DataglotError) -> Self {
        DataFusionError::External(Arc::new(err).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DataglotError::federation("pushdown failed");
        assert_eq!(err.to_string(), "Federation error: pushdown failed");
    }

    #[test]
    fn test_error_from_datafusion() {
        let df_err = DataFusionError::Plan("bad plan".to_string());
        let err: DataglotError = df_err.into();
        assert!(matches!(err, DataglotError::DataFusion(_)));
    }

    #[test]
    fn test_error_constructors() {
        assert!(matches!(
            DataglotError::catalog("not found"),
            DataglotError::Catalog(_)
        ));
        assert!(matches!(
            DataglotError::policy("denied"),
            DataglotError::Policy(_)
        ));
        assert!(matches!(
            DataglotError::connection("timeout"),
            DataglotError::Connection(_)
        ));
    }

    #[test]
    fn test_all_error_variants_display() {
        // Ensure Display is implemented for all variants
        let errors = vec![
            DataglotError::federation("test"),
            DataglotError::catalog("test"),
            DataglotError::plan_serialization("test"),
            DataglotError::policy("test"),
            DataglotError::protocol("test"),
            DataglotError::configuration("test"),
            DataglotError::connection("test"),
            DataglotError::internal("test"),
        ];

        for err in errors {
            let display = err.to_string();
            assert!(!display.is_empty());
            assert!(display.contains("test"));
        }
    }

    #[test]
    fn test_error_to_datafusion_roundtrip() {
        let original = DataglotError::federation("round trip test");
        let df_err: DataFusionError = original.into();
        assert!(matches!(df_err, DataFusionError::External(_)));
    }

    #[test]
    fn test_error_debug_impl() {
        let err = DataglotError::internal("debug test");
        let debug = format!("{err:?}");
        assert!(debug.contains("Internal"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn error_display_never_panics(msg in ".*") {
            // Property: Display should never panic for any input
            let _ = DataglotError::federation(&msg).to_string();
            let _ = DataglotError::catalog(&msg).to_string();
            let _ = DataglotError::connection(&msg).to_string();
            let _ = DataglotError::internal(&msg).to_string();
        }

        #[test]
        fn error_message_preserved(msg in "[a-zA-Z0-9 ]+") {
            // Property: Error message should be preserved in Display output
            let err = DataglotError::connection(&msg);
            let display = err.to_string();
            prop_assert!(display.contains(&msg));
        }

        #[test]
        fn error_debug_contains_variant(msg in "[a-zA-Z]+") {
            // Property: Debug output should contain the variant name
            let err = DataglotError::federation(&msg);
            let debug = format!("{err:?}");
            prop_assert!(debug.contains("Federation"));
        }

        #[test]
        fn datafusion_conversion_preserves_error(msg in "[a-zA-Z0-9 ]+") {
            // Property: Converting to DataFusionError should preserve error info
            let original = DataglotError::internal(&msg);
            let df_err: DataFusionError = original.into();
            let display = df_err.to_string();
            prop_assert!(display.contains(&msg));
        }
    }
}
