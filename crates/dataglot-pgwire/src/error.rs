//! Error types for the pg wire protocol layer.
//!
//! Uses `thiserror` for typed errors per hard rule 8.

use thiserror::Error;

/// Errors that can occur in the pg wire protocol layer.
#[derive(Error, Debug)]
pub enum PgWireError {
    /// Error from the underlying pgwire library.
    #[error("Protocol error: {0}")]
    Protocol(#[from] pgwire::error::PgWireError),

    /// Error from `DataFusion` query execution.
    #[error("DataFusion error: {0}")]
    DataFusion(#[from] datafusion::error::DataFusionError),

    /// I/O error during connection handling.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Connection was closed unexpectedly.
    #[error("Connection closed")]
    ConnectionClosed,
}

/// Result type for pg wire operations.
pub type Result<T> = std::result::Result<T, PgWireError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PgWireError::ConnectionClosed;
        assert_eq!(err.to_string(), "Connection closed");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let err: PgWireError = io_err.into();
        assert!(err.to_string().contains("I/O error"));
    }
}
