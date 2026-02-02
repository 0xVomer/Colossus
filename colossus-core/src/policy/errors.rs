use core::num::TryFromIntError;

use cosmian_crypto_core::CryptoCoreError;
use thiserror::Error;

/// Errors that can occur during policy operations.
#[derive(Error, Debug)]
pub enum PolicyError {
    /// KEM operation failed
    #[error("KEM error: {0}")]
    Kem(String),

    /// Underlying crypto library error
    #[error("CryptoCore error: {0}")]
    CryptoCoreError(#[from] CryptoCoreError),

    /// Key-related error
    #[error("key error: {0}")]
    KeyError(String),

    /// The requested attribute was not found
    #[error("attribute not found: {0}")]
    AttributeNotFound(String),

    /// Attempted to add a dimension that already exists
    #[error("dimension '{0}' already exists")]
    ExistingDimension(String),

    /// The operation is not permitted in the current state
    #[error("operation not permitted: {0}")]
    OperationNotPermitted(String),

    /// The boolean expression is invalid or malformed
    #[error("invalid boolean expression: {0}")]
    InvalidBooleanExpression(String),

    /// The attribute format is invalid
    #[error("invalid attribute: {0}")]
    InvalidAttribute(String),

    /// The requested dimension was not found
    #[error("dimension not found: {0}")]
    DimensionNotFound(String),

    /// Type conversion failed
    #[error("conversion failed: {0}")]
    ConversionFailed(String),

    /// Tracing-related error
    #[error("tracing error: {0}")]
    Tracing(String),

    /// Dimensions are incompatible for the operation
    #[error("incompatible dimensions")]
    IncompatibleDimensions,

    /// The credential proof is invalid
    #[error("invalid credential proof")]
    InvalidCredProof,

    /// A mutex lock was poisoned (another thread panicked while holding the lock)
    #[error("mutex lock poisoned")]
    MutexPoisoned,

    /// Poseidon2 AEAD operation failed
    #[error("Poseidon2 AEAD error: {0}")]
    Poseidon2Error(String),
}

impl From<TryFromIntError> for PolicyError {
    fn from(e: TryFromIntError) -> Self {
        Self::ConversionFailed(e.to_string())
    }
}

impl From<crate::dac::error::Error> for PolicyError {
    fn from(e: crate::dac::error::Error) -> Self {
        Self::ConversionFailed(e.to_string())
    }
}
