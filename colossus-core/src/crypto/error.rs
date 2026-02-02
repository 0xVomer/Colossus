//! Unified error types for the crypto module.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid point on the G1 curve
    #[error("invalid G1 point")]
    InvalidG1Point,

    /// Invalid point on the G2 curve
    #[error("invalid G2 point")]
    InvalidG2Point,

    /// Invalid scalar value
    #[error("invalid scalar: {0}")]
    InvalidScalar(String),

    /// Pairing operation failed
    #[error("pairing operation failed: {0}")]
    PairingError(String),

    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid signature format
    #[error("invalid signature format: {0}")]
    InvalidSignature(String),

    /// Key generation failed
    #[error("key generation failed: {0}")]
    KeyGenerationError(String),

    /// Invalid key format
    #[error("invalid key format: {0}")]
    InvalidKey(String),

    /// Hash operation failed
    #[error("hash operation failed: {0}")]
    HashError(String),

    /// KEM operation failed
    #[error("KEM operation failed: {0}")]
    KemError(String),

    /// Serialization/deserialization error
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Feature not available
    #[error("feature not available: {0}")]
    NotAvailable(String),
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        CryptoError::SerializationError(e.to_string())
    }
}
