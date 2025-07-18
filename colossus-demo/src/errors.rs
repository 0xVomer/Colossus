//! Cryptographic related Errors

use core::{fmt::Display, num::TryFromIntError};

#[derive(Debug)]
pub enum ZeroTrustError {}

impl Display for ZeroTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Self::Kem(err) => write!(f, "Kyber error: {err}"),
            // Self::CryptoCoreError(err) => write!(f, "CryptoCore error{err}"),
            // Self::KeyError(err) => write!(f, "{err}"),
            // Self::AttributeNotFound(err) => write!(f, "attribute not found: {err}"),
            // Self::ExistingDimension(dimension) => {
            //     write!(f, "dimension {dimension} already exists")
            // },
            // Self::InvalidBooleanExpression(expr_str) => {
            //     write!(f, "invalid boolean expression: {expr_str}")
            // },
            // Self::InvalidAttribute(attr) => write!(f, "invalid attribute: {attr}"),
            // Self::DimensionNotFound(dim_str) => write!(f, "cannot find dimension: {dim_str}"),
            // Self::ConversionFailed(err) => write!(f, "Conversion failed: {err}"),
            // Self::OperationNotPermitted(err) => write!(f, "Operation not permitted: {err}"),
            // Self::Tracing(err) => write!(f, "tracing error: {err}"),
        }
    }
}

impl From<TryFromIntError> for ZeroTrustError {
    fn from(e: TryFromIntError) -> Self {
        Self::ConversionFailed(e.to_string())
    }
}

impl std::error::Error for PolicyError {}
