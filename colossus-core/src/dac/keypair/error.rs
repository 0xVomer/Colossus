use thiserror::Error;

/// Errors that can occur during credential update operations.
#[derive(Error, Debug)]
pub enum UpdateError {
    /// Generic update error with message
    #[error("update error: {0}")]
    Error(String),
}

/// Errors that can occur during issuer operations.
#[derive(Error, Debug, Clone)]
pub enum IssuerError {
    /// Too many attributes per entry (exceeds max cardinality)
    #[error(
        "too many attributes per entry: reduce the number of attributes to be less than the max cardinality of this Issuer"
    )]
    TooLargeCardinality,

    /// Too many entries (exceeds max entries)
    #[error(
        "too many entries: reduce the number of entries to be less than the max entries of this Issuer"
    )]
    TooLongEntries,

    /// Attributes are not covered by the issuer's access structure
    #[error(
        "attributes not covered: the attributes are not covered by the issuer's access structure"
    )]
    AttributesNotCovered,

    /// The alias proof is invalid
    #[error("invalid alias proof: the proof of the pseudoalias is invalid")]
    InvalidAliasProof,

    /// The verification key is invalid or malformed
    #[error("invalid verification key: {0}")]
    InvalidVerificationKey(String),

    /// Update operation failed
    #[error("update error: {0}")]
    UpdateError(String),

    /// Access structure error
    #[error("access structure error: {0}")]
    AccessStructureError(String),

    /// Access rights are not covered by the credential
    #[error("access rights not covered: the access rights are not covered by your credential")]
    AccessRightsNotCovered,

    /// Scalar inversion failed (scalar was zero)
    #[error("scalar inversion failed: scalar is zero")]
    ScalarInversionFailed,
}

impl From<UpdateError> for IssuerError {
    fn from(item: UpdateError) -> Self {
        IssuerError::UpdateError(item.to_string())
    }
}
