use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid Signature {0}")]
    InvalidSignature(String),

    #[error("Change Relations Failed, {0}")]
    ChangeRelationsFailed(String),

    #[error("Failed to accept a Credential offer {0}")]
    AcceptOfferFailed(String),

    #[error("Failed to use their Verification Key(expected {expected:?}, found {found:?})")]
    InvalidVerificationKey { expected: String, found: String },

    #[error("Proof is not valid, did not pass verify_proof function")]
    InvalidProof,

    #[error("Tried to convert bytes into an Attribute, but failed")]
    InvalidAttribute(#[from] cid::Error),

    #[error("Tried to convert bytes into a Scalar and it failed")]
    InvalidScalar,

    #[error("Tried to apply CBOR coded, but failed {0}")]
    CBORError(String),

    #[error("The given Nonce bytes were not convertable to Scalar")]
    NonceConversionError,

    #[error("The given Scalar bytes were not convertable to Scalar")]
    ScalarConversionError,

    #[error("Error converting Credential")]
    CredentialConversionError(#[from] serde_json::Error),

    #[error("Invalid G1 point")]
    InvalidG1Point,

    #[error("Invalid G2 point")]
    InvalidG2Point,
}
