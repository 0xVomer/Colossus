#[derive(Debug)]
pub enum UpdateError {
    Error(String),
}

impl std::error::Error for UpdateError {}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UpdateError::Error(e) => write!(f, "UpdateError: {}", e),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IssuerError {
    TooLargeCardinality,
    TooLongEntries,
    InvalidAliasProof,
    UpdateError(String),
}

impl std::error::Error for IssuerError {}

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IssuerError::TooLargeCardinality => write!(
                f,
                "TooLargeCardinality. You passed too many attributes per Entry. Hint: reduce the number of attributes to be less than the max cardinality of this Issuer."
            ),
            IssuerError::TooLongEntries => write!(
                f,
                "TooLongEntries. You passed too many Entries. Hint: reduce the number of Entries to be less than the max entries of this Issuer."
            ),
            IssuerError::InvalidAliasProof => {
                write!(f, "InvalidAliasProof. The proof of the pseudoalias is invalid.")
            },
            IssuerError::UpdateError(e) => write!(f, "UpdateError: {}", e),
        }
    }
}

impl From<UpdateError> for IssuerError {
    fn from(item: UpdateError) -> Self {
        IssuerError::UpdateError(item.to_string())
    }
}
