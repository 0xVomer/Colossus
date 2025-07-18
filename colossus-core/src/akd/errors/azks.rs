/// An error thrown by the Azks data structure.
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum AzksError {
    /// Membership proof did not verify
    VerifyMembershipProof(String),
    /// Append-only proof did not verify
    VerifyAppendOnlyProof,
    /// Thrown when a place where an epoch is needed wasn't provided one.
    NoEpochGiven,
}

impl std::error::Error for AzksError {}

impl std::fmt::Display for AzksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifyMembershipProof(error_string) => {
                write!(f, "{error_string}")
            },
            Self::VerifyAppendOnlyProof => {
                write!(f, "Append only proof did not verify!")
            },
            Self::NoEpochGiven => {
                write!(f, "An epoch was required but not supplied")
            },
        }
    }
}
