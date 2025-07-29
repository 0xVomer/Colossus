#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum AzksError {
    VerifyMembershipProof(String),

    VerifyAppendOnlyProof,

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
