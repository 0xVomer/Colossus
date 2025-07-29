use super::VerificationError;

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum DirectoryError {
    Verification(VerificationError),

    InvalidEpoch(String),

    ReadOnlyDirectory(String),

    Publish(String),

    InvalidVersion(String),
}

impl std::error::Error for DirectoryError {}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verification(err) => {
                write!(f, "Verification failure {err}")
            },
            Self::InvalidEpoch(err_string) => {
                write!(f, "Invalid epoch {err_string}")
            },
            Self::ReadOnlyDirectory(inner_message) => {
                write!(f, "Directory in read-only mode: {inner_message}")
            },
            Self::Publish(inner_message) => {
                write!(f, "Directory publish error: {inner_message}")
            },
            Self::InvalidVersion(inner_message) => {
                write!(f, "Invalid version error: {inner_message}")
            },
        }
    }
}

impl From<VerificationError> for DirectoryError {
    fn from(err: VerificationError) -> Self {
        Self::Verification(err)
    }
}
