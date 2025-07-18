use super::VerificationError;

/// The errors thrown by various algorithms in [crate::directory::Directory]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum DirectoryError {
    /// A verification error occurred
    Verification(VerificationError),
    /// Tried to perform an operation on an invalid epoch or epoch range
    InvalidEpoch(String),
    /// AZKS not found in read-only directory mode
    ReadOnlyDirectory(String),
    /// Publish
    Publish(String),
    /// Detected an invalid version
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
