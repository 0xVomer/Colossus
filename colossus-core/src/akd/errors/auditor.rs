/// The errors thrown by various algorithms in [crate::directory::Directory]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum AuditorError {
    /// A general auditor error
    VerifyAuditProof(String),
}

impl std::error::Error for AuditorError {}

impl std::fmt::Display for AuditorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifyAuditProof(err_string) => {
                write!(f, "Failed to verify audit {err_string}")
            },
        }
    }
}
