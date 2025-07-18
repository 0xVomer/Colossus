use super::VrfError;

/// Proof verification error types
#[derive(Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// Error verifying a membership proof
    MembershipProof(String),
    /// Error verifying a non-membership proof
    NonMembershipProof(String),
    /// Error verifying a lookup proof
    LookupProof(String),
    /// Error verifying a history proof
    HistoryProof(String),
    /// Error verifying a VRF proof
    Vrf(VrfError),
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            VerificationError::MembershipProof(err) => format!("(Membership proof) - {err}"),
            VerificationError::NonMembershipProof(err) => {
                format!("(Non-membership proof) - {err}")
            },
            VerificationError::LookupProof(err) => format!("(Lookup proof) - {err}"),
            VerificationError::HistoryProof(err) => format!("(History proof) - {err}"),
            VerificationError::Vrf(vrf) => vrf.to_string(),
        };
        write!(f, "Verification error {code}")
    }
}

impl From<VrfError> for VerificationError {
    fn from(input: VrfError) -> Self {
        VerificationError::Vrf(input)
    }
}
