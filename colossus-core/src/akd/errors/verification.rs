use super::VrfError;

#[derive(Debug, Eq, PartialEq)]
pub enum VerificationError {
    MembershipProof(String),

    NonMembershipProof(String),

    LookupProof(String),

    HistoryProof(String),

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
