/// A error related to verifiable random functions
#[derive(Debug, Eq, PartialEq)]
pub enum VrfError {
    /// A problem retrieving or decoding the VRF public key
    PublicKey(String),
    /// A problem retrieving or decoding the VRF signing key
    SigningKey(String),
    /// A problem verifying the VRF proof
    Verification(String),
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            VrfError::PublicKey(msg) => format!("(Public Key) - {msg}"),
            VrfError::SigningKey(msg) => format!("(Signing Key) - {msg}"),
            VrfError::Verification(msg) => format!("(Verification) - {msg}"),
        };
        write!(f, "Verifiable random function error {code}")
    }
}
