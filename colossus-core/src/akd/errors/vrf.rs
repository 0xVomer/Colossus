#[derive(Debug, Eq, PartialEq)]
pub enum VrfError {
    PublicKey(String),

    SigningKey(String),

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
