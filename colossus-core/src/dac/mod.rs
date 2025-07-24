pub mod ec;
pub mod entry;
pub mod error;
pub mod keypair;
pub mod set_commit;

use crate::policy::QualifiedAttribute as Attribute;

/// Default Max Attributes: The maximum number of attribute entries allowed in a credential.
pub const DEFAULT_MAX_ENTRIES: usize = 6;

/// Default Max Cardinality: The maximum number of total attribute elements allowed in a credential. The Default is 8 is chosen as it is the maximum number tha will fit into an Issuer QR Code.
pub const DEFAULT_MAX_CARDINALITY: usize = 8;

pub const CHALLENGE_STATE_NAME: &str = "schnorr";
