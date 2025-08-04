pub mod builder;
pub mod ec;
pub mod entry;
pub mod error;
pub mod keypair;
pub mod keys;
pub mod set_commits;
pub mod utils;
pub mod zkp;

pub const DEFAULT_MAX_ENTRIES: usize = 6;

pub const DEFAULT_MAX_CARDINALITY: usize = 8;

pub const CHALLENGE_STATE_NAME: &str = "schnorr";

pub type Attributes = entry::Entry<crate::policy::QualifiedAttribute>;
pub type AccessRights = entry::Entry<crate::policy::Right>;

impl entry::Attribute for crate::policy::QualifiedAttribute {
    fn digest(&self) -> &[u8] {
        self.hash_digest()
    }
}

impl entry::Attribute for crate::policy::Right {
    fn digest(&self) -> &[u8] {
        &self.0
    }
}
