pub mod builder;
pub mod ec;
pub mod entry;
pub mod error;
pub mod keypair;
pub mod keys;
pub mod set_commits;
pub mod utils;
pub mod zkp;

use crate::policy::QualifiedAttribute as Attribute;

pub const DEFAULT_MAX_ENTRIES: usize = 6;

pub const DEFAULT_MAX_CARDINALITY: usize = 8;

pub const CHALLENGE_STATE_NAME: &str = "schnorr";
