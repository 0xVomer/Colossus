//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
//! This module contains verification calls for different proofs contained in the AKD crate

mod base;
mod history;
mod lookup;

// Re-export the necessary verification functions
pub use base::{verify_membership_for_tests_only, verify_nonmembership_for_tests_only};
pub use history::{HistoryParams, HistoryVerificationParams, key_history_verify};
pub use lookup::lookup_verify;

use super::{
    AkdLabel, AkdValue, AzksValue, Configuration, Digest, Direction, NodeLabel, TOMBSTONE,
    VersionFreshness,
    ecvrf::{Output, Proof, VRFPublicKey},
    errors::{VerificationError, VrfError},
    proofs::{
        HistoryProof, LookupProof, MembershipProof, NonMembershipProof, UpdateProof, VerifyResult,
    },
    utils::{get_marker_version_log2, get_marker_versions},
};
