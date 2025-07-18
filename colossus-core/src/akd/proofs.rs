use super::{ARITY, AkdValue, AzksElement, AzksValue, Direction, NodeLabel};
use serde::{Deserialize, Serialize};

/// Represents a specific level of the tree with the parental sibling and the direction
/// of the parent for use in tree hash calculations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingProof {
    /// The parent's label
    pub label: NodeLabel,
    /// Sibling of the parent that is not on the path
    pub siblings: [AzksElement; 1],
    /// The direction
    pub direction: Direction,
}

/// Merkle proof of membership of a [`NodeLabel`] with a particular hash
/// value in the tree at a given epoch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipProof {
    /// The node label
    pub label: NodeLabel,
    /// The hash of the value
    pub hash_val: AzksValue,
    /// The parents of the node in question
    pub sibling_proofs: Vec<SiblingProof>,
}

/// Merkle Patricia proof of non-membership for a [`NodeLabel`] in the tree
/// at a given epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonMembershipProof {
    /// The label in question
    pub label: NodeLabel,
    /// The longest prefix in the tree
    pub longest_prefix: NodeLabel,
    /// The children of the longest prefix
    pub longest_prefix_children: [AzksElement; ARITY],
    /// The membership proof of the longest prefix
    pub longest_prefix_membership_proof: MembershipProof,
}

/// Proof that a given label was at a particular state at the given epoch.
/// This means we need to show that the state and version we are claiming for this node must have been:
/// * committed in the tree,
/// * not too far ahead of the most recent marker version,
/// * not stale when served.
///
/// This proof is sent in response to a lookup query for a particular key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupProof {
    /// The epoch of this record
    pub epoch: u64,
    /// The plaintext value in question
    pub value: AkdValue,
    /// The version of the record
    pub version: u64,
    /// VRF proof for the label corresponding to this version
    pub existence_vrf_proof: Vec<u8>,
    /// Record existence proof
    pub existence_proof: MembershipProof,
    /// VRF proof for the marker preceding (less than or equal to) this version
    pub marker_vrf_proof: Vec<u8>,
    /// Existence at specific marker
    pub marker_proof: MembershipProof,
    /// VRF proof for the label corresponding to this version being stale
    pub freshness_vrf_proof: Vec<u8>,
    /// Freshness proof (non member at previous epoch)
    pub freshness_proof: NonMembershipProof,
    /// Proof for commitment value derived from raw AkdLabel and AkdValue
    pub commitment_nonce: Vec<u8>,
}

/// A vector of UpdateProofs are sent as the proof to a history query for a particular key.
/// For each version of the value associated with the key, the verifier must check that:
/// * the version was included in the claimed epoch,
/// * the previous version was retired at this epoch,
/// * the version did not exist prior to this epoch,
/// * the next few versions (up until the next marker), did not exist at this epoch,
/// * the future marker versions did  not exist at this epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateProof {
    /// Epoch of this update
    pub epoch: u64,
    /// Value at this update
    pub value: AkdValue,
    /// Version at this update
    pub version: u64,
    /// VRF proof for the label for the current version
    pub existence_vrf_proof: Vec<u8>,
    /// Membership proof to show that the key was included in this epoch
    pub existence_proof: MembershipProof,
    /// VRF proof for the label for the previous version which became stale
    pub previous_version_vrf_proof: Option<Vec<u8>>,
    /// Proof that previous value was set to old at this epoch
    pub previous_version_proof: Option<MembershipProof>,
    /// Nonce for commitment value derived from raw AkdLabel and AkdValue
    pub commitment_nonce: Vec<u8>,
}

/// A client can query for a history of all versions associated with a given [AkdLabel], or the most recent k versions.
/// The server returns a [HistoryProof] which can be verified to extract a list of [VerifyResult]s, one for each
/// version.
/// Let `n` be the latest version, `n_prev_pow` be the power of 2 that is at most n, `n_next_pow` the next power of 2 after `n`, and `epoch_prev_pow` be the power of 2 that
/// is at most the current epoch. The [HistoryProof] consists of:
/// - A list of [UpdateProof]s, one for each version, which each contain a membership proof for the version `n` being fresh,
///   and a membership proof for the version `n-1` being stale
/// - A membership proof for `n_prev_pow` (or empty if n is a power of 2)
/// - A series of non-membership proofs for each version in the range `[n+1, n_next_pow]`
/// - A series of non-membership proofs for each power of 2 in the range `[n_next_pow, epoch_prev_pow]`
///
/// A client verifies this proof by first verifying each of the update proofs, checking that they are in decreasing
/// consecutive order by version. Then, it verifies the remaining proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryProof {
    /// The update proofs in the key history
    pub update_proofs: Vec<UpdateProof>,
    /// VRF Proofs for the labels of the values for past markers
    pub past_marker_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that the values for the past markers exist
    pub existence_of_past_marker_proofs: Vec<MembershipProof>,
    /// VRF proofs for the labels of future marker entries
    pub future_marker_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that future markers did not exist
    pub non_existence_of_future_marker_proofs: Vec<NonMembershipProof>,
}

/// The payload that is outputted as a result of successful verification of
/// a [LookupProof] or [HistoryProof]. This includes the fields containing the
/// epoch that the leaf was published in, the version corresponding to the value,
/// and the value itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    /// The epoch of this record
    pub epoch: u64,
    /// Version at this update
    pub version: u64,
    /// The plaintext value associated with the record
    pub value: AkdValue,
}

/// Proof that no leaves were deleted from the initial epoch.
/// This means that unchanged_nodes should hash to the initial root hash
/// and the vec of inserted is the set of leaves inserted between these epochs.
/// If we built the tree using the nodes in inserted and the nodes in unchanged_nodes
/// as the leaves with the correct epoch of insertion,
/// it should result in the final root hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleAppendOnlyProof {
    /// The inserted nodes & digests
    pub inserted: Vec<AzksElement>,
    /// The unchanged nodes & digests
    pub unchanged_nodes: Vec<AzksElement>,
}

/// Proof that no leaves were deleted from the initial epoch.
/// This is done using a list of SingleAppendOnly proofs, one proof
/// for each epoch between the initial epoch and final epochs which are
/// being audited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendOnlyProof {
    /// Proof for a single epoch being append-only
    pub proofs: Vec<SingleAppendOnlyProof>,
    /// Epochs over which this audit is being performed
    pub epochs: Vec<u64>,
}
