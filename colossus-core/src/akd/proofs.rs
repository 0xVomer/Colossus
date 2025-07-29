use super::{ARITY, AkdValue, AzksElement, AzksValue, Direction, NodeLabel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingProof {
    pub label: NodeLabel,

    pub siblings: [AzksElement; 1],

    pub direction: Direction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipProof {
    pub label: NodeLabel,

    pub hash_val: AzksValue,

    pub sibling_proofs: Vec<SiblingProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonMembershipProof {
    pub label: NodeLabel,

    pub longest_prefix: NodeLabel,

    pub longest_prefix_children: [AzksElement; ARITY],

    pub longest_prefix_membership_proof: MembershipProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupProof {
    pub epoch: u64,

    pub value: AkdValue,

    pub version: u64,

    pub existence_vrf_proof: Vec<u8>,

    pub existence_proof: MembershipProof,

    pub marker_vrf_proof: Vec<u8>,

    pub marker_proof: MembershipProof,

    pub freshness_vrf_proof: Vec<u8>,

    pub freshness_proof: NonMembershipProof,

    pub commitment_nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateProof {
    pub epoch: u64,

    pub value: AkdValue,

    pub version: u64,

    pub existence_vrf_proof: Vec<u8>,

    pub existence_proof: MembershipProof,

    pub previous_version_vrf_proof: Option<Vec<u8>>,

    pub previous_version_proof: Option<MembershipProof>,

    pub commitment_nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryProof {
    pub update_proofs: Vec<UpdateProof>,

    pub past_marker_vrf_proofs: Vec<Vec<u8>>,

    pub existence_of_past_marker_proofs: Vec<MembershipProof>,

    pub future_marker_vrf_proofs: Vec<Vec<u8>>,

    pub non_existence_of_future_marker_proofs: Vec<NonMembershipProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub epoch: u64,

    pub version: u64,

    pub value: AkdValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleAppendOnlyProof {
    pub inserted: Vec<AzksElement>,

    pub unchanged_nodes: Vec<AzksElement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendOnlyProof {
    pub proofs: Vec<SingleAppendOnlyProof>,

    pub epochs: Vec<u64>,
}
