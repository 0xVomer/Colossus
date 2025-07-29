use super::{
    AkdLabel, AkdValue, AzksValue, Configuration, Digest, Direction, MembershipProof, NodeLabel,
    NonMembershipProof, Proof, VerificationError, VersionFreshness, VrfError,
};
use alloc::format;
use alloc::string::ToString;
use core::convert::TryFrom;

pub fn verify_membership_for_tests_only<TC: Configuration>(
    root_hash: Digest,
    proof: &MembershipProof,
) -> Result<(), VerificationError> {
    verify_membership::<TC>(root_hash, proof)
}

pub(crate) fn verify_membership<TC: Configuration>(
    root_hash: Digest,
    proof: &MembershipProof,
) -> Result<(), VerificationError> {
    let mut curr_val = proof.hash_val;
    let mut curr_label = proof.label;

    for sibling_proof in proof.sibling_proofs.iter().rev() {
        let sibling = sibling_proof.siblings[0];
        let (left_val, left_label, right_val, right_label) = match sibling_proof.direction {
            Direction::Left => {
                (curr_val, curr_label.value::<TC>(), sibling.value, sibling.label.value::<TC>())
            },
            Direction::Right => {
                (sibling.value, sibling.label.value::<TC>(), curr_val, curr_label.value::<TC>())
            },
        };
        curr_val =
            TC::compute_parent_hash_from_children(&left_val, &left_label, &right_val, &right_label);
        curr_label = sibling_proof.label;
    }

    if TC::compute_root_hash_from_val(&curr_val) == root_hash {
        Ok(())
    } else {
        Err(VerificationError::MembershipProof(format!(
            "Membership proof for label {:?} did not verify",
            proof.label
        )))
    }
}

pub fn verify_nonmembership_for_tests_only<TC: Configuration>(
    root_hash: Digest,
    proof: &NonMembershipProof,
) -> Result<(), VerificationError> {
    verify_nonmembership::<TC>(root_hash, proof)
}

pub(crate) fn verify_nonmembership<TC: Configuration>(
    root_hash: Digest,
    proof: &NonMembershipProof,
) -> Result<(), VerificationError> {
    if proof.label == proof.longest_prefix_children[0].label
        || proof.label == proof.longest_prefix_children[1].label
    {
        return Err(VerificationError::NonMembershipProof(
            "Proof's label is equal to one of the children's labels".to_string(),
        ));
    }

    if !proof.longest_prefix.is_prefix_of(&proof.label) {
        return Err(VerificationError::NonMembershipProof(
            "Proof's longest prefix is not a prefix of the proof's label".to_string(),
        ));
    }

    let mut lcp_children = proof.longest_prefix_children[0]
        .label
        .get_longest_common_prefix::<TC>(proof.longest_prefix_children[1].label);
    if lcp_children == TC::empty_label() {
        lcp_children = NodeLabel::root();
    }
    if proof.longest_prefix != lcp_children {
        return Err(VerificationError::NonMembershipProof(
            "longest_prefix != computed lcp".to_string(),
        ));
    }

    let lcp_hash = TC::compute_parent_hash_from_children(
        &proof.longest_prefix_children[0].value,
        &proof.longest_prefix_children[0].label.value::<TC>(),
        &proof.longest_prefix_children[1].value,
        &proof.longest_prefix_children[1].label.value::<TC>(),
    );
    if lcp_children != proof.longest_prefix_membership_proof.label
        || lcp_hash != proof.longest_prefix_membership_proof.hash_val
    {
        return Err(VerificationError::NonMembershipProof(
            "lcp_hash != longest_prefix_hash".to_string(),
        ));
    }
    verify_membership::<TC>(root_hash, &proof.longest_prefix_membership_proof)?;

    Ok(())
}

fn verify_label<TC: Configuration>(
    vrf_public_key: &[u8],
    akd_label: &AkdLabel,
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    node_label: NodeLabel,
) -> Result<(), VerificationError> {
    let vrf_pk = super::VRFPublicKey::try_from(vrf_public_key)?;
    let hashed_label = TC::get_hash_from_label_input(akd_label, freshness, version);

    let proof = Proof::try_from(vrf_proof)?;
    vrf_pk.verify(&proof, &hashed_label)?;
    let output: super::Output = (&proof).into();

    if NodeLabel::new(output.to_truncated_bytes(), 256) != node_label {
        return Err(VerificationError::Vrf(VrfError::Verification(
            "Expected first 32 bytes of the proof output did NOT match the supplied label"
                .to_string(),
        )));
    }
    Ok(())
}

pub(crate) fn verify_existence<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: &AkdLabel,
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    membership_proof: &MembershipProof,
) -> Result<(), VerificationError> {
    verify_label::<TC>(
        vrf_public_key,
        akd_label,
        freshness,
        version,
        vrf_proof,
        membership_proof.label,
    )?;
    verify_membership::<TC>(root_hash, membership_proof)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_existence_with_val<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: &AkdLabel,
    akd_value: &AkdValue,
    epoch: u64,
    commitment_nonce: &[u8],
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    membership_proof: &MembershipProof,
) -> Result<(), VerificationError> {
    if TC::hash_leaf_with_value(akd_value, epoch, commitment_nonce).0 != membership_proof.hash_val.0
    {
        return Err(VerificationError::MembershipProof(
            "Hash of plaintext value did not match existence proof hash".to_string(),
        ));
    }
    verify_existence::<TC>(
        vrf_public_key,
        root_hash,
        akd_label,
        freshness,
        version,
        vrf_proof,
        membership_proof,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_existence_with_commitment<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: &AkdLabel,
    commitment: AzksValue,
    epoch: u64,
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    membership_proof: &MembershipProof,
) -> Result<(), VerificationError> {
    if TC::hash_leaf_with_commitment(commitment, epoch).0 != membership_proof.hash_val.0 {
        return Err(VerificationError::MembershipProof(
            "Hash of plaintext value did not match existence proof hash".to_string(),
        ));
    }
    verify_existence::<TC>(
        vrf_public_key,
        root_hash,
        akd_label,
        freshness,
        version,
        vrf_proof,
        membership_proof,
    )?;

    Ok(())
}

pub(crate) fn verify_nonexistence<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: &AkdLabel,
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    nonmembership_proof: &NonMembershipProof,
) -> Result<(), VerificationError> {
    verify_label::<TC>(
        vrf_public_key,
        akd_label,
        freshness,
        version,
        vrf_proof,
        nonmembership_proof.label,
    )?;
    verify_nonmembership::<TC>(root_hash, nonmembership_proof)?;
    Ok(())
}
