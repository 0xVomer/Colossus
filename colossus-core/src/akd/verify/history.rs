use super::{
    AkdLabel, Configuration, Digest, HistoryProof, UpdateProof, VerificationError, VerifyResult,
    VersionFreshness,
    base::{
        verify_existence, verify_existence_with_commitment, verify_existence_with_val,
        verify_nonexistence,
    },
};
use alloc::{format, string::ToString, vec::Vec};

#[derive(Copy, Clone, Debug)]
pub enum HistoryParams {
    Complete,

    MostRecent(usize),
}

impl Default for HistoryParams {
    fn default() -> Self {
        Self::Complete
    }
}

#[derive(Copy, Clone)]
pub enum HistoryVerificationParams {
    Default { history_params: HistoryParams },

    AllowMissingValues { history_params: HistoryParams },
}

impl Default for HistoryVerificationParams {
    fn default() -> Self {
        Self::Default { history_params: HistoryParams::default() }
    }
}

fn verify_with_history_params(
    current_epoch: u64,
    akd_label: &AkdLabel,
    proof: &HistoryProof,
    params: HistoryParams,
) -> Result<(Vec<u64>, Vec<u64>), VerificationError> {
    let num_proofs = proof.update_proofs.len();

    if num_proofs == 0 {
        return Err(VerificationError::HistoryProof(format!(
            "No update proofs included in the proof of user {akd_label:?} at epoch {current_epoch:?}!"
        )));
    }

    for count in 1..num_proofs {
        let prev_version = proof.update_proofs[count - 1].version;
        let curr_version = proof.update_proofs[count].version;
        if curr_version + 1 != prev_version {
            return Err(VerificationError::HistoryProof(format!(
                "Update proofs should be ordered consecutively and in decreasing order.
                Error detected with version {} at index {}, followed by version {} at index {}",
                prev_version,
                count - 1,
                curr_version,
                count
            )));
        }
    }

    let mut start_version = proof.update_proofs[0].version;
    let mut end_version = proof.update_proofs[0].version;
    proof.update_proofs.iter().for_each(|update_proof| {
        if update_proof.version < start_version {
            start_version = update_proof.version;
        }
        if update_proof.version > end_version {
            end_version = update_proof.version;
        }
    });

    if start_version == 0 {
        return Err(VerificationError::HistoryProof(
            "Computed start version for the key history should be non-zero".to_string(),
        ));
    }

    if end_version > current_epoch {
        return Err(VerificationError::HistoryProof(
            "Computed end version for the key history should not exceed current epoch".to_string(),
        ));
    }

    match params {
        HistoryParams::Complete => {
            if start_version != 1 {
                return Err(VerificationError::HistoryProof(format!(
                    "Expected start version to be 1 given that it is a complete history, but got start_version = {}",
                    start_version
                )));
            }
        },
        HistoryParams::MostRecent(recency) => {
            use core::cmp::Ordering;
            match num_proofs.cmp(&recency) {
                Ordering::Greater => {
                    return Err(VerificationError::HistoryProof(format!(
                        "Expected at most {} update proofs, but got {} of them",
                        recency, num_proofs
                    )));
                },
                Ordering::Less => {
                    if start_version != 1 {
                        return Err(VerificationError::HistoryProof(format!(
                            "Expected at most {} update proofs, but got {} of them",
                            recency, num_proofs
                        )));
                    }
                },
                Ordering::Equal => {},
            }
        },
    }

    let (past_marker_versions, future_marker_versions) =
        super::get_marker_versions(start_version, end_version, current_epoch);

    if past_marker_versions.len() != proof.past_marker_vrf_proofs.len() {
        return Err(VerificationError::HistoryProof(format!(
            "Expected {} past marker proofs, but got {}",
            past_marker_versions.len(),
            proof.past_marker_vrf_proofs.len()
        )));
    }
    if proof.past_marker_vrf_proofs.len() != proof.existence_of_past_marker_proofs.len() {
        return Err(VerificationError::HistoryProof(format!(
            "Expected equal number of past marker proofs, but got ({}, {})",
            proof.past_marker_vrf_proofs.len(),
            proof.existence_of_past_marker_proofs.len()
        )));
    }

    if future_marker_versions.len() != proof.future_marker_vrf_proofs.len() {
        return Err(VerificationError::HistoryProof(format!(
            "Expected {} future marker proofs, but got {}",
            future_marker_versions.len(),
            proof.future_marker_vrf_proofs.len()
        )));
    }
    if proof.future_marker_vrf_proofs.len() != proof.non_existence_of_future_marker_proofs.len() {
        return Err(VerificationError::HistoryProof(format!(
            "Expected equal number of future marker proofs, but got ({}, {})",
            proof.future_marker_vrf_proofs.len(),
            proof.non_existence_of_future_marker_proofs.len()
        )));
    }

    Ok((past_marker_versions, future_marker_versions))
}

pub fn key_history_verify<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash: Digest,
    current_epoch: u64,
    akd_label: AkdLabel,
    proof: HistoryProof,
    verification_params: HistoryVerificationParams,
) -> Result<Vec<VerifyResult>, VerificationError> {
    let mut results = Vec::new();

    let params: HistoryParams = match verification_params {
        HistoryVerificationParams::Default { history_params } => history_params,
        HistoryVerificationParams::AllowMissingValues { history_params } => history_params,
    };
    let (past_marker_versions, future_marker_versions) =
        verify_with_history_params(current_epoch, &akd_label, &proof, params)?;

    let mut maybe_previous_update_epoch = None;
    for update_proof in proof.update_proofs.into_iter() {
        if let Some(previous_update_epoch) = maybe_previous_update_epoch {
            if update_proof.epoch > previous_update_epoch {
                return Err(VerificationError::HistoryProof(format!(
                    "Version numbers for updates are decreasing, but their corresponding
                    epochs are not decreasing: epoch = {}, previous epoch = {}",
                    update_proof.epoch, previous_update_epoch
                )));
            }
        }
        maybe_previous_update_epoch = Some(update_proof.epoch);
        let result = verify_single_update_proof::<TC>(
            root_hash,
            vrf_public_key,
            update_proof,
            &akd_label,
            verification_params,
        )?;
        results.push(result);
    }

    for (i, version) in past_marker_versions.iter().enumerate() {
        verify_existence::<TC>(
            vrf_public_key,
            root_hash,
            &akd_label,
            VersionFreshness::Fresh,
            *version,
            &proof.past_marker_vrf_proofs[i],
            &proof.existence_of_past_marker_proofs[i],
        )?;
    }

    for (i, version) in future_marker_versions.iter().enumerate() {
        verify_nonexistence::<TC>(
            vrf_public_key,
            root_hash,
            &akd_label,
            VersionFreshness::Fresh,
            *version,
            &proof.future_marker_vrf_proofs[i],
            &proof.non_existence_of_future_marker_proofs[i],
        )
        .map_err(|_| {
            VerificationError::HistoryProof(format!(
                "Non-existence of future marker proof of label {akd_label:?} with
                version {version:?} at epoch {current_epoch:?} does not verify"
            ))
        })?;
    }

    Ok(results)
}

fn verify_single_update_proof<TC: Configuration>(
    root_hash: Digest,
    vrf_public_key: &[u8],
    proof: UpdateProof,
    akd_label: &AkdLabel,
    params: HistoryVerificationParams,
) -> Result<VerifyResult, VerificationError> {
    match (params, &proof.value) {
        (HistoryVerificationParams::AllowMissingValues { .. }, bytes)
            if bytes.0 == super::TOMBSTONE =>
        {
            verify_existence::<TC>(
                vrf_public_key,
                root_hash,
                akd_label,
                VersionFreshness::Fresh,
                proof.version,
                &proof.existence_vrf_proof,
                &proof.existence_proof,
            )?;
        },
        (_, akd_value) => {
            verify_existence_with_val::<TC>(
                vrf_public_key,
                root_hash,
                akd_label,
                akd_value,
                proof.epoch,
                &proof.commitment_nonce,
                VersionFreshness::Fresh,
                proof.version,
                &proof.existence_vrf_proof,
                &proof.existence_proof,
            )?;
        },
    };

    let verify_result = VerifyResult {
        epoch: proof.epoch,
        version: proof.version,
        value: proof.value,
    };

    if proof.version <= 1 {
        return Ok(verify_result);
    }

    let previous_version_proof = proof.previous_version_proof.as_ref().ok_or_else(|| {
        VerificationError::HistoryProof("Missing membership proof for previous version".to_string())
    })?;
    let previous_version_vrf_proof =
        proof.previous_version_vrf_proof.as_ref().ok_or_else(|| {
            VerificationError::HistoryProof("Missing VRF proof for previous version".to_string())
        })?;

    verify_existence_with_commitment::<TC>(
        vrf_public_key,
        root_hash,
        akd_label,
        TC::stale_azks_value(),
        proof.epoch,
        VersionFreshness::Stale,
        proof.version - 1,
        previous_version_vrf_proof,
        previous_version_proof,
    )?;

    Ok(verify_result)
}
