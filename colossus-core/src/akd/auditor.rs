use super::{
    Azks, AzksParallelismConfig, AzksValue, Configuration, Digest, InsertMode,
    errors::{AkdError, AuditorError, AzksError},
    proofs::{AppendOnlyProof, SingleAppendOnlyProof},
};
use crate::storage::{manager::StorageManager, memory::AsyncInMemoryDatabase};

#[tracing::instrument(skip_all)]
pub async fn audit_verify<TC: Configuration>(
    hashes: Vec<Digest>,
    proof: AppendOnlyProof,
) -> Result<(), AkdError> {
    if proof.epochs.len() + 1 != hashes.len() {
        return Err(AkdError::AuditErr(AuditorError::VerifyAuditProof(format!(
            "The proof has a different number of epochs than needed for hashes.
            The number of hashes you provide should be one more than the number of epochs!
            Number of epochs = {}, number of hashes = {}",
            proof.epochs.len(),
            hashes.len()
        ))));
    }
    if proof.epochs.len() != proof.proofs.len() {
        return Err(AkdError::AuditErr(AuditorError::VerifyAuditProof(format!(
            "The proof has {} epochs and {} proofs. These should be equal!",
            proof.epochs.len(),
            proof.proofs.len()
        ))));
    }
    for i in 0..hashes.len() - 1 {
        let start_hash = hashes[i];
        let end_hash = hashes[i + 1];
        verify_consecutive_append_only::<TC>(
            &proof.proofs[i],
            start_hash,
            end_hash,
            proof.epochs[i] + 1,
        )
        .await?;
    }
    Ok(())
}

#[tracing::instrument(skip_all)]
pub async fn verify_consecutive_append_only<TC: Configuration>(
    proof: &SingleAppendOnlyProof,
    start_hash: Digest,
    end_hash: Digest,
    end_epoch: u64,
) -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let manager = StorageManager::new_no_cache(db);

    let mut azks = Azks::new::<TC, _>(&manager).await?;
    azks.batch_insert_nodes::<TC, _>(
        &manager,
        proof.unchanged_nodes.clone(),
        InsertMode::Auditor,
        AzksParallelismConfig::default(),
    )
    .await?;
    let computed_start_root_hash: Digest = azks.get_root_hash::<TC, _>(&manager).await?;
    let mut verified = computed_start_root_hash == start_hash;
    azks.latest_epoch = end_epoch - 1;
    let updated_inserted = proof
        .inserted
        .iter()
        .map(|x| {
            let mut y = *x;
            y.value = AzksValue(TC::hash_leaf_with_commitment(x.value, end_epoch).0);
            y
        })
        .collect();
    azks.batch_insert_nodes::<TC, _>(
        &manager,
        updated_inserted,
        InsertMode::Auditor,
        AzksParallelismConfig::default(),
    )
    .await?;
    let computed_end_root_hash: Digest = azks.get_root_hash::<TC, _>(&manager).await?;
    verified = verified && (computed_end_root_hash == end_hash);
    if !verified {
        return Err(AkdError::AzksErr(AzksError::VerifyAppendOnlyProof));
    }
    Ok(())
}
