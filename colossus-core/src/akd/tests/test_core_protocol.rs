use crate::{
    Configuration,
    akd::{
        AkdLabel, AkdValue, AzksParallelismConfig, DIGEST_BYTES, EpochHash,
        auditor::{audit_verify, verify_consecutive_append_only},
        ecvrf::HardCodedAkdVRF,
        errors::AkdError,
        proofs::{AppendOnlyProof, VerifyResult},
        verify::{HistoryParams, HistoryVerificationParams, key_history_verify, lookup_verify},
    },
    directory::Directory,
    storage::{ecvrf::VRFKeyStorage, manager::StorageManager, memory::AsyncInMemoryDatabase},
    test_config,
};
use rand::{SeedableRng, rngs::StdRng};

test_config!(test_empty_tree_root_hash);
async fn test_empty_tree_root_hash<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd: Directory<_, AsyncInMemoryDatabase, HardCodedAkdVRF> =
        Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    let hash = akd.get_epoch_hash().await?.1;

    assert_eq!(TC::compute_root_hash_from_val(&TC::empty_root_value()), hash);

    Ok(())
}

test_config!(test_simple_publish);
async fn test_simple_publish<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world"))]).await?;
    Ok(())
}

test_config!(test_complex_publish);
async fn test_complex_publish<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    let num_entries = 10000;
    let mut entries = vec![];
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0..num_entries {
        let label = AkdLabel::random(&mut rng);
        let value = AkdValue::random(&mut rng);
        entries.push((label, value));
    }
    akd.publish(entries).await?;
    Ok(())
}

test_config!(test_simple_lookup);
async fn test_simple_lookup<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world")),
        (AkdLabel::from("hello2"), AkdValue::from("world2")),
    ])
    .await?;

    let (lookup_proof, root_hash) = akd.lookup(AkdLabel::from("hello")).await?;

    let vrf_pk = akd.get_public_key().await?;

    lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        lookup_proof,
    )?;
    Ok(())
}

test_config!(test_small_key_history);
async fn test_small_key_history<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world"))]).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world2"))]).await?;

    let (key_history_proof, root_hash) =
        akd.key_history(&AkdLabel::from("hello"), HistoryParams::default()).await?;

    let vrf_pk = akd.get_public_key().await?;

    let result = key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    )?;

    assert_eq!(
        result,
        vec![
            VerifyResult {
                epoch: 2,
                version: 2,
                value: AkdValue::from("world2")
            },
            VerifyResult {
                epoch: 1,
                version: 1,
                value: AkdValue::from("world")
            },
        ]
    );

    Ok(())
}

test_config!(test_simple_key_history);
async fn test_simple_key_history<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world")),
        (AkdLabel::from("hello2"), AkdValue::from("world2")),
    ])
    .await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world_2")),
        (AkdLabel::from("hello2"), AkdValue::from("world2_2")),
    ])
    .await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world3")),
        (AkdLabel::from("hello2"), AkdValue::from("world4")),
    ])
    .await?;

    akd.publish(vec![
        (AkdLabel::from("hello3"), AkdValue::from("world")),
        (AkdLabel::from("hello4"), AkdValue::from("world2")),
    ])
    .await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world_updated"))])
        .await?;

    akd.publish(vec![
        (AkdLabel::from("hello3"), AkdValue::from("world6")),
        (AkdLabel::from("hello4"), AkdValue::from("world12")),
    ])
    .await?;

    let (key_history_proof, _) =
        akd.key_history(&AkdLabel::from("hello"), HistoryParams::default()).await?;

    if key_history_proof.update_proofs.len() != 4 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 4 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }

    let EpochHash(current_epoch, root_hash) = akd.get_epoch_hash().await?;

    let vrf_pk = akd.get_public_key().await?;
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    )?;

    let (key_history_proof, _) =
        akd.key_history(&AkdLabel::from("hello2"), HistoryParams::default()).await?;

    if key_history_proof.update_proofs.len() != 3 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 3 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from("hello2"),
        key_history_proof,
        HistoryVerificationParams::default(),
    )?;

    let (key_history_proof, _) =
        akd.key_history(&AkdLabel::from("hello3"), HistoryParams::default()).await?;

    if key_history_proof.update_proofs.len() != 2 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 2 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from("hello3"),
        key_history_proof,
        HistoryVerificationParams::default(),
    )?;

    let (key_history_proof, _) =
        akd.key_history(&AkdLabel::from("hello4"), HistoryParams::default()).await?;

    if key_history_proof.update_proofs.len() != 2 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 2 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from("hello4"),
        key_history_proof.clone(),
        HistoryVerificationParams::default(),
    )?;

    let mut borked_proof = key_history_proof;
    borked_proof.update_proofs = borked_proof.update_proofs.into_iter().rev().collect();
    let result = key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from("hello4"),
        borked_proof,
        HistoryVerificationParams::default(),
    );
    assert!(result.is_err(), "{}", "{result:?}");

    Ok(())
}

test_config!(test_complex_verification_many_versions);
async fn test_complex_verification_many_versions<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};

    let akd =
        Directory::<TC, _, _>::new(storage_manager, vrf, AzksParallelismConfig::default()).await?;
    let vrf_pk = akd.get_public_key().await?;

    let num_labels = 4;
    let num_iterations = 20;
    let mut previous_hash = [0u8; DIGEST_BYTES];
    for epoch in 1..num_iterations {
        let mut to_insert = vec![];
        for i in 0..num_labels {
            let index = 1 << i;
            let label = AkdLabel::from(format!("{index}").as_str());
            let value = AkdValue::from(format!("{index},{epoch}").as_str());
            if epoch % index == 0 {
                to_insert.push((label, value));
            }
        }
        let epoch_hash = akd.publish(to_insert).await?;

        if epoch > 1 {
            let audit_proof = akd.audit(epoch_hash.epoch() - 1, epoch_hash.epoch()).await?;
            crate::akd::auditor::audit_verify::<TC>(
                vec![previous_hash, epoch_hash.hash()],
                audit_proof,
            )
            .await?;
        }

        previous_hash = epoch_hash.hash();

        for i in 0..num_labels {
            let index = 1 << i;
            if epoch < index {
                continue;
            }
            let latest_added_epoch = epoch_hash.epoch() - (epoch_hash.epoch() % index);
            let label = AkdLabel::from(format!("{index}").as_str());
            let lookup_value = AkdValue::from(format!("{index},{latest_added_epoch}").as_str());

            let (lookup_proof, epoch_hash_from_lookup) = akd.lookup(label.clone()).await?;
            assert_eq!(epoch_hash, epoch_hash_from_lookup);
            let lookup_verify_result = lookup_verify::<TC>(
                vrf_pk.as_bytes(),
                epoch_hash.hash(),
                epoch_hash.epoch(),
                label.clone(),
                lookup_proof,
            )?;
            assert_eq!(lookup_verify_result.epoch, latest_added_epoch);
            assert_eq!(lookup_verify_result.value, lookup_value);
            assert_eq!(lookup_verify_result.version, epoch / index);

            let (history_proof, epoch_hash_from_history) =
                akd.key_history(&label, HistoryParams::Complete).await?;
            assert_eq!(epoch_hash, epoch_hash_from_history);
            let history_results = key_history_verify::<TC>(
                vrf_pk.as_bytes(),
                epoch_hash.hash(),
                epoch_hash.epoch(),
                label,
                history_proof,
                HistoryVerificationParams::default(),
            )?;
            for (j, res) in history_results.iter().enumerate() {
                let added_in_epoch =
                    epoch_hash.epoch() - (epoch_hash.epoch() % index) - (j as u64) * index;
                let history_value = AkdValue::from(format!("{index},{added_in_epoch}").as_str());
                assert_eq!(res.epoch, added_in_epoch);
                assert_eq!(res.value, history_value);
                assert_eq!(res.version, epoch / index - j as u64);
            }
        }
    }

    Ok(())
}

test_config!(test_limited_key_history);
async fn test_limited_key_history<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};

    let akd =
        Directory::<TC, _, _>::new(storage_manager, vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world")),
        (AkdLabel::from("hello2"), AkdValue::from("world2")),
    ])
    .await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world_2")),
        (AkdLabel::from("hello2"), AkdValue::from("world2_2")),
    ])
    .await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world3")),
        (AkdLabel::from("hello2"), AkdValue::from("world4")),
    ])
    .await?;

    akd.publish(vec![
        (AkdLabel::from("hello3"), AkdValue::from("world")),
        (AkdLabel::from("hello4"), AkdValue::from("world2")),
    ])
    .await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world_updated"))])
        .await?;

    akd.publish(vec![
        (AkdLabel::from("hello3"), AkdValue::from("world6")),
        (AkdLabel::from("hello4"), AkdValue::from("world12")),
    ])
    .await?;

    akd.publish(vec![
        (AkdLabel::from("hello3"), AkdValue::from("world7")),
        (AkdLabel::from("hello4"), AkdValue::from("world13")),
    ])
    .await?;

    let vrf_pk = akd.get_public_key().await?;

    let current_azks = akd.retrieve_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();

    let (history_proof, root_hash) =
        akd.key_history(&AkdLabel::from("hello"), HistoryParams::MostRecent(1)).await?;
    assert_eq!(1, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);

    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        current_epoch,
        AkdLabel::from("hello"),
        history_proof,
        HistoryVerificationParams::Default {
            history_params: HistoryParams::MostRecent(1),
        },
    )?;

    let (history_proof, root_hash) =
        akd.key_history(&AkdLabel::from("hello"), HistoryParams::MostRecent(3)).await?;
    assert_eq!(3, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);
    assert_eq!(3, history_proof.update_proofs[1].epoch);
    assert_eq!(2, history_proof.update_proofs[2].epoch);

    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        current_epoch,
        AkdLabel::from("hello"),
        history_proof,
        HistoryVerificationParams::Default {
            history_params: HistoryParams::MostRecent(3),
        },
    )?;

    Ok(())
}

test_config!(test_simple_audit);
async fn test_simple_audit<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world")),
        (AkdLabel::from("hello2"), AkdValue::from("world2")),
    ])
    .await?;

    let root_hash_1 = akd.get_epoch_hash().await?.1;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world_2")),
        (AkdLabel::from("hello2"), AkdValue::from("world2_2")),
    ])
    .await?;

    let root_hash_2 = akd.get_epoch_hash().await?.1;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world3")),
        (AkdLabel::from("hello2"), AkdValue::from("world4")),
    ])
    .await?;

    let root_hash_3 = akd.get_epoch_hash().await?.1;

    akd.publish(vec![
        (AkdLabel::from("hello3"), AkdValue::from("world")),
        (AkdLabel::from("hello4"), AkdValue::from("world2")),
    ])
    .await?;

    let root_hash_4 = akd.get_epoch_hash().await?.1;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world_updated"))])
        .await?;

    let root_hash_5 = akd.get_epoch_hash().await?.1;

    akd.publish(vec![
        (AkdLabel::from("hello3"), AkdValue::from("world6")),
        (AkdLabel::from("hello4"), AkdValue::from("world12")),
    ])
    .await?;

    let root_hash_6 = akd.get_epoch_hash().await?.1;

    let audit_proof_1 = akd.audit(1, 2).await?;
    audit_verify::<TC>(vec![root_hash_1, root_hash_2], audit_proof_1).await?;

    let audit_proof_2 = akd.audit(1, 3).await?;
    audit_verify::<TC>(vec![root_hash_1, root_hash_2, root_hash_3], audit_proof_2).await?;

    let audit_proof_3 = akd.audit(1, 4).await?;
    audit_verify::<TC>(vec![root_hash_1, root_hash_2, root_hash_3, root_hash_4], audit_proof_3)
        .await?;

    let audit_proof_4 = akd.audit(1, 5).await?;
    audit_verify::<TC>(
        vec![root_hash_1, root_hash_2, root_hash_3, root_hash_4, root_hash_5],
        audit_proof_4,
    )
    .await?;

    let audit_proof_5 = akd.audit(2, 3).await?;
    audit_verify::<TC>(vec![root_hash_2, root_hash_3], audit_proof_5).await?;

    let audit_proof_6 = akd.audit(2, 4).await?;
    audit_verify::<TC>(vec![root_hash_2, root_hash_3, root_hash_4], audit_proof_6).await?;

    let audit_proof_7 = akd.audit(4, 6).await?;
    audit_verify::<TC>(vec![root_hash_4, root_hash_5, root_hash_6], audit_proof_7).await?;

    let audit_proof_8 = akd.audit(4, 6).await?;
    let invalid_audit_verification = audit_verify::<TC>(
        vec![root_hash_1, root_hash_2, root_hash_3, root_hash_4, root_hash_5],
        audit_proof_8,
    )
    .await;
    assert!(matches!(invalid_audit_verification, Err(AkdError::AuditErr(_))));

    let audit_proof_9 = akd.audit(1, 5).await?;
    let audit_proof_10 = akd.audit(4, 6).await?;
    let invalid_audit_proof = AppendOnlyProof {
        proofs: audit_proof_10.proofs,
        epochs: audit_proof_9.epochs,
    };
    let invalid_audit_verification = audit_verify::<TC>(
        vec![root_hash_1, root_hash_2, root_hash_3, root_hash_4, root_hash_5],
        invalid_audit_proof,
    )
    .await;
    assert!(matches!(invalid_audit_verification, Err(AkdError::AuditErr(_))));

    let audit_proof_11 = akd.audit(1, 2).await?;
    let verification = verify_consecutive_append_only::<TC>(
        &audit_proof_11.proofs[0],
        root_hash_1,
        root_hash_3, // incorrect end hash - should be root_hash_2
        audit_proof_11.epochs[0] + 1,
    )
    .await;
    assert!(matches!(verification, Err(AkdError::AzksErr(_))));

    let invalid_audit = akd.audit(3, 3).await;
    assert!(invalid_audit.is_err());

    let invalid_audit = akd.audit(3, 2).await;
    assert!(invalid_audit.is_err());

    let invalid_audit = akd.audit(6, 7).await;
    assert!(invalid_audit.is_err());

    Ok(())
}

test_config!(test_simple_lookup_for_small_tree);
async fn test_simple_lookup_for_small_tree<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};

    let akd =
        Directory::<TC, _, _>::new(storage, vrf.clone(), AzksParallelismConfig::default()).await?;

    let mut updates = vec![];
    for i in 0..2 {
        updates.push((
            AkdLabel(format!("hello1{i}").as_bytes().to_vec()),
            AkdValue(format!("hello1{i}").as_bytes().to_vec()),
        ));
    }

    akd.publish(updates).await?;

    let target_label = AkdLabel(format!("hello1{}", 0).as_bytes().to_vec());

    let (lookup_proof, root_hash) = akd.lookup(target_label.clone()).await?;

    let vrf_pk = vrf.get_vrf_public_key().await?;

    let akd_result = crate::akd::verify::lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        target_label.clone(),
        lookup_proof,
    )?;

    assert_eq!(
        akd_result,
        VerifyResult {
            epoch: 1,
            version: 1,
            value: AkdValue::from("hello10")
        },
    );

    Ok(())
}

test_config!(test_tombstoned_key_history);
async fn test_tombstoned_key_history<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};

    let akd =
        Directory::<TC, _, _>::new(storage.clone(), vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world"))]).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world2"))]).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world3"))]).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world4"))]).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world5"))]).await?;

    let vrf_pk = akd.get_public_key().await?;

    storage.tombstone_value_states(&AkdLabel::from("hello"), 2).await?;

    let (history_proof, root_hash) =
        akd.key_history(&AkdLabel::from("hello"), HistoryParams::default()).await?;
    assert_eq!(5, history_proof.update_proofs.len());

    let tombstones = key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        history_proof.clone(),
        HistoryVerificationParams::default(),
    );
    assert!(tombstones.is_err());

    let results = key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        history_proof,
        HistoryVerificationParams::AllowMissingValues { history_params: HistoryParams::default() },
    )?;
    assert_ne!(crate::akd::TOMBSTONE, results[0].value.0);
    assert_ne!(crate::akd::TOMBSTONE, results[1].value.0);
    assert_ne!(crate::akd::TOMBSTONE, results[2].value.0);
    assert_eq!(crate::akd::TOMBSTONE, results[3].value.0);
    assert_eq!(crate::akd::TOMBSTONE, results[4].value.0);

    Ok(())
}
