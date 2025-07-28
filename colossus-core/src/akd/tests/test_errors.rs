use crate::{
    Configuration,
    akd::{
        AkdLabel, AkdValue, Azks, AzksParallelismConfig, EpochHash, NodeLabel,
        auditor::audit_verify,
        ecvrf::HardCodedAkdVRF,
        errors::{AkdError, DirectoryError, StorageError},
        tests::{MockLocalDatabase, setup_mocked_db},
        tree_node::TreeNodeWithPreviousValue,
        verify::{HistoryParams, HistoryVerificationParams, key_history_verify, lookup_verify},
    },
    directory::{Directory, PublishCorruption, ReadOnlyDirectory},
    storage::{
        ecvrf::VRFKeyStorage,
        manager::StorageManager,
        memory::AsyncInMemoryDatabase,
        traits::Database,
        types::{DbRecord, KeyData, ValueState},
    },
    test_config,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::default::Default;

test_config!(test_directory_azks_bootstrapping);
async fn test_directory_azks_bootstrapping<TC: Configuration>() -> Result<(), AkdError> {
    let vrf = HardCodedAkdVRF {};

    let mut mock_db = MockLocalDatabase { ..Default::default() };
    mock_db
        .expect_get::<Azks>()
        .returning(|_| Err(StorageError::Connection("Fire!".to_string())));
    mock_db.expect_set().times(0);
    let storage = StorageManager::new_no_cache(mock_db);

    let maybe_akd =
        Directory::<TC, _, _>::new(storage, vrf.clone(), AzksParallelismConfig::default()).await;
    assert!(maybe_akd.is_err());

    let mut mock_db = MockLocalDatabase { ..Default::default() };
    let test_db = AsyncInMemoryDatabase::new();
    setup_mocked_db(&mut mock_db, &test_db);
    let storage = StorageManager::new_no_cache(mock_db);

    let maybe_akd =
        Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await;
    assert!(maybe_akd.is_ok());

    let akd = maybe_akd.expect("Failed to get create a Directory!");
    let azks = akd.retrieve_azks().await.expect("Failed to get aZKS!");
    assert_eq!(0, azks.get_latest_epoch());

    Ok(())
}

test_config!(test_key_history_dirty_reads);
async fn test_key_history_dirty_reads<TC: Configuration>() -> Result<(), AkdError> {
    let committed_epoch = 10;
    let dirty_epoch = 11;

    let mut mock_db = MockLocalDatabase::default();
    mock_db.expect_get::<Azks>().returning(move |_| {
        Ok(DbRecord::Azks(Azks {
            latest_epoch: committed_epoch,
            num_nodes: 1,
        }))
    });
    mock_db.expect_get_user_data().returning(move |_| {
        Ok(KeyData {
            states: vec![ValueState {
                value: AkdValue(Vec::new()),
                version: 2,
                label: NodeLabel { label_val: [0u8; 32], label_len: 32 },
                epoch: dirty_epoch,
                username: AkdLabel::from("ferris"),
            }],
        })
    });

    mock_db
        .expect_get::<TreeNodeWithPreviousValue>()
        .returning(|_| Err(StorageError::Other("Fake!".to_string())));

    let storage = StorageManager::new_no_cache(mock_db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    let _res = akd.key_history(&AkdLabel::from("ferris"), HistoryParams::MostRecent(1)).await;

    Ok(())
}

test_config!(test_read_during_publish);
async fn test_read_during_publish<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db.clone());
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world")),
        (AkdLabel::from("hello2"), AkdValue::from("world2")),
    ])
    .await
    .unwrap();

    let root_hash_1 = akd.get_epoch_hash().await?.1;

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world_2")),
        (AkdLabel::from("hello2"), AkdValue::from("world2_2")),
    ])
    .await
    .unwrap();

    let root_hash_2 = akd.get_epoch_hash().await?.1;

    let checkpoint_azks = akd.retrieve_azks().await.unwrap();

    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world_3")),
        (AkdLabel::from("hello2"), AkdValue::from("world2_3")),
        (AkdLabel::from("hello3"), AkdValue::from("world3")),
    ])
    .await
    .unwrap();

    db.set(DbRecord::Azks(checkpoint_azks))
        .await
        .expect("Error resetting directory to previous epoch");

    let storage = StorageManager::new_no_cache(db.clone());
    let vrf = HardCodedAkdVRF {};
    let akd = ReadOnlyDirectory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default())
        .await
        .unwrap();

    let vrf_pk = akd.get_public_key().await.unwrap();

    let (lookup_proof, root_hash) = akd.lookup(AkdLabel::from("hello")).await.unwrap();
    assert_eq!(AkdValue::from("world_2"), lookup_proof.value);
    lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        lookup_proof,
    )
    .unwrap();

    let (history_proof, root_hash) = akd
        .key_history(&AkdLabel::from("hello"), HistoryParams::default())
        .await
        .unwrap();
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        history_proof,
        HistoryVerificationParams::default(),
    )
    .unwrap();

    let recently_added_lookup_result = akd.lookup(AkdLabel::from("hello3")).await;
    assert!(matches!(
        recently_added_lookup_result,
        Err(AkdError::Storage(StorageError::NotFound(_)))
    ));

    let recently_added_history_result =
        akd.key_history(&AkdLabel::from("hello3"), HistoryParams::default()).await;
    assert!(matches!(
        recently_added_history_result,
        Err(AkdError::Storage(StorageError::NotFound(_)))
    ));

    let audit_proof = akd.audit(1, 2).await.unwrap();
    audit_verify::<TC>(vec![root_hash_1, root_hash_2], audit_proof).await.unwrap();

    let invalid_audit = akd.audit(2, 3).await;
    assert!(invalid_audit.is_err());

    Ok(())
}

test_config!(test_directory_read_only_mode);
async fn test_directory_read_only_mode<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};

    let akd =
        ReadOnlyDirectory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await;
    assert!(akd.is_err());

    Ok(())
}

test_config!(test_publish_duplicate_entries);
async fn test_publish_duplicate_entries<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd =
        Directory::<TC, _, _>::new(storage, vrf.clone(), AzksParallelismConfig::default()).await?;

    let mut updates = vec![];
    for i in 0..10 {
        updates.push((
            AkdLabel(format!("hello1{i}").as_bytes().to_vec()),
            AkdValue(format!("hello1{i}").as_bytes().to_vec()),
        ));
    }

    updates.push(updates[0].clone());

    let Err(AkdError::Directory(DirectoryError::Publish(_))) = akd.publish(updates).await else {
        panic!("Expected a directory publish error");
    };

    Ok(())
}

test_config!(test_malicious_key_history);
async fn test_malicious_key_history<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default()).await?;

    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world"))]).await?;

    let corruption_2 = PublishCorruption::UnmarkedStaleVersion(AkdLabel::from("hello"));
    akd.publish_malicious_update(
        vec![(AkdLabel::from("hello"), AkdValue::from("world2"))],
        corruption_2,
    )
    .await?;

    let (key_history_proof, root_hash) =
        akd.key_history(&AkdLabel::from("hello"), HistoryParams::default()).await?;

    let vrf_pk = akd.get_public_key().await?;

    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    ).expect_err("The key history proof should fail here since the previous value was not marked stale at all");

    let corruption_3 = PublishCorruption::MarkVersionStale(AkdLabel::from("hello"), 1);
    akd.publish_malicious_update(
        vec![(AkdLabel::from("hello2"), AkdValue::from("world"))],
        corruption_3,
    )
    .await?;

    let (key_history_proof, root_hash) =
        akd.key_history(&AkdLabel::from("hello"), HistoryParams::default()).await?;

    let vrf_pk = akd.get_public_key().await?;

    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    ).expect_err("The key history proof should fail here since the previous value was marked stale one epoch too late.");

    Ok(())
}

test_config!(test_key_history_verify_malformed);
async fn test_key_history_verify_malformed<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd =
        Directory::<TC, _, _>::new(storage, vrf.clone(), AzksParallelismConfig::default()).await?;
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    for _ in 0..100 {
        let mut updates = vec![];
        updates
            .push((AkdLabel("label".to_string().as_bytes().to_vec()), AkdValue::random(&mut rng)));
        akd.publish(updates.clone()).await?;
    }

    for _ in 0..100 {
        let mut updates = vec![];
        updates.push((
            AkdLabel("another label".to_string().as_bytes().to_vec()),
            AkdValue::random(&mut rng),
        ));
        akd.publish(updates.clone()).await?;
    }

    let EpochHash(current_epoch, root_hash) = akd.get_epoch_hash().await?;

    let vrf_pk = akd.get_public_key().await?;
    let target_label = AkdLabel("label".to_string().as_bytes().to_vec());

    let history_params_5 = HistoryParams::MostRecent(5);

    let (key_history_proof, _) = akd.key_history(&target_label, history_params_5).await?;

    let correct_verification_params =
        HistoryVerificationParams::Default { history_params: history_params_5 };

    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        target_label.clone(),
        key_history_proof.clone(),
        correct_verification_params,
    )?;

    for bad_params in [
        HistoryParams::MostRecent(1),
        HistoryParams::MostRecent(4),
        HistoryParams::MostRecent(6),
        HistoryParams::default(),
    ] {
        assert!(
            key_history_verify::<TC>(
                vrf_pk.as_bytes(),
                root_hash,
                current_epoch,
                target_label.clone(),
                key_history_proof.clone(),
                HistoryVerificationParams::Default { history_params: bad_params },
            )
            .is_err()
        );
    }

    let mut malformed_proof_1 = key_history_proof.clone();
    malformed_proof_1.past_marker_vrf_proofs = key_history_proof.past_marker_vrf_proofs
        [..key_history_proof.past_marker_vrf_proofs.len() - 1]
        .to_vec();
    let mut malformed_proof_2 = key_history_proof.clone();
    malformed_proof_2.existence_of_past_marker_proofs = key_history_proof
        .existence_of_past_marker_proofs
        [..key_history_proof.existence_of_past_marker_proofs.len() - 1]
        .to_vec();
    let mut malformed_proof_3 = key_history_proof.clone();
    malformed_proof_3.future_marker_vrf_proofs = key_history_proof.future_marker_vrf_proofs
        [..key_history_proof.future_marker_vrf_proofs.len() - 1]
        .to_vec();
    let mut malformed_proof_4 = key_history_proof.clone();
    malformed_proof_4.non_existence_of_future_marker_proofs = key_history_proof
        .non_existence_of_future_marker_proofs
        [..key_history_proof.non_existence_of_future_marker_proofs.len() - 1]
        .to_vec();

    for malformed_proof in
        [malformed_proof_1, malformed_proof_2, malformed_proof_3, malformed_proof_4]
    {
        assert!(
            key_history_verify::<TC>(
                vrf_pk.as_bytes(),
                root_hash,
                current_epoch,
                target_label.clone(),
                malformed_proof,
                correct_verification_params
            )
            .is_err()
        );
    }

    let mut malformed_proof_start_version_is_zero = key_history_proof.clone();
    malformed_proof_start_version_is_zero.update_proofs[0].epoch = 0;
    let mut malformed_proof_end_version_exceeds_epoch = key_history_proof.clone();
    malformed_proof_end_version_exceeds_epoch.update_proofs[0].epoch = current_epoch + 1;

    for malformed_proof in
        [malformed_proof_start_version_is_zero, malformed_proof_end_version_exceeds_epoch]
    {
        assert!(
            key_history_verify::<TC>(
                vrf_pk.as_bytes(),
                root_hash,
                current_epoch,
                target_label.clone(),
                malformed_proof,
                correct_verification_params,
            )
            .is_err()
        );
    }

    Ok(())
}

test_config!(test_lookup_verify_invalid_version_number);
async fn test_lookup_verify_invalid_version_number<TC: Configuration>() -> Result<(), AkdError> {
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

    for _ in 0..10 {
        akd.publish(updates.clone()).await?;
    }

    let target_label = AkdLabel(format!("hello1{}", 0).as_bytes().to_vec());

    let (lookup_proof, root_hash) = akd.lookup(target_label.clone()).await?;

    let vrf_pk = vrf.get_vrf_public_key().await?;

    let akd_result = crate::akd::verify::lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch() - 1, // To fake a lower epoch and trigger the error condition
        target_label.clone(),
        lookup_proof,
    );

    match akd_result {
        Err(crate::akd::errors::VerificationError::LookupProof(_)) => (),
        _ => panic!("Expected an invalid epoch error"),
    }

    Ok(())
}

/*
=========== Test Helpers ===========
*/

async fn async_poll_helper_proof<TC: Configuration, T: Database + 'static, V: VRFKeyStorage>(
    reader: &ReadOnlyDirectory<TC, T, V>,
    value: AkdValue,
) -> Result<(), AkdError> {
    let (lookup_proof, root_hash) = reader.lookup(AkdLabel::from("hello")).await?;
    assert_eq!(value, lookup_proof.value);
    let pk = reader.get_public_key().await?;
    lookup_verify::<TC>(
        pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        lookup_proof,
    )?;
    Ok(())
}
