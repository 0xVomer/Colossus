use crate::{
    Configuration,
    akd::{
        AkdLabel, AkdValue, AzksParallelismConfig,
        ecvrf::HardCodedAkdVRF,
        errors::{AkdError, StorageError},
        tests::{MockLocalDatabase, setup_mocked_db},
        tree_node::TreeNodeWithPreviousValue,
    },
    directory::Directory,
    storage::{manager::StorageManager, memory::AsyncInMemoryDatabase},
    test_config,
};

test_config!(test_publish_op_makes_no_get_requests);
async fn test_publish_op_makes_no_get_requests<TC: Configuration>() -> Result<(), AkdError> {
    let test_db = AsyncInMemoryDatabase::new();

    let mut db = MockLocalDatabase { ..Default::default() };
    setup_mocked_db(&mut db, &test_db);

    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default())
        .await
        .expect("Failed to create directory");

    let mut updates = vec![];
    for i in 0..2 {
        updates.push((
            AkdLabel(format!("hello1{i}").as_bytes().to_vec()),
            AkdValue(format!("hello1{i}").as_bytes().to_vec()),
        ));
    }

    akd.publish(updates).await.expect("Failed to do initial publish");

    let mut db2 = MockLocalDatabase { ..Default::default() };
    setup_mocked_db(&mut db2, &test_db);
    db2.expect_get::<TreeNodeWithPreviousValue>()
        .returning(|_| Err(StorageError::Other("Boom!".to_string())));

    let storage = StorageManager::new_no_cache(db2);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf, AzksParallelismConfig::default())
        .await
        .expect("Failed to create directory");

    let mut updates = vec![];
    for i in 0..2 {
        updates.push((
            AkdLabel(format!("hello1{i}").as_bytes().to_vec()),
            AkdValue(format!("hello1{}", i + 1).as_bytes().to_vec()),
        ));
    }

    akd.publish(updates).await.expect("Failed to do subsequent publish");

    Ok(())
}
