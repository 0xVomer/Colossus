use super::*;
use crate::{
    akd::{
        Azks, EMPTY_DIGEST, NodeLabel,
        tree_node::{NodeKey, TreeNodeWithPreviousValue},
    },
    storage::{memory::AsyncInMemoryDatabase, traits::StorageUtil, types::*},
};

#[tokio::test]
async fn test_storage_manager_transaction() {
    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new_no_cache(db);

    assert!(storage_manager.begin_transaction(), "Failed to start transaction");

    let mut records = (0..10)
        .map(|i| {
            let label = NodeLabel { label_len: i, label_val: [i as u8; 32] };
            DbRecord::TreeNode(DbRecord::build_tree_node_with_previous_value(
                label.label_val,
                label.label_len,
                0,
                0,
                [0u8; 32],
                0,
                0,
                None,
                None,
                EMPTY_DIGEST,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ))
        })
        .collect::<Vec<_>>();

    records.push(DbRecord::Azks(Azks { latest_epoch: 0, num_nodes: 0 }));

    storage_manager
        .batch_set(records)
        .await
        .expect("Failed to set batch of records");

    assert_eq!(Ok(0), storage_manager.db.batch_get_all_direct().await.map(|items| items.len()));
    assert_eq!(11, storage_manager.transaction.count());

    let key = NodeKey(NodeLabel { label_len: 2, label_val: [2u8; 32] });
    storage_manager
        .get::<TreeNodeWithPreviousValue>(&key)
        .await
        .expect("Failed to get database record for node label 2");

    let keys = vec![key, NodeKey(NodeLabel { label_len: 3, label_val: [3u8; 32] })];
    let got = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to batch-get");
    assert_eq!(2, got.len());

    storage_manager
        .commit_transaction()
        .await
        .expect("Failed to commit transaction");

    assert_eq!(Ok(11), storage_manager.db.batch_get_all_direct().await.map(|items| items.len()));
    assert_eq!(0, storage_manager.transaction.count());
}

#[tokio::test]
async fn test_storage_manager_cache_populated_by_batch_set() {
    let db = AsyncInMemoryDatabase::new();

    let storage_manager = StorageManager::new(db, None, None, None);

    let mut records = (0..10)
        .map(|i| {
            let label = NodeLabel { label_len: i, label_val: [i as u8; 32] };
            DbRecord::TreeNode(DbRecord::build_tree_node_with_previous_value(
                label.label_val,
                label.label_len,
                0,
                0,
                [0u8; 32],
                0,
                0,
                None,
                None,
                EMPTY_DIGEST,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ))
        })
        .collect::<Vec<_>>();

    records.push(DbRecord::Azks(Azks { latest_epoch: 0, num_nodes: 0 }));

    storage_manager
        .batch_set(records)
        .await
        .expect("Failed to set batch of records");

    storage_manager.db.clear();

    let key = NodeKey(NodeLabel { label_len: 2, label_val: [2u8; 32] });
    storage_manager
        .get::<TreeNodeWithPreviousValue>(&key)
        .await
        .expect("Failed to get database record for node label 2");

    let keys = vec![key, NodeKey(NodeLabel { label_len: 3, label_val: [3u8; 32] })];
    let got = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to batch-get");
    assert_eq!(2, got.len());

    storage_manager.flush_cache().await;

    let got = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to batch-get");
    assert_eq!(0, got.len());
}

#[tokio::test]
async fn test_storage_manager_cache_populated_by_batch_get() {
    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new(db, None, None, None);

    let mut keys = vec![];
    let mut records = (0..10)
        .map(|i| {
            let label = NodeLabel { label_len: i, label_val: [i as u8; 32] };
            keys.push(NodeKey(label));
            DbRecord::TreeNode(DbRecord::build_tree_node_with_previous_value(
                label.label_val,
                label.label_len,
                0,
                0,
                [0u8; 32],
                0,
                0,
                None,
                None,
                EMPTY_DIGEST,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ))
        })
        .collect::<Vec<_>>();

    records.push(DbRecord::Azks(Azks { latest_epoch: 0, num_nodes: 0 }));

    storage_manager
        .batch_set(records)
        .await
        .expect("Failed to set batch of records");

    let db_arc = storage_manager.get_db();

    drop(storage_manager);

    let storage_manager = StorageManager::new(
        Arc::try_unwrap(db_arc).expect("Failed to grab arc"),
        Some(std::time::Duration::from_secs(1000)),
        None,
        None,
    );

    let _ = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to get a batch of records");

    storage_manager.db.clear();

    let key = NodeKey(NodeLabel { label_len: 2, label_val: [2u8; 32] });
    storage_manager
        .get::<TreeNodeWithPreviousValue>(&key)
        .await
        .expect("Failed to get database record for node label 2");

    let keys = vec![key, NodeKey(NodeLabel { label_len: 3, label_val: [3u8; 32] })];
    let got = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to batch-get");
    assert_eq!(2, got.len());

    storage_manager.flush_cache().await;

    assert_eq!(Ok(vec![]), storage_manager.batch_get::<TreeNodeWithPreviousValue>(&keys).await);
}
