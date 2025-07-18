use super::*;
use crate::{
    storage::{
        StorageManager, memory::AsyncInMemoryDatabase, traits::StorageUtil, types::DbRecord,
    },
    test_config,
};
use itertools::Itertools;
use rand::{RngCore, SeedableRng, rngs::StdRng, seq::SliceRandom};
use std::time::Duration;

// #[cfg(feature = "greedy_lookup_preload")]
// test_config!(test_maximal_node_set_resolution);
// #[cfg(feature = "greedy_lookup_preload")]
// async fn test_maximal_node_set_resolution<TC: Configuration>() -> Result<(), AkdError> {
//     let mut rng = StdRng::seed_from_u64(42);
//     let database = AsyncInMemoryDatabase::new();
//     let db = StorageManager::new_no_cache(database);
//     let azks1 = Azks::new::<TC, _>(&db).await.unwrap();
//     let label = NodeLabel {
//         label_len: 256,
//         label_val: [
//             1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1,
//             0, 1, 0, 1,
//         ],
//     };

//     let lookup_info = LookupInfo {
//         existent_label: label,
//         marker_label: label,
//         marker_version: 1,
//         non_existent_label: label,
//         value_state: crate::storage::types::ValueState {
//             epoch: 1,
//             label,
//             username: crate::AkdLabel::random(&mut rng),
//             value: crate::AkdValue::random(&mut rng),
//             version: 1,
//         },
//     };

//     let max_set = azks1
//         .build_lookup_maximal_node_set(&db, lookup_info)
//         .await
//         .expect("Failed to build maximal set");

//     // since the label is there 3 times, it should all resolve to the same data
//     assert_eq!(256, max_set.len());
//     Ok(())
// }

test_config!(test_batch_insert_basic);
async fn test_batch_insert_basic<TC: Configuration>() -> Result<(), AkdError> {
    let mut rng = StdRng::seed_from_u64(42);
    let num_nodes = 10;
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks1 = Azks::new::<TC, _>(&db).await?;
    azks1.increment_epoch();

    let mut azks_element_set: Vec<AzksElement> = vec![];
    for _ in 0..num_nodes {
        let label = crate::akd::utils::random_label(&mut rng);
        let mut input = crate::akd::EMPTY_DIGEST;
        rng.fill_bytes(&mut input);
        let value = TC::hash(&input);
        let node = AzksElement { label, value: AzksValue(value) };
        azks_element_set.push(node);
        let (root_node, is_new, _) = Azks::recursive_batch_insert_nodes::<TC, _>(
            &db,
            Some(NodeLabel::root()),
            AzksElementSet::from(vec![node]),
            1,
            InsertMode::Directory,
            None,
        )
        .await?;
        root_node.write_to_storage(&db, is_new).await?;
    }

    let database2 = AsyncInMemoryDatabase::new();
    let db2 = StorageManager::new_no_cache(database2);
    let mut azks2 = Azks::new::<TC, _>(&db2).await?;

    azks2
        .batch_insert_nodes::<TC, _>(
            &db2,
            azks_element_set,
            InsertMode::Directory,
            AzksParallelismConfig::default(),
        )
        .await?;

    assert_eq!(
        azks1.get_root_hash::<TC, _>(&db).await?,
        azks2.get_root_hash::<TC, _>(&db2).await?,
        "Batch insert doesn't match individual insert"
    );

    Ok(())
}

test_config!(test_batch_insert_root_hash);
async fn test_batch_insert_root_hash<TC: Configuration>() -> Result<(), AkdError> {
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);

    // manually construct a 3-layer tree and compute the root hash
    let mut nodes = Vec::<AzksElement>::new();
    let mut leaves = Vec::<TreeNode>::new();
    let mut leaf_hashes = Vec::new();
    for i in 0u64..8u64 {
        let leaf_u64 = i << 61;
        let label = NodeLabel::new(byte_arr_from_u64(leaf_u64), 3u32);
        let value = AzksValue(TC::hash(&leaf_u64.to_be_bytes()));
        nodes.push(AzksElement { label, value });

        let new_leaf = new_leaf_node::<TC>(label, &value, 7 - i + 1);
        leaf_hashes.push((
            TC::hash_leaf_with_commitment(AzksValue(TC::hash(&leaf_u64.to_be_bytes())), 7 - i + 1),
            new_leaf.label.value::<TC>(),
        ));
        leaves.push(new_leaf);
    }

    let mut layer_1_hashes = Vec::new();
    for (i, j) in (0u64..4).enumerate() {
        let left_child_hash = leaf_hashes[2 * i].clone();
        let right_child_hash = leaf_hashes[2 * i + 1].clone();
        layer_1_hashes.push((
            TC::compute_parent_hash_from_children(
                &AzksValue(left_child_hash.0.0),
                &left_child_hash.1,
                &AzksValue(right_child_hash.0.0),
                &right_child_hash.1,
            ),
            NodeLabel::new(byte_arr_from_u64(j << 62), 2u32).value::<TC>(),
        ));
    }

    let mut layer_2_hashes = Vec::new();
    for (i, j) in (0u64..2).enumerate() {
        let left_child_hash = layer_1_hashes[2 * i].clone();
        let right_child_hash = layer_1_hashes[2 * i + 1].clone();
        layer_2_hashes.push((
            TC::compute_parent_hash_from_children(
                &AzksValue(left_child_hash.0.0),
                &left_child_hash.1,
                &AzksValue(right_child_hash.0.0),
                &right_child_hash.1,
            ),
            NodeLabel::new(byte_arr_from_u64(j << 63), 1u32).value::<TC>(),
        ));
    }

    let expected = TC::compute_root_hash_from_val(&TC::compute_parent_hash_from_children(
        &AzksValue(layer_2_hashes[0].0.0),
        &layer_2_hashes[0].1,
        &AzksValue(layer_2_hashes[1].0.0),
        &layer_2_hashes[1].1,
    ));

    // create a 3-layer tree with batch insert operations and get root hash
    let mut azks = Azks::new::<TC, _>(&db).await?;
    for i in 0..8 {
        let node = nodes[7 - i];
        azks.batch_insert_nodes::<TC, _>(
            &db,
            vec![node],
            InsertMode::Directory,
            AzksParallelismConfig::default(),
        )
        .await?;
    }

    let root_digest = azks.get_root_hash::<TC, _>(&db).await.unwrap();

    // assert root hash from batch insert matches manually computed root hash
    assert_eq!(root_digest, expected, "Root hash not equal to expected");
    Ok(())
}

test_config!(test_insert_permuted);
async fn test_insert_permuted<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 10;
    let mut rng = StdRng::seed_from_u64(42);
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks1 = Azks::new::<TC, _>(&db).await?;
    azks1.increment_epoch();
    let mut azks_element_set: Vec<AzksElement> = vec![];

    for _ in 0..num_nodes {
        let label = crate::akd::utils::random_label(&mut rng);
        let mut value = crate::akd::EMPTY_DIGEST;
        rng.fill_bytes(&mut value);
        let node = AzksElement { label, value: AzksValue(value) };
        azks_element_set.push(node);
        let (root_node, is_new, _) = Azks::recursive_batch_insert_nodes::<TC, _>(
            &db,
            Some(NodeLabel::root()),
            AzksElementSet::from(vec![node]),
            1,
            InsertMode::Directory,
            None,
        )
        .await?;
        root_node.write_to_storage(&db, is_new).await?;
    }

    // Try randomly permuting
    azks_element_set.shuffle(&mut rng);

    let database2 = AsyncInMemoryDatabase::new();
    let db2 = StorageManager::new_no_cache(database2);
    let mut azks2 = Azks::new::<TC, _>(&db2).await?;

    azks2
        .batch_insert_nodes::<TC, _>(
            &db2,
            azks_element_set,
            InsertMode::Directory,
            AzksParallelismConfig::default(),
        )
        .await?;

    assert_eq!(
        azks1.get_root_hash::<TC, _>(&db).await?,
        azks2.get_root_hash::<TC, _>(&db2).await?,
        "Batch insert doesn't match individual insert"
    );

    Ok(())
}

test_config!(test_insert_num_nodes);
async fn test_insert_num_nodes<TC: Configuration>() -> Result<(), AkdError> {
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database.clone());
    let mut azks = Azks::new::<TC, _>(&db).await?;

    // expected nodes inserted: 1 root
    let expected_num_nodes = 1;
    let azks_num_nodes = azks.num_nodes;
    let database_num_nodes =
        database.batch_get_type_direct::<TreeNodeWithPreviousValue>().await?.len() as u64;

    assert_eq!(expected_num_nodes, azks_num_nodes);
    assert_eq!(expected_num_nodes, database_num_nodes);

    // insert 3 leaves
    let nodes = vec![
        NodeLabel::new(byte_arr_from_u64(0b0110 << 60), 64),
        NodeLabel::new(byte_arr_from_u64(0b0111 << 60), 64),
        NodeLabel::new(byte_arr_from_u64(0b0010 << 60), 64),
    ]
    .into_iter()
    .map(|label| AzksElement { label, value: AzksValue(EMPTY_DIGEST) })
    .collect();

    azks.batch_insert_nodes::<TC, _>(
        &db,
        nodes,
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;

    // expected nodes inserted: 3 leaves, 2 internal nodes
    //                   -
    //          0
    //    0010     011
    //          0110  0111
    let expected_num_nodes = 5 + 1;
    let azks_num_nodes = azks.num_nodes;
    let database_num_nodes =
        database.batch_get_type_direct::<TreeNodeWithPreviousValue>().await?.len() as u64;

    assert_eq!(expected_num_nodes, azks_num_nodes);
    assert_eq!(expected_num_nodes, database_num_nodes);

    // insert another 3 leaves
    let nodes = vec![
        NodeLabel::new(byte_arr_from_u64(0b1000 << 60), 64),
        NodeLabel::new(byte_arr_from_u64(0b0110 << 60), 64),
        NodeLabel::new(byte_arr_from_u64(0b0011 << 60), 64),
    ]
    .into_iter()
    .map(|label| AzksElement { label, value: AzksValue(EMPTY_DIGEST) })
    .collect();

    azks.batch_insert_nodes::<TC, _>(
        &db,
        nodes,
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;

    // expected nodes inserted: 2 leaves, 1 internal node
    //                   -
    //          -               1000
    //    001         -
    //  -  0011     -   -
    let expected_num_nodes = 3 + 5 + 1;
    let azks_num_nodes = azks.num_nodes;
    let database_num_nodes =
        database.batch_get_type_direct::<TreeNodeWithPreviousValue>().await?.len() as u64;

    assert_eq!(expected_num_nodes, azks_num_nodes);
    assert_eq!(expected_num_nodes, database_num_nodes);

    Ok(())
}

test_config!(test_preload_nodes_accuracy);
async fn test_preload_nodes_accuracy<TC: Configuration>() -> Result<(), AkdError> {
    let database = AsyncInMemoryDatabase::new();
    let storage_manager =
        StorageManager::new(database, Some(Duration::from_secs(180u64)), None, None);
    let mut azks = Azks::new::<TC, _>(&storage_manager).await.expect("Failed to create azks!");
    azks.increment_epoch();

    // Construct our tree
    let root_label = NodeLabel::root();

    let left_label = NodeLabel::new(byte_arr_from_u64(1), 1);
    let left = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
        label: left_label,
        last_epoch: 1,
        min_descendant_epoch: 1,
        parent: root_label,
        node_type: TreeNodeType::Leaf,
        left_child: None,
        right_child: None,
        hash: AzksValue(EMPTY_DIGEST),
    }));
    let right_label = NodeLabel::new(byte_arr_from_u64(2), 2);
    let right = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
        label: right_label,
        last_epoch: 1,
        min_descendant_epoch: 1,
        parent: root_label,
        node_type: TreeNodeType::Leaf,
        left_child: None,
        right_child: None,
        hash: AzksValue(EMPTY_DIGEST),
    }));
    let root = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
        label: root_label,
        last_epoch: 1,
        min_descendant_epoch: 1,
        parent: root_label,
        node_type: TreeNodeType::Root,
        left_child: Some(left_label),
        right_child: Some(right_label),
        hash: AzksValue(EMPTY_DIGEST),
    }));

    // Seed the database and cache with our tree
    storage_manager
        .batch_set(vec![root, left, right])
        .await
        .expect("Failed to seed database for preload test");

    // Preload nodes to populate storage manager cache
    let azks_element_set = AzksElementSet::from(vec![
        AzksElement {
            label: root_label,
            value: AzksValue(EMPTY_DIGEST),
        },
        AzksElement {
            label: left_label,
            value: AzksValue(EMPTY_DIGEST),
        },
        AzksElement {
            label: right_label,
            value: AzksValue(EMPTY_DIGEST),
        },
    ]);
    let expected_preload_count = 3u64;
    let actual_preload_count = azks
        .preload_nodes(
            &storage_manager,
            &azks_element_set,
            AzksParallelismConfig {
                preload: AzksParallelismOption::Static(32),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to preload nodes");

    assert_eq!(
        expected_preload_count, actual_preload_count,
        "Preload count returned unexpected value!"
    );

    // Test preload with parallelism disabled
    let actual_preload_count = azks
        .preload_nodes(&storage_manager, &azks_element_set, AzksParallelismConfig::disabled())
        .await
        .expect("Failed to preload nodes");

    assert_eq!(
        expected_preload_count, actual_preload_count,
        "Preload count returned unexpected value!"
    );
    Ok(())
}

test_config!(test_azks_element_set_partition);
async fn test_azks_element_set_partition<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 5;
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks1 = Azks::new::<TC, _>(&db).await?;
    azks1.increment_epoch();

    // manually construct both types of node sets with the same data
    let mut rng = StdRng::seed_from_u64(42);
    let nodes = gen_random_elements(num_nodes, &mut rng);
    let unsorted_set = AzksElementSet::Unsorted(nodes.clone());
    let bin_searchable_set = {
        let mut nodes = nodes;
        nodes.sort_unstable();
        AzksElementSet::BinarySearchable(nodes)
    };

    // assert that node sets always return the same partitions
    let assert_fun = |prefix_label: NodeLabel| match (
        unsorted_set.clone().partition(prefix_label),
        bin_searchable_set.clone().partition(prefix_label),
    ) {
        (
            (
                AzksElementSet::Unsorted(mut left_unsorted),
                AzksElementSet::Unsorted(mut right_unsorted),
            ),
            (
                AzksElementSet::BinarySearchable(left_bin_searchable),
                AzksElementSet::BinarySearchable(right_bin_searchable),
            ),
        ) => {
            left_unsorted.sort_unstable();
            right_unsorted.sort_unstable();
            assert_eq!(left_unsorted, *left_bin_searchable);
            assert_eq!(right_unsorted, *right_bin_searchable);
        },
        _ => panic!("Unexpected enum variant returned from partition call"),
    };

    let lcp_label = bin_searchable_set[0]
        .label
        .get_longest_common_prefix::<TC>(bin_searchable_set[num_nodes - 1].label);

    assert_fun(lcp_label);
    assert_fun(TC::empty_label());

    Ok(())
}

test_config!(test_azks_element_set_get_longest_common_prefix);
async fn test_azks_element_set_get_longest_common_prefix<TC: Configuration>() -> Result<(), AkdError>
{
    let num_nodes = 10;
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks1 = Azks::new::<TC, _>(&db).await?;
    azks1.increment_epoch();

    // manually construct both types of node sets with the same data
    let mut rng = StdRng::seed_from_u64(42);
    let nodes = gen_random_elements(num_nodes, &mut rng);
    let unsorted_set = AzksElementSet::Unsorted(nodes.clone());
    let bin_searchable_set = {
        let mut nodes = nodes;
        nodes.sort_unstable();
        AzksElementSet::BinarySearchable(nodes)
    };

    // assert that node sets always return the same LCP
    assert_eq!(
        unsorted_set.get_longest_common_prefix::<TC>(),
        bin_searchable_set.get_longest_common_prefix::<TC>()
    );

    Ok(())
}

test_config!(test_get_child_azks_element);
async fn test_get_child_azks_element<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 5;
    let mut rng = StdRng::seed_from_u64(42);

    let mut azks_element_set: Vec<AzksElement> = vec![];

    for _ in 0..num_nodes {
        let label = crate::akd::utils::random_label(&mut rng);
        let mut hash = crate::akd::EMPTY_DIGEST;
        rng.fill_bytes(&mut hash);
        let node = AzksElement { label, value: AzksValue(hash) };
        azks_element_set.push(node);
    }

    // Try tests against all permutations of the set
    for perm in azks_element_set.into_iter().permutations(num_nodes) {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;
        azks.batch_insert_nodes::<TC, _>(
            &db,
            perm,
            InsertMode::Directory,
            AzksParallelismConfig::default(),
        )
        .await?;

        // Recursively traverse the tree and check that the sibling of each node is correct
        let root_node = TreeNode::get_from_storage(&db, &NodeKey(NodeLabel::root()), 1).await?;
        let mut nodes: Vec<TreeNode> = vec![root_node];
        while let Some(current_node) = nodes.pop() {
            let left_child = current_node.get_child_node(&db, Direction::Left, 1).await?;
            let right_child = current_node.get_child_node(&db, Direction::Right, 1).await?;

            if let Some(left_child) = left_child {
                let sibling_label = azks
                    .get_child_azks_element_in_dir::<TC, _>(&db, &current_node, Direction::Left, 1)
                    .await?
                    .label;
                assert_eq!(left_child.label, sibling_label);
                nodes.push(left_child);
            }

            if let Some(right_child) = right_child {
                println!("right_child.label: {:?}", right_child.label);
                let sibling_label = azks
                    .get_child_azks_element_in_dir::<TC, _>(&db, &current_node, Direction::Right, 1)
                    .await?
                    .label;
                assert_eq!(right_child.label, sibling_label);
                nodes.push(right_child);
            }
        }
    }

    Ok(())
}

test_config!(test_membership_proof_permuted);
async fn test_membership_proof_permuted<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 10;

    let mut rng = StdRng::seed_from_u64(42);
    let mut azks_element_set = gen_random_elements(num_nodes, &mut rng);

    // Try randomly permuting
    azks_element_set.shuffle(&mut rng);
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks = Azks::new::<TC, _>(&db).await?;
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set.clone(),
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;

    let proof = azks.get_membership_proof::<TC, _>(&db, azks_element_set[0].label).await?;

    verify_membership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;

    Ok(())
}

test_config!(test_membership_proof_small);
async fn test_membership_proof_small<TC: Configuration>() -> Result<(), AkdError> {
    for num_nodes in 1..10 {
        let mut azks_element_set: Vec<AzksElement> = vec![];

        for i in 0..num_nodes {
            let mut label_arr = [0u8; 32];
            label_arr[0] = i;
            let label = NodeLabel::new(label_arr, 256u32);
            let node = AzksElement { label, value: AzksValue(EMPTY_DIGEST) };
            azks_element_set.push(node);
        }

        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;
        azks.batch_insert_nodes::<TC, _>(
            &db,
            azks_element_set.clone(),
            InsertMode::Directory,
            AzksParallelismConfig::default(),
        )
        .await?;

        let proof = azks.get_membership_proof::<TC, _>(&db, azks_element_set[0].label).await?;

        verify_membership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;
    }
    Ok(())
}

test_config!(test_membership_proof_failing);
async fn test_membership_proof_failing<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 10;

    let mut rng = StdRng::seed_from_u64(42);
    let mut azks_element_set = gen_random_elements(num_nodes, &mut rng);

    // Try randomly permuting
    azks_element_set.shuffle(&mut rng);
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks = Azks::new::<TC, _>(&db).await?;
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set.clone(),
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;

    let mut proof = azks.get_membership_proof::<TC, _>(&db, azks_element_set[0].label).await?;
    let hash_val = EMPTY_DIGEST;
    proof = MembershipProof {
        label: proof.label,
        hash_val: AzksValue(hash_val),
        sibling_proofs: proof.sibling_proofs,
    };
    assert!(
        verify_membership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)
            .is_err(),
        "Membership proof does verify, despite being wrong"
    );

    Ok(())
}

test_config!(test_nonmembership_proof_intermediate);
async fn test_nonmembership_proof_intermediate<TC: Configuration>() -> Result<(), AkdError> {
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);

    let azks_element_set: Vec<AzksElement> = vec![
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b1 << 63), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b11 << 62), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b01 << 62), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b111 << 61), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
    ];

    let mut azks = Azks::new::<TC, _>(&db).await?;
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set,
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let search_label = NodeLabel::new(byte_arr_from_u64(0b1111 << 60), 64);
    let proof = azks.get_non_membership_proof::<TC, _>(&db, search_label).await?;
    assert!(
        verify_nonmembership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)
            .is_ok(),
        "Nonmembership proof does not verify"
    );
    Ok(())
}

// This test checks that a non-membership proof in a tree with 1 leaf verifies.
test_config!(test_nonmembership_proof_very_small);
async fn test_nonmembership_proof_very_small<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 2;

    let mut azks_element_set: Vec<AzksElement> = vec![];

    for i in 0..num_nodes {
        let mut label_arr = [0u8; 32];
        label_arr[31] = i;
        let label = NodeLabel::new(label_arr, 256u32);
        let mut hash = EMPTY_DIGEST;
        hash[31] = i;
        let node = AzksElement { label, value: AzksValue(hash) };
        azks_element_set.push(node);
    }
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks = Azks::new::<TC, _>(&db).await?;
    let search_label = azks_element_set[0].label;
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set.clone()[1..2].to_vec(),
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let proof = azks.get_non_membership_proof::<TC, _>(&db, search_label).await?;

    verify_nonmembership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;

    Ok(())
}

// This test verifies if a non-membership proof in a small tree of 2 leaves
// verifies.
test_config!(test_nonmembership_proof_small);
async fn test_nonmembership_proof_small<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 3;

    let mut rng = StdRng::seed_from_u64(42);
    let azks_element_set = gen_random_elements(num_nodes, &mut rng);
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks = Azks::new::<TC, _>(&db).await?;
    let search_label = azks_element_set[num_nodes - 1].label;
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set.clone()[0..num_nodes - 1].to_vec(),
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let proof = azks.get_non_membership_proof::<TC, _>(&db, search_label).await?;

    verify_nonmembership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;

    Ok(())
}

test_config!(test_nonmembership_proof);
async fn test_nonmembership_proof<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 10;

    let mut rng = StdRng::seed_from_u64(42);
    let azks_element_set = gen_random_elements(num_nodes, &mut rng);
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks = Azks::new::<TC, _>(&db).await?;
    let search_label = azks_element_set[num_nodes - 1].label;
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set.clone()[0..num_nodes - 1].to_vec(),
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let proof = azks.get_non_membership_proof::<TC, _>(&db, search_label).await?;

    verify_nonmembership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;

    Ok(())
}

test_config!(test_append_only_proof_very_tiny);
async fn test_append_only_proof_very_tiny<TC: Configuration>() -> Result<(), AkdError> {
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks = Azks::new::<TC, _>(&db).await?;

    let azks_element_set_1: Vec<AzksElement> = vec![AzksElement {
        label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
        value: AzksValue(EMPTY_DIGEST),
    }];
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set_1,
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let start_hash = azks.get_root_hash::<TC, _>(&db).await?;

    let azks_element_set_2: Vec<AzksElement> = vec![AzksElement {
        label: NodeLabel::new(byte_arr_from_u64(0b01 << 62), 64),
        value: AzksValue(EMPTY_DIGEST),
    }];

    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set_2,
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let end_hash = azks.get_root_hash::<TC, _>(&db).await?;

    let proof = azks
        .get_append_only_proof::<TC, _>(&db, 1, 2, AzksParallelismConfig::default())
        .await?;
    audit_verify::<TC>(vec![start_hash, end_hash], proof).await?;

    Ok(())
}

test_config!(test_append_only_proof_tiny);
async fn test_append_only_proof_tiny<TC: Configuration>() -> Result<(), AkdError> {
    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks = Azks::new::<TC, _>(&db).await?;

    let azks_element_set_1: Vec<AzksElement> = vec![
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b1 << 63), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
    ];

    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set_1,
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let start_hash = azks.get_root_hash::<TC, _>(&db).await?;

    let azks_element_set_2: Vec<AzksElement> = vec![
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b1 << 62), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
        AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b111 << 61), 64),
            value: AzksValue(EMPTY_DIGEST),
        },
    ];

    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set_2,
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let end_hash = azks.get_root_hash::<TC, _>(&db).await?;

    let proof = azks
        .get_append_only_proof::<TC, _>(&db, 1, 2, AzksParallelismConfig::default())
        .await?;
    audit_verify::<TC>(vec![start_hash, end_hash], proof).await?;
    Ok(())
}

test_config!(test_append_only_proof);
async fn test_append_only_proof<TC: Configuration>() -> Result<(), AkdError> {
    let num_nodes = 10;

    let mut rng = StdRng::seed_from_u64(42);
    let azks_element_set_1 = gen_random_elements(num_nodes, &mut rng);

    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new_no_cache(database);
    let mut azks = Azks::new::<TC, _>(&db).await?;
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set_1.clone(),
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;

    let start_hash = azks.get_root_hash::<TC, _>(&db).await?;

    let azks_element_set_2 = gen_random_elements(num_nodes, &mut rng);
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set_2.clone(),
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;

    let middle_hash = azks.get_root_hash::<TC, _>(&db).await?;

    let azks_element_set_3: Vec<AzksElement> = gen_random_elements(num_nodes, &mut rng);
    azks.batch_insert_nodes::<TC, _>(
        &db,
        azks_element_set_3.clone(),
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;

    let end_hash = azks.get_root_hash::<TC, _>(&db).await?;

    let proof = azks
        .get_append_only_proof::<TC, _>(&db, 1, 3, AzksParallelismConfig::default())
        .await?;
    let hashes = vec![start_hash, middle_hash, end_hash];
    audit_verify::<TC>(hashes, proof).await?;

    Ok(())
}

test_config!(future_epoch_throws_error);
async fn future_epoch_throws_error<TC: Configuration>() -> Result<(), AkdError> {
    let database = AsyncInMemoryDatabase::new();

    let db = StorageManager::new_no_cache(database);
    let azks = Azks::new::<TC, _>(&db).await?;

    let out = azks.get_root_hash_safe::<TC, _>(&db, 123).await;

    assert!(matches!(out, Err(AkdError::Directory(DirectoryError::InvalidEpoch(_)))));
    Ok(())
}

fn gen_random_elements(num_nodes: usize, rng: &mut StdRng) -> Vec<AzksElement> {
    (0..num_nodes)
        .map(|_| {
            let label = crate::akd::utils::random_label(rng);
            let mut value = EMPTY_DIGEST;
            rng.fill_bytes(&mut value);
            AzksElement { label, value: AzksValue(value) }
        })
        .collect()
}
