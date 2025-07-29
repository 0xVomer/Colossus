use super::{
    Direction, PrefixOrdering,
    azks::AzksValue,
    errors::{AkdError, StorageError, TreeNodeError},
    hash::EMPTY_DIGEST,
    node_label::*,
    serde_helpers::{azks_value_hex_deserialize, azks_value_hex_serialize},
};
use crate::{
    configuration::Configuration,
    storage::{
        manager::StorageManager,
        traits::{Database, Storable},
        types::{DbRecord, StorageType},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::{max, min},
    convert::TryInto,
    marker::Sync,
};

#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TreeNodeType {
    Leaf = 1,

    Root = 2,

    Interior = 3,
}

impl super::SizeOf for TreeNodeType {
    fn size_of(&self) -> usize {
        1
    }
}

impl TreeNodeType {
    pub(crate) fn from_u8(code: u8) -> Self {
        match code {
            1 => Self::Leaf,
            2 => Self::Root,
            3 => Self::Interior,
            _ => Self::Leaf,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TreeNodeWithPreviousValue {
    pub label: NodeLabel,

    pub latest_node: TreeNode,

    pub previous_node: Option<TreeNode>,
}

impl super::SizeOf for TreeNodeWithPreviousValue {
    fn size_of(&self) -> usize {
        self.label.size_of()
            + self.latest_node.size_of()
            + self.previous_node.as_ref().map_or(8, |v| v.size_of() + 8)
    }
}

impl Storable for TreeNodeWithPreviousValue {
    type StorageKey = NodeKey;

    fn data_type() -> StorageType {
        StorageType::TreeNode
    }

    fn get_id(&self) -> NodeKey {
        NodeKey(self.label)
    }

    fn get_full_binary_key_id(key: &NodeKey) -> Vec<u8> {
        let mut result = vec![StorageType::TreeNode as u8];
        result.extend_from_slice(&key.0.label_len.to_be_bytes());
        result.extend_from_slice(&key.0.label_val);
        result
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<NodeKey, String> {
        if bin.len() < 37 {
            return Err("Not enough bytes to form a proper key".to_string());
        }

        if bin[0] != StorageType::TreeNode as u8 {
            return Err("Not a tree node key".to_string());
        }

        let len_bytes: [u8; 4] = bin[1..=4].try_into().expect("Slice with incorrect length");
        let val_bytes: [u8; 32] = bin[5..=36].try_into().expect("Slice with incorrect length");
        let len = u32::from_be_bytes(len_bytes);

        Ok(NodeKey(NodeLabel::new(val_bytes, len)))
    }
}

impl TreeNodeWithPreviousValue {
    pub(crate) fn determine_node_to_get(
        &self,
        target_epoch: u64,
    ) -> Result<TreeNode, StorageError> {
        if self.latest_node.last_epoch > target_epoch {
            if let Some(previous_node) = &self.previous_node {
                Ok(previous_node.clone())
            } else {
                Err(StorageError::NotFound(format!(
                    "TreeNode {:?} at epoch {}",
                    NodeKey(self.label),
                    target_epoch
                )))
            }
        } else {
            Ok(self.latest_node.clone())
        }
    }

    pub(crate) fn from_tree_node(node: TreeNode) -> Self {
        Self {
            label: node.label,
            latest_node: node,
            previous_node: None,
        }
    }

    pub(crate) async fn write_to_storage<S: Database>(
        &self,
        storage: &StorageManager<S>,
    ) -> Result<(), StorageError> {
        storage.set(DbRecord::TreeNode(self.clone())).await
    }

    pub(crate) async fn get_appropriate_tree_node_from_storage<S: Database>(
        storage: &StorageManager<S>,
        key: &NodeKey,
        target_epoch: u64,
    ) -> Result<TreeNode, StorageError> {
        match storage.get::<Self>(key).await? {
            DbRecord::TreeNode(node) => node.determine_node_to_get(target_epoch),
            _ => Err(StorageError::NotFound(format!("TreeNodeWithPreviousValue {key:?}"))),
        }
    }

    pub(crate) async fn batch_get_appropriate_tree_node_from_storage<S: Database>(
        storage: &StorageManager<S>,
        keys: &[NodeKey],
        target_epoch: u64,
    ) -> Result<Vec<TreeNode>, StorageError> {
        let node_records: Vec<DbRecord> = storage.batch_get::<Self>(keys).await?;
        let mut nodes = Vec::<TreeNode>::new();
        for node in node_records.into_iter() {
            if let DbRecord::TreeNode(node) = node {
                if let Ok(correct_node) = node.determine_node_to_get(target_epoch) {
                    nodes.push(correct_node);
                }
            } else {
                return Err(StorageError::NotFound(
                    "Batch retrieve returned types <> TreeNodeWithPreviousValue".to_string(),
                ));
            }
        }
        Ok(nodes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct TreeNode {
    pub label: NodeLabel,

    pub last_epoch: u64,

    pub min_descendant_epoch: u64,

    pub parent: NodeLabel,

    pub node_type: TreeNodeType,

    pub left_child: Option<NodeLabel>,

    pub right_child: Option<NodeLabel>,

    #[serde(serialize_with = "azks_value_hex_serialize")]
    #[serde(deserialize_with = "azks_value_hex_deserialize")]
    pub hash: AzksValue, // FIXME: we should rename this field to "value" (but it will affect fixture generation)
}

impl super::SizeOf for TreeNode {
    fn size_of(&self) -> usize {
        self.label.size_of()
            + std::mem::size_of::<u64>() * 2
            + self.parent.size_of()
            + self.node_type.size_of()
            + self.left_child.as_ref().map_or(8, |v| v.size_of() + 8)
            + self.right_child.as_ref().map_or(8, |v| v.size_of() + 8)
            + 32
    }
}

impl TreeNode {
    pub(crate) async fn write_to_storage<S: Database>(
        &self,
        storage: &StorageManager<S>,
        is_new: bool,
    ) -> Result<(), StorageError> {
        let target_epoch = match self.last_epoch {
            e if e > 0 => e - 1,
            other => other,
        };

        let previous = if is_new {
            None
        } else {
            match TreeNodeWithPreviousValue::get_appropriate_tree_node_from_storage(
                storage,
                &NodeKey(self.label),
                target_epoch,
            )
            .await
            {
                Ok(p) => Some(p),
                Err(StorageError::NotFound(_)) => None,
                Err(other) => return Err(other),
            }
        };

        let left_shifted = TreeNodeWithPreviousValue {
            label: self.label,
            latest_node: self.clone(),
            previous_node: previous,
        };

        left_shifted.write_to_storage(storage).await
    }

    pub(crate) async fn get_from_storage<S: Database>(
        storage: &StorageManager<S>,
        key: &NodeKey,
        target_epoch: u64,
    ) -> Result<TreeNode, StorageError> {
        TreeNodeWithPreviousValue::get_appropriate_tree_node_from_storage(
            storage,
            key,
            target_epoch,
        )
        .await
    }

    pub(crate) async fn batch_get_from_storage<S: Database>(
        storage: &StorageManager<S>,
        keys: &[NodeKey],
        target_epoch: u64,
    ) -> Result<Vec<TreeNode>, StorageError> {
        TreeNodeWithPreviousValue::batch_get_appropriate_tree_node_from_storage(
            storage,
            keys,
            target_epoch,
        )
        .await
    }
}

#[derive(Clone, PartialEq, Eq, Hash, std::fmt::Debug, Deserialize, Serialize)]
pub struct NodeKey(pub NodeLabel);

unsafe impl Sync for TreeNode {}

impl TreeNode {
    fn new(
        label: NodeLabel,
        parent: NodeLabel,
        node_type: TreeNodeType,
        birth_epoch: u64,
        min_descendant_epoch: u64,
        value: AzksValue,
    ) -> Self {
        TreeNode {
            label,
            last_epoch: birth_epoch,
            min_descendant_epoch,
            parent, // Root node is its own parent
            node_type,
            left_child: None,
            right_child: None,
            hash: value,
        }
    }

    pub(crate) async fn update_hash<TC: Configuration, S: Database>(
        &mut self,
        storage: &StorageManager<S>,
        hash_mode: NodeHashingMode,
    ) -> Result<(), AkdError> {
        match self.node_type {
            TreeNodeType::Leaf => {},

            _ => {
                let left_child =
                    self.get_child_node(storage, Direction::Left, self.last_epoch).await?;
                let right_child =
                    self.get_child_node(storage, Direction::Right, self.last_epoch).await?;
                self.hash = TC::compute_parent_hash_from_children(
                    &node_to_azks_value::<TC>(&left_child, hash_mode),
                    &node_to_label::<TC>(&left_child).value::<TC>(),
                    &node_to_azks_value::<TC>(&right_child, hash_mode),
                    &node_to_label::<TC>(&right_child).value::<TC>(),
                );
            },
        }

        Ok(())
    }

    pub(crate) fn set_child(&mut self, child_node: &mut TreeNode) -> Result<(), TreeNodeError> {
        match self.label.get_prefix_ordering(child_node.label) {
            PrefixOrdering::Invalid => {
                return Err(TreeNodeError::NoDirection(child_node.label, None));
            },
            PrefixOrdering::WithZero => {
                self.left_child = Some(child_node.label);
            },
            PrefixOrdering::WithOne => {
                self.right_child = Some(child_node.label);
            },
        }

        child_node.parent = self.label;

        self.last_epoch = max(self.last_epoch, child_node.last_epoch);

        if self.min_descendant_epoch == 0u64 {
            self.min_descendant_epoch = child_node.min_descendant_epoch;
        } else {
            self.min_descendant_epoch =
                min(self.min_descendant_epoch, child_node.min_descendant_epoch);
        };

        Ok(())
    }

    pub(crate) async fn get_child_node<S: Database>(
        &self,
        storage: &StorageManager<S>,
        direction: Direction,
        epoch: u64,
    ) -> Result<Option<TreeNode>, AkdError> {
        if let Some(child_label) = self.get_child_label(direction) {
            let child_key = NodeKey(child_label);
            let get_result = Self::get_from_storage(storage, &child_key, epoch).await;
            match get_result {
                Ok(node) => Ok(Some(node)),
                Err(StorageError::NotFound(_)) => Ok(None),
                _ => Err(AkdError::Storage(StorageError::NotFound(format!(
                    "TreeNode {child_key:?}"
                )))),
            }
        } else {
            Ok(None)
        }
    }

    pub(crate) fn get_child_label(&self, direction: Direction) -> Option<NodeLabel> {
        match direction {
            Direction::Left => self.left_child,
            Direction::Right => self.right_child,
        }
    }

    /* Functions for compression-related operations */

    pub(crate) fn get_latest_epoch(&self) -> u64 {
        self.last_epoch
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum NodeHashingMode {
    WithLeafEpoch,

    NoLeafEpoch,
}

pub(crate) fn node_to_label<TC: Configuration>(input: &Option<TreeNode>) -> NodeLabel {
    match input {
        Some(child_state) => child_state.label,
        None => TC::empty_label(),
    }
}

pub(crate) fn node_to_azks_value<TC: Configuration>(
    input: &Option<TreeNode>,
    hash_mode: NodeHashingMode,
) -> AzksValue {
    match input {
        Some(child_state) => {
            let mut value = child_state.hash;
            if let (TreeNodeType::Leaf, NodeHashingMode::WithLeafEpoch) =
                (child_state.node_type, hash_mode)
            {
                value = AzksValue(TC::hash_leaf_with_commitment(value, child_state.last_epoch).0);
            }
            value
        },
        None => TC::empty_node_hash(),
    }
}

pub(crate) fn new_root_node<TC: Configuration>() -> TreeNode {
    let empty_root_hash = TC::empty_root_value();
    TreeNode::new(
        NodeLabel::root(),
        NodeLabel::root(),
        TreeNodeType::Root,
        0u64,
        0u64,
        empty_root_hash,
    )
}

pub(crate) fn new_interior_node<TC: Configuration>(label: NodeLabel, birth_epoch: u64) -> TreeNode {
    TreeNode::new(
        label,
        TC::empty_label(), // A placeholder that will get updated once the node is inserted
        TreeNodeType::Interior,
        birth_epoch,
        birth_epoch,
        AzksValue(EMPTY_DIGEST), // A placeholder that will get updated once the node is inserted
    )
}

pub(crate) fn new_leaf_node<TC: Configuration>(
    label: NodeLabel,
    value: &AzksValue,
    birth_epoch: u64,
) -> TreeNode {
    TreeNode::new(
        label,
        TC::empty_label(), // A placeholder that will get updated once the node is inserted
        TreeNodeType::Leaf,
        birth_epoch,
        birth_epoch,
        *value,
    )
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::akd::{DIGEST_BYTES, utils::byte_arr_from_u64};
    type InMemoryDb = crate::storage::memory::AsyncInMemoryDatabase;
    use crate::storage::manager::StorageManager;
    use crate::test_config;

    test_config!(test_smallest_descendant_ep);
    async fn test_smallest_descendant_ep<TC: Configuration>() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);
        let mut root = new_root_node::<TC>();

        let mut right_child =
            new_interior_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32), 3);

        let mut new_leaf = new_leaf_node::<TC>(
            NodeLabel::new(byte_arr_from_u64(0b00u64), 2u32),
            &AzksValue([0u8; DIGEST_BYTES]),
            1,
        );

        let mut leaf_1 = new_leaf_node::<TC>(
            NodeLabel::new(byte_arr_from_u64(0b11u64 << 62), 2u32),
            &AzksValue([1u8; DIGEST_BYTES]),
            2,
        );

        let mut leaf_2 = new_leaf_node::<TC>(
            NodeLabel::new(byte_arr_from_u64(0b10u64 << 62), 2u32),
            &AzksValue([2u8; DIGEST_BYTES]),
            3,
        );

        right_child.set_child(&mut leaf_2)?;
        right_child.set_child(&mut leaf_1)?;
        right_child.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        leaf_2.write_to_storage(&db, false).await?;
        leaf_1.write_to_storage(&db, false).await?;
        right_child.write_to_storage(&db, false).await?;

        root.set_child(&mut new_leaf)?;
        root.set_child(&mut right_child)?;
        root.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        new_leaf.write_to_storage(&db, false).await?;
        right_child.write_to_storage(&db, false).await?;
        root.write_to_storage(&db, false).await?;

        let stored_root = db.get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root())).await?;

        let root_smallest_descendant_ep = match stored_root {
            DbRecord::TreeNode(node) => node.latest_node.min_descendant_epoch,
            _ => panic!("Root not found in storage."),
        };

        let stored_right_child =
            db.get::<TreeNodeWithPreviousValue>(&NodeKey(root.right_child.unwrap())).await?;

        let right_child_smallest_descendant_ep = match stored_right_child {
            DbRecord::TreeNode(node) => node.latest_node.min_descendant_epoch,
            _ => panic!("Root not found in storage."),
        };

        let stored_left_child =
            db.get::<TreeNodeWithPreviousValue>(&NodeKey(root.left_child.unwrap())).await?;

        let left_child_smallest_descendant_ep = match stored_left_child {
            DbRecord::TreeNode(node) => node.latest_node.min_descendant_epoch,
            _ => panic!("Root not found in storage."),
        };

        let root_expected_min_dec = 1u64;
        assert_eq!(
            root_expected_min_dec, root_smallest_descendant_ep,
            "Minimum descendant epoch not equal to expected: root, expected: {root_expected_min_dec:?}, got: {root_smallest_descendant_ep:?}"
        );

        let right_child_expected_min_dec = 2u64;
        assert_eq!(
            right_child_expected_min_dec, right_child_smallest_descendant_ep,
            "Minimum descendant epoch not equal to expected: right child"
        );

        let left_child_expected_min_dec = 1u64;
        assert_eq!(
            left_child_expected_min_dec, left_child_smallest_descendant_ep,
            "Minimum descendant epoch not equal to expected: left child"
        );

        Ok(())
    }

    test_config!(test_insert_single_leaf_root);
    async fn test_insert_single_leaf_root<TC: Configuration>() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);

        let mut root = new_root_node::<TC>();

        let val_0 = AzksValue([0u8; DIGEST_BYTES]);
        let val_1 = AzksValue([1u8; DIGEST_BYTES]);

        let mut leaf_0 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32), &val_0, 0);

        let mut leaf_1 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32), &val_1, 0);

        root.set_child(&mut leaf_0)?;
        root.set_child(&mut leaf_1)?;
        leaf_0.write_to_storage(&db, false).await?;
        leaf_1.write_to_storage(&db, false).await?;

        root.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        root.write_to_storage(&db, false).await?;

        let leaves_hash = TC::compute_parent_hash_from_children(
            &AzksValue(TC::hash_leaf_with_commitment(val_0, 0).0),
            &leaf_0.label.value::<TC>(),
            &AzksValue(TC::hash_leaf_with_commitment(val_1, 0).0),
            &leaf_1.label.value::<TC>(),
        );

        let expected = TC::compute_root_hash_from_val(&leaves_hash);

        let stored_root = db.get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root())).await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => TC::compute_root_hash_from_val(&node.latest_node.hash),
            _ => panic!("Root not found in storage."),
        };

        assert_eq!(root_digest, expected, "Root hash not equal to expected");

        Ok(())
    }

    test_config!(test_insert_single_leaf_below_root);
    async fn test_insert_single_leaf_below_root<TC: Configuration>() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);
        let mut root = new_root_node::<TC>();

        let val_0 = AzksValue([0u8; DIGEST_BYTES]);
        let val_1 = AzksValue([1u8; DIGEST_BYTES]);
        let val_2 = AzksValue([2u8; DIGEST_BYTES]);

        let mut right_child =
            new_interior_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32), 3);

        let mut leaf_0 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b00u64), 2u32), &val_0, 1);

        let mut leaf_1 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b11u64 << 62), 2u32), &val_1, 2);

        let mut leaf_2 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b10u64 << 62), 2u32), &val_2, 3);

        right_child.set_child(&mut leaf_2)?;
        right_child.set_child(&mut leaf_1)?;
        leaf_2.write_to_storage(&db, false).await?;
        leaf_1.write_to_storage(&db, false).await?;

        right_child.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        right_child.write_to_storage(&db, false).await?;

        root.set_child(&mut leaf_0)?;
        root.set_child(&mut right_child)?;
        leaf_0.write_to_storage(&db, false).await?;
        right_child.write_to_storage(&db, false).await?;

        root.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        root.write_to_storage(&db, false).await?;

        let leaf_0_hash = (TC::hash_leaf_with_commitment(val_0, 1), leaf_0.label.value::<TC>());

        let leaf_1_hash = (TC::hash_leaf_with_commitment(val_1, 2), leaf_1.label.value::<TC>());

        let leaf_2_hash = (TC::hash_leaf_with_commitment(val_2, 3), leaf_2.label.value::<TC>());

        let right_child_expected_hash = (
            TC::compute_parent_hash_from_children(
                &AzksValue(leaf_2_hash.0.0),
                &leaf_2_hash.1,
                &AzksValue(leaf_1_hash.0.0),
                &leaf_1_hash.1,
            ),
            NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32).value::<TC>(),
        );

        let stored_root = db.get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root())).await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => TC::compute_root_hash_from_val(&node.latest_node.hash),
            _ => panic!("Root not found in storage."),
        };

        let expected = TC::compute_root_hash_from_val(&TC::compute_parent_hash_from_children(
            &AzksValue(leaf_0_hash.0.0),
            &leaf_0_hash.1,
            &AzksValue(right_child_expected_hash.0.0),
            &right_child_expected_hash.1,
        ));
        assert!(root_digest == expected, "Root hash not equal to expected");
        Ok(())
    }

    test_config!(test_insert_single_leaf_below_root_both_sides);
    async fn test_insert_single_leaf_below_root_both_sides<TC: Configuration>()
    -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);
        let mut root = new_root_node::<TC>();

        let mut left_child =
            new_interior_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32), 4);

        let mut right_child =
            new_interior_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32), 3);

        let val_0 = AzksValue([0u8; DIGEST_BYTES]);
        let val_1 = AzksValue([1u8; DIGEST_BYTES]);
        let val_2 = AzksValue([2u8; DIGEST_BYTES]);
        let val_3 = AzksValue([3u8; DIGEST_BYTES]);

        let mut leaf_0 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b000u64), 3u32), &val_0, 1);

        let mut leaf_1 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b111u64 << 61), 3u32), &val_1, 2);

        let mut leaf_2 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b100u64 << 61), 3u32), &val_2, 3);

        let mut leaf_3 =
            new_leaf_node::<TC>(NodeLabel::new(byte_arr_from_u64(0b010u64 << 61), 3u32), &val_3, 4);

        left_child.set_child(&mut leaf_0)?;
        left_child.set_child(&mut leaf_3)?;
        leaf_0.write_to_storage(&db, false).await?;
        leaf_3.write_to_storage(&db, false).await?;

        left_child.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        left_child.write_to_storage(&db, false).await?;

        right_child.set_child(&mut leaf_2)?;
        right_child.set_child(&mut leaf_1)?;
        leaf_2.write_to_storage(&db, false).await?;
        leaf_1.write_to_storage(&db, false).await?;

        right_child.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        right_child.write_to_storage(&db, false).await?;

        root.set_child(&mut left_child)?;
        root.set_child(&mut right_child)?;
        left_child.write_to_storage(&db, false).await?;
        right_child.write_to_storage(&db, false).await?;

        root.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        root.write_to_storage(&db, false).await?;

        let leaf_0_hash = (TC::hash_leaf_with_commitment(val_0, 1), leaf_0.label.value::<TC>());

        let leaf_1_hash = (TC::hash_leaf_with_commitment(val_1, 2), leaf_1.label.value::<TC>());
        let leaf_2_hash = (TC::hash_leaf_with_commitment(val_2, 3), leaf_2.label.value::<TC>());

        let leaf_3_hash = (TC::hash_leaf_with_commitment(val_3, 4), leaf_3.label.value::<TC>());

        let right_child_expected_hash = (
            TC::compute_parent_hash_from_children(
                &AzksValue(leaf_2_hash.0.0),
                &leaf_2_hash.1,
                &AzksValue(leaf_1_hash.0.0),
                &leaf_1_hash.1,
            ),
            NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32).value::<TC>(),
        );

        let left_child_expected_hash = (
            TC::compute_parent_hash_from_children(
                &AzksValue(leaf_0_hash.0.0),
                &leaf_0_hash.1,
                &AzksValue(leaf_3_hash.0.0),
                &leaf_3_hash.1,
            ),
            NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32).value::<TC>(),
        );

        let stored_root = db.get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root())).await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => TC::compute_root_hash_from_val(&node.latest_node.hash),
            _ => panic!("Root not found in storage."),
        };

        let expected = TC::compute_root_hash_from_val(&TC::compute_parent_hash_from_children(
            &left_child_expected_hash.0,
            &left_child_expected_hash.1,
            &right_child_expected_hash.0,
            &right_child_expected_hash.1,
        ));
        assert_eq!(root_digest, expected, "Root hash not equal to expected");

        Ok(())
    }

    test_config!(test_insert_single_leaf_full_tree);
    async fn test_insert_single_leaf_full_tree<TC: Configuration>() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);
        let mut root = new_root_node::<TC>();

        let mut leaves = Vec::<TreeNode>::new();
        let mut leaf_hashes = Vec::new();
        for i in 0u64..8u64 {
            let leaf_u64 = i << 61;
            let new_leaf = new_leaf_node::<TC>(
                NodeLabel::new(byte_arr_from_u64(leaf_u64), 3u32),
                &AzksValue(TC::hash(&leaf_u64.to_be_bytes())),
                7 - i,
            );
            leaf_hashes.push((
                TC::hash_leaf_with_commitment(AzksValue(TC::hash(&leaf_u64.to_be_bytes())), 7 - i),
                new_leaf.label.value::<TC>(),
            ));
            leaves.push(new_leaf);
        }

        let mut layer_1_interior = Vec::new();
        let mut layer_1_hashes = Vec::new();
        for (i, j) in (0u64..4).enumerate() {
            let interior_u64 = j << 62;
            layer_1_interior.push(new_interior_node::<TC>(
                NodeLabel::new(byte_arr_from_u64(interior_u64), 2u32),
                7 - (2 * j),
            ));

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

        let mut layer_2_interior = Vec::new();
        let mut layer_2_hashes = Vec::new();
        for (i, j) in (0u64..2).enumerate() {
            let interior_u64 = j << 63;
            layer_2_interior.push(new_interior_node::<TC>(
                NodeLabel::new(byte_arr_from_u64(interior_u64), 1u32),
                7 - (4 * j),
            ));

            let left_child_hash = layer_1_hashes[2 * i].clone();
            let right_child_hash = layer_1_hashes[2 * i + 1].clone();
            layer_2_hashes.push((
                TC::compute_parent_hash_from_children(
                    &left_child_hash.0,
                    &left_child_hash.1,
                    &right_child_hash.0,
                    &right_child_hash.1,
                ),
                NodeLabel::new(byte_arr_from_u64(j << 63), 1u32).value::<TC>(),
            ));
        }

        let expected = TC::compute_root_hash_from_val(&TC::compute_parent_hash_from_children(
            &layer_2_hashes[0].0,
            &layer_2_hashes[0].1,
            &layer_2_hashes[1].0,
            &layer_2_hashes[1].1,
        ));

        for node in layer_1_interior.iter_mut() {
            let mut left_child = leaves.remove(0);
            let mut right_child = leaves.remove(0);

            node.set_child(&mut left_child)?;
            node.set_child(&mut right_child)?;
            left_child.write_to_storage(&db, false).await?;
            right_child.write_to_storage(&db, false).await?;

            node.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
            node.write_to_storage(&db, false).await?;
        }

        for node in layer_2_interior.iter_mut() {
            let mut left_child = layer_1_interior.remove(0);
            let mut right_child = layer_1_interior.remove(0);

            node.set_child(&mut left_child)?;
            node.set_child(&mut right_child)?;
            left_child.write_to_storage(&db, false).await?;
            right_child.write_to_storage(&db, false).await?;

            node.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
            node.write_to_storage(&db, false).await?;
        }

        let mut left_child = layer_2_interior.remove(0);
        let mut right_child = layer_2_interior.remove(0);

        root.set_child(&mut left_child)?;
        root.set_child(&mut right_child)?;
        left_child.write_to_storage(&db, false).await?;
        right_child.write_to_storage(&db, false).await?;

        root.update_hash::<TC, _>(&db, NodeHashingMode::WithLeafEpoch).await?;
        root.write_to_storage(&db, false).await?;

        let stored_root = db.get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root())).await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => TC::compute_root_hash_from_val(&node.latest_node.hash),
            _ => panic!("Root not found in storage."),
        };

        assert_eq!(root_digest, expected, "Root hash not equal to expected");
        Ok(())
    }
}
