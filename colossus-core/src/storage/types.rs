use super::traits::Storable;
use crate::akd::{
    AkdLabel, AkdValue, Azks, AzksValue, NodeLabel,
    tree_node::{TreeNode, TreeNodeType, TreeNodeWithPreviousValue},
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(PartialEq, Eq, Debug, Hash, Clone, Copy)]
pub enum StorageType {
    Azks = 1,

    TreeNode = 2,

    ValueState = 4,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
pub struct ValueStateKey(pub Vec<u8>, pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct ValueState {
    pub value: AkdValue, // The actual value

    pub version: u64,

    pub label: NodeLabel,

    pub epoch: u64,

    pub username: AkdLabel,
}

impl crate::akd::SizeOf for ValueState {
    fn size_of(&self) -> usize {
        self.value.size_of()
            + std::mem::size_of::<u64>()
            + self.label.size_of()
            + std::mem::size_of::<u64>()
            + self.username.size_of()
    }
}

impl super::traits::Storable for ValueState {
    type StorageKey = ValueStateKey;

    fn data_type() -> StorageType {
        StorageType::ValueState
    }

    fn get_id(&self) -> ValueStateKey {
        ValueStateKey(self.username.to_vec(), self.epoch)
    }

    fn get_full_binary_key_id(key: &ValueStateKey) -> Vec<u8> {
        let mut result = vec![StorageType::ValueState as u8];
        result.extend_from_slice(&key.1.to_be_bytes());
        result.extend_from_slice(&key.0);

        result
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<ValueStateKey, String> {
        if bin.len() < 10 {
            return Err("Not enough bytes to form a proper key".to_string());
        }

        if bin[0] != StorageType::ValueState as u8 {
            return Err("Not a value state key".to_string());
        }

        let epoch_bytes: [u8; 8] = bin[1..=8].try_into().expect("Slice with incorrect length");
        let epoch = u64::from_be_bytes(epoch_bytes);
        Ok(ValueStateKey(bin[9..].to_vec(), epoch))
    }
}

impl ValueState {
    pub(crate) fn new(
        username: AkdLabel,
        plaintext_val: AkdValue,
        version: u64,
        label: NodeLabel,
        epoch: u64,
    ) -> Self {
        ValueState {
            value: plaintext_val,
            version,
            label,
            epoch,
            username,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct KeyData {
    pub states: Vec<ValueState>,
}

#[derive(std::fmt::Debug, Clone, Copy)]
pub enum ValueStateRetrievalFlag {
    SpecificVersion(u64),

    SpecificEpoch(u64),

    LeqEpoch(u64),

    MaxEpoch,

    MinEpoch,
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum DbRecord {
    Azks(Azks),

    TreeNode(TreeNodeWithPreviousValue),

    ValueState(ValueState),
}

impl crate::akd::SizeOf for DbRecord {
    fn size_of(&self) -> usize {
        match &self {
            DbRecord::Azks(azks) => azks.size_of(),
            DbRecord::TreeNode(node) => node.size_of(),
            DbRecord::ValueState(state) => state.size_of(),
        }
    }
}

impl Clone for DbRecord {
    fn clone(&self) -> Self {
        match &self {
            DbRecord::Azks(azks) => DbRecord::Azks(azks.clone()),
            DbRecord::TreeNode(node) => DbRecord::TreeNode(node.clone()),
            DbRecord::ValueState(state) => DbRecord::ValueState(state.clone()),
        }
    }
}

impl DbRecord {
    pub fn get_full_binary_id(&self) -> Vec<u8> {
        match &self {
            DbRecord::Azks(azks) => azks.get_full_binary_id(),
            DbRecord::TreeNode(node) => node.get_full_binary_id(),
            DbRecord::ValueState(state) => state.get_full_binary_id(),
        }
    }

    pub(crate) fn transaction_priority(&self) -> u8 {
        match &self {
            DbRecord::Azks(_) => 2,
            _ => 1,
        }
    }

    /* Data Layer Builders */

    pub fn build_azks(latest_epoch: u64, num_nodes: u64) -> Azks {
        Azks { latest_epoch, num_nodes }
    }

    #[allow(clippy::too_many_arguments)]

    pub fn build_tree_node_with_previous_value(
        label_val: [u8; 32],
        label_len: u32,
        last_epoch: u64,
        least_descendant_ep: u64,
        parent_label_val: [u8; 32],
        parent_label_len: u32,
        node_type: u8,
        left_child: Option<NodeLabel>,
        right_child: Option<NodeLabel>,
        value: crate::akd::Digest,
        p_last_epoch: Option<u64>,
        p_least_descendant_ep: Option<u64>,
        p_parent_label_val: Option<[u8; 32]>,
        p_parent_label_len: Option<u32>,
        p_node_type: Option<u8>,
        p_left_child: Option<NodeLabel>,
        p_right_child: Option<NodeLabel>,
        p_value: Option<crate::akd::Digest>,
    ) -> TreeNodeWithPreviousValue {
        let label = NodeLabel::new(label_val, label_len);
        let p_node = match (
            p_last_epoch,
            p_least_descendant_ep,
            p_parent_label_val,
            p_parent_label_len,
            p_node_type,
            p_value,
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => Some(TreeNode {
                label,
                last_epoch: a,
                min_descendant_epoch: b,
                parent: NodeLabel::new(c, d),
                node_type: TreeNodeType::from_u8(e),
                left_child: p_left_child,
                right_child: p_right_child,
                hash: AzksValue(f),
            }),
            _ => None,
        };
        TreeNodeWithPreviousValue {
            label,
            latest_node: TreeNode {
                label,
                last_epoch,
                min_descendant_epoch: least_descendant_ep,
                parent: NodeLabel::new(parent_label_val, parent_label_len),
                node_type: TreeNodeType::from_u8(node_type),
                left_child,
                right_child,
                hash: AzksValue(value),
            },
            previous_node: p_node,
        }
    }

    pub fn build_user_state(
        username: Vec<u8>,
        plaintext_val: Vec<u8>,
        version: u64,
        label_len: u32,
        label_val: [u8; 32],
        epoch: u64,
    ) -> ValueState {
        ValueState {
            value: AkdValue(plaintext_val),
            version,
            label: NodeLabel::new(label_val, label_len),
            epoch,
            username: AkdLabel(username),
        }
    }
}
