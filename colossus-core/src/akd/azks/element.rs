use super::{Digest, NodeLabel, SizeOf, azks_value_hex_deserialize, azks_value_hex_serialize};
use serde::{Deserialize, Serialize};
use std::cmp::{Ord, Ordering, PartialOrd};

pub const EMPTY_VALUE: [u8; 1] = [0u8];

pub const TOMBSTONE: &[u8] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AzksValue(pub Digest);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzksValueWithEpoch(pub Digest);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzksElement {
    pub label: NodeLabel,

    #[serde(serialize_with = "azks_value_hex_serialize")]
    #[serde(deserialize_with = "azks_value_hex_deserialize")]
    pub value: AzksValue,
}

impl SizeOf for AzksElement {
    fn size_of(&self) -> usize {
        self.label.size_of() + self.value.0.len()
    }
}

impl PartialOrd for AzksElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AzksElement {
    fn cmp(&self, other: &Self) -> Ordering {
        self.label.cmp(&other.label)
    }
}
