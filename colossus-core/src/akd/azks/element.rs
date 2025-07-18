use super::{Digest, NodeLabel, SizeOf, azks_value_hex_deserialize, azks_value_hex_serialize};
use serde::{Deserialize, Serialize};
use std::cmp::{Ord, Ordering, PartialOrd};

/// The value to be hashed every time an empty node's hash is to be considered
pub const EMPTY_VALUE: [u8; 1] = [0u8];

/// A "tombstone" is a false value in an AKD ValueState denoting that a real value has been removed (e.g. data rentention policies).
/// Should a tombstone be encountered, we have to assume that the hash of the value is correct, and we move forward without being able to
/// verify the raw value. We utilize an empty array to save space in the storage layer
///
/// See [GitHub issue #130](https://github.com/facebook/akd/issues/130) for more context
pub const TOMBSTONE: &[u8] = &[];

/// The value associated with an element of the AZKS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AzksValue(pub Digest);

/// Used to denote an azks value that has been hashed together with an epoch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzksValueWithEpoch(pub Digest);

/// Represents an element to be inserted into the AZKS. This
/// is a pair consisting of a label ([NodeLabel]) and a value.
/// The purpose of the directory publish is to convert an
/// insertion set of ([AkdLabel], [AkdValue]) tuples into a
/// set of [AzksElement]s, which are then inserted into
/// the AZKS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzksElement {
    /// The label of the node
    pub label: NodeLabel,
    /// The associated hash of the node
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
