mod akd_label;
mod akd_value;
pub mod auditor;
mod azks;
pub mod ecvrf;
pub mod errors;
mod hash;
pub mod local_auditing;
mod node_label;
pub mod proofs;
pub mod tree_node;
pub mod verify;

use crate::{configuration::Configuration, storage::types::ValueState};
pub use akd_label::AkdLabel;
pub use akd_value::AkdValue;
pub use azks::{
    Azks, AzksElement, AzksParallelismConfig, AzksValue, AzksValueWithEpoch, DEFAULT_AZKS_KEY,
    InsertMode, TOMBSTONE,
};
pub use hash::{DIGEST_BYTES, Digest, EMPTY_DIGEST, try_parse_digest};
pub use node_label::{NodeLabel, random_label};
use serde::{Deserialize, Serialize};

#[macro_use]
pub mod utils;
pub mod test_utils;
#[cfg(test)]
mod tests;

// ========== Constants and type aliases ========== //

/// The number of children each non-leaf node has in the tree in AKD
pub const ARITY: usize = 2;

/// The length of a leaf node's label (in bits)
pub const LEAF_LEN: u32 = 256;

/// The label used for a root node
pub const ROOT_LABEL: node_label::NodeLabel = NodeLabel { label_val: [0u8; 32], label_len: 0 };

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Bit {
    Zero = 0u8,
    One = 1u8,
}

// ============================================
// Traits
// ============================================

/// Retrieve the in-memory size of a structure
pub trait SizeOf {
    /// Retrieve the in-memory size of a structure
    fn size_of(&self) -> usize;
}

// ============================================
// Typedefs and constants
// ============================================

/// Whether or not a node is marked as stale or fresh
/// Stale nodes are no longer active because a newer
/// version exists to replace them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VersionFreshness {
    /// Represents not being the most recent version
    Stale = 0u8,
    /// Corresponds to the most recent version
    Fresh = 1u8,
}

/// This type is used to indicate whether or not
/// one label is a prefix of another, and if so,
/// whether the longer string has a 0 after the prefix,
/// or a 1 after the prefix. If the first label is equal
/// to the second, or not a prefix of the second, then it
/// is considered invalid.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PrefixOrdering {
    /// Corresponds to a [Direction::Left]
    WithZero = 0u8,
    /// Corresponds to a [Direction::Right]
    WithOne = 1u8,
    /// First label is either equal to the second, or
    /// simply not a prefix of the second
    Invalid = u8::MAX,
}

impl SizeOf for PrefixOrdering {
    fn size_of(&self) -> usize {
        // The size of the enum is 24 bytes. The extra 8 bytes are used to store a 64-bit
        // discriminator that is used to identify the variant currently saved in the enum.
        24usize
    }
}

impl From<Bit> for PrefixOrdering {
    fn from(bit: Bit) -> Self {
        match bit {
            Bit::Zero => Self::WithZero,
            Bit::One => Self::WithOne,
        }
    }
}

/// This type is used to indicate a direction for a
/// particular node relative to its parent. We use
/// 0 to represent "left" and 1 to represent "right".
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Direction {
    /// Left
    Left = 0u8,
    /// Right
    Right = 1u8,
}

impl SizeOf for Direction {
    fn size_of(&self) -> usize {
        // The size of the enum is 24 bytes. The extra 8 bytes are used to store a 64-bit
        // discriminator that is used to identify the variant currently saved in the enum.
        24usize
    }
}

impl From<Bit> for Direction {
    fn from(bit: Bit) -> Self {
        match bit {
            Bit::Zero => Self::Left,
            Bit::One => Self::Right,
        }
    }
}

impl core::convert::TryFrom<PrefixOrdering> for Direction {
    type Error = String;
    fn try_from(prefix_ordering: PrefixOrdering) -> Result<Self, Self::Error> {
        match prefix_ordering {
            PrefixOrdering::WithZero => Ok(Direction::Left),
            PrefixOrdering::WithOne => Ok(Direction::Right),
            _ => Err("Could not convert from PrefixOrdering to Direction".to_string()),
        }
    }
}

impl Direction {
    /// Returns the opposite of the direction
    pub fn other(&self) -> Self {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

/// Root hash of the tree and its associated epoch
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EpochHash(pub u64, pub Digest);

impl EpochHash {
    /// Get the contained epoch
    pub fn epoch(&self) -> u64 {
        self.0
    }
    /// Get the contained hash
    pub fn hash(&self) -> Digest {
        self.1
    }
}

#[derive(Clone, Debug)]
/// Info needed for a lookup of a user for an epoch
pub struct LookupInfo {
    pub(crate) value_state: ValueState,
    pub(crate) marker_version: u64,
    pub(crate) existent_label: NodeLabel,
    pub(crate) marker_label: NodeLabel,
    pub(crate) non_existent_label: NodeLabel,
}

/// Serde serialization helpers
pub mod serde_helpers {
    use hex::{FromHex, ToHex};
    use serde::Deserialize;

    use super::azks::AzksValue;

    /// A serde hex serializer for bytes
    pub fn bytes_serialize_hex<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: AsRef<[u8]>,
    {
        let hex_str = &x.as_ref().encode_hex_upper::<String>();
        s.serialize_str(hex_str)
    }

    /// A serde hex deserializer for bytes
    pub fn bytes_deserialize_hex<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: AsRef<[u8]> + FromHex,
        <T as FromHex>::Error: core::fmt::Display,
    {
        let hex_str = String::deserialize(deserializer)?;
        T::from_hex(hex_str).map_err(serde::de::Error::custom)
    }

    /// Serialize a digest
    pub fn azks_value_hex_serialize<S>(x: &AzksValue, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        bytes_serialize_hex(&x.0, s)
    }

    /// Deserialize an [AzksValue]
    pub fn azks_value_hex_deserialize<'de, D>(deserializer: D) -> Result<AzksValue, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(AzksValue(bytes_deserialize_hex(deserializer)?))
    }

    /// Serialize a digest
    pub fn azks_value_serialize<S>(x: &AzksValue, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde_bytes::Serialize;
        x.0.to_vec().serialize(s)
    }

    /// Deserialize an [AzksValue]
    pub fn azks_value_deserialize<'de, D>(deserializer: D) -> Result<AzksValue, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = <Vec<u8> as serde_bytes::Deserialize>::deserialize(deserializer)?;
        Ok(AzksValue(crate::akd::try_parse_digest(&buf).map_err(serde::de::Error::custom)?))
    }
}
