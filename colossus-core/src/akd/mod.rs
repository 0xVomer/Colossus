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

pub const ARITY: usize = 2;

pub const LEAF_LEN: u32 = 256;

pub const ROOT_LABEL: node_label::NodeLabel = NodeLabel { label_val: [0u8; 32], label_len: 0 };

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Bit {
    Zero = 0u8,
    One = 1u8,
}

pub trait SizeOf {
    fn size_of(&self) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VersionFreshness {
    Stale = 0u8,

    Fresh = 1u8,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PrefixOrdering {
    WithZero = 0u8,

    WithOne = 1u8,

    Invalid = u8::MAX,
}

impl SizeOf for PrefixOrdering {
    fn size_of(&self) -> usize {
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Direction {
    Left = 0u8,

    Right = 1u8,
}

impl SizeOf for Direction {
    fn size_of(&self) -> usize {
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
    pub fn other(&self) -> Self {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EpochHash(pub u64, pub Digest);

impl EpochHash {
    pub fn epoch(&self) -> u64 {
        self.0
    }

    pub fn hash(&self) -> Digest {
        self.1
    }
}

#[derive(Clone, Debug)]

pub struct LookupInfo {
    pub(crate) value_state: ValueState,
    pub(crate) marker_version: u64,
    pub(crate) existent_label: NodeLabel,
    pub(crate) marker_label: NodeLabel,
    pub(crate) non_existent_label: NodeLabel,
}

pub mod serde_helpers {
    use hex::{FromHex, ToHex};
    use serde::Deserialize;

    use super::azks::AzksValue;

    pub fn bytes_serialize_hex<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: AsRef<[u8]>,
    {
        let hex_str = &x.as_ref().encode_hex_upper::<String>();
        s.serialize_str(hex_str)
    }

    pub fn bytes_deserialize_hex<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: AsRef<[u8]> + FromHex,
        <T as FromHex>::Error: core::fmt::Display,
    {
        let hex_str = String::deserialize(deserializer)?;
        T::from_hex(hex_str).map_err(serde::de::Error::custom)
    }

    pub fn azks_value_hex_serialize<S>(x: &AzksValue, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        bytes_serialize_hex(&x.0, s)
    }

    pub fn azks_value_hex_deserialize<'de, D>(deserializer: D) -> Result<AzksValue, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(AzksValue(bytes_deserialize_hex(deserializer)?))
    }

    pub fn azks_value_serialize<S>(x: &AzksValue, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde_bytes::Serialize;
        x.0.to_vec().serialize(s)
    }

    pub fn azks_value_deserialize<'de, D>(deserializer: D) -> Result<AzksValue, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = <Vec<u8> as serde_bytes::Deserialize>::deserialize(deserializer)?;
        Ok(AzksValue(crate::akd::try_parse_digest(&buf).map_err(serde::de::Error::custom)?))
    }
}
