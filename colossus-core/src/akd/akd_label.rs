use super::{
    SizeOf,
    serde_helpers::{bytes_deserialize_hex, bytes_serialize_hex},
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

/// The label of a particular entry in the AKD
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AkdLabel(
    #[serde(serialize_with = "bytes_serialize_hex")]
    #[serde(deserialize_with = "bytes_deserialize_hex")]
    pub Vec<u8>,
);

impl SizeOf for AkdLabel {
    fn size_of(&self) -> usize {
        self.0.len()
    }
}

impl core::ops::Deref for AkdLabel {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for AkdLabel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::convert::From<&str> for AkdLabel {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl core::convert::From<&String> for AkdLabel {
    fn from(s: &String) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl AkdLabel {
    /// Gets a random label
    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes.to_vec())
    }
}
