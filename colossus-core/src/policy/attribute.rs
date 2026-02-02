use cid::multibase;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

/// A raw attribute identifier stored as bytes.
///
/// This is the base type for attribute storage, used internally by both
/// blinded and legacy attribute systems.
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub struct ATTRIBUTE(pub(crate) Vec<u8>);

impl ToString for ATTRIBUTE {
    fn to_string(&self) -> String {
        multibase::encode(multibase::Base::Base64, &self.0)
    }
}

impl Deref for ATTRIBUTE {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ATTRIBUTE {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for ATTRIBUTE {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}
