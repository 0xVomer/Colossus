use serde::{Deserialize, Serialize};
use std::{fmt::Debug, ops::BitOr};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Attribute {
    pub(crate) id: usize,
    pub(crate) write_status: AttributeStatus,
}

impl Attribute {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_status(&self) -> AttributeStatus {
        self.write_status
    }
}

/// Whether to provide an encryption key in the master public key for this
/// attribute.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttributeStatus {
    EncryptDecrypt,
    DecryptOnly,
}

impl BitOr for AttributeStatus {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::DecryptOnly || rhs == Self::DecryptOnly {
            Self::DecryptOnly
        } else {
            Self::EncryptDecrypt
        }
    }
}

impl From<AttributeStatus> for bool {
    fn from(val: AttributeStatus) -> Self {
        val == AttributeStatus::EncryptDecrypt
    }
}

/// A qualified attribute is composed of a dimension an attribute name.
#[derive(Hash, PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "&str", into = "String")]
pub struct QualifiedAttribute {
    pub dimension: String,
    pub name: String,
}

impl QualifiedAttribute {
    /// Creates a qualified attribute with the given dimension and attribute names.
    #[must_use]
    pub fn new(dimension: &str, name: &str) -> Self {
        Self {
            dimension: dimension.to_owned(),
            name: name.to_owned(),
        }
    }
}

impl Debug for QualifiedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}::{}", &self.dimension, &self.name))
    }
}

impl std::fmt::Display for QualifiedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.dimension, self.name)
    }
}

impl From<QualifiedAttribute> for String {
    fn from(attr: QualifiedAttribute) -> Self {
        attr.to_string()
    }
}

impl From<(&str, &str)> for QualifiedAttribute {
    fn from(input: (&str, &str)) -> Self {
        Self {
            dimension: input.0.to_owned(),
            name: input.1.to_owned(),
        }
    }
}

impl From<(String, String)> for QualifiedAttribute {
    fn from(input: (String, String)) -> Self {
        Self { dimension: input.0, name: input.1 }
    }
}

impl TryFrom<&str> for QualifiedAttribute {
    type Error = crate::policy::errors::PolicyError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (dimension, component) = s.split_once("::").ok_or_else(|| {
            crate::policy::errors::PolicyError::InvalidAttribute(format!(
                "at least one separator '::' expected in {s}"
            ))
        })?;

        if component.contains("::") {
            return Err(crate::policy::errors::PolicyError::InvalidAttribute(format!(
                "separator '::' expected only once in {s}"
            )));
        }

        if dimension.is_empty() || component.is_empty() {
            return Err(crate::policy::errors::PolicyError::InvalidAttribute(format!(
                "empty dimension or empty name in {s}"
            )));
        }

        Ok(Self::new(dimension.trim(), component.trim()))
    }
}
