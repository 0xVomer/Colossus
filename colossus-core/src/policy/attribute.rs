use cid::{CidGeneric, multibase, multihash::Multihash};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, ops::Deref};
use tiny_keccak::{Hasher, Sha3};

const RAW: u64 = 0x55;
const DIGEST_LEN: usize = 32;
const SHA3_256: u64 = 0x16;

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

pub fn attribute_cid(
    dimension: impl AsRef<[u8]>,
    attribute: impl AsRef<[u8]>,
) -> CidGeneric<DIGEST_LEN> {
    let mut hasher = Sha3::v256();
    let mut input_digest = [0u8; DIGEST_LEN];
    hasher.update(dimension.as_ref());
    hasher.update(attribute.as_ref());
    hasher.finalize(&mut input_digest);
    let mhash = Multihash::<DIGEST_LEN>::wrap(SHA3_256, &input_digest).unwrap();
    CidGeneric::<DIGEST_LEN>::new_v1(RAW, mhash)
}

#[derive(Hash, PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "&str", into = "String")]
pub struct QualifiedAttribute {
    pub dimension: String,
    pub cid: cid::CidGeneric<DIGEST_LEN>,
}

impl QualifiedAttribute {
    #[must_use]
    pub fn new(dimension: &str, name: &str) -> Self {
        Self {
            dimension: dimension.to_owned(),
            cid: attribute_cid(dimension.as_bytes(), name.as_bytes()),
        }
    }

    pub fn hash(&self) -> &Multihash<DIGEST_LEN> {
        self.cid.hash()
    }

    pub fn hash_digest(&self) -> &[u8] {
        self.cid.hash().digest()
    }

    pub fn bytes(&self) -> ATTRIBUTE {
        ATTRIBUTE::from(self.cid.to_bytes())
    }

    pub fn cid(&self) -> &cid::CidGeneric<DIGEST_LEN> {
        &self.cid
    }

    pub fn to_string_of_base(
        &self,
        base: multibase::Base,
    ) -> core::result::Result<String, cid::Error> {
        self.cid.to_string_of_base(base)
    }

    pub fn from_cid(dim: String, cid: &cid::CidGeneric<DIGEST_LEN>) -> Option<Self> {
        if cid.codec() == RAW
            && cid.hash().code() == SHA3_256
            && cid.hash().digest().len() == DIGEST_LEN
        {
            Some(QualifiedAttribute { dimension: dim, cid: *cid })
        } else {
            None
        }
    }
}

impl Debug for QualifiedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self.cid))
    }
}

impl std::fmt::Display for QualifiedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cid)
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
            cid: attribute_cid(input.0.as_bytes(), input.1.as_bytes()),
        }
    }
}

impl From<(&str, &ATTRIBUTE)> for QualifiedAttribute {
    fn from(input: (&str, &ATTRIBUTE)) -> Self {
        let cid = CidGeneric::try_from(input.1.0.clone());
        Self {
            dimension: input.0.to_owned(),
            cid: cid.unwrap(),
        }
    }
}

impl From<(String, String)> for QualifiedAttribute {
    fn from(input: (String, String)) -> Self {
        Self {
            dimension: input.0.to_owned(),
            cid: attribute_cid(input.0.as_bytes(), input.1.as_bytes()),
        }
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
