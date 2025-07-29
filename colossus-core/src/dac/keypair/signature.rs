use crate::dac::ec::G1Projective;
use crate::dac::utils::{try_decompress_g1, try_decompress_g2};
pub use bls12_381_plus::{G2Projective, group::GroupEncoding};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Signature {
    pub(super) z: G1Projective,
    pub(super) y_g1: G1Projective,
    pub(super) y_hat: G2Projective,
    pub(super) t: G1Projective,
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sig_compressed = SignatureCompressed::from(self.clone());
        let sig_json = serde_json::to_string(&sig_compressed).unwrap();
        write!(f, "{}", sig_json)
    }
}

impl FromStr for Signature {
    type Err = crate::dac::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sig_compressed: SignatureCompressed = serde_json::from_str(s)?;
        Signature::try_from(sig_compressed)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignatureCompressed {
    pub z: Vec<u8>,
    pub y_g1: Vec<u8>,
    pub y_hat: Vec<u8>,
    pub t: Vec<u8>,
}

impl From<Signature> for SignatureCompressed {
    fn from(sig: Signature) -> Self {
        SignatureCompressed {
            z: sig.z.to_bytes().into(),
            y_g1: sig.y_g1.to_bytes().into(),
            y_hat: sig.y_hat.to_bytes().into(),
            t: sig.t.to_bytes().into(),
        }
    }
}

impl TryFrom<SignatureCompressed> for Signature {
    type Error = crate::dac::error::Error;

    fn try_from(sig: SignatureCompressed) -> Result<Self, Self::Error> {
        let z = try_decompress_g1(sig.z)?.into();
        let y_g1 = try_decompress_g1(sig.y_g1)?.into();
        let y_hat = try_decompress_g2(sig.y_hat)?.into();
        let t = try_decompress_g1(sig.t)?.into();

        Ok(Signature { z, y_g1, y_hat, t })
    }
}
