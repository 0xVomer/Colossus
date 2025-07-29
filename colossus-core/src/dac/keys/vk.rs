use blastkids::GroupEncoding;
use bls12_381_plus::{G1Affine, G2Affine};
use bls12_381_plus::{G1Projective, G2Projective};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VK {
    G1(G1Projective),
    G2(G2Projective),
}

impl VK {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VK::G1(g1) => g1.to_compressed().to_vec(),
            VK::G2(g2) => g2.to_compressed().to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VKCompact {
    pub g1: [u8; G1Affine::COMPRESSED_BYTES],
    pub g2: [u8; G2Affine::COMPRESSED_BYTES],
}

impl VKCompact {
    pub fn new(g1: G1Affine, g2: G2Affine) -> Self {
        Self {
            g1: g1.to_compressed(),
            g2: g2.to_compressed(),
        }
    }
}

impl TryFrom<Vec<VK>> for VKCompact {
    type Error = String;

    fn try_from(vk: Vec<VK>) -> Result<Self, Self::Error> {
        if vk.is_empty() {
            return Err("Empty VK".to_string());
        }

        let g1 = match &vk[0] {
            VK::G1(g1) => g1.to_compressed(),
            VK::G2(_) => return Err("First element is not G1".to_string()),
        };

        let g2 = match &vk[1] {
            VK::G2(g2) => g2.to_compressed(),
            VK::G1(_) => return Err("Second element is not G2".to_string()),
        };

        Ok(Self { g1, g2 })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VKCompressed {
    G1(Vec<u8>),
    G2(Vec<u8>),
}

impl From<VK> for VKCompressed {
    fn from(vk: VK) -> Self {
        match vk {
            VK::G1(g1) => Self::G1(g1.to_compressed().into()),
            VK::G2(g2) => Self::G2(g2.to_compressed().into()),
        }
    }
}

impl From<&VK> for VKCompressed {
    fn from(vk: &VK) -> Self {
        match vk {
            VK::G1(g1) => Self::G1(g1.to_compressed().into()),
            VK::G2(g2) => Self::G2(g2.to_compressed().into()),
        }
    }
}

impl std::convert::TryFrom<VKCompressed> for VK {
    type Error = String;

    fn try_from(vk_compressed: VKCompressed) -> Result<Self, Self::Error> {
        match vk_compressed {
            VKCompressed::G1(g1) => {
                let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(g1.as_ref());
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    return Err("Invalid G1 point".to_string());
                }

                Ok(VK::G1(g1_maybe.unwrap().into()))
            },
            VKCompressed::G2(g2) => {
                let mut g2_bytes = [0u8; G2Affine::COMPRESSED_BYTES];
                g2_bytes.copy_from_slice(g2.as_ref());
                let g2 = G2Affine::from_compressed(&g2_bytes);

                if g2.is_none().into() {
                    return Err("Invalid G2 point".to_string());
                }

                Ok(VK::G2(g2.unwrap().into()))
            },
        }
    }
}

impl std::convert::TryFrom<Vec<u8>> for VK {
    type Error = String;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        match v.len() {
            48 => {
                let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(&v[..]);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    return Err("Invalid G1 point".to_string());
                }

                Ok(VK::G1(g1_maybe.unwrap().into()))
            },
            96 => {
                let mut g2_bytes = [0u8; G2Affine::COMPRESSED_BYTES];
                g2_bytes.copy_from_slice(&v[..]);
                let g2 = G2Affine::from_compressed(&g2_bytes);

                if g2.is_none().into() {
                    return Err("Invalid G2 point".to_string());
                }

                Ok(VK::G2(g2.unwrap().into()))
            },
            _ => Err("Invalid Verification Key (VK) length".to_string()),
        }
    }
}

impl TryFrom<&Vec<u8>> for VKCompressed {
    type Error = String;

    fn try_from(v: &Vec<u8>) -> Result<Self, Self::Error> {
        match v.len() {
            48 => {
                let mut bytes = [0u8; 48];
                bytes.copy_from_slice(&v[..]);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    return Err("Invalid G1 point".to_string());
                }

                Ok(VKCompressed::G1(g1_maybe.unwrap().to_bytes().into()))
            },
            96 => {
                let mut g2_bytes = [0u8; 96];
                g2_bytes.copy_from_slice(&v[..]);
                let g2 = G2Affine::from_compressed(&g2_bytes);

                if g2.is_none().into() {
                    return Err("Invalid G2 point".to_string());
                }

                Ok(VKCompressed::G2(g2.unwrap().to_bytes().into()))
            },
            _ => Err("Invalid Verification Key (VK) length".to_string()),
        }
    }
}

impl AsRef<[u8]> for VKCompressed {
    fn as_ref(&self) -> &[u8] {
        match self {
            VKCompressed::G1(g1) => g1.as_ref(),
            VKCompressed::G2(g2) => g2.as_ref(),
        }
    }
}

impl From<Vec<u8>> for VKCompressed {
    fn from(v: Vec<u8>) -> Self {
        match v.len() {
            48 => {
                let mut bytes = [0u8; 48];
                bytes.copy_from_slice(&v[..]);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    panic!("Invalid G1 point");
                }

                VKCompressed::G1(g1_maybe.unwrap().to_bytes().into())
            },
            96 => {
                let mut g2_bytes = [0u8; 96];
                g2_bytes.copy_from_slice(&v[..]);
                let g2 = G2Affine::from_compressed(&g2_bytes);

                if g2.is_none().into() {
                    panic!("Invalid G2 point");
                }

                VKCompressed::G2(g2.unwrap().to_bytes().into())
            },
            _ => panic!("Invalid VK length"),
        }
    }
}

#[cfg(test)]
mod vk_tests {
    use blastkids::Group;
    use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};

    use super::*;

    #[test]
    fn test_vk_compressed() {
        let mut rng = CsRng::from_entropy();

        let vk = VK::G1(G1Projective::random(&mut rng));
        let vk_compressed: VKCompressed = vk.clone().into();
        let vk2: VK = vk_compressed.try_into().unwrap();

        assert_eq!(vk, vk2);

        let vk = VK::G2(G2Projective::random(&mut rng.clone()));
        let vk_compressed: VKCompressed = vk.clone().into();
        let vk2: VK = vk_compressed.try_into().unwrap();

        assert_eq!(vk, vk2);
    }
}
