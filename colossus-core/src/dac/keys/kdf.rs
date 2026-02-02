// Key derivation functions - some are reserved for future use
#![allow(dead_code)]

use super::{Error, vk};
use blastkids::kdf;
use bls12_381_plus::elliptic_curve::hash2curve::ExpandMsgXmd;

use bls12_381_plus::G1Affine;
pub use bls12_381_plus::G1Projective;
use bls12_381_plus::G2Affine;
pub use bls12_381_plus::G2Projective;
pub use bls12_381_plus::Scalar;
pub use bls12_381_plus::group::Curve;
pub use bls12_381_plus::group::Group;
pub use secrecy::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub use secrecy::{ExposeSecret, SecretBox};

use bls12_381_plus::elliptic_curve::ops::MulByGenerator;

const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub struct Manager {
    master_sk: SecretBox<Scalar>,
}

impl Clone for Manager {
    fn clone(&self) -> Self {
        Self {
            master_sk: SecretBox::new(Box::new(*self.master_sk.expose_secret())),
        }
    }
}

impl PartialEq for Manager {
    fn eq(&self, other: &Self) -> bool {
        self.master_sk.expose_secret() == other.master_sk.expose_secret()
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            master_sk: SecretBox::new(Box::new(Scalar::ZERO)),
        }
    }
}

impl Manager {
    fn new(master_sk: SecretBox<Scalar>) -> Self {
        Self { master_sk }
    }

    pub fn from_seed(seed: impl AsRef<[u8]> + Zeroize + ZeroizeOnDrop) -> Self {
        let master_sk: Scalar =
            kdf::derive_master_sk(seed.as_ref()).expect("Seed has length of 32 bytes");
        Self::new(SecretBox::new(Box::new(master_sk)))
    }

    pub fn account(&self, index: u32) -> Account {
        let sk: SecretBox<Scalar> =
            SecretBox::new(Box::new(kdf::ckd_sk_hardened(self.master_sk.expose_secret(), index)));
        let sk_hardened_0 =
            Zeroizing::new(kdf::ckd_sk_normal::<G2Projective>(sk.expose_secret(), 0));
        let pk_g1 = G1Projective::mul_by_generator(&sk_hardened_0);
        let pk_g2 = G2Projective::mul_by_generator(sk.expose_secret());

        Account { index, sk, pk_g1, pk_g2 }
    }
}

pub struct Account {
    pub index: u32,
    sk: SecretBox<Scalar>,
    pub pk_g1: G1Projective,
    pub pk_g2: G2Projective,
}

impl Account {
    pub fn new(index: u32, sk: Scalar, pk_g1: G1Projective, pk_g2: G2Projective) -> Self {
        Self {
            index,
            sk: SecretBox::new(Box::new(sk)),
            pk_g1,
            pk_g2,
        }
    }

    pub fn pk_g1(&self) -> G1Affine {
        self.pk_g1.to_affine()
    }

    pub fn pk_g2(&self) -> G2Affine {
        self.pk_g2.to_affine()
    }

    pub fn expand_to(&self, length: u8) -> SecretBox<Vec<Scalar>> {
        SecretBox::new(Box::new(
            (0..length)
                .map(|i| kdf::ckd_sk_normal::<G2Projective>(self.sk.expose_secret(), i as u32))
                .collect::<Vec<Scalar>>(),
        ))
    }

    pub fn sign(&self, message: &[u8]) -> [u8; G2Affine::COMPRESSED_BYTES] {
        let sk_normal_0 =
            Zeroizing::new(kdf::ckd_sk_normal::<G2Projective>(self.sk.expose_secret(), 0));

        let g2_point = G2Projective::hash::<ExpandMsgXmd<sha3::Sha3_256>>(message, DST);

        let signature = g2_point * *sk_normal_0;

        signature.to_compressed()
    }
}

pub fn verify(pk: &G1Affine, message: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let sig_g2 = try_decompress_g2(signature.to_vec())?;

    let hashed_msg_g2 =
        G2Projective::hash::<ExpandMsgXmd<sha3::Sha3_256>>(message, DST).to_affine();
    let g1_generator = G1Projective::generator().to_affine();

    let result = bls12_381_plus::pairing(&pk, &hashed_msg_g2)
        == bls12_381_plus::pairing(&g1_generator, &sig_g2);

    Ok(result)
}

pub fn derive(pk_g1: &G1Projective, pk_g2: &G2Projective, length: u8) -> Vec<vk::VK> {
    let vk_g2_expanded: Vec<vk::VK> = (0..(length - 1))
        .map(|i| vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2Projective>(pk_g2, i as u32)))
        .collect();

    let mut vk = Vec::with_capacity(length as usize);
    vk.push(vk::VK::G1(*pk_g1));
    vk.extend(vk_g2_expanded);
    vk
}

pub fn try_decompress_g1(value: Vec<u8>) -> Result<G1Affine, Error> {
    let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
    bytes.copy_from_slice(&value);
    let maybe_g1 = G1Affine::from_compressed(&bytes);

    if maybe_g1.is_none().into() {
        return Err(Error::InvalidG1Point);
    } else {
        Ok(maybe_g1.unwrap())
    }
}

pub(crate) fn try_decompress_g2(value: Vec<u8>) -> Result<G2Affine, Error> {
    let mut bytes = [0u8; G2Affine::COMPRESSED_BYTES];
    bytes.copy_from_slice(&value);
    let maybe_g2 = G2Affine::from_compressed(&bytes);

    if maybe_g2.is_none().into() {
        return Err(Error::InvalidG2Point);
    } else {
        Ok(maybe_g2.unwrap())
    }
}

#[cfg(test)]
mod basic_test {

    use super::*;

    #[test]
    fn smoke() {
        let seed = Zeroizing::new([69u8; 32]);
        let manager: Manager = Manager::from_seed(seed);

        let account = manager.account(1);

        let expanded = account.expand_to(2);

        let pk_g1 = G1Projective::mul_by_generator(&expanded.expose_secret()[0]);
        let pk_g2_0 = G2Projective::mul_by_generator(&expanded.expose_secret()[0]);
        let pk_g2_1 = G2Projective::mul_by_generator(&expanded.expose_secret()[1]);

        let vk = derive(&account.pk_g1, &account.pk_g2, 3);

        assert_eq!(vk, vec![vk::VK::G1(pk_g1), vk::VK::G2(pk_g2_0), vk::VK::G2(pk_g2_1)]);

        assert_eq!(
            vk,
            vec![
                vk::VK::G1(account.pk_g1),
                vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2Projective>(&account.pk_g2, 0)),
                vk::VK::G2(blastkids::kdf::ckd_pk_normal::<G2Projective>(&account.pk_g2, 1))
            ]
        );
    }

    #[test]
    fn test_sign_roundtrip() {
        let seed = Zeroizing::new([69u8; 32]);
        let manager: Manager = Manager::from_seed(seed);

        let indices = vec![0, 1, 2, 3];

        for index in indices {
            let account = manager.account(index);

            let message = b"hello world";
            let signature = account.sign(message);

            let verified = verify(&account.pk_g1.to_affine(), message, &signature).unwrap();
            assert!(verified);
        }
    }

    #[test]
    fn test_sign_roundtrip_fail() {
        let seed = Zeroizing::new([69u8; 32]);
        let manager: Manager = Manager::from_seed(seed);

        let account = manager.account(1);

        let message = b"hello world";
        let signature = account.sign(message);

        let verified = verify(&account.pk_g1.to_affine(), b"hello world!", &signature).unwrap();
        assert!(!verified);
    }
}
