use super::{
    error::Error,
    keypair::AliasProof,
    utils::{try_decompress_g1, try_into_scalar},
};
use bls12_381_plus::{
    G1Affine, G1Projective, Scalar,
    elliptic_curve::{bigint, ops::MulByGenerator},
    ff::Field,
    group::{Curve, GroupEncoding, prime::PrimeCurveAffine},
};
use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, ops::Deref};
use tiny_keccak::{Hasher, Sha3};

pub type Challenge = Scalar;

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Nonce(pub(crate) Scalar);

impl Nonce {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha3::v256();
        let mut chash = [0u8; 32];

        hasher.update(bytes.as_ref());
        hasher.finalize(&mut chash);

        Self(Scalar::from(bigint::U256::from_be_slice(&chash)))
    }
}

impl Default for Nonce {
    fn default() -> Self {
        let rng = CsRng::from_entropy();
        Self(Scalar::random(rng))
    }
}

impl TryFrom<[u8; 32]> for Nonce {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        let maybe_coverted = Scalar::from_be_bytes(&bytes);
        if maybe_coverted.is_some().into() {
            Ok(Self(maybe_coverted.unwrap()))
        } else {
            Err(Error::NonceConversionError)
        }
    }
}

impl TryFrom<&[u8; 32]> for Nonce {
    type Error = Error;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        let maybe_coverted = Scalar::from_be_bytes(bytes);
        if maybe_coverted.is_some().into() {
            Ok(Self(maybe_coverted.unwrap()))
        } else {
            Err(Error::NonceConversionError)
        }
    }
}

impl From<Vec<u8>> for Nonce {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes.as_slice())
    }
}

impl From<&Vec<u8>> for Nonce {
    fn from(bytes: &Vec<u8>) -> Self {
        Self::new(bytes.as_slice())
    }
}

impl From<&[u8]> for Nonce {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl Deref for Nonce {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<bls12_381_plus::Scalar> for &Nonce {
    fn eq(&self, other: &bls12_381_plus::Scalar) -> bool {
        self.0 == Scalar::from(*other)
    }
}

impl From<Option<&[u8]>> for Nonce {
    fn from(bytes: Option<&[u8]>) -> Self {
        match bytes {
            Some(bytes) => Self::new(bytes),
            None => Self::default(),
        }
    }
}

impl From<Nonce> for Vec<u8> {
    fn from(nonce: Nonce) -> Self {
        nonce.0.to_be_bytes().to_vec()
    }
}

impl From<&Nonce> for Vec<u8> {
    fn from(nonce: &Nonce) -> Self {
        nonce.0.to_be_bytes().to_vec()
    }
}

impl From<Nonce> for [u8; 32] {
    fn from(nonce: Nonce) -> Self {
        nonce.0.to_be_bytes()
    }
}

impl From<&Nonce> for [u8; 32] {
    fn from(nonce: &Nonce) -> Self {
        nonce.0.to_be_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct ChallengeState<T: PrimeCurveAffine> {
    pub name: String,
    pub g: T,
    pub statement: Vec<T>,
    pub hash: [u8; 32],
}

impl<T: PrimeCurveAffine + GroupEncoding> ChallengeState<T> {
    pub fn new(statement: Vec<T>, announcement: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha3::v256();
        let mut ahash = [0u8; 32];

        hasher.update(announcement.as_ref());
        hasher.finalize(&mut ahash);

        Self {
            name: crate::dac::CHALLENGE_STATE_NAME.to_string(),
            g: <T as PrimeCurveAffine>::generator(),
            statement,
            hash: ahash,
        }
    }
}

pub trait Schnorr {
    fn new() -> Self;

    fn challenge<T: PrimeCurveAffine + GroupEncoding<Repr = impl AsRef<[u8]>> + Display>(
        state: &ChallengeState<T>,
    ) -> Scalar {
        let mut state_bytes = Vec::new();
        state_bytes.extend_from_slice(state.name.as_bytes());
        state_bytes.extend_from_slice(state.g.to_bytes().as_ref());

        for stmt in &state.statement {
            state_bytes.extend_from_slice(stmt.to_bytes().as_ref());
        }

        state_bytes.extend_from_slice(&state.hash);

        let mut hasher = Sha3::v256();
        let mut digest = [0u8; 32];

        hasher.update(&state_bytes);
        hasher.finalize(&mut digest);

        Scalar::from(bigint::U256::from_be_slice(&digest))
    }

    fn response(
        challenge: &Scalar,
        announce_randomness: &Scalar,
        stm: &G1Affine,
        secret_wit: &SecretBox<Scalar>,
    ) -> Scalar {
        assert!(G1Projective::mul_by_generator(secret_wit.expose_secret()).to_affine() == *stm);
        Scalar::from(*announce_randomness + Scalar::from(*challenge) * secret_wit.expose_secret())
    }
}

pub struct ZKPSchnorr {}

impl Schnorr for ZKPSchnorr {
    fn new() -> Self {
        Self {}
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DamgardTransform {
    pub pedersen: Pedersen,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DamgardTransformCompressed {
    pub pedersen: PedersenCompressed,
}

impl From<DamgardTransform> for DamgardTransformCompressed {
    fn from(damgard: DamgardTransform) -> Self {
        Self { pedersen: damgard.pedersen.into() }
    }
}

impl TryFrom<DamgardTransformCompressed> for DamgardTransform {
    type Error = crate::dac::error::Error;

    fn try_from(damgard_compressed: DamgardTransformCompressed) -> Result<Self, Self::Error> {
        Ok(Self {
            pedersen: Pedersen::try_from(damgard_compressed.pedersen)?,
        })
    }
}

impl DamgardTransform {
    pub fn announce(&self, nonce: &Nonce) -> (PedersenCommit, PedersenOpen) {
        let rng = CsRng::from_entropy();

        let w_random = Scalar::random(rng);
        let w_element = G1Projective::mul_by_generator(&w_random).to_affine();
        let (pedersen_commit, mut pedersen_open) = self.pedersen.commit(nonce, w_random);
        pedersen_open.element(w_element);
        (pedersen_commit, pedersen_open)
    }

    pub fn verify(nym_proof: &AliasProof, nonce: Option<&Nonce>) -> bool {
        if let Some(nonce) = nonce {
            if nym_proof.pedersen_open.open_randomness != *nonce {
                return false;
            }
        }
        let left_side = G1Projective::mul_by_generator(&nym_proof.response);
        let right_side = nym_proof.pedersen_open.announce_element.as_ref().unwrap()
            + nym_proof.challenge * nym_proof.public_key;
        let decommit = nym_proof
            .damgard
            .pedersen
            .decommit(&nym_proof.pedersen_open, &nym_proof.pedersen_commit.into());

        (left_side == right_side) && decommit
    }
}

impl Schnorr for DamgardTransform {
    fn new() -> Self {
        let pedersen = Pedersen::new();
        Self { pedersen }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pedersen {
    pub h: G1Projective,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PedersenCompressed {
    h: Vec<u8>,
}

impl PedersenCompressed {
    pub fn h(&self) -> Vec<u8> {
        self.h.clone()
    }
}

impl From<Vec<u8>> for PedersenCompressed {
    fn from(h: Vec<u8>) -> Self {
        Self { h }
    }
}

impl From<Pedersen> for PedersenCompressed {
    fn from(pedersen: Pedersen) -> Self {
        Self { h: pedersen.h.to_compressed().to_vec() }
    }
}

impl TryFrom<PedersenCompressed> for Pedersen {
    type Error = crate::dac::error::Error;

    fn try_from(pedersen_compressed: PedersenCompressed) -> Result<Self, Self::Error> {
        try_decompress_g1(pedersen_compressed.h).map(|h| Pedersen { h: h.into() })
    }
}

pub type PedersenCommit = G1Affine;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenOpen {
    pub open_randomness: Nonce,

    pub announce_randomness: Scalar,

    pub announce_element: Option<G1Affine>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PedersenOpenCompressed {
    pub open_randomness: Vec<u8>,
    pub announce_randomness: Vec<u8>,
    pub announce_element: Option<Vec<u8>>,
}

impl From<PedersenOpen> for PedersenOpenCompressed {
    fn from(pedersen_open: PedersenOpen) -> Self {
        let announce_element =
            pedersen_open.announce_element.map(|elem| elem.to_compressed().to_vec());
        Self {
            open_randomness: pedersen_open.open_randomness.into(),
            announce_randomness: pedersen_open.announce_randomness.into(),
            announce_element,
        }
    }
}

impl From<&PedersenOpen> for PedersenOpenCompressed {
    fn from(pedersen_open: &PedersenOpen) -> Self {
        let announce_element = pedersen_open
            .announce_element
            .as_ref()
            .map(|elem| elem.to_compressed().to_vec());
        Self {
            open_randomness: pedersen_open.open_randomness.clone().into(),
            announce_randomness: pedersen_open.announce_randomness.into(),
            announce_element,
        }
    }
}

impl std::convert::TryFrom<PedersenOpenCompressed> for PedersenOpen {
    type Error = crate::dac::error::Error;

    fn try_from(pedersen_open_compressed: PedersenOpenCompressed) -> Result<Self, Self::Error> {
        let announce_element = pedersen_open_compressed
            .announce_element
            .map(|elem| {
                let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(&elem);
                let maybe_g1 = G1Affine::from_compressed(&bytes);
                if maybe_g1.is_none().into() {
                    return Err(Self::Error::InvalidG1Point);
                }

                Ok(maybe_g1.expect("G1Affine is Some"))
            })
            .transpose()?;
        Ok(Self {
            open_randomness: Nonce(try_into_scalar(pedersen_open_compressed.open_randomness)?),
            announce_randomness: try_into_scalar(pedersen_open_compressed.announce_randomness)?,
            announce_element,
        })
    }
}

impl PedersenOpen {
    pub fn element(&mut self, elem: G1Affine) {
        self.announce_element = Some(elem);
    }
}
impl Default for Pedersen {
    fn default() -> Self {
        Self::new()
    }
}
impl Pedersen {
    pub fn new() -> Self {
        let rng = CsRng::from_entropy();

        let d = SecretBox::new(Box::new(Scalar::random(rng))); // trapdoor
        let h = G1Projective::mul_by_generator(d.expose_secret());
        Pedersen { h: h.into() }
    }

    pub fn commit(&self, nonce: &Nonce, msg: Scalar) -> (PedersenCommit, PedersenOpen) {
        let r: Scalar = **nonce;
        let pedersen_commit = r * self.h + G1Projective::mul_by_generator(&msg);
        let pedersen_open = PedersenOpen {
            open_randomness: nonce.clone(),
            announce_randomness: msg,
            announce_element: None,
        };

        (pedersen_commit.into(), pedersen_open)
    }

    pub fn decommit(&self, pedersen_open: &PedersenOpen, pedersen_commit: &PedersenCommit) -> bool {
        let c2 = self.h * (*pedersen_open.open_randomness)
            + G1Projective::mul_by_generator(&pedersen_open.announce_randomness);
        &c2.to_affine() == pedersen_commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_damgard_transform() {
        let nonce: Nonce = Nonce::default();
        let damgard = DamgardTransform::new();
        let rng = CsRng::from_entropy();

        let secret = SecretBox::new(Box::new(Scalar::random(rng))); // x

        let statement = G1Projective::mul_by_generator(secret.expose_secret()).to_affine();

        let (pedersen_commit, pedersen_open) = damgard.announce(&nonce);

        let state = ChallengeState::new(vec![statement], &pedersen_commit.to_bytes());

        let challenge = DamgardTransform::challenge(&state); // uses triat default

        let response = DamgardTransform::response(
            &challenge,
            &pedersen_open.announce_randomness,
            &statement,
            &secret,
        );

        let proof_nym = AliasProof {
            challenge,
            pedersen_open,
            pedersen_commit,
            public_key: statement.into(),
            response,
            damgard,
        };

        assert!(DamgardTransform::verify(&proof_nym, Some(&nonce)));
    }

    #[test]
    fn test_roundtrip_nonce() {
        let b = [42u8; 32];
        let scalar = Scalar::from_be_bytes(&b).expect("bytes to be canonical");
        let bytes = scalar.to_be_bytes();
        let scalar2 = Scalar::from_be_bytes(&bytes).expect("bytes to be canonical");
        assert_eq!(scalar, scalar2);

        let nonce = Nonce::try_from(&b).expect("bytes to be canonical");
        let bytes: [u8; 32] = nonce.clone().try_into().expect("nonce to be 32 bytes");
        let nonce2 = Nonce::try_from(bytes).expect("bytes to be canonical");
        assert_eq!(nonce, nonce2);

        let nonce = Nonce::new(b);
        let bytes: Vec<u8> = nonce.clone().into();
        let nonce2 = Nonce(try_into_scalar(bytes).unwrap());
        assert_eq!(nonce, nonce2);
    }

    #[test]
    fn test_roundtrip_damgard_transform() {
        let damgard = DamgardTransform::new();
        let damgard_compressed = DamgardTransformCompressed::from(damgard.clone());
        let damgard2 =
            DamgardTransform::try_from(damgard_compressed).expect("compressed to be canonical");
        assert_eq!(damgard, damgard2);
    }
}
