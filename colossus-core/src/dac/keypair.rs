mod alias;
mod cbor;
mod cred_proof;
mod error;
mod issuer;
mod offer;
mod signature;
pub mod spseq_uc;

use super::{
    Attributes,
    ec::{Scalar, curve::pairing},
    entry::{MaxEntries, entry_to_scalar},
    keys::VK,
    set_commits::{Commitment, CrossSetCommitment, ParamSetCommitment},
    zkp::{DamgardTransform, Nonce},
};
pub use alias::{Alias, AliasProof, AliasProofCompressed};
pub use bls12_381_plus::{
    G1Affine, G1Projective, G2Affine, G2Projective, Gt,
    elliptic_curve::{bigint, ops::MulByGenerator},
    ff::Field,
    group::{Curve, Group, GroupEncoding},
};
pub use cbor::CBORCodec;
use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
pub use cred_proof::{CredProof, CredProofCompressed};
pub use error::{IssuerError, UpdateError};
pub use issuer::{Issuer, IssuerPublic, IssuerPublicCompressed};
pub use offer::{Offer, OfferCompressed};
pub use signature::{Signature, SignatureCompressed};
pub use spseq_uc::AccessCredential;
use std::{
    fmt::Display,
    ops::{Deref, Mul},
};

pub struct Initial;

pub struct Randomized;

#[derive(Debug, Clone, PartialEq)]
pub struct MaxCardinality(pub usize);

impl From<&usize> for MaxCardinality {
    fn from(item: &usize) -> Self {
        MaxCardinality(*item)
    }
}

impl From<usize> for MaxCardinality {
    fn from(item: usize) -> Self {
        MaxCardinality(item)
    }
}

impl From<u8> for MaxCardinality {
    fn from(item: u8) -> Self {
        MaxCardinality(item as usize)
    }
}

impl From<MaxCardinality> for usize {
    fn from(item: MaxCardinality) -> Self {
        item.0
    }
}

impl Deref for MaxCardinality {
    type Target = usize;
    fn deref(&self) -> &usize {
        &self.0
    }
}

impl Default for MaxCardinality {
    fn default() -> Self {
        MaxCardinality(super::DEFAULT_MAX_CARDINALITY)
    }
}

impl MaxCardinality {
    pub fn new(item: usize) -> Self {
        MaxCardinality(item)
    }
}

/// Verifies a signature against a verification key and commitment vector.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
/// or `Err` if the verification key structure is malformed.
#[must_use]
pub fn verify(
    vk: &[VK],
    pk_u: &G1Projective,
    commitment_vector: &[G1Projective],
    sigma: &Signature,
) -> Result<bool, IssuerError> {
    let g_1 = &G1Projective::GENERATOR;
    let g_2 = &G2Projective::GENERATOR;
    let Signature { z, y_g1, y_hat, t } = sigma;

    // Validate verification key has minimum required elements
    if vk.len() < 3 {
        return Err(IssuerError::InvalidVerificationKey(
            "verification key must have at least 3 elements".to_string(),
        ));
    }

    let pairing_op = commitment_vector
        .iter()
        .zip(vk.iter().skip(3))
        .map(|(c, vkj3)| {
            if let VK::G2(vkj3) = vkj3 {
                Ok(pairing(c, vkj3))
            } else {
                Err(IssuerError::InvalidVerificationKey(
                    "expected G2 element in verification key".to_string(),
                ))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    let vk2 = match &vk[2] {
        VK::G2(v) => v,
        _ => {
            return Err(IssuerError::InvalidVerificationKey(
                "vk[2] must be a G2 element".to_string(),
            ));
        },
    };

    let vk1 = match &vk[1] {
        VK::G2(v) => v,
        _ => {
            return Err(IssuerError::InvalidVerificationKey(
                "vk[1] must be a G2 element".to_string(),
            ));
        },
    };

    let a = pairing(y_g1, g_2) == pairing(g_1, y_hat);
    let b = pairing(t, g_2) == pairing(y_g1, vk2) * pairing(pk_u, vk1);
    let c = pairing(z, y_hat) == pairing_op.iter().fold(Gt::IDENTITY, Gt::mul);

    Ok(a && b && c)
}

/// Verifies a credential proof against an issuer's public parameters.
///
/// Returns `true` if all verification checks pass:
/// - Cross-set commitment verification
/// - Zero-knowledge proof verification
/// - Signature verification
#[must_use]
pub fn verify_proof(
    issuer_public: &IssuerPublic,
    proof: &CredProof,
    selected_attrs: &[Attributes],
    nonce: Option<&Nonce>,
) -> bool {
    let commitment_vectors = proof
        .commitment_vector
        .iter()
        .zip(selected_attrs.iter())
        .filter(|(_, selected_attr)| !selected_attr.is_empty())
        .map(|(commitment_vector, _)| *commitment_vector)
        .collect::<Vec<_>>();

    let check_verify_cross = CrossSetCommitment::verify_cross(
        &issuer_public.parameters,
        &commitment_vectors.iter().map(|c| c.into()).collect::<Vec<_>>(),
        selected_attrs,
        &proof.witness_pi.into(),
    );

    let check_zkp_verify = DamgardTransform::verify(&proof.alias_proof, nonce);

    let verify_sig = match verify(
        &issuer_public.vk,
        &proof.alias_proof.public_key.into(),
        &proof.commitment_vector.iter().map(|c| c.into()).collect::<Vec<_>>(),
        &proof.sigma,
    ) {
        Ok(valid) => valid,
        Err(_) => false,
    };

    check_verify_cross && check_zkp_verify && verify_sig
}
