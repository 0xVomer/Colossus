use super::{
    CBORCodec, CredProof, Credential, Entry, Initial, Offer, Randomized, Signature, verify,
};
use crate::dac::{
    builder::{OfferBuilder, ProofBuilder},
    ec::Scalar,
    keys::VK,
    set_commits::{Commitment, CrossSetCommitment},
    utils::try_into_scalar,
    zkp::{
        ChallengeState, DamgardTransform, DamgardTransformCompressed, Nonce, PedersenOpen,
        PedersenOpenCompressed, Schnorr,
    },
};
use bls12_381_plus::{
    G1Affine, G1Projective,
    elliptic_curve::ops::MulByGenerator,
    ff::Field,
    group::{Curve, GroupEncoding},
};
use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
pub use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, Neg};

pub struct Alias<Stage> {
    secret: SecretBox<Scalar>,
    pub public: AliasPublic,
    stage: std::marker::PhantomData<Stage>,
}

#[derive(Clone)]
pub struct AliasPublic {
    pub damgard: DamgardTransform,
    pub key: G1Projective,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasProof {
    pub challenge: Scalar,
    pub pedersen_open: PedersenOpen,
    pub pedersen_commit: G1Affine,
    pub public_key: G1Affine,
    pub response: Scalar,
    pub damgard: DamgardTransform,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AliasProofCompressed {
    pub challenge: Vec<u8>,
    pub pedersen_open: PedersenOpenCompressed,
    pub pedersen_commit: Vec<u8>,
    pub public_key: Vec<u8>,
    pub response: Vec<u8>,
    pub damgard: DamgardTransformCompressed,
}

impl CBORCodec for AliasProofCompressed {}

impl From<AliasProof> for AliasProofCompressed {
    fn from(item: AliasProof) -> Self {
        Self {
            challenge: item.challenge.into(),
            pedersen_open: PedersenOpenCompressed::from(item.pedersen_open),
            pedersen_commit: item.pedersen_commit.to_compressed().to_vec(),
            public_key: item.public_key.to_compressed().to_vec(),
            response: item.response.into(),
            damgard: DamgardTransformCompressed::from(item.damgard),
        }
    }
}

impl TryFrom<AliasProofCompressed> for AliasProof {
    type Error = crate::dac::error::Error;

    fn try_from(item: AliasProofCompressed) -> Result<Self, Self::Error> {
        let challenge = try_into_scalar(item.challenge)?;
        let response = try_into_scalar(item.response)?;
        let damgard = DamgardTransform::try_from(item.damgard)?;

        let pedersen_open = PedersenOpen::try_from(item.pedersen_open)?;
        let pedersen_commit = {
            let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
            bytes.copy_from_slice(&item.pedersen_commit);
            let maybe_g1 = G1Affine::from_compressed(&bytes);

            if maybe_g1.is_none().into() {
                return Err(crate::dac::error::Error::InvalidG1Point);
            } else {
                G1Projective::from(maybe_g1.unwrap())
            }
        };

        let public_key = {
            let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
            bytes.copy_from_slice(&item.public_key);
            let maybe_g1 = G1Affine::from_compressed(&bytes);

            if maybe_g1.is_none().into() {
                return Err(crate::dac::error::Error::InvalidG1Point);
            } else {
                G1Projective::from(maybe_g1.unwrap())
            }
        };

        Ok(Self {
            challenge,
            pedersen_open,
            pedersen_commit: pedersen_commit.into(),
            public_key: public_key.into(),
            response,
            damgard,
        })
    }
}

impl<Stage> Alias<Stage> {
    fn new_from_secret(secret_bytes: SecretBox<Scalar>) -> Alias<Stage> {
        let key = G1Projective::mul_by_generator(secret_bytes.expose_secret());
        Alias::<Stage> {
            stage: std::marker::PhantomData,
            secret: secret_bytes,
            public: AliasPublic { damgard: DamgardTransform::new(), key },
        }
    }

    pub fn randomize(&self) -> Alias<Randomized> {
        let rng = CsRng::from_entropy();

        let psi = Scalar::random(rng.clone());

        let chi = Scalar::random(rng);

        let secret_wit = SecretBox::new(Box::new((self.secret.expose_secret() + chi) * psi));

        Alias::new_from_secret(secret_wit)
    }

    pub fn offer_builder<'a>(
        &'a self,
        cred: &'a Credential,
        entries: &[Entry],
    ) -> OfferBuilder<'a, Stage> {
        OfferBuilder::new(self, cred, entries)
    }

    pub fn proof_builder<'a>(
        &'a self,
        cred: &'a Credential,
        entries: &'a [Entry],
    ) -> ProofBuilder<'a, Stage> {
        ProofBuilder::new(self, cred, entries)
    }

    pub fn extend(
        &self,
        cred: &Credential,
        addl_attrs: &Entry,
    ) -> Result<Credential, crate::dac::error::Error> {
        let mu = Scalar::ONE;

        let cred = super::spseq_uc::change_rel(
            &cred.issuer_public.parameters,
            addl_attrs,
            cred.clone(),
            &mu,
        )
        .map_err(|e| {
            crate::dac::error::Error::ChangeRelationsFailed(format!(
                "Change Relations Failed: {}",
                e
            ))
        })?;

        Ok(cred)
    }

    pub fn offer(
        &self,
        cred: &Credential,
        addl_attrs: &Option<Entry>,
    ) -> Result<Offer, crate::dac::error::Error> {
        let rng = CsRng::from_entropy();

        let mu = Scalar::ONE;
        let psi = Scalar::random(rng);

        let (alias_p_pk, cred_prime, chi) =
            super::spseq_uc::change_rep(&self.public.key, cred, &mu, &psi, true);

        let alias = Alias::from_components(&self.secret, Chi(chi), Psi(psi));

        let mut cred_prime = cred_prime;
        if let Some(addl_attrs) = addl_attrs {
            cred_prime = match super::spseq_uc::change_rel(
                &cred.issuer_public.parameters,
                addl_attrs,
                cred_prime.clone(),
                &mu,
            ) {
                Ok(cred_pushed) => cred_pushed,
                Err(e) => {
                    return Err(crate::dac::error::Error::ChangeRelationsFailed(format!(
                        "Change Relations Failed: {}",
                        e
                    )));
                },
            };
        }

        if !verify(
            &cred_prime.issuer_public.vk,
            &alias_p_pk,
            &cred_prime.commitment_vector,
            &cred_prime.sigma,
        ) {
            return Err(crate::dac::error::Error::InvalidSignature(
                "Credential Signature is not valid for the new Alias".into(),
            ));
        }

        let orphan = alias.send_convert_sig(&cred_prime.issuer_public.vk, cred_prime.sigma.clone());

        Ok(Offer(Credential { sigma: orphan, ..cred_prime }))
    }

    pub fn accept(
        &self,
        offer: &Offer, // credential got from delegator
    ) -> Result<Credential, crate::dac::error::Error> {
        let sigma_new = self.receive_cred(&offer.issuer_public.vk, offer.sigma.clone())?;

        if !verify(&offer.issuer_public.vk, &self.public.key, &offer.commitment_vector, &sigma_new)
        {
            return Err(crate::dac::error::Error::AcceptOfferFailed(String::from(
                "Invalid Signature",
            )));
        }

        Ok(Credential { sigma: sigma_new, ..offer.clone().into() })
    }

    fn receive_cred(
        &self,
        vk: &[VK],
        mut orphan: Signature,
    ) -> Result<Signature, crate::dac::error::Error> {
        match &vk[0] {
            VK::G1(vk0) => {
                orphan.t += vk0 * self.secret.expose_secret();
                Ok(orphan)
            },
            _ => Err(crate::dac::error::Error::InvalidVerificationKey {
                expected: String::from("G1"),
                found: String::from("G2"),
            }),
        }
    }

    pub fn prove(
        &self,
        cred: &Credential,
        all_attributes: &[Entry],
        selected_attrs: &[Entry],
        nonce: &Nonce,
    ) -> CredProof {
        let rng = CsRng::from_entropy();

        let mu = Scalar::random(rng.clone());
        let psi = Scalar::random(rng);

        let (_alias_p, cred_p, chi) =
            super::spseq_uc::change_rep(&self.public.key, cred, &mu, &psi, false);

        let alias: Alias<Randomized> = Alias::from_components(&self.secret, Chi(chi), Psi(psi));

        let (witness_vector, commit_vector) = selected_attrs
            .iter()
            .enumerate()
            .filter(|(_, selected_attr)| !selected_attr.is_empty())
            .fold(
                (Vec::new(), Vec::new()),
                |(mut witness, mut commitment_vectors), (i, selected_attr)| {
                    if let Some(opened) = CrossSetCommitment::open_subset(
                        &cred.issuer_public.parameters,
                        &all_attributes[i],
                        &cred_p.opening_vector[i],
                        selected_attr,
                    ) {
                        witness.push(opened);
                        commitment_vectors.push(cred_p.commitment_vector[i]);
                    }
                    (witness, commitment_vectors)
                },
            );

        let witness_pi = CrossSetCommitment::aggregate_cross(&witness_vector, &commit_vector);

        CredProof {
            sigma: cred_p.sigma,
            commitment_vector: cred_p.commitment_vector.iter().map(|c| c.to_affine()).collect(),
            witness_pi: witness_pi.into(),
            alias_proof: alias.alias_proof(nonce),
        }
    }

    pub fn alias_proof(&self, nonce: &Nonce) -> AliasProof {
        let (pedersen_commit, pedersen_open) = self.public.damgard.announce(nonce);

        let state = ChallengeState::new(
            vec![self.public.damgard.pedersen.h.to_affine()],
            &pedersen_commit.to_bytes(),
        );

        let challenge = DamgardTransform::challenge(&state);

        let response = DamgardTransform::response(
            &challenge,
            &pedersen_open.announce_randomness,
            &self.public.key.into(),
            &self.secret,
        );

        AliasProof {
            challenge,
            pedersen_open,
            pedersen_commit,
            public_key: self.public.key.into(),
            response,
            damgard: self.public.damgard.clone(),
        }
    }
}

impl Default for Alias<Randomized> {
    fn default() -> Self {
        Self::new()
    }
}

struct Chi(Scalar);

impl Deref for Chi {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct Psi(Scalar);

impl Deref for Psi {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Alias<Initial> {
    pub fn from_secret(secret_bytes: SecretBox<Scalar>) -> Self {
        Alias::new_from_secret(secret_bytes)
    }
}

impl Alias<Randomized> {
    pub fn new() -> Self {
        let rng = CsRng::from_entropy();

        let secret = SecretBox::new(Box::new(Scalar::random(rng)));
        Alias::new_from_secret(secret)
    }

    fn from_components(secret: &SecretBox<Scalar>, chi: Chi, psi: Psi) -> Self {
        let secret_wit = SecretBox::new(Box::new((secret.expose_secret() + (*chi)) * (*psi)));
        Alias::new_from_secret(secret_wit)
    }

    fn send_convert_sig(&self, vk: &[VK], mut sigma: Signature) -> Signature {
        if let VK::G1(vk0) = &vk[0] {
            sigma.t += (vk0 * self.secret.expose_secret()).neg();

            sigma
        } else {
            panic!("Invalid verification key"); // TODO: Remove panics, switch to Result
        }
    }
}
