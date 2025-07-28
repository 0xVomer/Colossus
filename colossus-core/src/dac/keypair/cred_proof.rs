use super::{AliasProof, AliasProofCompressed, CBORCodec, Signature, SignatureCompressed};
use bls12_381_plus::{G1Affine, G1Projective, group::Curve};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq)]
pub struct CredProof {
    pub(super) sigma: Signature,
    pub(super) commitment_vector: Vec<G1Affine>,
    pub(super) witness_pi: G1Affine,
    pub(super) nym_proof: AliasProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredProofCompressed {
    pub sigma: SignatureCompressed,

    pub commitment_vector: Vec<Vec<u8>>,

    pub witness_pi: Vec<u8>,

    pub nym_proof: AliasProofCompressed,
}

impl CBORCodec for CredProofCompressed {}

impl From<CredProof> for CredProofCompressed {
    fn from(item: CredProof) -> Self {
        Self {
            sigma: SignatureCompressed::from(item.sigma),
            commitment_vector: item
                .commitment_vector
                .iter()
                .map(|c| c.to_compressed().to_vec())
                .collect(),
            witness_pi: item.witness_pi.to_compressed().to_vec(),
            nym_proof: AliasProofCompressed::from(item.nym_proof),
        }
    }
}

impl TryFrom<CredProofCompressed> for CredProof {
    type Error = crate::dac::error::Error;

    fn try_from(item: CredProofCompressed) -> Result<Self, Self::Error> {
        let sigma = Signature::try_from(item.sigma)?;
        let nym_proof = AliasProof::try_from(item.nym_proof)?;

        let commitment_vector = item
            .commitment_vector
            .iter()
            .map(|c| {
                let mut byte = [0u8; G1Affine::COMPRESSED_BYTES];
                byte.copy_from_slice(c);
                let maybe_g1 = G1Affine::from_compressed(&byte);

                if maybe_g1.is_none().into() {
                    return Err(crate::dac::error::Error::InvalidG1Point);
                } else {
                    Ok(G1Projective::from(maybe_g1.unwrap()))
                }
            })
            .map(|item| item.unwrap().into())
            .collect::<Vec<G1Projective>>();

        let witness_pi = {
            let mut byte = [0u8; G1Affine::COMPRESSED_BYTES];
            byte.copy_from_slice(&item.witness_pi);
            let maybe_g1 = G1Affine::from_compressed(&byte);

            if maybe_g1.is_none().into() {
                return Err(crate::dac::error::Error::InvalidG1Point);
            } else {
                G1Projective::from(maybe_g1.unwrap())
            }
        };

        Ok(Self {
            sigma,
            commitment_vector: commitment_vector.iter().map(|c| c.to_affine()).collect(),
            witness_pi: witness_pi.into(),
            nym_proof,
        })
    }
}
