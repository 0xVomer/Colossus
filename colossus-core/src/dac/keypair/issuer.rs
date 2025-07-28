use super::{
    AliasProof, CBORCodec, Credential, Entry, IssuerError, MaxCardinality, MaxEntries, Signature,
    verify,
};
use crate::dac::{
    builder::CredentialBuilder,
    ec::Scalar,
    keys::{VK, VKCompressed},
    set_commits::{
        Commitment, CrossSetCommitment, ParamSetCommitment, ParamSetCommitmentCompressed,
    },
    zkp::{DamgardTransform, Nonce},
};
use bls12_381_plus::{
    G1Affine, G1Projective, G2Affine, G2Projective, elliptic_curve::ops::MulByGenerator, ff::Field,
    group::Group,
};
use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
pub use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

pub struct Issuer {
    pub public: IssuerPublic,
    sk: SecretBox<Vec<Scalar>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IssuerPublic {
    pub parameters: ParamSetCommitment,
    pub vk: Vec<VK>,
}

impl CBORCodec for IssuerPublicCompressed {}

impl IssuerPublic {
    pub fn to_compact(&self) -> IssuerPublicCompressed {
        let vk_b64 = self
            .vk
            .clone()
            .iter()
            .take(2)
            .map(|vk| match vk {
                VK::G1(vk) => VKCompressed::G1(vk.to_compressed().to_vec()),
                VK::G2(vk) => VKCompressed::G2(vk.to_compressed().to_vec()),
            })
            .collect::<Vec<_>>();

        IssuerPublicCompressed {
            vk: vk_b64,
            parameters: self.parameters.clone().into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssuerPublicCompressed {
    pub parameters: ParamSetCommitmentCompressed,

    pub vk: Vec<VKCompressed>,
}

impl ToString for IssuerPublicCompressed {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

impl From<IssuerPublic> for IssuerPublicCompressed {
    fn from(item: IssuerPublic) -> Self {
        Self {
            parameters: item.parameters.into(),
            vk: item.vk.iter().map(|vk| vk.into()).collect::<Vec<_>>(),
        }
    }
}

impl From<&IssuerPublic> for IssuerPublicCompressed {
    fn from(item: &IssuerPublic) -> Self {
        Self {
            parameters: item.parameters.clone().into(),
            vk: item.vk.iter().map(|vk| vk.into()).collect::<Vec<_>>(),
        }
    }
}

impl TryFrom<IssuerPublicCompressed> for IssuerPublic {
    type Error = crate::dac::error::Error;

    fn try_from(item: IssuerPublicCompressed) -> Result<Self, Self::Error> {
        let vk = item
            .vk
            .iter()
            .map(|vk| match vk {
                VKCompressed::G1(vk_g1) => {
                    let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                    bytes.copy_from_slice(&vk_g1);
                    let vk_g1_maybe = G1Affine::from_compressed(&bytes);

                    if vk_g1_maybe.is_none().into() {
                        return Err(crate::dac::error::Error::InvalidG1Point);
                    }

                    Ok(VK::G1(G1Projective::from(vk_g1_maybe.unwrap())))
                },
                VKCompressed::G2(vk_g2) => {
                    let mut bytes = [0u8; G2Affine::COMPRESSED_BYTES];
                    bytes.copy_from_slice(&vk_g2);
                    let vk_g2_maybe = G2Affine::from_compressed(&bytes);

                    if vk_g2_maybe.is_none().into() {
                        return Err(crate::dac::error::Error::InvalidG2Point);
                    }

                    Ok(VK::G2(G2Projective::from(vk_g2_maybe.unwrap())))
                },
            })
            .collect::<Result<Vec<_>, Self::Error>>()?;

        Ok(Self {
            parameters: item.parameters.try_into()?,
            vk,
        })
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new(MaxCardinality::default(), MaxEntries::default())
    }
}

impl Issuer {
    pub fn new(t: MaxCardinality, l_message: MaxEntries) -> Self {
        let rng = CsRng::from_entropy();

        let sk = SecretBox::new(Box::new(
            (0..l_message.0 + 2).map(|_| Scalar::random(rng.clone())).collect::<Vec<_>>(),
        ));

        Self::new_with_secret(sk, t)
    }

    pub fn new_with_secret(sk: SecretBox<Vec<Scalar>>, t: MaxCardinality) -> Self {
        let public_parameters = ParamSetCommitment::new(&t);

        Self::new_with_params(sk, public_parameters)
    }

    pub fn new_with_params(sk: SecretBox<Vec<Scalar>>, params: ParamSetCommitment) -> Self {
        let mut vk: Vec<VK> = sk
            .expose_secret()
            .iter()
            .map(|sk_i| VK::G2(G2Projective::mul_by_generator(sk_i)))
            .collect::<Vec<_>>();

        let x_0 = G1Projective::mul_by_generator(&sk.expose_secret()[0]);
        vk.insert(0, VK::G1(x_0)); // vk is now of length l_message + 1 (or sk + 1)

        Self {
            sk,
            public: IssuerPublic { parameters: params, vk },
        }
    }

    pub fn credential(&self) -> CredentialBuilder {
        CredentialBuilder::new(self)
    }

    pub fn issue_cred(
        &self,
        attr_vector: &[Entry],
        k_prime: Option<usize>,
        nym_proof: &AliasProof,
        nonce: Option<&Nonce>,
    ) -> Result<Credential, IssuerError> {
        if !DamgardTransform::verify(nym_proof, nonce) {
            return Err(IssuerError::InvalidAliasProof);
        }

        let cred = self.sign(&nym_proof.public_key.into(), attr_vector, k_prime)?;
        assert!(verify(
            &self.public.vk,
            &nym_proof.public_key.into(),
            &cred.commitment_vector,
            &cred.sigma
        ));
        Ok(cred)
    }

    fn sign(
        &self,
        pk_u: &G1Projective,
        messages_vector: &[Entry],
        k_prime: Option<usize>,
    ) -> Result<Credential, IssuerError> {
        let rng = CsRng::from_entropy();

        if messages_vector
            .iter()
            .any(|mess| mess.len() > self.public.parameters.pp_commit_g1.len())
        {
            return Err(IssuerError::TooLargeCardinality);
        }

        if messages_vector.len() >= self.public.vk.len() - 2 {
            return Err(IssuerError::TooLongEntries);
        }

        let (commitment_vector, opening_vector): (Vec<G1Projective>, Vec<Scalar>) = messages_vector
            .iter()
            .map(|mess| CrossSetCommitment::commit_set(&self.public.parameters, mess))
            .collect::<Vec<_>>()
            .into_iter()
            .unzip();

        let y_rand = Scalar::random(rng);

        let list_z = commitment_vector
            .iter()
            .enumerate()
            .map(|(i, c)| c * self.sk.expose_secret()[i + 2])
            .collect::<Vec<_>>();

        let temp_point = list_z.iter().fold(G1Projective::identity(), |acc, x| acc + x);

        let z = y_rand.invert().unwrap() * temp_point;

        let y_g1 = G1Projective::mul_by_generator(&y_rand);

        let y_hat = G2Projective::mul_by_generator(&y_rand);

        let t = y_g1 * self.sk.expose_secret()[1] + pk_u * self.sk.expose_secret()[0];

        let sigma = Signature { z, y_g1, y_hat, t };

        let mut update_key = None;
        if let Some(k_prime) = k_prime {
            if k_prime > messages_vector.len() {
                let k_prime = k_prime.min(self.sk.expose_secret().len() - 2);

                let mut usign = Vec::new();
                usign.resize(k_prime, Vec::new()); // update_key is k < k' < l, same length as l_message.length, which is same as sk

                for k in (messages_vector.len() + 1)..=k_prime {
                    let mut uk = Vec::new();
                    for i in 0..self.public.parameters.pp_commit_g1.len() {
                        let uk_i = self.public.parameters.pp_commit_g1[i]
                            * y_rand.invert().unwrap()
                            * self.sk.expose_secret()[k + 1]; // this is `k + 1` because sk[0] and sk[1] are used for t
                        uk.push(uk_i);
                    }
                    usign[k - 1] = uk; // first element is index 0 (message m is index m-1)
                }
                update_key = Some(usign);

                return Ok(Credential {
                    sigma,
                    update_key,
                    commitment_vector,
                    opening_vector,
                    issuer_public: self.public.clone(),
                });
            }
        }

        Ok(Credential {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public: self.public.clone(),
        })
    }
}
