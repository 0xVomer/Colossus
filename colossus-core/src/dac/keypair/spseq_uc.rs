use super::*;
use crate::dac::ec::{G1Projective, curve::polynomial_from_roots};
use serde::{Deserialize, Serialize};

pub type UpdateKey = Option<Vec<Vec<G1Projective>>>;

#[derive(Clone, Debug, PartialEq, Default)]
pub struct AccessCredential {
    pub sigma: Signature,
    pub update_key: UpdateKey, // Called DelegatableKey (dk for k prime) in the paper
    pub commitment_vector: Vec<G1Projective>,
    pub opening_vector: Vec<Scalar>,
    pub issuer_public: IssuerPublic,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessCredentialCompressed {
    pub sigma: SignatureCompressed,
    pub update_key: Option<Vec<Vec<Vec<u8>>>>,
    pub commitment_vector: Vec<Vec<u8>>,
    pub opening_vector: Vec<Vec<u8>>,
    pub issuer_public: IssuerPublicCompressed,
}

impl CBORCodec for AccessCredentialCompressed {}

impl TryFrom<AccessCredentialCompressed> for AccessCredential {
    type Error = crate::dac::error::Error;
    fn try_from(value: AccessCredentialCompressed) -> std::result::Result<Self, Self::Error> {
        let sigma = Signature::try_from(value.sigma)?;
        let update_key = match value.update_key {
            Some(usign) => {
                let mut usign_decompressed = Vec::new();
                usign_decompressed.resize(usign.len(), Vec::new());
                for k in 0..usign.len() {
                    usign_decompressed[k] = usign[k]
                        .iter()
                        .map(|item| {
                            let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                            bytes.copy_from_slice(item);
                            let g1_maybe = G1Affine::from_compressed(&bytes);

                            if g1_maybe.is_none().into() {
                                return Err(crate::dac::error::Error::InvalidG1Point);
                            }
                            Ok(g1_maybe.expect("it'll be fine, it passed the check"))
                        })
                        .map(|item| item.unwrap().into())
                        .collect::<Vec<G1Projective>>();
                }
                Some(usign_decompressed)
            },
            None => None,
        };

        let commitment_vector = value
            .commitment_vector
            .iter()
            .map(|item| {
                let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(item);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    return Err(crate::dac::error::Error::InvalidG1Point);
                }
                Ok(g1_maybe.expect("it'll be fine, it passed the check"))
            })
            .map(|item| item.unwrap().into())
            .collect::<Vec<G1Projective>>();

        let opening_vector = value
            .opening_vector
            .into_iter()
            .map(|item| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&item);
                let opening_info = OpeningInfo { inner: bytes };
                opening_info.into_scalar()
            })
            .collect::<Vec<Scalar>>();

        let issuer_public = IssuerPublic::try_from(value.issuer_public)?;

        Ok(AccessCredential {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public,
        })
    }
}

impl From<&AccessCredential> for AccessCredentialCompressed {
    fn from(cred: &AccessCredential) -> Self {
        let sigma = SignatureCompressed::from(cred.sigma.clone());
        let issuer_public = IssuerPublicCompressed::from(cred.issuer_public.clone());

        let update_key = match &cred.update_key {
            Some(usign) => {
                let mut usign_compressed = Vec::new();
                usign_compressed.resize(usign.len(), Vec::new());
                for k in 0..usign.len() {
                    usign_compressed[k] =
                        usign[k].iter().map(|item| item.to_compressed().to_vec()).collect();
                }
                Some(usign_compressed)
            },
            None => None,
        };

        let commitment_vector = cred
            .commitment_vector
            .iter()
            .map(|item| item.to_compressed().to_vec())
            .collect();

        let opening_vector = cred
            .opening_vector
            .clone()
            .into_iter()
            .map(|item| OpeningInfo::new(item).inner.to_vec())
            .collect::<Vec<Vec<u8>>>();

        AccessCredentialCompressed {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public,
        }
    }
}

impl From<AccessCredential> for AccessCredentialCompressed {
    fn from(cred: AccessCredential) -> Self {
        let sigma = SignatureCompressed::from(cred.sigma);
        let update_key = match cred.update_key {
            Some(usign) => {
                let mut usign_compressed = Vec::new();
                usign_compressed.resize(usign.len(), Vec::new());
                for k in 0..usign.len() {
                    usign_compressed[k] =
                        usign[k].iter().map(|item| item.to_compressed().to_vec()).collect();
                }
                Some(usign_compressed)
            },
            None => None,
        };
        let commitment_vector = cred
            .commitment_vector
            .iter()
            .map(|item| item.to_compressed().to_vec())
            .collect();
        let opening_vector = cred
            .opening_vector
            .clone()
            .into_iter()
            .map(|item| OpeningInfo::new(item).inner.to_vec())
            .collect::<Vec<Vec<u8>>>();

        let issuer_public: IssuerPublicCompressed = cred.issuer_public.into();

        AccessCredentialCompressed {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public,
        }
    }
}

pub struct OpeningInfo {
    inner: [u8; 32],
}

impl OpeningInfo {
    pub fn new(inner: Scalar) -> Self {
        OpeningInfo { inner: inner.to_be_bytes() }
    }

    pub fn into_scalar(self) -> Scalar {
        Scalar::from_be_bytes(&self.inner).unwrap()
    }
}

impl AsRef<[u8]> for OpeningInfo {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl From<Vec<u8>> for OpeningInfo {
    fn from(v: Vec<u8>) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&v[..]);
        OpeningInfo { inner: bytes }
    }
}

impl Display for AccessCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let comp = AccessCredentialCompressed::from(self);
        let comp_json = serde_json::to_string_pretty(&comp).unwrap();
        write!(f, "{}", comp_json)
    }
}

impl TryFrom<String> for AccessCredential {
    type Error = crate::dac::error::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let cred_compressed: AccessCredentialCompressed = serde_json::from_str(&s)?;
        cred_compressed.try_into()
    }
}

pub fn change_rep(
    pk_u: &G1Projective,
    cred: &AccessCredential,
    mu: &Scalar,
    psi: &Scalar,
    extendable: bool,
) -> (G1Projective, AccessCredential, Scalar) {
    let rng = CsRng::from_entropy();

    let chi = Scalar::random(rng);

    let rndmz_commit_vector = cred.commitment_vector.iter().map(|c| mu * c).collect();
    let rndmz_opening_vector = cred.opening_vector.iter().map(|o| mu * o).collect();

    let rndmz_pk_u = psi * (pk_u + G1Projective::mul_by_generator(&chi));

    let Signature { z, y_g1, y_hat, t } = &cred.sigma;

    if let VK::G1(vk0) = &cred.issuer_public.vk[0] {
        let sigma_prime = Signature {
            z: mu * psi.invert().unwrap() * z,
            y_g1: psi * y_g1,
            y_hat: psi * y_hat,
            t: psi * (t + chi * vk0),
        };

        let fresh_update_key = match &cred.update_key {
            Some(usign) if extendable => {
                let mut usign_prime = Vec::new();
                usign_prime.resize(usign.len(), Vec::new());
                for k in cred.commitment_vector.len()..usign.len() {
                    usign_prime[k] =
                        usign[k].iter().map(|item| mu * psi.invert().unwrap() * item).collect();
                }
                Some(usign_prime)
            },
            _ => None,
        };

        (
            rndmz_pk_u,
            AccessCredential {
                sigma: sigma_prime,
                update_key: fresh_update_key,
                commitment_vector: rndmz_commit_vector,
                opening_vector: rndmz_opening_vector,
                issuer_public: cred.issuer_public.clone(),
            },
            chi,
        )
    } else {
        panic!("Invalid verification key");
    }
}

pub fn change_rel(
    parameters: &ParamSetCommitment,
    addl_attribs: &Attributes,
    orig_sig: AccessCredential,
    mu: &Scalar,
) -> Result<AccessCredential, super::error::UpdateError> {
    let index_l = orig_sig.commitment_vector.len();

    match &orig_sig.update_key {
        Some(usign) if index_l < usign.len() => {
            let Signature { z, y_g1, y_hat, t } = orig_sig.sigma;
            let (commitment_l, opening_l) =
                CrossSetCommitment::commit_set(parameters, addl_attribs);

            let rndmz_commitment_l = mu * commitment_l;
            let rndmz_opening_l = mu * opening_l;

            let set_l = entry_to_scalar(addl_attribs);
            let monypolcoefficient = polynomial_from_roots(&set_l[..]);

            let list = usign.get(index_l).unwrap();
            let sum_points_uk_i = list
                .iter()
                .zip(monypolcoefficient.coefficients().iter())
                .fold(G1Projective::identity(), |acc, (list_i, monypolcoefficient_i)| {
                    acc + list_i * monypolcoefficient_i
                });

            let gama_l = sum_points_uk_i * opening_l;

            let z_tilde = z + gama_l;

            let sigma_tilde = Signature { z: z_tilde.into(), y_g1, y_hat, t };

            let mut commitment_vector_tilde = orig_sig.commitment_vector;
            commitment_vector_tilde.push(rndmz_commitment_l);

            let mut opening_vector_tilde = orig_sig.opening_vector;
            opening_vector_tilde.push(rndmz_opening_l);

            Ok(AccessCredential {
                sigma: sigma_tilde,
                commitment_vector: commitment_vector_tilde,
                opening_vector: opening_vector_tilde,
                ..orig_sig
            })
        },
        _ => Err(super::error::UpdateError::Error(
            "No update key, cannot change relations".to_string(),
        )),
    }
}

pub mod fixtures {

    use super::*;

    pub fn make_test_credential() -> AccessCredential {
        let rng = CsRng::from_entropy();

        let sigma = Signature {
            z: G1Projective::random(&mut rng.clone()).into(),
            y_g1: G1Projective::random(&mut rng.clone()).into(),
            y_hat: G2Projective::random(&mut rng.clone()).into(),
            t: G1Projective::random(&mut &mut rng.clone()).into(),
        };
        let update_key = Some(vec![vec![G1Projective::random(&mut rng.clone())]]);
        let commitment_vector = vec![G1Projective::random(&mut rng.clone())];
        let opening_vector = vec![Scalar::random(&mut rng.clone())];
        let issuer_public = IssuerPublic {
            vk: vec![VK::G1(G1Projective::random(&mut rng.clone()))],
            parameters: ParamSetCommitment {
                pp_commit_g1: vec![G1Projective::random(&mut rng.clone())],
                pp_commit_g2: vec![G2Projective::random(&mut rng.clone())],
            },
        };
        AccessCredential {
            sigma,
            update_key,
            commitment_vector,
            opening_vector,
            issuer_public,
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use fixtures::make_test_credential;

    #[test]
    fn test_credential_compressed_uncompress_roundtrip() {
        let cred = make_test_credential();
        let cred_compressed = AccessCredentialCompressed::from(&cred);
        let cred_uncompressed = AccessCredential::try_from(cred_compressed).unwrap();
        assert_eq!(cred, cred_uncompressed);
    }
}
