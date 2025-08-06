use super::{
    ec::{
        G1Projective, G2Projective, Scalar,
        curve::{Gt, pairing, polynomial_from_roots},
        univarpoly::UnivarPolynomial,
    },
    entry::{Attribute, Entry, entry_to_scalar},
    error,
    keypair::MaxCardinality,
};
use bls12_381_plus::elliptic_curve::bigint;
use bls12_381_plus::elliptic_curve::ops::MulByGenerator;
use bls12_381_plus::ff::Field;
use bls12_381_plus::group::{Curve, Group};
use bls12_381_plus::{G1Affine, G2Affine};
use cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{OsRng, SeedableRng},
};
use secrecy::ExposeSecret;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ParamSetCommitment {
    pub pp_commit_g1: Vec<G1Projective>,
    pub pp_commit_g2: Vec<G2Projective>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ParamSetCommitmentCompressed {
    pub pp_commit_g1: Vec<Vec<u8>>,
    pub pp_commit_g2: Vec<Vec<u8>>,
}

impl From<ParamSetCommitment> for ParamSetCommitmentCompressed {
    fn from(param_sc: ParamSetCommitment) -> Self {
        let pp_commit_g1_compressed = param_sc
            .pp_commit_g1
            .iter()
            .map(|g1| g1.to_compressed().to_vec())
            .collect::<Vec<_>>();

        let pp_commit_g2_compressed = param_sc
            .pp_commit_g2
            .iter()
            .map(|g2| g2.to_compressed().to_vec())
            .collect::<Vec<_>>();

        ParamSetCommitmentCompressed {
            pp_commit_g1: pp_commit_g1_compressed,
            pp_commit_g2: pp_commit_g2_compressed,
        }
    }
}

impl std::convert::TryFrom<ParamSetCommitmentCompressed> for ParamSetCommitment {
    type Error = error::Error;

    fn try_from(param_sc: ParamSetCommitmentCompressed) -> Result<Self, Self::Error> {
        let pp_commit_g1 = param_sc
            .pp_commit_g1
            .iter()
            .map(|g1| {
                let mut bytes = [0u8; G1Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(g1);
                let g1_maybe = G1Affine::from_compressed(&bytes);

                if g1_maybe.is_none().into() {
                    return Err(Self::Error::InvalidG1Point);
                }
                Ok(g1_maybe.expect("it'll be fine, it passed the check"))
            })
            .map(|item| item.unwrap().into())
            .collect::<Vec<_>>();

        let pp_commit_g2 = param_sc
            .pp_commit_g2
            .iter()
            .map(|g2| {
                let mut bytes = [0u8; G2Affine::COMPRESSED_BYTES];
                bytes.copy_from_slice(g2);
                let g2_maybe = G2Affine::from_compressed(&bytes);

                if g2_maybe.is_none().into() {
                    return Err(Self::Error::InvalidG2Point);
                }
                Ok(g2_maybe.expect("it'll be fine, it passed the check"))
            })
            .map(|item| item.unwrap().into())
            .collect::<Vec<_>>();

        Ok(ParamSetCommitment { pp_commit_g1, pp_commit_g2 })
    }
}

impl ToString for ParamSetCommitmentCompressed {
    fn to_string(&self) -> String {
        serde_json::to_string(self).expect("compressed should be well formed")
    }
}

impl ToString for ParamSetCommitment {
    fn to_string(&self) -> String {
        ParamSetCommitmentCompressed::from(self.clone()).to_string()
    }
}

impl ParamSetCommitment {
    pub fn new(t: &usize) -> ParamSetCommitment {
        let rng = CsRng::from_entropy();
        let base: SecretBox<Scalar> = SecretBox::new(Box::new(Scalar::random(rng))); // security parameter λ

        let pp_commit_g1 = (0..=*t)
            .map(|i| {
                G1Projective::mul_by_generator(&base.expose_secret().pow(&[i as u64, 0, 0, 0]))
            })
            .collect::<Vec<G1Projective>>();
        let pp_commit_g2 = (0..=*t)
            .map(|i| {
                G2Projective::mul_by_generator(&base.expose_secret().pow(&[i as u64, 0, 0, 0]))
            })
            .collect::<Vec<G2Projective>>();

        ParamSetCommitment { pp_commit_g2, pp_commit_g1 }
    }
}

pub trait Commitment {
    #[allow(dead_code)]
    fn new(t: MaxCardinality) -> Self;

    #[allow(dead_code)]
    fn public_parameters(self) -> ParamSetCommitment;

    fn commit_set<A: Attribute>(
        param_sc: &ParamSetCommitment,
        mess_set_str: &Entry<A>,
    ) -> (G1Projective, Scalar) {
        let mess_set: Vec<Scalar> = entry_to_scalar(mess_set_str);
        let monypol_coeff = polynomial_from_roots(&mess_set);
        let pre_commit = generate_pre_commit(monypol_coeff, param_sc);

        let open_info = Scalar::random(OsRng::default());

        let commitment = pre_commit * open_info;
        (commitment, open_info)
    }

    #[allow(dead_code)]
    fn open_set<A: Attribute>(
        param_sc: &ParamSetCommitment,
        commitment: &G1Projective,
        open_info: &Scalar,
        mess_set_str: &Entry<A>,
    ) -> bool {
        let mess_set: Vec<Scalar> = entry_to_scalar(mess_set_str);
        let monypol_coeff = polynomial_from_roots(&mess_set);
        let pre_commit = generate_pre_commit(monypol_coeff, param_sc);

        let commitment_check = pre_commit * open_info;

        *commitment == commitment_check
    }

    fn open_subset<A: Attribute>(
        param_sc: &ParamSetCommitment,
        all_messages: &Entry<A>,
        open_info: &Scalar,
        subset: &Entry<A>,
    ) -> Option<G1Projective> {
        if open_info.is_zero().into() {
            return None;
        }

        let mess_set: Vec<Scalar> = entry_to_scalar(all_messages);
        let mess_subset_t = entry_to_scalar(subset);

        if mess_subset_t.len() > mess_set.len() {
            return None;
        }

        if !mess_subset_t.iter().all(|item| mess_set.contains(item)) {
            return None;
        }

        let create_witn_elements: Vec<Scalar> = mess_set
            .into_iter()
            .filter(|itm| !mess_subset_t.contains(itm))
            .collect::<Vec<Scalar>>();

        let coeff_witn = polynomial_from_roots(&create_witn_elements);
        let witn_sum = generate_pre_commit(coeff_witn, param_sc);

        let witness = witn_sum * open_info;
        Some(witness)
    }

    #[allow(dead_code)]
    fn verify_subset<A: Attribute>(
        param_sc: &ParamSetCommitment,
        commitment: &G1Projective,
        subset_str: &Entry<A>,
        witness: &G1Projective,
    ) -> bool {
        let mess_subset_t: Vec<Scalar> = entry_to_scalar(subset_str);
        let coeff_t = polynomial_from_roots(&mess_subset_t);

        let subset_group_elements = param_sc
            .pp_commit_g2
            .iter()
            .zip(coeff_t.coefficients().iter())
            .map(|(g2, coeff)| g2 * coeff)
            .collect::<Vec<G2Projective>>();

        let subset_elements_sum =
            subset_group_elements.iter().fold(G2Projective::IDENTITY, |acc, x| acc + x);

        pairing(witness, &subset_elements_sum) == pairing(commitment, &G2Projective::GENERATOR)
    }
}

pub struct SetCommitment {
    param_sc: ParamSetCommitment,
}

impl Commitment for SetCommitment {
    fn new(t: MaxCardinality) -> Self {
        Self { param_sc: ParamSetCommitment::new(&t) }
    }

    fn public_parameters(self) -> ParamSetCommitment {
        self.param_sc
    }
}

pub struct CrossSetCommitment {
    pub param_sc: ParamSetCommitment,
}

impl Commitment for CrossSetCommitment {
    fn new(t: MaxCardinality) -> Self {
        CrossSetCommitment { param_sc: ParamSetCommitment::new(&t) }
    }

    fn public_parameters(self) -> ParamSetCommitment {
        self.param_sc
    }
}

impl CrossSetCommitment {
    pub fn aggregate_cross(
        witness_vector: &[G1Projective],
        commit_vector: &[G1Projective],
    ) -> G1Projective {
        witness_vector.iter().zip(commit_vector.iter()).fold(
            G1Projective::identity(),
            |acc, (witness, commit)| {
                let hash_i = hash_to_scalar(commit);
                acc + witness * hash_i
            },
        )
    }

    pub fn verify_cross<A: Attribute>(
        param_sc: &ParamSetCommitment,
        commit_vector: &[G1Projective],
        selected_entry_subset_vector: &[Entry<A>],
        proof: &G1Projective,
    ) -> bool {
        let subsets_vector: Vec<Vec<Scalar>> = selected_entry_subset_vector
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.is_empty())
            .map(|(_, entry)| entry_to_scalar(entry))
            .collect();

        let set_s = subsets_vector
            .iter()
            .fold(Vec::new(), |mut acc, x| {
                acc.extend(x.clone());
                acc
            })
            .into_iter()
            .collect::<Vec<Scalar>>();

        let coeff_set_s = polynomial_from_roots(&set_s);

        let set_s_group_element = param_sc
            .pp_commit_g2
            .iter()
            .zip(coeff_set_s.coefficients().iter())
            .map(|(g2, coeff)| g2 * coeff)
            .collect::<Vec<G2Projective>>();

        let set_s_elements_sum =
            set_s_group_element.iter().fold(G2Projective::IDENTITY, |acc, x| acc + x);

        let right_side = pairing(proof, &set_s_elements_sum);

        let set_s_not_t = subsets_vector
            .into_iter()
            .map(|x| not_intersection(&set_s, x))
            .collect::<Vec<Vec<Scalar>>>();

        let vector_gt = commit_vector
            .iter()
            .zip(set_s_not_t.iter())
            .map(|(commit, set_s_not_t)| {
                let coeff_s_not_t = polynomial_from_roots(set_s_not_t);

                let listpoints_s_not_t = param_sc
                    .pp_commit_g2
                    .iter()
                    .zip(coeff_s_not_t.coefficients().iter())
                    .map(|(g2, coeff)| g2 * coeff)
                    .collect::<Vec<G2Projective>>();

                let temp_sum =
                    listpoints_s_not_t.iter().fold(G2Projective::IDENTITY, |acc, x| acc + x);

                let hash_i = hash_to_scalar(commit);

                pairing(commit, &(hash_i * temp_sum))
            })
            .collect::<Vec<Gt>>();

        let left_side = vector_gt.iter().fold(Gt::IDENTITY, |acc, x| acc * *x);

        left_side == right_side
    }
}

fn hash_to_scalar(commit: &G1Projective) -> Scalar {
    let mut hasher = Sha3::v256();
    let mut chash = [0u8; 32];

    hasher.update(commit.to_affine().to_uncompressed().as_ref());
    hasher.finalize(&mut chash);
    bigint::U256::from_be_slice(&chash).into()
}

pub fn generate_pre_commit(
    monypol_coeff: UnivarPolynomial,
    param_sc: &ParamSetCommitment,
) -> G1Projective {
    let coef_points = param_sc
        .pp_commit_g1
        .iter()
        .zip(monypol_coeff.coefficients().iter())
        .map(|(g1, coeff)| g1 * coeff)
        .collect::<Vec<G1Projective>>();

    coef_points.iter().fold(G1Projective::IDENTITY, |acc, x| acc + x)
}

pub fn not_intersection(list_s: &[Scalar], list_t: Vec<Scalar>) -> Vec<Scalar> {
    list_s
        .iter()
        .filter(|value| !list_t.contains(value))
        .cloned()
        .collect::<Vec<Scalar>>()
}

#[cfg(test)]
mod test {
    use crate::dac::Attributes;
    use crate::policy::QualifiedAttribute;

    use super::*;

    #[test]
    fn test_commit_and_open() {
        let max_cardinal = 5;

        let attrib_set: Attributes = Entry(vec![
            QualifiedAttribute::from(("Age", "Over18")),
            QualifiedAttribute::from(("Sex", "female")),
            QualifiedAttribute::from(("License", "Driver")),
        ]);

        let sc = SetCommitment::new(MaxCardinality(max_cardinal));
        let (commitment, witness) = SetCommitment::commit_set(&sc.param_sc, &attrib_set);

        assert!(SetCommitment::open_set(&sc.param_sc, &commitment, &witness, &attrib_set));
    }

    #[test]
    fn test_open_verify_subset() {
        let max_cardinal = 5;

        let attrib_set: Attributes = Entry(vec![
            QualifiedAttribute::from(("Age", "Over18")),
            QualifiedAttribute::from(("Sex", "female")),
            QualifiedAttribute::from(("License", "Driver")),
        ]);
        let attrib_subset = Entry(vec![
            QualifiedAttribute::from(("Age", "Over18")),
            QualifiedAttribute::from(("License", "Driver")),
        ]);

        let sc = SetCommitment::new(MaxCardinality(max_cardinal));
        let (commitment, opening_info) = SetCommitment::commit_set(&sc.param_sc, &attrib_set);
        let witness_subset =
            SetCommitment::open_subset(&sc.param_sc, &attrib_set, &opening_info, &attrib_subset);

        assert!(witness_subset.is_some());

        let witness_subset = witness_subset.expect("Some witness");

        assert!(SetCommitment::verify_subset(
            &sc.param_sc,
            &commitment,
            &attrib_subset,
            &witness_subset
        ));
    }

    #[test]
    fn test_aggregate_verify_cross() {
        let attrib_set_a: Attributes = Entry(vec![
            QualifiedAttribute::from(("AGE", "OVER18")),
            QualifiedAttribute::from(("GENDER", "FEM")),
            QualifiedAttribute::from(("LICENSE", "DRIVER")),
        ]);

        let attrib_set_b: Attributes = Entry(vec![
            QualifiedAttribute::from(("DRIVER", "TYPEB")),
            QualifiedAttribute::from(("COMPANY", "ACME")),
            QualifiedAttribute::from(("ROLE", "DELIVERY")),
        ]);

        let max_cardinal = 5;

        let csc = CrossSetCommitment::new(MaxCardinality(max_cardinal));
        let (commitment_1, opening_info_1) =
            CrossSetCommitment::commit_set(&csc.param_sc, &attrib_set_a);
        let (commitment_2, opening_info_2) =
            CrossSetCommitment::commit_set(&csc.param_sc, &attrib_set_b);

        let commit_vector = &vec![commitment_1, commitment_2];

        let attrib_subset_1 = Entry(vec![
            QualifiedAttribute::from(("AGE", "OVER18")),
            QualifiedAttribute::from(("GENDER", "FEM")),
            QualifiedAttribute::from(("LICENSE", "DRIVER")),
        ]);
        let attrib_subset_2 = Entry(vec![
            QualifiedAttribute::from(("DRIVER", "TYPEB")),
            QualifiedAttribute::from(("COMPANY", "ACME")),
        ]);

        let witness_1 = CrossSetCommitment::open_subset(
            &csc.param_sc,
            &attrib_set_a,
            &opening_info_1,
            &attrib_subset_1,
        )
        .expect("Some Witness");

        let witness_2 = CrossSetCommitment::open_subset(
            &csc.param_sc,
            &attrib_set_b,
            &opening_info_2,
            &attrib_subset_2,
        )
        .expect("Some Witness");

        let proof = CrossSetCommitment::aggregate_cross(&vec![witness_1, witness_2], commit_vector);

        assert!(CrossSetCommitment::verify_cross(
            &csc.param_sc,
            commit_vector,
            &[attrib_subset_1, attrib_subset_2],
            &proof
        ));
    }

    #[test]
    fn test_little_endien_power() {
        let base: Scalar = Scalar::ONE + Scalar::ONE;

        let result = &base.pow(&[2u64, 0, 0, 0]);

        let expected = Scalar::from(4u64);

        assert_eq!(result, &expected);
    }

    #[test]
    fn test_param_set_commitment_roundtrip() {
        let max_cardinal = 5;
        let param_sc = ParamSetCommitment::new(&max_cardinal);
        let param_sc_compressed = ParamSetCommitmentCompressed::from(param_sc.clone());
        let param_sc_decompressed = ParamSetCommitment::try_from(param_sc_compressed).unwrap();
        assert_eq!(param_sc, param_sc_decompressed);
    }
}
