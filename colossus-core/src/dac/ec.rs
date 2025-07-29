pub mod univarpoly;

pub use bls12_381_plus::{G1Projective, G2Projective, Scalar};
use univarpoly::UnivarPolynomial;

pub mod curve {
    use super::*;

    pub use bls12_381_plus::Gt;

    use bls12_381_plus::group::Curve;

    pub fn pairing(a: &G1Projective, b: &G2Projective) -> Gt {
        bls12_381_plus::pairing(&a.to_affine(), &b.to_affine())
    }

    pub fn polynomial_from_roots(roots: &[Scalar]) -> UnivarPolynomial {
        UnivarPolynomial::new_with_roots(roots)
    }
}
