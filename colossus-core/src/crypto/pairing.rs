//! Pairing provider trait and implementations.
//!
//! Provides an abstraction over bilinear pairing operations,
//! enabling future migration to alternative pairing-friendly curves
//! or post-quantum alternatives when they become available.

use super::CryptoError;
use bls12_381_plus::{
    G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar,
    elliptic_curve::ops::MulByGenerator,
    group::{Curve, GroupEncoding},
};

/// Trait for pairing-based cryptographic operations.
///
/// This trait abstracts over the bilinear pairing operation `e: G1 x G2 -> Gt`
/// used throughout the DAC module.
pub trait PairingProvider {
    /// The first source group (typically smaller)
    type G1: Clone + PartialEq;
    /// The second source group (typically larger)
    type G2: Clone + PartialEq;
    /// The target group
    type Gt: Clone + PartialEq;
    /// The scalar field
    type Scalar: Clone + PartialEq;

    /// Compute the bilinear pairing: e(a, b) -> Gt
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt;

    /// Get the generator of G1
    fn g1_generator() -> Self::G1;

    /// Get the generator of G2
    fn g2_generator() -> Self::G2;

    /// Get the identity element of G1
    fn g1_identity() -> Self::G1;

    /// Get the identity element of G2
    fn g2_identity() -> Self::G2;

    /// Get the identity element of Gt
    fn gt_identity() -> Self::Gt;

    /// Scalar multiplication in G1: scalar * point
    fn g1_mul(point: &Self::G1, scalar: &Self::Scalar) -> Self::G1;

    /// Scalar multiplication in G2: scalar * point
    fn g2_mul(point: &Self::G2, scalar: &Self::Scalar) -> Self::G2;

    /// Point addition in G1
    fn g1_add(a: &Self::G1, b: &Self::G1) -> Self::G1;

    /// Point addition in G2
    fn g2_add(a: &Self::G2, b: &Self::G2) -> Self::G2;

    /// Multiplication in Gt
    fn gt_mul(a: &Self::Gt, b: &Self::Gt) -> Self::Gt;

    /// Generate a random scalar
    fn random_scalar<R: rand_core::RngCore>(rng: &mut R) -> Self::Scalar;

    /// Get the zero scalar
    fn scalar_zero() -> Self::Scalar;

    /// Get the one scalar
    fn scalar_one() -> Self::Scalar;

    /// Scalar multiplication by generator in G1
    fn g1_mul_generator(scalar: &Self::Scalar) -> Self::G1;

    /// Scalar multiplication by generator in G2
    fn g2_mul_generator(scalar: &Self::Scalar) -> Self::G2;

    /// Compress a G1 point to bytes
    fn g1_to_bytes(point: &Self::G1) -> Vec<u8>;

    /// Compress a G2 point to bytes
    fn g2_to_bytes(point: &Self::G2) -> Vec<u8>;

    /// Decompress bytes to a G1 point
    fn g1_from_bytes(bytes: &[u8]) -> Result<Self::G1, CryptoError>;

    /// Decompress bytes to a G2 point
    fn g2_from_bytes(bytes: &[u8]) -> Result<Self::G2, CryptoError>;
}

/// BLS12-381 pairing implementation.
///
/// This is the default pairing provider used by Colossus.
/// BLS12-381 provides 128-bit classical security.
///
/// **Note**: BLS12-381 is NOT post-quantum secure. It is vulnerable
/// to Shor's algorithm on a sufficiently large quantum computer.
pub struct Bls12_381Pairing;

impl PairingProvider for Bls12_381Pairing {
    type G1 = G1Projective;
    type G2 = G2Projective;
    type Gt = Gt;
    type Scalar = Scalar;

    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt {
        bls12_381_plus::pairing(&a.to_affine(), &b.to_affine())
    }

    fn g1_generator() -> Self::G1 {
        G1Projective::GENERATOR
    }

    fn g2_generator() -> Self::G2 {
        G2Projective::GENERATOR
    }

    fn g1_identity() -> Self::G1 {
        G1Projective::IDENTITY
    }

    fn g2_identity() -> Self::G2 {
        G2Projective::IDENTITY
    }

    fn gt_identity() -> Self::Gt {
        Gt::IDENTITY
    }

    fn g1_mul(point: &Self::G1, scalar: &Self::Scalar) -> Self::G1 {
        point * scalar
    }

    fn g2_mul(point: &Self::G2, scalar: &Self::Scalar) -> Self::G2 {
        point * scalar
    }

    fn g1_add(a: &Self::G1, b: &Self::G1) -> Self::G1 {
        a + b
    }

    fn g2_add(a: &Self::G2, b: &Self::G2) -> Self::G2 {
        a + b
    }

    fn gt_mul(a: &Self::Gt, b: &Self::Gt) -> Self::Gt {
        a * b
    }

    fn random_scalar<R: rand_core::RngCore>(rng: &mut R) -> Self::Scalar {
        // bls12_381_plus Scalar::random requires CryptoRng
        // We use a workaround by generating random bytes
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_wide(&bytes)
    }

    fn scalar_zero() -> Self::Scalar {
        Scalar::ZERO
    }

    fn scalar_one() -> Self::Scalar {
        Scalar::ONE
    }

    fn g1_mul_generator(scalar: &Self::Scalar) -> Self::G1 {
        G1Projective::mul_by_generator(scalar)
    }

    fn g2_mul_generator(scalar: &Self::Scalar) -> Self::G2 {
        G2Projective::mul_by_generator(scalar)
    }

    fn g1_to_bytes(point: &Self::G1) -> Vec<u8> {
        point.to_bytes().as_ref().to_vec()
    }

    fn g2_to_bytes(point: &Self::G2) -> Vec<u8> {
        point.to_bytes().as_ref().to_vec()
    }

    fn g1_from_bytes(bytes: &[u8]) -> Result<Self::G1, CryptoError> {
        if bytes.len() != G1Affine::COMPRESSED_BYTES {
            return Err(CryptoError::InvalidG1Point);
        }
        let mut arr = [0u8; G1Affine::COMPRESSED_BYTES];
        arr.copy_from_slice(bytes);
        let maybe_affine = G1Affine::from_compressed(&arr);
        if maybe_affine.is_none().into() {
            return Err(CryptoError::InvalidG1Point);
        }
        Ok(maybe_affine.unwrap().into())
    }

    fn g2_from_bytes(bytes: &[u8]) -> Result<Self::G2, CryptoError> {
        if bytes.len() != G2Affine::COMPRESSED_BYTES {
            return Err(CryptoError::InvalidG2Point);
        }
        let mut arr = [0u8; G2Affine::COMPRESSED_BYTES];
        arr.copy_from_slice(bytes);
        let maybe_affine = G2Affine::from_compressed(&arr);
        if maybe_affine.is_none().into() {
            return Err(CryptoError::InvalidG2Point);
        }
        Ok(maybe_affine.unwrap().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;

    #[test]
    fn test_pairing_bilinearity() {
        // Test: e(aP, bQ) = e(P, Q)^(ab)
        let a = Bls12_381Pairing::random_scalar(&mut rng());
        let b = Bls12_381Pairing::random_scalar(&mut rng());

        let p = Bls12_381Pairing::g1_generator();
        let q = Bls12_381Pairing::g2_generator();

        let ap = Bls12_381Pairing::g1_mul(&p, &a);
        let bq = Bls12_381Pairing::g2_mul(&q, &b);

        let lhs = Bls12_381Pairing::pairing(&ap, &bq);

        // e(P, Q)^(ab) = e(abP, Q)
        let ab = a * b;
        let abp = Bls12_381Pairing::g1_mul(&p, &ab);
        let rhs = Bls12_381Pairing::pairing(&abp, &q);

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_generator_is_not_identity() {
        let g1 = Bls12_381Pairing::g1_generator();
        let g2 = Bls12_381Pairing::g2_generator();
        let i1 = Bls12_381Pairing::g1_identity();
        let i2 = Bls12_381Pairing::g2_identity();

        assert_ne!(g1, i1);
        assert_ne!(g2, i2);
    }

    #[test]
    fn test_scalar_zero_one() {
        let zero = Bls12_381Pairing::scalar_zero();
        let one = Bls12_381Pairing::scalar_one();

        assert_ne!(zero, one);

        // Multiply by zero gives identity
        let g1 = Bls12_381Pairing::g1_generator();
        let result = Bls12_381Pairing::g1_mul(&g1, &zero);
        assert_eq!(result, Bls12_381Pairing::g1_identity());

        // Multiply by one gives the same point
        let result = Bls12_381Pairing::g1_mul(&g1, &one);
        assert_eq!(result, g1);
    }

    #[test]
    fn test_g1_serialization_roundtrip() {
        let scalar = Bls12_381Pairing::random_scalar(&mut rng());
        let point = Bls12_381Pairing::g1_mul_generator(&scalar);

        let bytes = Bls12_381Pairing::g1_to_bytes(&point);
        let recovered = Bls12_381Pairing::g1_from_bytes(&bytes).unwrap();

        assert_eq!(point, recovered);
    }

    #[test]
    fn test_g2_serialization_roundtrip() {
        let scalar = Bls12_381Pairing::random_scalar(&mut rng());
        let point = Bls12_381Pairing::g2_mul_generator(&scalar);

        let bytes = Bls12_381Pairing::g2_to_bytes(&point);
        let recovered = Bls12_381Pairing::g2_from_bytes(&bytes).unwrap();

        assert_eq!(point, recovered);
    }

    #[test]
    fn test_invalid_bytes() {
        let bad_bytes = vec![0u8; 48];
        let result = Bls12_381Pairing::g1_from_bytes(&bad_bytes);
        assert!(result.is_err());
    }
}
