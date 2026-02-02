//! Unified crypto provider trait.
//!
//! This module provides a single trait that combines all cryptographic
//! primitives needed by Colossus, enabling easy swapping of implementations.

use super::{
    CryptoError,
    hash::{Blake3Hash, Hash256, HashProvider},
    pairing::{Bls12_381Pairing, PairingProvider},
};

/// Unified cryptographic provider trait.
///
/// This trait combines all cryptographic primitives used by Colossus
/// into a single interface. By implementing this trait, alternative
/// cryptographic backends can be plugged in.
///
/// # Design Rationale
///
/// The DAC module requires bilinear pairings which are currently only
/// available from classical (non-post-quantum) elliptic curves. This
/// trait is designed to allow:
///
/// 1. **Current use**: BLS12-381 for all pairing operations
/// 2. **Future migration**: When PQ pairings become available, swap implementation
/// 3. **Hybrid schemes**: Combine classical and PQ primitives for defense-in-depth
///
/// # Example
///
/// ```ignore
/// use colossus_core::crypto::{CryptoProvider, DefaultCryptoProvider};
///
/// // Hash data using the default provider
/// let hash = DefaultCryptoProvider::hash(b"my data");
///
/// // Perform a pairing operation
/// let g1 = DefaultCryptoProvider::g1_generator();
/// let g2 = DefaultCryptoProvider::g2_generator();
/// let gt = DefaultCryptoProvider::pairing(&g1, &g2);
/// ```
pub trait CryptoProvider: Sized {
    /// The underlying pairing provider
    type Pairing: PairingProvider;
    /// The underlying hash provider
    type Hash: HashProvider<Output = Hash256>;

    // === Hash Operations ===

    /// Hash data using the configured hash function
    fn hash(data: &[u8]) -> Hash256 {
        Self::Hash::hash(data)
    }

    /// Hash multiple chunks of data
    fn hash_chunks<I, T>(chunks: I) -> Hash256
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        Self::Hash::hash_chunks(chunks)
    }

    // === Pairing Operations (delegated to PairingProvider) ===

    /// Compute the bilinear pairing
    fn pairing(
        a: &<Self::Pairing as PairingProvider>::G1,
        b: &<Self::Pairing as PairingProvider>::G2,
    ) -> <Self::Pairing as PairingProvider>::Gt {
        Self::Pairing::pairing(a, b)
    }

    /// Get the G1 generator
    fn g1_generator() -> <Self::Pairing as PairingProvider>::G1 {
        Self::Pairing::g1_generator()
    }

    /// Get the G2 generator
    fn g2_generator() -> <Self::Pairing as PairingProvider>::G2 {
        Self::Pairing::g2_generator()
    }

    /// Get the G1 identity
    fn g1_identity() -> <Self::Pairing as PairingProvider>::G1 {
        Self::Pairing::g1_identity()
    }

    /// Get the G2 identity
    fn g2_identity() -> <Self::Pairing as PairingProvider>::G2 {
        Self::Pairing::g2_identity()
    }

    /// Get the Gt identity
    fn gt_identity() -> <Self::Pairing as PairingProvider>::Gt {
        Self::Pairing::gt_identity()
    }

    /// Scalar multiplication in G1
    fn g1_mul(
        point: &<Self::Pairing as PairingProvider>::G1,
        scalar: &<Self::Pairing as PairingProvider>::Scalar,
    ) -> <Self::Pairing as PairingProvider>::G1 {
        Self::Pairing::g1_mul(point, scalar)
    }

    /// Scalar multiplication in G2
    fn g2_mul(
        point: &<Self::Pairing as PairingProvider>::G2,
        scalar: &<Self::Pairing as PairingProvider>::Scalar,
    ) -> <Self::Pairing as PairingProvider>::G2 {
        Self::Pairing::g2_mul(point, scalar)
    }

    /// Point addition in G1
    fn g1_add(
        a: &<Self::Pairing as PairingProvider>::G1,
        b: &<Self::Pairing as PairingProvider>::G1,
    ) -> <Self::Pairing as PairingProvider>::G1 {
        Self::Pairing::g1_add(a, b)
    }

    /// Point addition in G2
    fn g2_add(
        a: &<Self::Pairing as PairingProvider>::G2,
        b: &<Self::Pairing as PairingProvider>::G2,
    ) -> <Self::Pairing as PairingProvider>::G2 {
        Self::Pairing::g2_add(a, b)
    }

    /// Multiplication in Gt
    fn gt_mul(
        a: &<Self::Pairing as PairingProvider>::Gt,
        b: &<Self::Pairing as PairingProvider>::Gt,
    ) -> <Self::Pairing as PairingProvider>::Gt {
        Self::Pairing::gt_mul(a, b)
    }

    /// Generate a random scalar
    fn random_scalar<R: rand_core::RngCore>(
        rng: &mut R,
    ) -> <Self::Pairing as PairingProvider>::Scalar {
        Self::Pairing::random_scalar(rng)
    }

    /// Get the zero scalar
    fn scalar_zero() -> <Self::Pairing as PairingProvider>::Scalar {
        Self::Pairing::scalar_zero()
    }

    /// Get the one scalar
    fn scalar_one() -> <Self::Pairing as PairingProvider>::Scalar {
        Self::Pairing::scalar_one()
    }

    /// Scalar multiplication by generator in G1
    fn g1_mul_generator(
        scalar: &<Self::Pairing as PairingProvider>::Scalar,
    ) -> <Self::Pairing as PairingProvider>::G1 {
        Self::Pairing::g1_mul_generator(scalar)
    }

    /// Scalar multiplication by generator in G2
    fn g2_mul_generator(
        scalar: &<Self::Pairing as PairingProvider>::Scalar,
    ) -> <Self::Pairing as PairingProvider>::G2 {
        Self::Pairing::g2_mul_generator(scalar)
    }

    /// Serialize a G1 point to bytes
    fn g1_to_bytes(point: &<Self::Pairing as PairingProvider>::G1) -> Vec<u8> {
        Self::Pairing::g1_to_bytes(point)
    }

    /// Serialize a G2 point to bytes
    fn g2_to_bytes(point: &<Self::Pairing as PairingProvider>::G2) -> Vec<u8> {
        Self::Pairing::g2_to_bytes(point)
    }

    /// Deserialize a G1 point from bytes
    fn g1_from_bytes(bytes: &[u8]) -> Result<<Self::Pairing as PairingProvider>::G1, CryptoError> {
        Self::Pairing::g1_from_bytes(bytes)
    }

    /// Deserialize a G2 point from bytes
    fn g2_from_bytes(bytes: &[u8]) -> Result<<Self::Pairing as PairingProvider>::G2, CryptoError> {
        Self::Pairing::g2_from_bytes(bytes)
    }
}

/// Default crypto provider using BLS12-381 and BLAKE3.
///
/// This is the standard provider for Colossus, offering:
/// - **Pairing**: BLS12-381 (128-bit classical security)
/// - **Hash**: BLAKE3 (256-bit output, quantum-resistant)
///
/// # Security Notes
///
/// BLS12-381 is NOT post-quantum secure. The pairing operations
/// are vulnerable to Shor's algorithm. However, no practical
/// quantum computer capable of breaking BLS12-381 currently exists.
///
/// For defense-in-depth, consider using hybrid schemes where
/// critical data is also protected by post-quantum primitives.
pub struct DefaultCryptoProvider;

impl CryptoProvider for DefaultCryptoProvider {
    type Pairing = Bls12_381Pairing;
    type Hash = Blake3Hash;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;

    #[test]
    fn test_default_provider_hash() {
        let data = b"test data";
        let hash = DefaultCryptoProvider::hash(data);
        assert_eq!(hash.as_ref().len(), 32);
    }

    #[test]
    fn test_default_provider_pairing() {
        let g1 = DefaultCryptoProvider::g1_generator();
        let g2 = DefaultCryptoProvider::g2_generator();
        let gt = DefaultCryptoProvider::pairing(&g1, &g2);

        // Pairing of generators should not be identity
        let gt_id = DefaultCryptoProvider::gt_identity();
        assert_ne!(gt, gt_id);
    }

    #[test]
    fn test_default_provider_scalar_ops() {
        let scalar = DefaultCryptoProvider::random_scalar(&mut rng());
        let g1 = DefaultCryptoProvider::g1_mul_generator(&scalar);
        let g1_id = DefaultCryptoProvider::g1_identity();

        assert_ne!(g1, g1_id);
    }

    #[test]
    fn test_default_provider_serialization() {
        let scalar = DefaultCryptoProvider::random_scalar(&mut rng());
        let point = DefaultCryptoProvider::g1_mul_generator(&scalar);

        let bytes = DefaultCryptoProvider::g1_to_bytes(&point);
        let recovered = DefaultCryptoProvider::g1_from_bytes(&bytes).unwrap();

        assert_eq!(point, recovered);
    }
}
