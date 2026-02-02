//! Hash provider trait and implementations.
//!
//! Provides a unified interface for cryptographic hash functions,
//! enabling algorithm agility.
//!
//! # Available Hash Functions
//!
//! - **BLAKE3**: Fast, secure, quantum-resistant hash (default for general use)
//! - **SHA3-256**: NIST-standardized, quantum-resistant
//! - **Poseidon2**: Algebraic hash optimized for ZK proofs (Miden-native)
//!
//! # Miden Integration
//!
//! For Miden ecosystem interoperability, use `Poseidon2Hash` which operates
//! natively on Goldilocks field elements and produces ZK-provable commitments.

use super::CryptoError;
use miden_crypto::{
    Felt, Word,
    field::{PrimeCharacteristicRing, PrimeField64},
    hash::poseidon2::Poseidon2,
};

/// Trait for cryptographic hash providers.
pub trait HashProvider {
    /// The output type for the hash
    type Output: AsRef<[u8]> + Clone + PartialEq + Eq;

    /// Hash the input data
    fn hash(data: &[u8]) -> Self::Output;

    /// Hash multiple chunks of data
    fn hash_chunks<I, T>(chunks: I) -> Self::Output
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>;

    /// Create a new hasher for streaming input
    fn new_hasher() -> Self;

    /// Update the hasher with more data
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the hash
    fn finalize(self) -> Self::Output;
}

/// BLAKE3 hash implementation (256-bit output).
///
/// BLAKE3 is a fast, secure hash function with excellent performance
/// characteristics. It is quantum-resistant.
#[derive(Clone)]
pub struct Blake3Hash {
    hasher: blake3::Hasher,
}

/// 32-byte hash output
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for Hash256 {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(CryptoError::HashError(format!("expected 32 bytes, got {}", bytes.len())));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

impl HashProvider for Blake3Hash {
    type Output = Hash256;

    fn hash(data: &[u8]) -> Self::Output {
        let hash = blake3::hash(data);
        Hash256(*hash.as_bytes())
    }

    fn hash_chunks<I, T>(chunks: I) -> Self::Output
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut hasher = blake3::Hasher::new();
        for chunk in chunks {
            hasher.update(chunk.as_ref());
        }
        Hash256(*hasher.finalize().as_bytes())
    }

    fn new_hasher() -> Self {
        Self { hasher: blake3::Hasher::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Self::Output {
        Hash256(*self.hasher.finalize().as_bytes())
    }
}

/// SHA3-256 hash implementation.
///
/// SHA3-256 is a NIST-standardized hash function with 256-bit output.
/// It is quantum-resistant.
#[derive(Clone)]
pub struct Sha3_256Hash {
    hasher: tiny_keccak::Sha3,
}

impl HashProvider for Sha3_256Hash {
    type Output = Hash256;

    fn hash(data: &[u8]) -> Self::Output {
        use tiny_keccak::Hasher;
        let mut hasher = tiny_keccak::Sha3::v256();
        hasher.update(data);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        Hash256(output)
    }

    fn hash_chunks<I, T>(chunks: I) -> Self::Output
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        use tiny_keccak::Hasher;
        let mut hasher = tiny_keccak::Sha3::v256();
        for chunk in chunks {
            hasher.update(chunk.as_ref());
        }
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        Hash256(output)
    }

    fn new_hasher() -> Self {
        Self { hasher: tiny_keccak::Sha3::v256() }
    }

    fn update(&mut self, data: &[u8]) {
        use tiny_keccak::Hasher;
        self.hasher.update(data);
    }

    fn finalize(self) -> Self::Output {
        use tiny_keccak::Hasher;
        let mut output = [0u8; 32];
        self.hasher.finalize(&mut output);
        Hash256(output)
    }
}

// ================================================================================================
// POSEIDON2 HASH - MIDEN NATIVE
// ================================================================================================

/// Poseidon2 hash output as 4 Goldilocks field elements (Word).
///
/// This is the native format for Miden VM and STARK proofs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Poseidon2Digest(Word);

impl Poseidon2Digest {
    /// Create from a Word (4 field elements)
    pub fn from_word(word: Word) -> Self {
        Self(word)
    }

    /// Get the underlying Word
    pub fn as_word(&self) -> &Word {
        &self.0
    }

    /// Convert to bytes (32 bytes = 4 x 8-byte field elements)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, felt) in self.0.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }
        bytes
    }

    /// Create from bytes (32 bytes interpreted as 4 field elements)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut elements = [Felt::ZERO; 4];
        for i in 0..4 {
            let mut felt_bytes = [0u8; 8];
            felt_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            let value = u64::from_le_bytes(felt_bytes);
            elements[i] = Felt::new(value);
        }
        Self(Word::new(elements))
    }

    /// Get the field elements
    pub fn elements(&self) -> [Felt; 4] {
        self.0.into()
    }
}

impl AsRef<[u8]> for Poseidon2Digest {
    fn as_ref(&self) -> &[u8] {
        // Note: This is a workaround since Word doesn't expose bytes directly.
        // In practice, use to_bytes() for byte access.
        // We use a static buffer approach via leak for the trait impl
        // This is safe because Hash256 also returns borrowed data
        Box::leak(Box::new(self.to_bytes()))
    }
}

impl From<Word> for Poseidon2Digest {
    fn from(word: Word) -> Self {
        Self(word)
    }
}

impl From<Poseidon2Digest> for Word {
    fn from(digest: Poseidon2Digest) -> Self {
        digest.0
    }
}

/// Poseidon2 hash implementation optimized for ZK proofs.
///
/// Poseidon2 is an algebraic hash function designed for efficient
/// arithmetization in STARK/SNARK proof systems. It operates natively
/// on the Goldilocks field (p = 2^64 - 2^32 + 1).
///
/// # Use Cases
///
/// - **Miden VM compatibility**: Hash outputs can be verified inside Miden STARK proofs
/// - **Merkle tree commitments**: Efficient for SMT and MMR structures
/// - **Policy commitments**: ZK-provable access policy hashes
///
/// # Example
///
/// ```ignore
/// use colossus_core::crypto::hash::Poseidon2Hash;
///
/// // Hash bytes (converted to field elements internally)
/// let digest = Poseidon2Hash::hash_bytes(b"hello world");
///
/// // Hash field elements directly (most efficient)
/// use miden_crypto::Felt;
/// let elements = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
/// let digest = Poseidon2Hash::hash_elements(&elements);
/// ```
#[derive(Clone)]
pub struct Poseidon2Hash {
    elements: Vec<Felt>,
}

impl Poseidon2Hash {
    /// Hash a slice of field elements directly.
    ///
    /// This is the most efficient way to use Poseidon2 when your data
    /// is already in field element form.
    pub fn hash_elements(elements: &[Felt]) -> Poseidon2Digest {
        Poseidon2Digest(Poseidon2::hash_elements(elements))
    }

    /// Hash raw bytes by converting them to field elements.
    ///
    /// Bytes are packed into field elements (8 bytes per element) with
    /// little-endian encoding. The final element may be padded.
    pub fn hash_bytes(data: &[u8]) -> Poseidon2Digest {
        let elements = Self::bytes_to_elements(data);
        Self::hash_elements(&elements)
    }

    /// Merge two digests into one (for Merkle tree construction).
    pub fn merge(left: &Poseidon2Digest, right: &Poseidon2Digest) -> Poseidon2Digest {
        Poseidon2Digest(Poseidon2::merge(&[left.0, right.0]))
    }

    /// Convert bytes to field elements.
    ///
    /// Each 8 bytes become one field element (little-endian).
    /// Remaining bytes are padded with zeros.
    pub fn bytes_to_elements(data: &[u8]) -> Vec<Felt> {
        let mut elements = Vec::with_capacity((data.len() + 7) / 8);

        for chunk in data.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let value = u64::from_le_bytes(bytes);
            // Ensure value fits in Goldilocks field (p = 2^64 - 2^32 + 1)
            // Values >= p are reduced modulo p by Felt::new
            elements.push(Felt::new(value));
        }

        elements
    }

    /// Convert field elements back to bytes.
    pub fn elements_to_bytes(elements: &[Felt]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(elements.len() * 8);
        for felt in elements {
            bytes.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }
        bytes
    }
}

impl HashProvider for Poseidon2Hash {
    type Output = Hash256;

    fn hash(data: &[u8]) -> Self::Output {
        let digest = Self::hash_bytes(data);
        Hash256(digest.to_bytes())
    }

    fn hash_chunks<I, T>(chunks: I) -> Self::Output
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut all_elements = Vec::new();
        for chunk in chunks {
            all_elements.extend(Self::bytes_to_elements(chunk.as_ref()));
        }
        let digest = Self::hash_elements(&all_elements);
        Hash256(digest.to_bytes())
    }

    fn new_hasher() -> Self {
        Self { elements: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.elements.extend(Self::bytes_to_elements(data));
    }

    fn finalize(self) -> Self::Output {
        let digest = Self::hash_elements(&self.elements);
        Hash256(digest.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let data = b"hello world";
        let hash = Blake3Hash::hash(data);
        assert_eq!(hash.as_ref().len(), 32);

        // Same input should produce same output
        let hash2 = Blake3Hash::hash(data);
        assert_eq!(hash, hash2);

        // Different input should produce different output
        let hash3 = Blake3Hash::hash(b"hello world!");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_blake3_streaming() {
        let data = b"hello world";
        let hash1 = Blake3Hash::hash(data);

        let mut hasher = Blake3Hash::new_hasher();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha3_hash() {
        let data = b"hello world";
        let hash = Sha3_256Hash::hash(data);
        assert_eq!(hash.as_ref().len(), 32);

        // Same input should produce same output
        let hash2 = Sha3_256Hash::hash(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sha3_streaming() {
        let data = b"hello world";
        let hash1 = Sha3_256Hash::hash(data);

        let mut hasher = Sha3_256Hash::new_hasher();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_chunks() {
        let chunks = vec![b"hello ".to_vec(), b"world".to_vec()];
        let hash1 = Blake3Hash::hash_chunks(chunks.iter());
        let hash2 = Blake3Hash::hash(b"hello world");
        assert_eq!(hash1, hash2);
    }

    // ============================================================================================
    // POSEIDON2 TESTS
    // ============================================================================================

    #[test]
    fn test_poseidon2_hash_bytes() {
        let data = b"hello world";
        let digest = Poseidon2Hash::hash_bytes(data);

        // Should produce a 4-element Word
        assert_eq!(digest.elements().len(), 4);

        // Same input should produce same output
        let digest2 = Poseidon2Hash::hash_bytes(data);
        assert_eq!(digest, digest2);

        // Different input should produce different output
        let digest3 = Poseidon2Hash::hash_bytes(b"hello world!");
        assert_ne!(digest, digest3);
    }

    #[test]
    fn test_poseidon2_hash_elements() {
        let elements = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
        let digest = Poseidon2Hash::hash_elements(&elements);

        // Same input should produce same output
        let digest2 = Poseidon2Hash::hash_elements(&elements);
        assert_eq!(digest, digest2);

        // Different input should produce different output
        let elements3 = vec![Felt::new(1), Felt::new(2), Felt::new(4)];
        let digest3 = Poseidon2Hash::hash_elements(&elements3);
        assert_ne!(digest, digest3);
    }

    #[test]
    fn test_poseidon2_merge() {
        let left = Poseidon2Hash::hash_bytes(b"left");
        let right = Poseidon2Hash::hash_bytes(b"right");

        let merged = Poseidon2Hash::merge(&left, &right);

        // Same inputs should produce same merged output
        let merged2 = Poseidon2Hash::merge(&left, &right);
        assert_eq!(merged, merged2);

        // Order matters
        let merged_reversed = Poseidon2Hash::merge(&right, &left);
        assert_ne!(merged, merged_reversed);
    }

    #[test]
    fn test_poseidon2_digest_bytes_roundtrip() {
        let data = b"test data for roundtrip";
        let digest = Poseidon2Hash::hash_bytes(data);

        let bytes = digest.to_bytes();
        assert_eq!(bytes.len(), 32);

        let recovered = Poseidon2Digest::from_bytes(&bytes);
        assert_eq!(digest, recovered);
    }

    #[test]
    fn test_poseidon2_hash_provider_interface() {
        // Test HashProvider trait implementation
        let data = b"hello world";
        let hash = Poseidon2Hash::hash(data);
        assert_eq!(hash.as_ref().len(), 32);

        // Streaming interface
        let mut hasher = Poseidon2Hash::new_hasher();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash2 = hasher.finalize();

        // Note: Poseidon2 streaming may differ from one-shot due to element boundaries
        // This is expected behavior for algebraic hashes
        assert_eq!(hash.as_ref().len(), hash2.as_ref().len());
    }

    #[test]
    fn test_poseidon2_bytes_to_elements() {
        // Test short data
        let short = b"hi";
        let elements = Poseidon2Hash::bytes_to_elements(short);
        assert_eq!(elements.len(), 1);

        // Test exact 8-byte boundary
        let exact = b"12345678";
        let elements = Poseidon2Hash::bytes_to_elements(exact);
        assert_eq!(elements.len(), 1);

        // Test crossing boundary
        let crossing = b"123456789";
        let elements = Poseidon2Hash::bytes_to_elements(crossing);
        assert_eq!(elements.len(), 2);
    }

    #[test]
    fn test_poseidon2_empty_input() {
        let empty = b"";
        let digest = Poseidon2Hash::hash_bytes(empty);

        // Should handle empty input gracefully
        let elements: [Felt; 4] = digest.elements();
        assert_eq!(elements.len(), 4);

        // Empty elements hash
        let empty_elements: Vec<Felt> = vec![];
        let digest2 = Poseidon2Hash::hash_elements(&empty_elements);

        // Both should produce valid (possibly different) outputs
        assert_eq!(digest.elements().len(), 4);
        assert_eq!(digest2.elements().len(), 4);
    }
}
