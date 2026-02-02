//! Post-Quantum Digital Signatures using Falcon512-Poseidon2
//!
//! This module provides a wrapper around miden-crypto's Falcon512-Poseidon2 digital signature
//! scheme. Falcon is a lattice-based signature scheme that is resistant to attacks by quantum
//! computers, making it suitable for long-term security in the Miden ecosystem.
//!
//! # Security Properties
//!
//! - **Post-Quantum Security**: Based on the hardness of NTRU lattice problems
//! - **Deterministic Signing**: Signatures are deterministic for a given message and key
//! - **ZK-Compatible**: Uses Poseidon2 hash function for hash-to-point, enabling efficient
//!   verification in STARK proofs
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Falcon512 Signature Module                    │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              Falcon512Keypair                            │   │
//! │  │   - secret_key: SecretKey (1281 bytes)                   │   │
//! │  │   - public_key: PublicKey (897 bytes)                    │   │
//! │  │   - Derived from OS entropy or provided RNG              │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                           │                                     │
//! │                           ▼                                     │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              Falcon512Signature                          │   │
//! │  │   - Deterministic signature over Word (4 field elements) │   │
//! │  │   - Verifiable against public key commitment             │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use colossus_core::crypto::signature::{Falcon512Keypair, Falcon512Signature};
//! use miden_crypto::Word;
//!
//! // Generate a new keypair
//! let keypair = Falcon512Keypair::new();
//!
//! // Sign a message (represented as a Word)
//! let message = Word::default();
//! let signature = keypair.sign(&message);
//!
//! // Verify the signature
//! assert!(keypair.verify(&message, &signature));
//!
//! // Get the public key for distribution
//! let public_key = keypair.public_key();
//!
//! // Get the public key commitment (Poseidon2 hash) for on-chain storage
//! let commitment = keypair.public_key_commitment();
//! ```

use crate::crypto::error::CryptoError;
use miden_crypto::Word;
use miden_crypto::dsa::falcon512_poseidon2::{PK_LEN, PublicKey, SK_LEN, SecretKey, Signature};
use miden_crypto::utils::{Deserializable, Serializable};

/// Length of the serialized public key in bytes
pub const FALCON512_PUBLIC_KEY_LEN: usize = PK_LEN;

/// Length of the serialized secret key in bytes
pub const FALCON512_SECRET_KEY_LEN: usize = SK_LEN;

/// A Falcon512-Poseidon2 keypair for post-quantum digital signatures.
///
/// This keypair can be used to sign messages and verify signatures. The secret key
/// should be kept private, while the public key can be distributed to verifiers.
///
/// # Security Considerations
///
/// - The secret key is zeroized on drop to prevent leakage
/// - Key generation uses OS-provided randomness by default
/// - Signing is deterministic to avoid nonce reuse vulnerabilities
#[derive(Clone)]
pub struct Falcon512Keypair {
    secret_key: SecretKey,
}

impl Falcon512Keypair {
    /// Generate a new keypair from OS-provided randomness.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random number generator is unavailable.
    pub fn new() -> Self {
        Self { secret_key: SecretKey::new() }
    }

    /// Generate a new keypair using the provided random number generator.
    ///
    /// This is useful for deterministic key generation from a seed in testing,
    /// or when using a custom entropy source.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator implementing `rand::Rng`
    pub fn with_rng<R: rand::Rng>(rng: &mut R) -> Self {
        Self { secret_key: SecretKey::with_rng(rng) }
    }

    /// Get the public key associated with this keypair.
    pub fn public_key(&self) -> Falcon512PublicKey {
        Falcon512PublicKey(self.secret_key.public_key())
    }

    /// Get the Poseidon2 commitment to the public key.
    ///
    /// This commitment is suitable for on-chain storage and verification
    /// in STARK proofs.
    pub fn public_key_commitment(&self) -> Word {
        self.secret_key.public_key().to_commitment()
    }

    /// Sign a message represented as a Word (4 Goldilocks field elements).
    ///
    /// The signature is deterministic: signing the same message with the same
    /// key always produces the same signature.
    pub fn sign(&self, message: &Word) -> Falcon512Signature {
        Falcon512Signature(self.secret_key.sign(*message))
    }

    /// Sign a message using the provided random number generator.
    ///
    /// This variant is useful for testing with deterministic randomness.
    pub fn sign_with_rng<R: rand::Rng>(&self, message: &Word, rng: &mut R) -> Falcon512Signature {
        Falcon512Signature(self.secret_key.sign_with_rng(*message, rng))
    }

    /// Verify a signature against this keypair's public key.
    pub fn verify(&self, message: &Word, signature: &Falcon512Signature) -> bool {
        self.secret_key.public_key().verify(*message, &signature.0)
    }

    /// Serialize the secret key to bytes.
    ///
    /// # Security Warning
    ///
    /// The returned bytes contain sensitive key material. Handle with care
    /// and zeroize after use.
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.secret_key.write_into(&mut bytes);
        bytes
    }

    /// Deserialize a keypair from secret key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes don't represent a valid secret key.
    pub fn from_secret_key_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let secret_key = SecretKey::read_from_bytes(bytes).map_err(|e| {
            CryptoError::InvalidKey(format!("failed to deserialize Falcon512 secret key: {}", e))
        })?;
        Ok(Self { secret_key })
    }
}

impl Default for Falcon512Keypair {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Debug without exposing secret key material
impl std::fmt::Debug for Falcon512Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Falcon512Keypair")
            .field("public_key_commitment", &self.public_key_commitment())
            .finish_non_exhaustive()
    }
}

/// A Falcon512-Poseidon2 public key for signature verification.
///
/// This key can be freely distributed to anyone who needs to verify
/// signatures created with the corresponding secret key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Falcon512PublicKey(PublicKey);

impl Falcon512PublicKey {
    /// Verify a signature against this public key.
    pub fn verify(&self, message: &Word, signature: &Falcon512Signature) -> bool {
        self.0.verify(*message, &signature.0)
    }

    /// Get the Poseidon2 commitment to this public key.
    ///
    /// This commitment is suitable for on-chain storage and verification
    /// in STARK proofs.
    pub fn commitment(&self) -> Word {
        self.0.to_commitment()
    }

    /// Serialize the public key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        (&self.0).write_into(&mut bytes);
        bytes
    }

    /// Deserialize a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes don't represent a valid public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let public_key = PublicKey::read_from_bytes(bytes).map_err(|e| {
            CryptoError::InvalidKey(format!("failed to deserialize Falcon512 public key: {}", e))
        })?;
        Ok(Self(public_key))
    }

    /// Recover the public key from a signature.
    ///
    /// This extracts the public key that was used to create the signature.
    /// Useful for verification when only the signature is available.
    pub fn recover_from_signature(message: &Word, signature: &Falcon512Signature) -> Self {
        Self(PublicKey::recover_from(*message, &signature.0))
    }
}

/// A Falcon512-Poseidon2 signature.
///
/// Signatures are deterministic: the same message signed with the same key
/// always produces the same signature.
#[derive(Debug, Clone)]
pub struct Falcon512Signature(Signature);

impl PartialEq for Falcon512Signature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Falcon512Signature {}

impl Falcon512Signature {
    /// Verify this signature against a public key and message.
    pub fn verify(&self, message: &Word, public_key: &Falcon512PublicKey) -> bool {
        public_key.0.verify(*message, &self.0)
    }

    /// Serialize the signature to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        (&self.0).write_into(&mut bytes);
        bytes
    }

    /// Deserialize a signature from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes don't represent a valid signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let signature = Signature::read_from_bytes(bytes).map_err(|e| {
            CryptoError::InvalidSignature(format!(
                "failed to deserialize Falcon512 signature: {}",
                e
            ))
        })?;
        Ok(Self(signature))
    }

    /// Get the public key embedded in this signature.
    ///
    /// Falcon signatures include the public key polynomial, allowing
    /// verification without separately providing the public key.
    pub fn embedded_public_key(&self) -> Falcon512PublicKey {
        Falcon512PublicKey(self.0.public_key().clone())
    }
}

/// Trait for types that can be signed with Falcon512.
///
/// This trait allows signing arbitrary data by first converting it to a Word.
pub trait Falcon512Signable {
    /// Convert this value to a Word for signing.
    fn to_signing_message(&self) -> Word;
}

impl Falcon512Signable for Word {
    fn to_signing_message(&self) -> Word {
        *self
    }
}

impl Falcon512Signable for [u8; 32] {
    fn to_signing_message(&self) -> Word {
        use crate::crypto::Poseidon2Hash;
        Poseidon2Hash::hash_bytes(self).as_word().clone()
    }
}

impl Falcon512Signable for &[u8] {
    fn to_signing_message(&self) -> Word {
        use crate::crypto::Poseidon2Hash;
        Poseidon2Hash::hash_bytes(self).as_word().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([0u8; 32])
    }

    #[test]
    fn test_keypair_generation() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);

        // Public key should be derivable
        let pk = keypair.public_key();
        assert!(!pk.to_bytes().is_empty());

        // Commitment should be deterministic
        let commitment1 = keypair.public_key_commitment();
        let commitment2 = keypair.public_key_commitment();
        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);

        use miden_crypto::field::PrimeCharacteristicRing;
        let message = Word::new([
            miden_crypto::Felt::ONE,
            miden_crypto::Felt::new(2),
            miden_crypto::Felt::new(3),
            miden_crypto::Felt::new(4),
        ]);

        let signature = keypair.sign(&message);

        // Signature should verify with the correct keypair
        assert!(keypair.verify(&message, &signature));

        // Signature should verify with just the public key
        let pk = keypair.public_key();
        assert!(pk.verify(&message, &signature));
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);

        use miden_crypto::field::PrimeCharacteristicRing;
        let message1 = Word::new([miden_crypto::Felt::ONE; 4]);
        let message2 = Word::new([miden_crypto::Felt::new(2); 4]);

        let signature = keypair.sign(&message1);

        // Should not verify with wrong message
        assert!(!keypair.verify(&message2, &signature));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let mut rng = test_rng();
        let keypair1 = Falcon512Keypair::with_rng(&mut rng);
        let keypair2 = Falcon512Keypair::with_rng(&mut rng);

        use miden_crypto::field::PrimeCharacteristicRing;
        let message = Word::new([miden_crypto::Felt::ONE; 4]);

        let signature = keypair1.sign(&message);

        // Should not verify with wrong key
        assert!(!keypair2.verify(&message, &signature));
    }

    #[test]
    fn test_deterministic_signing() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);

        use miden_crypto::field::PrimeCharacteristicRing;
        let message = Word::new([miden_crypto::Felt::ONE; 4]);

        let sig1 = keypair.sign(&message);
        let sig2 = keypair.sign(&message);

        // Signatures should be identical for same message
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);
        let pk = keypair.public_key();

        let bytes = pk.to_bytes();
        let pk_restored = Falcon512PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk.commitment(), pk_restored.commitment());
    }

    #[test]
    fn test_signature_serialization() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);

        use miden_crypto::field::PrimeCharacteristicRing;
        let message = Word::new([miden_crypto::Felt::ONE; 4]);
        let signature = keypair.sign(&message);

        let bytes = signature.to_bytes();
        let sig_restored = Falcon512Signature::from_bytes(&bytes).unwrap();

        // Restored signature should still verify
        assert!(keypair.verify(&message, &sig_restored));
    }

    #[test]
    fn test_secret_key_serialization() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);

        let bytes = keypair.secret_key_bytes();
        let keypair_restored = Falcon512Keypair::from_secret_key_bytes(&bytes).unwrap();

        // Commitments should match
        assert_eq!(keypair.public_key_commitment(), keypair_restored.public_key_commitment());

        // Signing should produce same signature
        use miden_crypto::field::PrimeCharacteristicRing;
        let message = Word::new([miden_crypto::Felt::ONE; 4]);
        let sig1 = keypair.sign(&message);
        let sig2 = keypair_restored.sign(&message);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_recover_public_key_from_signature() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);

        use miden_crypto::field::PrimeCharacteristicRing;
        let message = Word::new([miden_crypto::Felt::ONE; 4]);
        let signature = keypair.sign(&message);

        let recovered_pk = Falcon512PublicKey::recover_from_signature(&message, &signature);

        // Recovered key should have same commitment
        assert_eq!(keypair.public_key().commitment(), recovered_pk.commitment());
    }

    #[test]
    fn test_sign_arbitrary_bytes() {
        let mut rng = test_rng();
        let keypair = Falcon512Keypair::with_rng(&mut rng);

        let data: &[u8] = b"Hello, Miden!";
        let message = data.to_signing_message();
        let signature = keypair.sign(&message);

        assert!(keypair.verify(&message, &signature));
    }
}
