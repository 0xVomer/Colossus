//! AEAD Poseidon2 implementation for Colossus.
//!
//! This module provides an authenticated encryption scheme based on the Poseidon2
//! permutation, which is optimized for zero-knowledge proof systems (STARKs).
//!
//! The implementation wraps the `miden-crypto` crate's AEAD Poseidon2 scheme,
//! adapting it to Colossus's `AE` trait interface.
//!
//! # Security Properties
//!
//! - **Key size**: 32 bytes (256 bits, represented as 4 Goldilocks field elements)
//! - **Nonce size**: 32 bytes (256 bits, represented as 4 Goldilocks field elements)
//! - **Auth tag size**: 32 bytes (256 bits, represented as 4 Goldilocks field elements)
//! - **Security level**: 128-bit
//!
//! # References
//!
//! - [Poseidon2 Paper](https://eprint.iacr.org/2023/323)
//! - [AEAD Construction Paper](https://eprint.iacr.org/2023/1668)

use crate::{access_control::cryptography::traits::AE, policy::Error};
use cosmian_crypto_core::{SymmetricKey, reexport::rand_core::CryptoRngCore};
use miden_crypto::aead::aead_poseidon2::{Nonce, SecretKey};
use zeroize::Zeroizing;

/// Key size in bytes for Poseidon2 AEAD (4 Goldilocks field elements = 32 bytes)
pub const POSEIDON2_KEY_SIZE: usize = 32;

/// Nonce size in bytes for Poseidon2 AEAD (4 Goldilocks field elements = 32 bytes)
pub const POSEIDON2_NONCE_SIZE: usize = 32;

/// Authentication tag size in bytes (4 Goldilocks field elements = 32 bytes)
#[allow(dead_code)] // Documented constant for API reference
pub const POSEIDON2_TAG_SIZE: usize = 32;

/// Poseidon2-based AEAD scheme.
///
/// This is an arithmetization-oriented AEAD that is highly efficient within
/// zero-knowledge proof systems (STARKs/SNARKs).
#[derive(Debug, Clone, Copy)]
pub struct Poseidon2Aead;

impl Poseidon2Aead {
    /// Key length in bytes
    #[allow(dead_code)] // Public API constant
    pub const KEY_LENGTH: usize = POSEIDON2_KEY_SIZE;

    /// Nonce length in bytes
    #[allow(dead_code)] // Public API constant
    pub const NONCE_LENGTH: usize = POSEIDON2_NONCE_SIZE;

    /// Convert a SymmetricKey to a miden-crypto SecretKey
    fn to_secret_key(key: &SymmetricKey<POSEIDON2_KEY_SIZE>) -> Result<SecretKey, Error> {
        use miden_crypto::utils::Deserializable;

        // The key bytes need to be converted to 4 Goldilocks field elements
        SecretKey::read_from_bytes(&key[..])
            .map_err(|_| Error::Poseidon2Error("Failed to create secret key".to_string()))
    }
}

impl AE<POSEIDON2_KEY_SIZE> for Poseidon2Aead {
    type Error = Error;

    fn encrypt(
        rng: &mut impl CryptoRngCore,
        key: &SymmetricKey<POSEIDON2_KEY_SIZE>,
        ptx: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use miden_crypto::utils::Serializable;

        let secret_key = Self::to_secret_key(key)?;

        // Generate nonce bytes manually and convert to Nonce
        let mut nonce_bytes = [0u8; POSEIDON2_NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);

        // Create nonce from random bytes - convert to field elements
        use miden_crypto::utils::Deserializable;
        let nonce = Nonce::read_from_bytes(&nonce_bytes)
            .map_err(|_| Error::Poseidon2Error("Failed to create nonce".to_string()))?;

        // Encrypt using miden-crypto's AEAD Poseidon2
        let encrypted_data = secret_key
            .encrypt_bytes_with_nonce(ptx, aad, nonce)
            .map_err(|e| Error::Poseidon2Error(format!("Encryption failed: {:?}", e)))?;

        // Serialize the encrypted data to bytes
        Ok(encrypted_data.to_bytes())
    }

    fn decrypt(
        key: &SymmetricKey<POSEIDON2_KEY_SIZE>,
        ctx: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        use miden_crypto::aead::aead_poseidon2::EncryptedData;
        use miden_crypto::utils::Deserializable;

        let secret_key = Self::to_secret_key(key)?;

        // Deserialize the encrypted data
        let encrypted_data = EncryptedData::read_from_bytes(ctx)
            .map_err(|_| Error::Poseidon2Error("Failed to deserialize ciphertext".to_string()))?;

        // Decrypt using miden-crypto's AEAD Poseidon2
        let plaintext = secret_key
            .decrypt_bytes_with_associated_data(&encrypted_data, aad)
            .map_err(|e| Error::Poseidon2Error(format!("Decryption failed: {:?}", e)))?;

        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_core::{CsRng, RandomFixedSizeCBytes, reexport::rand_core::SeedableRng};

    #[test]
    fn test_poseidon2_aead_roundtrip() {
        let mut rng = CsRng::from_seed([42u8; 32]);

        // Generate a random key
        let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);

        let plaintext = b"Hello, Poseidon2 AEAD!";
        let aad = b"additional authenticated data";

        // Encrypt
        let ciphertext =
            Poseidon2Aead::encrypt(&mut rng, &key, plaintext, aad).expect("encryption failed");

        // Decrypt
        let decrypted = Poseidon2Aead::decrypt(&key, &ciphertext, aad).expect("decryption failed");

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_poseidon2_aead_empty_plaintext() {
        let mut rng = CsRng::from_seed([42u8; 32]);
        let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);

        let plaintext = b"";
        let aad = b"";

        let ciphertext =
            Poseidon2Aead::encrypt(&mut rng, &key, plaintext, aad).expect("encryption failed");

        let decrypted = Poseidon2Aead::decrypt(&key, &ciphertext, aad).expect("decryption failed");

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_poseidon2_aead_wrong_aad_fails() {
        let mut rng = CsRng::from_seed([42u8; 32]);
        let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);

        let plaintext = b"secret message";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext =
            Poseidon2Aead::encrypt(&mut rng, &key, plaintext, aad).expect("encryption failed");

        // Decryption with wrong AAD should fail
        let result = Poseidon2Aead::decrypt(&key, &ciphertext, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_poseidon2_aead_wrong_key_fails() {
        let mut rng = CsRng::from_seed([42u8; 32]);
        let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);
        let wrong_key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);

        let plaintext = b"secret message";
        let aad = b"aad";

        let ciphertext =
            Poseidon2Aead::encrypt(&mut rng, &key, plaintext, aad).expect("encryption failed");

        // Decryption with wrong key should fail
        let result = Poseidon2Aead::decrypt(&wrong_key, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_poseidon2_aead_large_plaintext() {
        let mut rng = CsRng::from_seed([42u8; 32]);
        let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::new(&mut rng);

        // Test with larger plaintext (1KB)
        let plaintext: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let aad = b"large message test";

        let ciphertext =
            Poseidon2Aead::encrypt(&mut rng, &key, &plaintext, aad).expect("encryption failed");

        let decrypted = Poseidon2Aead::decrypt(&key, &ciphertext, aad).expect("decryption failed");

        assert_eq!(&*decrypted, &plaintext);
    }
}
