//! Capability Revocation using Sparse Merkle Trees (SMT)
//!
//! This module provides a ZK-proof compatible revocation system using miden-crypto's
//! Sparse Merkle Tree implementation. The SMT root can be committed on-chain in the
//! Miden rollup, enabling trustless verification of revocation status.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Revocation Registry                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              Sparse Merkle Tree (SMT)                    │   │
//! │  │   - Key: Capability ID (as Word)                        │   │
//! │  │   - Value: Revocation status + timestamp                │   │
//! │  │   - Root: Commitment for on-chain verification          │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                           │                                     │
//! │                           ▼                                     │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              Merkle Proofs (SmtProof)                    │   │
//! │  │   - Non-membership: Capability is NOT revoked           │   │
//! │  │   - Membership: Capability IS revoked                   │   │
//! │  │   - Verifiable in STARK proofs                          │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use colossus_core::access_control::revocation::{RevocationRegistry, RevocationProof};
//!
//! // Create a new registry
//! let mut registry = RevocationRegistry::new();
//!
//! // Revoke a capability
//! let capability_id = /* ... */;
//! registry.revoke(&capability_id)?;
//!
//! // Get the current root for on-chain commitment
//! let root = registry.root();
//!
//! // Generate a proof that a capability is NOT revoked
//! let proof = registry.prove_not_revoked(&capability_id)?;
//!
//! // Verify the proof (can be done off-chain or in STARK)
//! assert!(proof.verify(&root, &capability_id)?);
//! ```

use crate::access_control::capability::AuthorityIdentity;
use crate::crypto::{
    Falcon512PublicKey, Falcon512Signature, Felt, Poseidon2Digest, Poseidon2Hash, Word,
};
use crate::policy::Error;
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};
use miden_crypto::field::PrimeCharacteristicRing;
use miden_crypto::merkle::SparseMerklePath;
use miden_crypto::merkle::smt::{LeafIndex, SimpleSmt};

/// Depth of the revocation SMT (64 bits = full key space)
pub const REVOCATION_SMT_DEPTH: u8 = 64;

/// Get the revoked value marker
fn revoked_value() -> Word {
    Word::new([
        Felt::new(1), // Revocation flag
        Felt::ZERO,   // Reserved
        Felt::ZERO,   // Reserved
        Felt::ZERO,   // Reserved (could store timestamp)
    ])
}

/// Get the empty value (not revoked)
fn empty_value() -> Word {
    Word::new([Felt::ZERO; 4])
}

/// A revocation registry backed by a Sparse Merkle Tree.
///
/// The registry tracks revoked capability IDs using an SMT where:
/// - **Key**: Hash of the capability ID (as u64 leaf index)
/// - **Value**: `REVOKED_VALUE` if revoked, `EMPTY_VALUE` (default) if not
///
/// The SMT root serves as a cryptographic commitment to the entire revocation
/// state and can be posted on-chain for trustless verification.
#[derive(Debug, Clone)]
pub struct RevocationRegistry {
    /// The underlying Sparse Merkle Tree
    smt: SimpleSmt<REVOCATION_SMT_DEPTH>,
    /// Count of revoked capabilities
    revocation_count: usize,
}

/// Proof of revocation status for a capability.
#[derive(Debug, Clone)]
pub struct RevocationProof {
    /// The Merkle path from leaf to root
    pub path: SparseMerklePath,
    /// The leaf value (REVOKED_VALUE or EMPTY_VALUE)
    pub value: Word,
    /// The key (leaf index) this proof is for
    pub key: u64,
}

/// Identifier for a capability that can be revoked.
///
/// This is a wrapper around any bytes that can identify a capability,
/// hashed to a u64 leaf index using Poseidon2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityId(Vec<u8>);

impl CapabilityId {
    /// Create a new capability ID from bytes
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Create from a Word (4 field elements)
    pub fn from_word(word: &Word) -> Self {
        use miden_crypto::field::PrimeField64;
        let mut bytes = Vec::with_capacity(32);
        for felt in word.iter() {
            bytes.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Hash the capability ID to a leaf index using Poseidon2
    pub fn to_leaf_index(&self) -> u64 {
        let digest = Poseidon2Hash::hash_bytes(&self.0);
        // Take the first 8 bytes of the digest as the leaf index
        let bytes = digest.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    }

    /// Hash to a Word for SMT key
    pub fn to_word(&self) -> Word {
        Poseidon2Hash::hash_bytes(&self.0).as_word().clone()
    }
}

impl From<&[u8]> for CapabilityId {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<Vec<u8>> for CapabilityId {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl RevocationRegistry {
    /// Create a new empty revocation registry.
    pub fn new() -> Self {
        Self {
            smt: SimpleSmt::new().expect("failed to create SMT"),
            revocation_count: 0,
        }
    }

    /// Get the current SMT root.
    ///
    /// This root can be committed on-chain to enable trustless verification
    /// of revocation proofs.
    pub fn root(&self) -> Word {
        self.smt.root()
    }

    /// Get the root as a Poseidon2Digest for easier handling.
    pub fn root_digest(&self) -> Poseidon2Digest {
        Poseidon2Digest::from_word(self.root())
    }

    /// Get the number of revoked capabilities.
    pub fn revocation_count(&self) -> usize {
        self.revocation_count
    }

    /// Check if a capability is revoked (local check, no proof).
    pub fn is_revoked(&self, capability_id: &CapabilityId) -> Result<bool, Error> {
        let key = Self::make_leaf_index(capability_id.to_leaf_index())?;
        let value = self.smt.get_leaf(&key);
        Ok(value != empty_value())
    }

    /// Create a LeafIndex from a u64, handling the Result
    fn make_leaf_index(value: u64) -> Result<LeafIndex<REVOCATION_SMT_DEPTH>, Error> {
        LeafIndex::new(value)
            .map_err(|e| Error::OperationNotPermitted(format!("invalid leaf index: {:?}", e)))
    }

    /// Revoke a capability.
    ///
    /// Returns `Ok(true)` if the capability was newly revoked,
    /// `Ok(false)` if it was already revoked.
    pub fn revoke(&mut self, capability_id: &CapabilityId) -> Result<bool, Error> {
        let key = Self::make_leaf_index(capability_id.to_leaf_index())?;

        // Check if already revoked
        let old_value = self.smt.get_leaf(&key);
        if old_value != empty_value() {
            return Ok(false); // Already revoked
        }

        // Insert revocation (returns the old value, not a Result)
        let _ = self.smt.insert(key, revoked_value());

        self.revocation_count += 1;
        Ok(true)
    }

    /// Unrevoke a capability (restore access).
    ///
    /// Returns `Ok(true)` if the capability was unrevoked,
    /// `Ok(false)` if it wasn't revoked.
    pub fn unrevoke(&mut self, capability_id: &CapabilityId) -> Result<bool, Error> {
        let key = Self::make_leaf_index(capability_id.to_leaf_index())?;

        // Check if revoked
        let old_value = self.smt.get_leaf(&key);
        if old_value == empty_value() {
            return Ok(false); // Not revoked
        }

        // Remove revocation (insert empty value)
        let _ = self.smt.insert(key, empty_value());

        self.revocation_count = self.revocation_count.saturating_sub(1);
        Ok(true)
    }

    /// Generate a proof that a capability is NOT revoked.
    ///
    /// This proof can be verified against the registry root to confirm
    /// the capability's non-revoked status without trusting the registry owner.
    pub fn prove_not_revoked(
        &self,
        capability_id: &CapabilityId,
    ) -> Result<RevocationProof, Error> {
        let key_u64 = capability_id.to_leaf_index();
        let key = Self::make_leaf_index(key_u64)?;
        let proof = self.smt.open(&key);
        let value = proof.value;

        if value != empty_value() {
            return Err(Error::OperationNotPermitted(
                "capability is revoked, cannot prove non-revocation".to_string(),
            ));
        }

        Ok(RevocationProof {
            path: proof.path.clone(),
            value,
            key: key_u64,
        })
    }

    /// Generate a proof that a capability IS revoked.
    pub fn prove_revoked(&self, capability_id: &CapabilityId) -> Result<RevocationProof, Error> {
        let key_u64 = capability_id.to_leaf_index();
        let key = Self::make_leaf_index(key_u64)?;
        let proof = self.smt.open(&key);
        let value = proof.value;

        if value == empty_value() {
            return Err(Error::OperationNotPermitted(
                "capability is not revoked, cannot prove revocation".to_string(),
            ));
        }

        Ok(RevocationProof {
            path: proof.path.clone(),
            value,
            key: key_u64,
        })
    }

    /// Batch revoke multiple capabilities.
    ///
    /// This is more efficient than revoking one at a time as it can
    /// optimize tree updates.
    pub fn revoke_batch(
        &mut self,
        capability_ids: impl IntoIterator<Item = CapabilityId>,
    ) -> Result<usize, Error> {
        let mut revoked = 0;
        for id in capability_ids {
            if self.revoke(&id)? {
                revoked += 1;
            }
        }
        Ok(revoked)
    }
}

impl Default for RevocationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationProof {
    /// Verify this proof against a given root.
    ///
    /// Returns `true` if the proof is valid and shows the expected revocation status.
    pub fn verify(&self, expected_root: &Word, is_revoked: bool) -> Result<bool, Error> {
        // Check the value matches expected revocation status
        let expected_value = if is_revoked { revoked_value() } else { empty_value() };
        if self.value != expected_value {
            return Ok(false);
        }

        // Verify the Merkle path
        // The path should lead from the leaf to the expected root
        let leaf_hash = if self.value == empty_value() {
            // Empty leaf hash for SimpleSmt
            SimpleSmt::<REVOCATION_SMT_DEPTH>::EMPTY_VALUE
        } else {
            self.value
        };

        // Compute root from path
        let computed_root = self.path.compute_root(self.key, leaf_hash).map_err(|e| {
            Error::OperationNotPermitted(format!("path verification failed: {:?}", e))
        })?;

        Ok(computed_root == *expected_root)
    }

    /// Verify this is a valid non-revocation proof.
    pub fn verify_not_revoked(&self, expected_root: &Word) -> Result<bool, Error> {
        self.verify(expected_root, false)
    }

    /// Verify this is a valid revocation proof.
    pub fn verify_revoked(&self, expected_root: &Word) -> Result<bool, Error> {
        self.verify(expected_root, true)
    }
}

// ============================================================================
// Revocation Attestations - Authority-Signed Revocation State
// ============================================================================

/// An authority-signed attestation of the current revocation state.
///
/// This provides a verifiable commitment to the revocation registry state at a
/// specific point in time, signed with the authority's Falcon512 key. This
/// attestation can be:
///
/// - Posted on-chain as a signed state update
/// - Used for cross-system verification of revocation status
/// - Included in STARK proofs for trustless verification
///
/// # Structure
///
/// The attestation contains:
/// - The SMT root (cryptographic commitment to all revocation states)
/// - A timestamp for freshness verification
/// - The authority's public key for signature verification
/// - A Falcon512 signature over the root and timestamp
#[derive(Debug, Clone)]
pub struct RevocationAttestation {
    /// The SMT root being attested to
    pub root: Word,
    /// Timestamp when this attestation was created
    pub timestamp: u64,
    /// Total number of revocations at attestation time
    pub revocation_count: u64,
    /// The authority's public key
    pub authority_pk: Falcon512PublicKey,
    /// Falcon512 signature over (root || timestamp || count)
    pub signature: Falcon512Signature,
}

impl RevocationAttestation {
    /// Create a new revocation attestation for a registry state.
    ///
    /// The authority signs a commitment to:
    /// - The current SMT root
    /// - The timestamp
    /// - The revocation count
    pub fn create(
        registry: &RevocationRegistry,
        authority: &AuthorityIdentity,
        timestamp: u64,
    ) -> Self {
        let root = registry.root();
        let revocation_count = registry.revocation_count() as u64;

        // Create the message to sign: hash of (root || timestamp || count)
        let message = Self::compute_message(&root, timestamp, revocation_count);

        let signature = authority.sign(&message);

        Self {
            root,
            timestamp,
            revocation_count,
            authority_pk: authority.public_key(),
            signature,
        }
    }

    /// Compute the message to sign from components
    fn compute_message(root: &Word, timestamp: u64, revocation_count: u64) -> Word {
        // Combine all data into a hash
        let mut data = Vec::with_capacity(48); // 32 (root) + 8 + 8

        // Serialize root
        for felt in root.iter() {
            use miden_crypto::field::PrimeField64;
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        // Serialize timestamp and count
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&revocation_count.to_le_bytes());

        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }

    /// Verify this attestation's signature.
    ///
    /// Returns `true` if the signature is valid for the contained root,
    /// timestamp, and revocation count.
    pub fn verify(&self) -> bool {
        let message = Self::compute_message(&self.root, self.timestamp, self.revocation_count);
        self.authority_pk.verify(&message, &self.signature)
    }

    /// Verify this attestation against an expected authority.
    ///
    /// Checks both signature validity and that the signer matches the expected authority.
    pub fn verify_for_authority(&self, expected_authority_pk: &Falcon512PublicKey) -> bool {
        if self.authority_pk.commitment() != expected_authority_pk.commitment() {
            return false;
        }
        self.verify()
    }

    /// Get the root commitment this attestation covers.
    pub fn root_commitment(&self) -> Word {
        self.root
    }

    /// Check if this attestation is recent enough.
    pub fn is_fresh(&self, current_time: u64, max_age: u64) -> bool {
        current_time.saturating_sub(self.timestamp) <= max_age
    }
}

impl Serializable for RevocationAttestation {
    type Error = Error;

    fn length(&self) -> usize {
        // root (32) + timestamp (8) + count (8) + pk + signature
        32 + 8 + 8 + self.authority_pk.to_bytes().len() + self.signature.to_bytes().len() + 8 // length prefixes
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = 0;

        // Write root
        for felt in self.root.iter() {
            use miden_crypto::field::PrimeField64;
            n += ser.write_array(&felt.as_canonical_u64().to_le_bytes())?;
        }

        // Write timestamp and count
        n += ser.write_array(&self.timestamp.to_le_bytes())?;
        n += ser.write_array(&self.revocation_count.to_le_bytes())?;

        // Write public key
        let pk_bytes = self.authority_pk.to_bytes();
        n += ser.write_vec(&pk_bytes)?;

        // Write signature
        let sig_bytes = self.signature.to_bytes();
        n += ser.write_vec(&sig_bytes)?;

        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        // Read root
        let mut root_felts = [Felt::ZERO; 4];
        for felt in root_felts.iter_mut() {
            let bytes: [u8; 8] = de.read_array()?;
            *felt = Felt::new(u64::from_le_bytes(bytes));
        }
        let root = Word::new(root_felts);

        // Read timestamp and count
        let timestamp = u64::from_le_bytes(de.read_array()?);
        let revocation_count = u64::from_le_bytes(de.read_array()?);

        // Read public key
        let pk_bytes = de.read_vec()?;
        let authority_pk = Falcon512PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| Error::OperationNotPermitted(format!("invalid public key: {:?}", e)))?;

        // Read signature
        let sig_bytes = de.read_vec()?;
        let signature = Falcon512Signature::from_bytes(&sig_bytes)
            .map_err(|e| Error::OperationNotPermitted(format!("invalid signature: {:?}", e)))?;

        Ok(Self {
            root,
            timestamp,
            revocation_count,
            authority_pk,
            signature,
        })
    }
}

/// Combined proof of non-revocation with authority attestation.
///
/// This bundles a revocation proof with an authority attestation, providing
/// a complete package that proves:
/// 1. The revocation state is attested by a trusted authority
/// 2. A specific capability is not revoked in that state
///
/// This is useful for on-chain verification where both the authority's
/// endorsement and the specific capability status need to be verified.
#[derive(Debug, Clone)]
pub struct AttestedRevocationProof {
    /// The revocation proof (membership or non-membership)
    pub proof: RevocationProof,
    /// Authority attestation of the registry state
    pub attestation: RevocationAttestation,
}

impl AttestedRevocationProof {
    /// Create a new attested proof of non-revocation.
    pub fn prove_not_revoked(
        registry: &RevocationRegistry,
        capability_id: &CapabilityId,
        authority: &AuthorityIdentity,
        timestamp: u64,
    ) -> Result<Self, Error> {
        let proof = registry.prove_not_revoked(capability_id)?;
        let attestation = RevocationAttestation::create(registry, authority, timestamp);

        Ok(Self { proof, attestation })
    }

    /// Create a new attested proof of revocation.
    pub fn prove_revoked(
        registry: &RevocationRegistry,
        capability_id: &CapabilityId,
        authority: &AuthorityIdentity,
        timestamp: u64,
    ) -> Result<Self, Error> {
        let proof = registry.prove_revoked(capability_id)?;
        let attestation = RevocationAttestation::create(registry, authority, timestamp);

        Ok(Self { proof, attestation })
    }

    /// Verify this attested proof shows non-revocation.
    ///
    /// Verifies both:
    /// 1. The attestation signature is valid
    /// 2. The proof is valid against the attested root
    pub fn verify_not_revoked(&self) -> Result<bool, Error> {
        if !self.attestation.verify() {
            return Ok(false);
        }
        self.proof.verify_not_revoked(&self.attestation.root)
    }

    /// Verify this attested proof shows revocation.
    pub fn verify_revoked(&self) -> Result<bool, Error> {
        if !self.attestation.verify() {
            return Ok(false);
        }
        self.proof.verify_revoked(&self.attestation.root)
    }

    /// Verify against a specific expected authority.
    pub fn verify_not_revoked_for_authority(
        &self,
        expected_authority_pk: &Falcon512PublicKey,
    ) -> Result<bool, Error> {
        if !self.attestation.verify_for_authority(expected_authority_pk) {
            return Ok(false);
        }
        self.proof.verify_not_revoked(&self.attestation.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_registry_is_empty() {
        let registry = RevocationRegistry::new();
        assert_eq!(registry.revocation_count(), 0);
    }

    #[test]
    fn test_revoke_capability() {
        let mut registry = RevocationRegistry::new();
        let cap_id = CapabilityId::new(b"test-capability-1".to_vec());

        // Should not be revoked initially
        assert!(!registry.is_revoked(&cap_id).unwrap());

        // Revoke it
        let result = registry.revoke(&cap_id).unwrap();
        assert!(result); // Newly revoked
        assert!(registry.is_revoked(&cap_id).unwrap());
        assert_eq!(registry.revocation_count(), 1);

        // Revoking again should return false
        let result = registry.revoke(&cap_id).unwrap();
        assert!(!result); // Already revoked
        assert_eq!(registry.revocation_count(), 1);
    }

    #[test]
    fn test_unrevoke_capability() {
        let mut registry = RevocationRegistry::new();
        let cap_id = CapabilityId::new(b"test-capability-2".to_vec());

        // Revoke first
        registry.revoke(&cap_id).unwrap();
        assert!(registry.is_revoked(&cap_id).unwrap());

        // Unrevoke
        let result = registry.unrevoke(&cap_id).unwrap();
        assert!(result);
        assert!(!registry.is_revoked(&cap_id).unwrap());
        assert_eq!(registry.revocation_count(), 0);

        // Unrevoking again should return false
        let result = registry.unrevoke(&cap_id).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_root_changes_on_revocation() {
        let mut registry = RevocationRegistry::new();
        let initial_root = registry.root();

        let cap_id = CapabilityId::new(b"test-capability-3".to_vec());
        registry.revoke(&cap_id).unwrap();

        let new_root = registry.root();
        assert_ne!(initial_root, new_root);
    }

    #[test]
    fn test_prove_not_revoked() {
        let registry = RevocationRegistry::new();
        let cap_id = CapabilityId::new(b"test-capability-4".to_vec());
        let root = registry.root();

        // Get proof of non-revocation
        let proof = registry.prove_not_revoked(&cap_id).unwrap();

        // Verify the proof
        assert!(proof.verify_not_revoked(&root).unwrap());
        assert!(!proof.verify_revoked(&root).unwrap());
    }

    #[test]
    fn test_prove_revoked() {
        let mut registry = RevocationRegistry::new();
        let cap_id = CapabilityId::new(b"test-capability-5".to_vec());

        // Revoke first
        registry.revoke(&cap_id).unwrap();
        let root = registry.root();

        // Get proof of revocation
        let proof = registry.prove_revoked(&cap_id).unwrap();

        // Verify the proof
        assert!(proof.verify_revoked(&root).unwrap());
        assert!(!proof.verify_not_revoked(&root).unwrap());
    }

    #[test]
    fn test_prove_not_revoked_fails_for_revoked() {
        let mut registry = RevocationRegistry::new();
        let cap_id = CapabilityId::new(b"test-capability-6".to_vec());

        registry.revoke(&cap_id).unwrap();

        // Should fail to prove non-revocation
        let result = registry.prove_not_revoked(&cap_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_revoke() {
        let mut registry = RevocationRegistry::new();
        let ids: Vec<CapabilityId> = (0..10)
            .map(|i| CapabilityId::new(format!("capability-{}", i).into_bytes()))
            .collect();

        let revoked = registry.revoke_batch(ids.clone()).unwrap();
        assert_eq!(revoked, 10);
        assert_eq!(registry.revocation_count(), 10);

        // All should be revoked
        for id in &ids {
            assert!(registry.is_revoked(id).unwrap());
        }
    }

    #[test]
    fn test_proof_invalid_against_wrong_root() {
        let mut registry = RevocationRegistry::new();
        let cap_id = CapabilityId::new(b"test-capability-7".to_vec());

        // Get proof at initial state
        let proof = registry.prove_not_revoked(&cap_id).unwrap();
        let old_root = registry.root();

        // Revoke something else to change the root
        let other_id = CapabilityId::new(b"other-capability".to_vec());
        registry.revoke(&other_id).unwrap();
        let new_root = registry.root();

        // Proof should be valid against old root
        assert!(proof.verify_not_revoked(&old_root).unwrap());

        // But invalid against new root (root changed)
        assert!(!proof.verify_not_revoked(&new_root).unwrap());
    }

    #[test]
    fn test_capability_id_from_bytes() {
        let id1 = CapabilityId::from(b"test".as_slice());
        let id2 = CapabilityId::new(b"test".to_vec());
        assert_eq!(id1.as_bytes(), id2.as_bytes());
    }

    #[test]
    fn test_deterministic_leaf_index() {
        let id1 = CapabilityId::new(b"test".to_vec());
        let id2 = CapabilityId::new(b"test".to_vec());
        assert_eq!(id1.to_leaf_index(), id2.to_leaf_index());

        let id3 = CapabilityId::new(b"different".to_vec());
        assert_ne!(id1.to_leaf_index(), id3.to_leaf_index());
    }

    // ============================================================================
    // Attestation Tests
    // ============================================================================

    #[test]
    fn test_revocation_attestation_creation() {
        let registry = RevocationRegistry::new();
        let authority = AuthorityIdentity::new();
        let timestamp = 1234567890u64;

        let attestation = RevocationAttestation::create(&registry, &authority, timestamp);

        assert_eq!(attestation.root, registry.root());
        assert_eq!(attestation.timestamp, timestamp);
        assert_eq!(attestation.revocation_count, 0);
        assert!(attestation.verify());
    }

    #[test]
    fn test_revocation_attestation_verification() {
        let mut registry = RevocationRegistry::new();
        let authority = AuthorityIdentity::new();

        // Revoke some capabilities
        for i in 0..5 {
            let cap_id = CapabilityId::new(format!("cap-{}", i).into_bytes());
            registry.revoke(&cap_id).unwrap();
        }

        let attestation = RevocationAttestation::create(&registry, &authority, 1000);

        // Verify signature is valid
        assert!(attestation.verify());

        // Verify count matches
        assert_eq!(attestation.revocation_count, 5);

        // Verify against expected authority
        assert!(attestation.verify_for_authority(&authority.public_key()));

        // Verify fails against different authority
        let other_authority = AuthorityIdentity::new();
        assert!(!attestation.verify_for_authority(&other_authority.public_key()));
    }

    #[test]
    fn test_revocation_attestation_freshness() {
        let registry = RevocationRegistry::new();
        let authority = AuthorityIdentity::new();

        let attestation = RevocationAttestation::create(&registry, &authority, 1000);

        // Fresh at time 1000
        assert!(attestation.is_fresh(1000, 100));

        // Fresh at time 1050 with max age 100
        assert!(attestation.is_fresh(1050, 100));

        // Not fresh at time 1200 with max age 100
        assert!(!attestation.is_fresh(1200, 100));
    }

    #[test]
    fn test_revocation_attestation_serialization() {
        let mut registry = RevocationRegistry::new();
        let cap_id = CapabilityId::new(b"test-cap".to_vec());
        registry.revoke(&cap_id).unwrap();

        let authority = AuthorityIdentity::new();
        let attestation = RevocationAttestation::create(&registry, &authority, 12345);

        // Serialize
        let bytes = attestation.serialize().expect("serialization failed");
        assert!(!bytes.is_empty());

        // Deserialize
        let restored = RevocationAttestation::deserialize(&bytes).expect("deserialization failed");

        // Verify same data
        assert_eq!(attestation.root, restored.root);
        assert_eq!(attestation.timestamp, restored.timestamp);
        assert_eq!(attestation.revocation_count, restored.revocation_count);

        // Verify restored attestation is still valid
        assert!(restored.verify());
    }

    #[test]
    fn test_attested_revocation_proof_not_revoked() {
        let registry = RevocationRegistry::new();
        let authority = AuthorityIdentity::new();
        let cap_id = CapabilityId::new(b"test-capability".to_vec());

        let attested_proof =
            AttestedRevocationProof::prove_not_revoked(&registry, &cap_id, &authority, 1000)
                .unwrap();

        // Verify the complete proof
        assert!(attested_proof.verify_not_revoked().unwrap());
        assert!(!attested_proof.verify_revoked().unwrap());

        // Verify against specific authority
        assert!(
            attested_proof
                .verify_not_revoked_for_authority(&authority.public_key())
                .unwrap()
        );
    }

    #[test]
    fn test_attested_revocation_proof_revoked() {
        let mut registry = RevocationRegistry::new();
        let authority = AuthorityIdentity::new();
        let cap_id = CapabilityId::new(b"test-capability".to_vec());

        // Revoke the capability
        registry.revoke(&cap_id).unwrap();

        let attested_proof =
            AttestedRevocationProof::prove_revoked(&registry, &cap_id, &authority, 1000).unwrap();

        // Verify the complete proof
        assert!(attested_proof.verify_revoked().unwrap());
        assert!(!attested_proof.verify_not_revoked().unwrap());
    }

    #[test]
    fn test_attested_proof_fails_wrong_authority() {
        let registry = RevocationRegistry::new();
        let authority = AuthorityIdentity::new();
        let other_authority = AuthorityIdentity::new();
        let cap_id = CapabilityId::new(b"test-capability".to_vec());

        let attested_proof =
            AttestedRevocationProof::prove_not_revoked(&registry, &cap_id, &authority, 1000)
                .unwrap();

        // Should fail verification against different authority
        assert!(
            !attested_proof
                .verify_not_revoked_for_authority(&other_authority.public_key())
                .unwrap()
        );
    }
}
