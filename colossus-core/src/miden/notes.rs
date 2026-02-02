//! Miden Note Types for Colossus
//!
//! This module defines note types that represent Colossus access control primitives
//! in a format suitable for on-chain storage and STARK proof verification.
//!
//! # Design Principles
//!
//! 1. **Word-aligned**: All data structures are aligned to Miden's Word (4 Felt elements)
//! 2. **Poseidon2-compatible**: All commitments use Poseidon2 for STARK verification
//! 3. **Minimal on-chain footprint**: Store commitments, not full data
//! 4. **Version-tagged**: Support for future format evolution

use crate::access_control::{
    AuthorityIdentity, CapabilityAttestation, DelegationCertificate, RevocationAttestation,
};
use crate::crypto::{Falcon512Signature, Felt, Poseidon2Hash, Word};
use crate::policy::Error;
use miden_crypto::field::{PrimeCharacteristicRing, PrimeField64};

/// Note type discriminator stored in the first element of metadata
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteType {
    /// Capability token with authority attestation
    Capability = 1,
    /// Revocation registry state commitment
    Revocation = 2,
    /// Authority identity attestation
    Attestation = 3,
    /// Delegation certificate between authorities
    Delegation = 4,
}

impl NoteType {
    /// Convert to Felt for on-chain storage
    pub fn to_felt(self) -> Felt {
        Felt::new(self as u64)
    }

    /// Parse from Felt
    pub fn from_felt(felt: Felt) -> Option<Self> {
        match felt.as_canonical_u64() {
            1 => Some(NoteType::Capability),
            2 => Some(NoteType::Revocation),
            3 => Some(NoteType::Attestation),
            4 => Some(NoteType::Delegation),
            _ => None,
        }
    }
}

/// Current note format version
pub const NOTE_VERSION: u8 = 1;

/// Common metadata for all note types.
///
/// Stored as the first Word of every note for self-description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteMetadata {
    /// Type of note (discriminator)
    pub note_type: NoteType,
    /// Format version for forward compatibility
    pub version: u8,
    /// Creation timestamp (Unix epoch seconds)
    pub created_at: u64,
    /// Application-specific tag (e.g., for filtering)
    pub tag: u32,
}

impl NoteMetadata {
    /// Create new metadata with current version
    pub fn new(note_type: NoteType, created_at: u64) -> Self {
        Self {
            note_type,
            version: NOTE_VERSION,
            created_at,
            tag: 0,
        }
    }

    /// Create with custom tag
    pub fn with_tag(mut self, tag: u32) -> Self {
        self.tag = tag;
        self
    }

    /// Serialize to a Word
    pub fn to_word(&self) -> Word {
        Word::new([
            Felt::new(self.note_type as u64),
            Felt::new(self.version as u64),
            Felt::new(self.created_at),
            Felt::new(self.tag as u64),
        ])
    }

    /// Deserialize from a Word
    pub fn from_word(word: &Word) -> Result<Self, Error> {
        let note_type = NoteType::from_felt(word[0])
            .ok_or_else(|| Error::OperationNotPermitted("invalid note type".into()))?;

        Ok(Self {
            note_type,
            version: word[1].as_canonical_u64() as u8,
            created_at: word[2].as_canonical_u64(),
            tag: word[3].as_canonical_u64() as u32,
        })
    }
}

// ============================================================================
// Capability Note
// ============================================================================

/// On-chain representation of a capability token with authority attestation.
///
/// This note stores the essential data needed to verify a capability on-chain:
/// - The token commitment (Poseidon2 hash of the full token)
/// - The authority's public key commitment
/// - A hash of the granted rights
/// - Expiration timestamp
/// - The authority's Falcon512 signature
///
/// The full token data is stored off-chain; this note provides the on-chain
/// anchor for verification.
///
/// # Size
///
/// Total: 6 Words (24 Felt elements)
/// - 1 Word: Metadata
/// - 1 Word: Token commitment
/// - 1 Word: Authority public key commitment  
/// - 1 Word: Rights hash
/// - 1 Word: Expiration + reserved
/// - Variable: Signature (stored as commitment)
#[derive(Debug, Clone)]
pub struct CapabilityNote {
    /// Note metadata (type, version, timestamp)
    pub metadata: NoteMetadata,
    /// Poseidon2 commitment to the full capability token
    pub token_commitment: Word,
    /// Poseidon2 commitment to the authority's Falcon512 public key
    pub authority_pk_commitment: Word,
    /// Poseidon2 hash of the granted access rights
    pub rights_hash: Word,
    /// Expiration timestamp (0 = never expires)
    pub expires_at: u64,
    /// Poseidon2 commitment to the Falcon512 signature
    pub signature_commitment: Word,
}

impl CapabilityNote {
    /// Create a capability note from an attestation.
    pub fn from_attestation(attestation: &CapabilityAttestation, expires_at: u64) -> Self {
        Self {
            metadata: NoteMetadata::new(NoteType::Capability, attestation.timestamp),
            token_commitment: attestation.token_commitment,
            authority_pk_commitment: attestation.authority_pk.commitment(),
            rights_hash: Self::compute_signature_commitment(&attestation.signature),
            expires_at,
            signature_commitment: Self::compute_signature_commitment(&attestation.signature),
        }
    }

    /// Compute Poseidon2 commitment to a signature
    fn compute_signature_commitment(signature: &Falcon512Signature) -> Word {
        let sig_bytes = signature.to_bytes();
        Poseidon2Hash::hash_bytes(&sig_bytes).as_word().clone()
    }

    /// Check if this capability has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expires_at != 0 && current_time > self.expires_at
    }

    /// Serialize to Words for on-chain storage
    pub fn to_words(&self) -> Vec<Word> {
        vec![
            self.metadata.to_word(),
            self.token_commitment,
            self.authority_pk_commitment,
            self.rights_hash,
            Word::new([Felt::new(self.expires_at), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            self.signature_commitment,
        ]
    }

    /// Deserialize from Words
    pub fn from_words(words: &[Word]) -> Result<Self, Error> {
        if words.len() < 6 {
            return Err(Error::OperationNotPermitted(
                "insufficient words for CapabilityNote".into(),
            ));
        }

        let metadata = NoteMetadata::from_word(&words[0])?;
        if metadata.note_type != NoteType::Capability {
            return Err(Error::OperationNotPermitted("wrong note type for CapabilityNote".into()));
        }

        Ok(Self {
            metadata,
            token_commitment: words[1],
            authority_pk_commitment: words[2],
            rights_hash: words[3],
            expires_at: words[4][0].as_canonical_u64(),
            signature_commitment: words[5],
        })
    }

    /// Compute the note's unique identifier (hash of all data)
    pub fn note_id(&self) -> Word {
        let mut data = Vec::new();
        for word in self.to_words() {
            for felt in word.iter() {
                data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
            }
        }
        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }
}

// ============================================================================
// Revocation Note
// ============================================================================

/// On-chain commitment to a revocation registry state.
///
/// This note stores the SMT root and metadata signed by an authority,
/// allowing on-chain verification of revocation status without storing
/// the full registry.
///
/// # Verification Flow
///
/// 1. Client provides a Merkle proof against the on-chain SMT root
/// 2. Smart contract verifies the proof in STARK
/// 3. If the leaf is empty, the capability is not revoked
///
/// # Size
///
/// Total: 5 Words (20 Felt elements)
/// - 1 Word: Metadata
/// - 1 Word: SMT root
/// - 1 Word: Authority public key commitment
/// - 1 Word: Count + reserved
/// - 1 Word: Signature commitment
#[derive(Debug, Clone)]
pub struct RevocationNote {
    /// Note metadata
    pub metadata: NoteMetadata,
    /// SMT root (commitment to all revocation states)
    pub smt_root: Word,
    /// Authority's public key commitment
    pub authority_pk_commitment: Word,
    /// Number of revoked capabilities at this state
    pub revocation_count: u64,
    /// Poseidon2 commitment to the authority's signature
    pub signature_commitment: Word,
}

impl RevocationNote {
    /// Create a revocation note from an attestation
    pub fn from_attestation(attestation: &RevocationAttestation) -> Self {
        let sig_bytes = attestation.signature.to_bytes();
        let signature_commitment = Poseidon2Hash::hash_bytes(&sig_bytes).as_word().clone();

        Self {
            metadata: NoteMetadata::new(NoteType::Revocation, attestation.timestamp),
            smt_root: attestation.root,
            authority_pk_commitment: attestation.authority_pk.commitment(),
            revocation_count: attestation.revocation_count,
            signature_commitment,
        }
    }

    /// Serialize to Words
    pub fn to_words(&self) -> Vec<Word> {
        vec![
            self.metadata.to_word(),
            self.smt_root,
            self.authority_pk_commitment,
            Word::new([Felt::new(self.revocation_count), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            self.signature_commitment,
        ]
    }

    /// Deserialize from Words
    pub fn from_words(words: &[Word]) -> Result<Self, Error> {
        if words.len() < 5 {
            return Err(Error::OperationNotPermitted(
                "insufficient words for RevocationNote".into(),
            ));
        }

        let metadata = NoteMetadata::from_word(&words[0])?;
        if metadata.note_type != NoteType::Revocation {
            return Err(Error::OperationNotPermitted("wrong note type for RevocationNote".into()));
        }

        Ok(Self {
            metadata,
            smt_root: words[1],
            authority_pk_commitment: words[2],
            revocation_count: words[3][0].as_canonical_u64(),
            signature_commitment: words[4],
        })
    }

    /// Compute the note's unique identifier
    pub fn note_id(&self) -> Word {
        let mut data = Vec::new();
        for word in self.to_words() {
            for felt in word.iter() {
                data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
            }
        }
        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }
}

// ============================================================================
// Attestation Note
// ============================================================================

/// On-chain authority identity attestation.
///
/// This note registers an authority's identity on-chain, providing:
/// - A verifiable anchor for the authority's public key
/// - Self-attestation proving control of the private key
/// - Optional metadata commitment (e.g., organization name)
///
/// # Use Cases
///
/// - Register a new capability authority on-chain
/// - Update authority metadata
/// - Prove authority identity for cross-chain verification
///
/// # Size
///
/// Total: 5 Words
/// - 1 Word: Metadata
/// - 1 Word: Authority public key commitment
/// - 1 Word: Metadata hash (organization info, etc.)
/// - 1 Word: Self-attestation timestamp + reserved
/// - 1 Word: Self-attestation signature commitment
#[derive(Debug, Clone)]
pub struct AttestationNote {
    /// Note metadata
    pub metadata: NoteMetadata,
    /// Authority's Falcon512 public key commitment
    pub authority_pk_commitment: Word,
    /// Poseidon2 hash of authority metadata (name, org, etc.)
    pub metadata_hash: Word,
    /// Timestamp used in self-attestation
    pub attestation_timestamp: u64,
    /// Commitment to self-attestation signature
    pub self_attestation_commitment: Word,
}

impl AttestationNote {
    /// Create an attestation note from an authority identity
    pub fn from_identity(identity: &AuthorityIdentity, created_at: u64) -> Self {
        let metadata_hash = if identity.metadata().is_empty() {
            Word::new([Felt::ZERO; 4])
        } else {
            Poseidon2Hash::hash_bytes(identity.metadata()).as_word().clone()
        };

        let self_attestation_commitment = identity
            .self_attestation()
            .map(|sig| {
                let sig_bytes = sig.to_bytes();
                Poseidon2Hash::hash_bytes(&sig_bytes).as_word().clone()
            })
            .unwrap_or_else(|| Word::new([Felt::ZERO; 4]));

        Self {
            metadata: NoteMetadata::new(NoteType::Attestation, created_at),
            authority_pk_commitment: identity.commitment(),
            metadata_hash,
            attestation_timestamp: created_at,
            self_attestation_commitment,
        }
    }

    /// Serialize to Words
    pub fn to_words(&self) -> Vec<Word> {
        vec![
            self.metadata.to_word(),
            self.authority_pk_commitment,
            self.metadata_hash,
            Word::new([Felt::new(self.attestation_timestamp), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            self.self_attestation_commitment,
        ]
    }

    /// Deserialize from Words
    pub fn from_words(words: &[Word]) -> Result<Self, Error> {
        if words.len() < 5 {
            return Err(Error::OperationNotPermitted(
                "insufficient words for AttestationNote".into(),
            ));
        }

        let metadata = NoteMetadata::from_word(&words[0])?;
        if metadata.note_type != NoteType::Attestation {
            return Err(Error::OperationNotPermitted("wrong note type for AttestationNote".into()));
        }

        Ok(Self {
            metadata,
            authority_pk_commitment: words[1],
            metadata_hash: words[2],
            attestation_timestamp: words[3][0].as_canonical_u64(),
            self_attestation_commitment: words[4],
        })
    }

    /// Compute the note's unique identifier
    pub fn note_id(&self) -> Word {
        let mut data = Vec::new();
        for word in self.to_words() {
            for felt in word.iter() {
                data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
            }
        }
        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }
}

// ============================================================================
// Delegation Note
// ============================================================================

/// On-chain delegation certificate.
///
/// This note records a delegation of authority from one entity to another,
/// creating a verifiable chain of trust that can be validated on-chain.
///
/// # Delegation Chain
///
/// ```text
/// Root Authority → Intermediate → Leaf
///      │                │           │
///      └─ DelegationNote─┘           │
///                        └─ DelegationNote
/// ```
///
/// # Size
///
/// Total: 6 Words
/// - 1 Word: Metadata
/// - 1 Word: Delegator public key commitment
/// - 1 Word: Delegatee public key commitment
/// - 1 Word: Scope hash (what powers are delegated)
/// - 1 Word: Expiration + reserved
/// - 1 Word: Signature commitment
#[derive(Debug, Clone)]
pub struct DelegationNote {
    /// Note metadata
    pub metadata: NoteMetadata,
    /// Delegator's public key commitment (the one granting authority)
    pub delegator_pk_commitment: Word,
    /// Delegatee's public key commitment (the one receiving authority)
    pub delegatee_pk_commitment: Word,
    /// Hash of the delegation scope (Full, Rights, or Structure)
    pub scope_hash: Word,
    /// Expiration timestamp (0 = never expires)
    pub expires_at: u64,
    /// Commitment to the delegation signature
    pub signature_commitment: Word,
}

impl DelegationNote {
    /// Create a delegation note from a certificate
    pub fn from_certificate(cert: &DelegationCertificate, created_at: u64) -> Self {
        let scope_bytes = cert.scope.to_bytes();
        let scope_hash = Poseidon2Hash::hash_bytes(&scope_bytes).as_word().clone();

        let sig_bytes = cert.signature.to_bytes();
        let signature_commitment = Poseidon2Hash::hash_bytes(&sig_bytes).as_word().clone();

        Self {
            metadata: NoteMetadata::new(NoteType::Delegation, created_at),
            delegator_pk_commitment: cert.delegator_pk.commitment(),
            delegatee_pk_commitment: cert.delegatee_pk.commitment(),
            scope_hash,
            expires_at: cert.valid_until.unwrap_or(0),
            signature_commitment,
        }
    }

    /// Check if this delegation has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expires_at != 0 && current_time > self.expires_at
    }

    /// Serialize to Words
    pub fn to_words(&self) -> Vec<Word> {
        vec![
            self.metadata.to_word(),
            self.delegator_pk_commitment,
            self.delegatee_pk_commitment,
            self.scope_hash,
            Word::new([Felt::new(self.expires_at), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            self.signature_commitment,
        ]
    }

    /// Deserialize from Words
    pub fn from_words(words: &[Word]) -> Result<Self, Error> {
        if words.len() < 6 {
            return Err(Error::OperationNotPermitted(
                "insufficient words for DelegationNote".into(),
            ));
        }

        let metadata = NoteMetadata::from_word(&words[0])?;
        if metadata.note_type != NoteType::Delegation {
            return Err(Error::OperationNotPermitted("wrong note type for DelegationNote".into()));
        }

        Ok(Self {
            metadata,
            delegator_pk_commitment: words[1],
            delegatee_pk_commitment: words[2],
            scope_hash: words[3],
            expires_at: words[4][0].as_canonical_u64(),
            signature_commitment: words[5],
        })
    }

    /// Compute the note's unique identifier
    pub fn note_id(&self) -> Word {
        let mut data = Vec::new();
        for word in self.to_words() {
            for felt in word.iter() {
                data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
            }
        }
        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_control::{
        AuthorityIdentity, CapabilityAuthority, DelegationScope, RevocationRegistry,
        capability::{create_unsafe_capability_token, update_capability_authority},
        cryptography::MIN_TRACING_LEVEL,
    };
    use crate::policy::{AttributeStatus, Right};
    use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_note_metadata_roundtrip() {
        let metadata = NoteMetadata::new(NoteType::Capability, 1234567890).with_tag(42);

        let word = metadata.to_word();
        let restored = NoteMetadata::from_word(&word).unwrap();

        assert_eq!(metadata.note_type, restored.note_type);
        assert_eq!(metadata.version, restored.version);
        assert_eq!(metadata.created_at, restored.created_at);
        assert_eq!(metadata.tag, restored.tag);
    }

    #[test]
    fn test_note_type_conversion() {
        for note_type in [
            NoteType::Capability,
            NoteType::Revocation,
            NoteType::Attestation,
            NoteType::Delegation,
        ] {
            let felt = note_type.to_felt();
            let restored = NoteType::from_felt(felt).unwrap();
            assert_eq!(note_type, restored);
        }

        // Invalid type should return None
        assert!(NoteType::from_felt(Felt::new(99)).is_none());
    }

    #[test]
    fn test_capability_note_roundtrip() {
        let mut rng = CsRng::from_entropy();
        let right = Right::random(&mut rng);

        // Create authority with identity
        let mut auth =
            CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap().with_identity();

        update_capability_authority(
            &mut rng,
            &mut auth,
            HashMap::from([(right.clone(), AttributeStatus::EncryptDecrypt)]),
        )
        .unwrap();

        // Create token and attestation
        let token =
            create_unsafe_capability_token(&mut rng, &mut auth, HashSet::from([right])).unwrap();

        let attestation = auth.attest_token(&token, 1000).unwrap().unwrap();

        // Create note
        let note = CapabilityNote::from_attestation(&attestation, 2000);
        assert!(!note.is_expired(1500));
        assert!(note.is_expired(2500));

        // Roundtrip through Words
        let words = note.to_words();
        assert_eq!(words.len(), 6);

        let restored = CapabilityNote::from_words(&words).unwrap();
        assert_eq!(note.metadata.note_type, restored.metadata.note_type);
        assert_eq!(note.token_commitment, restored.token_commitment);
        assert_eq!(note.authority_pk_commitment, restored.authority_pk_commitment);
        assert_eq!(note.expires_at, restored.expires_at);
    }

    #[test]
    fn test_revocation_note_roundtrip() {
        let mut registry = RevocationRegistry::new();
        let authority = AuthorityIdentity::new();

        // Revoke some capabilities
        for i in 0..3 {
            let cap_id = crate::access_control::revocation::CapabilityId::new(
                format!("cap-{}", i).into_bytes(),
            );
            registry.revoke(&cap_id).unwrap();
        }

        // Create attestation and note
        let attestation = RevocationAttestation::create(&registry, &authority, 1000);
        let note = RevocationNote::from_attestation(&attestation);

        // Roundtrip
        let words = note.to_words();
        assert_eq!(words.len(), 5);

        let restored = RevocationNote::from_words(&words).unwrap();
        assert_eq!(note.smt_root, restored.smt_root);
        assert_eq!(note.revocation_count, restored.revocation_count);
        assert_eq!(note.authority_pk_commitment, restored.authority_pk_commitment);
    }

    #[test]
    fn test_attestation_note_roundtrip() {
        let mut identity = AuthorityIdentity::new().with_metadata(b"Test Authority");
        identity.create_self_attestation(1000);

        let note = AttestationNote::from_identity(&identity, 1000);

        // Roundtrip
        let words = note.to_words();
        assert_eq!(words.len(), 5);

        let restored = AttestationNote::from_words(&words).unwrap();
        assert_eq!(note.authority_pk_commitment, restored.authority_pk_commitment);
        assert_eq!(note.metadata_hash, restored.metadata_hash);
        assert_eq!(note.attestation_timestamp, restored.attestation_timestamp);
    }

    #[test]
    fn test_delegation_note_roundtrip() {
        let delegator = AuthorityIdentity::new();
        let delegatee = AuthorityIdentity::new();

        let cert =
            delegator.delegate(&delegatee.public_key(), DelegationScope::Full, Some(2000000));

        let note = DelegationNote::from_certificate(&cert, 1000);
        assert!(!note.is_expired(1500000));
        assert!(note.is_expired(3000000));

        // Roundtrip
        let words = note.to_words();
        assert_eq!(words.len(), 6);

        let restored = DelegationNote::from_words(&words).unwrap();
        assert_eq!(note.delegator_pk_commitment, restored.delegator_pk_commitment);
        assert_eq!(note.delegatee_pk_commitment, restored.delegatee_pk_commitment);
        assert_eq!(note.scope_hash, restored.scope_hash);
        assert_eq!(note.expires_at, restored.expires_at);
    }

    #[test]
    fn test_note_ids_are_unique() {
        let authority1 = AuthorityIdentity::new();
        let authority2 = AuthorityIdentity::new();

        let note1 = AttestationNote::from_identity(&authority1, 1000);
        let note2 = AttestationNote::from_identity(&authority2, 1000);

        // Different authorities should have different note IDs
        assert_ne!(note1.note_id(), note2.note_id());

        // Same authority, different timestamp should have different note IDs
        let note3 = AttestationNote::from_identity(&authority1, 2000);
        assert_ne!(note1.note_id(), note3.note_id());
    }

    #[test]
    fn test_wrong_note_type_rejected() {
        let metadata = NoteMetadata::new(NoteType::Capability, 1000);
        let words = vec![
            metadata.to_word(),
            Word::new([Felt::ZERO; 4]),
            Word::new([Felt::ZERO; 4]),
            Word::new([Felt::ZERO; 4]),
            Word::new([Felt::ZERO; 4]),
        ];

        // Trying to parse a Capability note as Revocation should fail
        let result = RevocationNote::from_words(&words);
        assert!(result.is_err());
    }
}
