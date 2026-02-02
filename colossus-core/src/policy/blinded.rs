//! Privacy-Preserving Blinded Attribute System
//!
//! This module provides a Poseidon2-based commitment scheme for attributes that:
//!
//! - **Hides** the actual attribute value and dimension from observers
//! - **Binds** attributes cryptographically to their Issuer and CapabilityAuthority
//! - **Enables** zero-knowledge proofs of attribute ownership
//! - **Prevents** cross-issuer/authority linkability through fresh randomness
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                     Blinded Attribute Commitment                             │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │  Plaintext Attribute                    Blinded Attribute                   │
//! │  ─────────────────────                  ─────────────────                   │
//! │  dimension: "Security"                                                       │
//! │  name: "TopSecret"        ──────►      commitment: Word                     │
//! │  issuer_pk: Word                        (Poseidon2 hash)                    │
//! │  authority_pk: Word                                                          │
//! │  salt: Word (random)                                                         │
//! │                                                                              │
//! │  ┌─────────────────────────────────────────────────────────────────────┐    │
//! │  │  commitment = Poseidon2(attr_scalar || issuer_pk || authority_pk || salt)│
//! │  └─────────────────────────────────────────────────────────────────────┘    │
//! │                                                                              │
//! │  Properties:                                                                 │
//! │  • Same attribute + different salt = different commitment (unlinkable)      │
//! │  • Same attribute + different issuer = different commitment (issuer-bound)  │
//! │  • Same attribute + different authority = different commitment (auth-bound) │
//! │  • Only preimage holder can prove ownership (STARK-verifiable)              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Model
//!
//! - **Hiding**: Poseidon2 is a one-way function; commitment reveals nothing about inputs
//! - **Binding**: Computationally binding; finding collisions is infeasible
//! - **Unlinkability**: Fresh salt per commitment prevents correlation attacks
//! - **Post-Quantum**: Hash-based, no reliance on discrete logarithm assumptions
//!
//! # Usage
//!
//! ```ignore
//! use colossus_core::policy::blinded::{BlindedAttribute, AttributePreimage};
//!
//! // Issuer creates a blinded attribute
//! let (blinded, preimage) = BlindedAttribute::commit(
//!     "Security",
//!     "TopSecret",
//!     &issuer_pk,
//!     &authority_pk,
//! );
//!
//! // Later, issuer can prove ownership
//! assert!(preimage.verify(&blinded.commitment));
//!
//! // The commitment can be shared publicly without revealing the attribute
//! println!("Blinded attribute: {:?}", blinded.commitment);
//! ```

use crate::crypto::{Felt, Poseidon2Hash, Word};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};
use miden_crypto::field::{PrimeCharacteristicRing, PrimeField64};
use rand::Rng;
use std::fmt;

use super::Error;

// ============================================================================
// Domain Separators
// ============================================================================

/// Domain separator for attribute scalar derivation
const ATTR_SCALAR_DOMAIN: &[u8] = b"COLOSSUS-ATTR-SCALAR-V1";

/// Domain separator for dimension commitment
const DIM_COMMIT_DOMAIN: &[u8] = b"COLOSSUS-DIM-COMMIT-V1";

/// Domain separator for blinded attribute commitment
const BLINDED_ATTR_DOMAIN: &[u8] = b"COLOSSUS-BLINDED-ATTR-V1";

// ============================================================================
// BlindedAttribute
// ============================================================================

/// A privacy-preserving blinded attribute identifier.
///
/// This replaces the deterministic `ATTRIBUTE` (which is just `SHA3(dim||name)`)
/// with a randomized commitment that:
///
/// - Hides the actual attribute value
/// - Is bound to a specific Issuer and CapabilityAuthority
/// - Is unlinkable across different usages (due to fresh salt)
///
/// The commitment is computed as:
/// ```text
/// commitment = Poseidon2(domain || attr_scalar || issuer_pk || authority_pk || salt)
/// ```
///
/// Where:
/// - `domain` = domain separator constant
/// - `attr_scalar` = Poseidon2(ATTR_DOMAIN || dimension || "::" || attribute_name)[0]
/// - `issuer_pk` = Issuer's Falcon512 public key commitment (4 field elements)
/// - `authority_pk` = CapabilityAuthority's identity commitment (4 field elements)
/// - `salt` = Fresh random value (4 field elements)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlindedAttribute {
    /// The Poseidon2 commitment (4 field elements = 256 bits)
    commitment: Word,
    /// Cached byte representation for efficient digest access
    commitment_bytes: [u8; 32],
}

impl BlindedAttribute {
    /// Create a new blinded attribute commitment.
    ///
    /// This generates a fresh random salt and computes the Poseidon2 commitment
    /// binding the attribute to the specified issuer and authority.
    ///
    /// # Arguments
    ///
    /// * `dimension` - The dimension name (e.g., "Security", "Department")
    /// * `attribute_name` - The attribute value (e.g., "TopSecret", "Engineering")
    /// * `issuer_pk` - The issuer's Falcon512 public key commitment
    /// * `authority_pk` - The CapabilityAuthority's identity commitment
    ///
    /// # Returns
    ///
    /// A tuple of (BlindedAttribute, AttributePreimage) where the preimage
    /// must be kept secret by the issuer for proving ownership.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (blinded, preimage) = BlindedAttribute::commit(
    ///     "Security",
    ///     "TopSecret",
    ///     &issuer.commitment(),
    ///     &authority.commitment(),
    /// );
    /// ```
    pub fn commit(
        dimension: &str,
        attribute_name: &str,
        issuer_pk: &Word,
        authority_pk: &Word,
    ) -> (Self, AttributePreimage) {
        // Generate fresh random salt
        let salt = Self::generate_salt();

        Self::commit_with_salt(dimension, attribute_name, issuer_pk, authority_pk, salt)
    }

    /// Create a blinded attribute with a specific salt.
    ///
    /// This is useful for:
    /// - Deterministic testing
    /// - Re-creating a commitment from stored preimage
    /// - Deriving salts from shared secrets (for deterministic registration)
    pub fn commit_with_salt(
        dimension: &str,
        attribute_name: &str,
        issuer_pk: &Word,
        authority_pk: &Word,
        salt: Word,
    ) -> (Self, AttributePreimage) {
        // Step 1: Derive attribute scalar from dimension and name
        let attr_scalar = Self::derive_attr_scalar(dimension, attribute_name);

        // Step 2: Create preimage structure
        let preimage = AttributePreimage {
            attr_scalar,
            issuer_pk: *issuer_pk,
            authority_pk: *authority_pk,
            salt,
            // Store plaintext for debugging/logging (optional, can be removed in production)
            #[cfg(debug_assertions)]
            dimension: dimension.to_string(),
            #[cfg(debug_assertions)]
            attribute_name: attribute_name.to_string(),
        };

        // Step 3: Compute commitment
        let commitment = preimage.compute_commitment();
        let commitment_bytes = Self::word_to_bytes(&commitment);

        (Self { commitment, commitment_bytes }, preimage)
    }

    /// Convert a Word to a 32-byte array.
    fn word_to_bytes(word: &Word) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, felt) in word.iter().enumerate() {
            let felt_bytes = felt.as_canonical_u64().to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&felt_bytes);
        }
        bytes
    }

    /// Create a BlindedAttribute from an existing commitment.
    ///
    /// Use this when deserializing or receiving a commitment from external sources.
    pub fn from_commitment(commitment: Word) -> Self {
        let commitment_bytes = Self::word_to_bytes(&commitment);
        Self { commitment, commitment_bytes }
    }

    /// Get the commitment value.
    pub fn commitment(&self) -> &Word {
        &self.commitment
    }

    /// Get the commitment as a byte slice reference.
    ///
    /// This is the primary method for accessing the commitment bytes efficiently.
    /// Used by the DAC `Attribute` trait implementation.
    pub fn commitment_bytes(&self) -> &[u8] {
        &self.commitment_bytes
    }

    /// Get the commitment as an owned byte vector (for storage/transmission).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.commitment_bytes.to_vec()
    }

    /// Get the commitment as an ATTRIBUTE type (for DAC compatibility).
    ///
    /// This allows `BlindedAttribute` to be used in contexts that expect
    /// attribute bytes for credential building and verification.
    pub fn bytes(&self) -> crate::policy::attribute::ATTRIBUTE {
        crate::policy::attribute::ATTRIBUTE::from(self.commitment_bytes.to_vec())
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 32 {
            return Err(Error::ConversionFailed(
                "BlindedAttribute requires at least 32 bytes".into(),
            ));
        }

        let mut felts = [Felt::ZERO; 4];
        let mut commitment_bytes = [0u8; 32];
        for i in 0..4 {
            let offset = i * 8;
            let value = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            felts[i] = Felt::new(value);
            commitment_bytes[offset..offset + 8].copy_from_slice(&bytes[offset..offset + 8]);
        }

        Ok(Self {
            commitment: Word::new(felts),
            commitment_bytes,
        })
    }

    /// Derive the attribute scalar from dimension and attribute name.
    ///
    /// This creates a deterministic scalar representation of the plaintext attribute
    /// that will be part of the commitment preimage.
    ///
    /// ```text
    /// attr_scalar = Poseidon2(ATTR_SCALAR_DOMAIN || dimension || "::" || name)[0]
    /// ```
    fn derive_attr_scalar(dimension: &str, attribute_name: &str) -> Felt {
        let input =
            [ATTR_SCALAR_DOMAIN, dimension.as_bytes(), b"::", attribute_name.as_bytes()].concat();

        Poseidon2Hash::hash_bytes(&input).elements()[0]
    }

    /// Generate cryptographically secure random salt.
    fn generate_salt() -> Word {
        let mut rng = rand::rng();
        Word::new([
            Felt::new(rng.random()),
            Felt::new(rng.random()),
            Felt::new(rng.random()),
            Felt::new(rng.random()),
        ])
    }
}

impl fmt::Debug for BlindedAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only show first 8 hex chars of commitment for readability
        let bytes = self.to_bytes();
        let hex: String = bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect();
        write!(f, "BlindedAttribute({}...)", hex)
    }
}

impl fmt::Display for BlindedAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Full hex representation
        let bytes = self.to_bytes();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        write!(f, "{}", hex)
    }
}

// ============================================================================
// AttributePreimage
// ============================================================================

/// The secret preimage for a BlindedAttribute commitment.
///
/// This structure contains all the inputs needed to compute a blinded attribute
/// commitment. It must be kept secret by the issuer to:
///
/// - Prove ownership of the blinded attribute
/// - Recreate the commitment for verification
/// - Generate zero-knowledge proofs
///
/// # Fields
///
/// - `attr_scalar`: Derived from dimension and attribute name
/// - `issuer_pk`: The issuer's public key commitment (binds to issuer)
/// - `authority_pk`: The authority's public key commitment (binds to authority)
/// - `salt`: Fresh randomness (provides unlinkability)
///
/// # Security
///
/// - Never share this structure publicly
/// - Store securely (encrypted at rest)
/// - Use only for generating proofs
#[derive(Clone)]
pub struct AttributePreimage {
    /// Scalar derived from H(dimension || "::" || attribute_name)
    pub attr_scalar: Felt,
    /// Issuer's public key commitment (4 field elements)
    pub issuer_pk: Word,
    /// CapabilityAuthority's identity commitment (4 field elements)
    pub authority_pk: Word,
    /// Fresh randomness for unlinkability (4 field elements)
    pub salt: Word,

    // Debug-only fields for logging/tracing
    #[cfg(debug_assertions)]
    dimension: String,
    #[cfg(debug_assertions)]
    attribute_name: String,
}

impl AttributePreimage {
    /// Create a preimage directly (for advanced use cases).
    ///
    /// Prefer using `BlindedAttribute::commit()` which handles salt generation.
    pub fn new(attr_scalar: Felt, issuer_pk: Word, authority_pk: Word, salt: Word) -> Self {
        Self {
            attr_scalar,
            issuer_pk,
            authority_pk,
            salt,
            #[cfg(debug_assertions)]
            dimension: String::new(),
            #[cfg(debug_assertions)]
            attribute_name: String::new(),
        }
    }

    /// Compute the commitment from this preimage.
    ///
    /// ```text
    /// commitment = Poseidon2(domain || attr_scalar || issuer_pk || authority_pk || salt)
    /// ```
    pub fn compute_commitment(&self) -> Word {
        // Build the input elements
        // Total: 1 (domain hash) + 1 (attr_scalar) + 4 (issuer_pk) + 4 (authority_pk) + 4 (salt) = 14 elements
        let mut elements = Vec::with_capacity(14);

        // Domain separator (hash the domain bytes to a single element)
        let domain_felt = Poseidon2Hash::hash_bytes(BLINDED_ATTR_DOMAIN).elements()[0];
        elements.push(domain_felt);

        // Attribute scalar
        elements.push(self.attr_scalar);

        // Issuer public key commitment (Word -> [Felt; 4])
        let issuer_felts: [Felt; 4] = self.issuer_pk.into();
        elements.extend_from_slice(&issuer_felts);

        // Authority public key commitment
        let authority_felts: [Felt; 4] = self.authority_pk.into();
        elements.extend_from_slice(&authority_felts);

        // Salt
        let salt_felts: [Felt; 4] = self.salt.into();
        elements.extend_from_slice(&salt_felts);

        // Compute Poseidon2 hash
        Poseidon2Hash::hash_elements(&elements).as_word().clone()
    }

    /// Verify that this preimage produces the expected commitment.
    pub fn verify(&self, expected: &Word) -> bool {
        &self.compute_commitment() == expected
    }

    /// Verify against a BlindedAttribute.
    pub fn verify_attribute(&self, attr: &BlindedAttribute) -> bool {
        self.verify(&attr.commitment)
    }

    /// Get the attribute scalar.
    pub fn attr_scalar(&self) -> Felt {
        self.attr_scalar
    }

    /// Get the issuer's public key commitment.
    pub fn issuer_pk(&self) -> &Word {
        &self.issuer_pk
    }

    /// Get the authority's public key commitment.
    pub fn authority_pk(&self) -> &Word {
        &self.authority_pk
    }

    /// Get the salt.
    pub fn salt(&self) -> &Word {
        &self.salt
    }

    /// Serialize to bytes for secure storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        // 8 (attr_scalar) + 32 (issuer_pk) + 32 (authority_pk) + 32 (salt) = 104 bytes
        let mut bytes = Vec::with_capacity(104);

        // Attribute scalar (single Felt = 8 bytes)
        bytes.extend_from_slice(&self.attr_scalar.as_canonical_u64().to_le_bytes());

        // Issuer PK (4 Felts = 32 bytes)
        for felt in self.issuer_pk.iter() {
            bytes.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        // Authority PK (4 Felts = 32 bytes)
        for felt in self.authority_pk.iter() {
            bytes.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        // Salt (4 Felts = 32 bytes)
        for felt in self.salt.iter() {
            bytes.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 104 {
            return Err(Error::ConversionFailed(
                "AttributePreimage requires at least 104 bytes".into(),
            ));
        }

        let mut offset = 0;

        // Read attr_scalar
        let attr_scalar =
            Felt::new(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()));
        offset += 8;

        // Read issuer_pk
        let mut issuer_felts = [Felt::ZERO; 4];
        for felt in &mut issuer_felts {
            *felt = Felt::new(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()));
            offset += 8;
        }
        let issuer_pk = Word::new(issuer_felts);

        // Read authority_pk
        let mut authority_felts = [Felt::ZERO; 4];
        for felt in &mut authority_felts {
            *felt = Felt::new(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()));
            offset += 8;
        }
        let authority_pk = Word::new(authority_felts);

        // Read salt
        let mut salt_felts = [Felt::ZERO; 4];
        for felt in &mut salt_felts {
            *felt = Felt::new(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()));
            offset += 8;
        }
        let salt = Word::new(salt_felts);

        Ok(Self {
            attr_scalar,
            issuer_pk,
            authority_pk,
            salt,
            #[cfg(debug_assertions)]
            dimension: String::new(),
            #[cfg(debug_assertions)]
            attribute_name: String::new(),
        })
    }
}

impl fmt::Debug for AttributePreimage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            f.debug_struct("AttributePreimage")
                .field("dimension", &self.dimension)
                .field("attribute", &self.attribute_name)
                .field("attr_scalar", &format!("{:016x}", self.attr_scalar.as_canonical_u64()))
                .field("issuer_pk", &"[HIDDEN]")
                .field("authority_pk", &"[HIDDEN]")
                .field("salt", &"[HIDDEN]")
                .finish()
        }
        #[cfg(not(debug_assertions))]
        {
            f.debug_struct("AttributePreimage")
                .field("attr_scalar", &format!("{:016x}", self.attr_scalar.as_canonical_u64()))
                .field("issuer_pk", &"[HIDDEN]")
                .field("authority_pk", &"[HIDDEN]")
                .field("salt", &"[HIDDEN]")
                .finish()
        }
    }
}

// ============================================================================
// DimensionCommitment
// ============================================================================

/// A blinded commitment to a dimension name.
///
/// This hides the dimension name while allowing verification that
/// attributes belong to the same dimension.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DimensionCommitment {
    /// The Poseidon2 commitment to the dimension name
    commitment: Word,
}

impl DimensionCommitment {
    /// Create a dimension commitment.
    ///
    /// The commitment is bound to the authority to prevent
    /// cross-authority dimension correlation.
    pub fn commit(dimension_name: &str, authority_pk: &Word) -> Self {
        let input = [
            DIM_COMMIT_DOMAIN,
            dimension_name.as_bytes(),
            &authority_pk[0].as_canonical_u64().to_le_bytes(),
            &authority_pk[1].as_canonical_u64().to_le_bytes(),
            &authority_pk[2].as_canonical_u64().to_le_bytes(),
            &authority_pk[3].as_canonical_u64().to_le_bytes(),
        ]
        .concat();

        let commitment = Poseidon2Hash::hash_bytes(&input).as_word().clone();
        Self { commitment }
    }

    /// Get the commitment value.
    pub fn commitment(&self) -> &Word {
        &self.commitment
    }

    /// Verify that a dimension name produces this commitment.
    pub fn verify(&self, dimension_name: &str, authority_pk: &Word) -> bool {
        let expected = Self::commit(dimension_name, authority_pk);
        self.commitment == expected.commitment
    }
}

impl fmt::Debug for DimensionCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: Vec<u8> = self
            .commitment
            .iter()
            .flat_map(|f| f.as_canonical_u64().to_le_bytes())
            .collect();
        let hex: String = bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect();
        write!(f, "DimensionCommitment({}...)", hex)
    }
}

// ============================================================================
// IssuerBlindingKey - Issuer's key for creating blinded attributes
// ============================================================================

/// An issuer's key for creating and managing blinded attributes.
///
/// This structure encapsulates the issuer's cryptographic identity and provides
/// methods for:
///
/// - Creating blinded attributes bound to specific authorities
/// - Tracking which authorities the issuer is registered with
/// - Managing attribute preimages for ownership proofs
///
/// # Security
///
/// - The `identity` contains the Falcon512 private key - keep secure
/// - Preimages stored in `attribute_preimages` are secrets - protect accordingly
/// - Authority bindings track registration state
#[derive(Clone)]
pub struct IssuerBlindingKey {
    /// The issuer's Falcon512 identity (contains private key)
    identity: IssuerIdentity,
    /// Authorities this issuer is registered with
    authority_bindings: std::collections::HashMap<[u8; 32], AuthorityBinding>,
    /// Stored preimages for attributes (dimension::name -> preimage per authority)
    attribute_preimages: std::collections::HashMap<String, Vec<StoredPreimage>>,
}

/// Issuer's cryptographic identity using Falcon512.
#[derive(Clone)]
pub struct IssuerIdentity {
    /// Falcon512 keypair
    keypair: crate::crypto::Falcon512Keypair,
    /// Optional metadata (issuer name, organization, etc.)
    metadata: Vec<u8>,
}

impl IssuerIdentity {
    /// Create a new issuer identity with fresh keypair.
    pub fn new() -> Self {
        Self {
            keypair: crate::crypto::Falcon512Keypair::new(),
            metadata: Vec::new(),
        }
    }

    /// Create with RNG.
    pub fn with_rng<R: rand::Rng>(rng: &mut R) -> Self {
        Self {
            keypair: crate::crypto::Falcon512Keypair::with_rng(rng),
            metadata: Vec::new(),
        }
    }

    /// Set metadata.
    pub fn with_metadata(mut self, metadata: impl Into<Vec<u8>>) -> Self {
        self.metadata = metadata.into();
        self
    }

    /// Get the Poseidon2 commitment to the public key.
    pub fn commitment(&self) -> Word {
        self.keypair.public_key_commitment()
    }

    /// Get the public key.
    pub fn public_key(&self) -> crate::crypto::Falcon512PublicKey {
        self.keypair.public_key()
    }

    /// Sign a message.
    pub fn sign(&self, message: &Word) -> crate::crypto::Falcon512Signature {
        self.keypair.sign(message)
    }

    /// Verify a signature.
    pub fn verify(&self, message: &Word, signature: &crate::crypto::Falcon512Signature) -> bool {
        self.keypair.verify(message, signature)
    }
}

impl Default for IssuerIdentity {
    fn default() -> Self {
        Self::new()
    }
}

/// Binding between an issuer and a capability authority.
#[derive(Clone, Debug)]
pub struct AuthorityBinding {
    /// Authority's public key commitment (as bytes for HashMap key)
    pub authority_pk: Word,
    /// When the issuer registered with this authority
    pub registered_at: u64,
    /// Optional shared secret for deterministic salt derivation
    pub shared_secret: Option<[u8; 32]>,
}

/// A stored preimage with its associated authority.
#[derive(Clone)]
pub struct StoredPreimage {
    /// The authority this preimage is for
    pub authority_pk: Word,
    /// The blinded attribute commitment
    pub blinded: BlindedAttribute,
    /// The secret preimage
    pub preimage: AttributePreimage,
}

impl IssuerBlindingKey {
    /// Create a new issuer blinding key with fresh identity.
    pub fn new() -> Self {
        Self {
            identity: IssuerIdentity::new(),
            authority_bindings: std::collections::HashMap::new(),
            attribute_preimages: std::collections::HashMap::new(),
        }
    }

    /// Create with RNG.
    pub fn with_rng<R: rand::Rng>(rng: &mut R) -> Self {
        Self {
            identity: IssuerIdentity::with_rng(rng),
            authority_bindings: std::collections::HashMap::new(),
            attribute_preimages: std::collections::HashMap::new(),
        }
    }

    /// Create from existing identity.
    pub fn from_identity(identity: IssuerIdentity) -> Self {
        Self {
            identity,
            authority_bindings: std::collections::HashMap::new(),
            attribute_preimages: std::collections::HashMap::new(),
        }
    }

    /// Get the issuer's public key commitment.
    pub fn commitment(&self) -> Word {
        self.identity.commitment()
    }

    /// Get the issuer's identity.
    pub fn identity(&self) -> &IssuerIdentity {
        &self.identity
    }

    /// Register with a capability authority.
    ///
    /// Returns a registration proof that should be submitted to the authority.
    pub fn register_with_authority(
        &mut self,
        authority_pk: Word,
        timestamp: u64,
    ) -> IssuerRegistration {
        // Create binding
        let binding = AuthorityBinding {
            authority_pk,
            registered_at: timestamp,
            shared_secret: None,
        };

        // Store binding (convert Word to bytes for HashMap key)
        let key = word_to_bytes(&authority_pk);
        self.authority_bindings.insert(key, binding);

        // Create registration proof
        let issuer_pk = self.identity.commitment();
        let message = Self::registration_message(&issuer_pk, &authority_pk, timestamp);
        let signature = self.identity.sign(&message);

        IssuerRegistration {
            issuer_pk,
            authority_pk,
            timestamp,
            signature,
        }
    }

    /// Check if registered with an authority.
    pub fn is_registered_with(&self, authority_pk: &Word) -> bool {
        let key = word_to_bytes(authority_pk);
        self.authority_bindings.contains_key(&key)
    }

    /// Create a blinded attribute for a specific authority.
    ///
    /// The preimage is automatically stored for later ownership proofs.
    pub fn create_blinded_attribute(
        &mut self,
        dimension: &str,
        attribute_name: &str,
        authority_pk: &Word,
    ) -> Result<BlindedAttribute, Error> {
        // Verify registration
        if !self.is_registered_with(authority_pk) {
            return Err(Error::OperationNotPermitted(
                "Issuer not registered with this authority".into(),
            ));
        }

        let issuer_pk = self.identity.commitment();
        let (blinded, preimage) =
            BlindedAttribute::commit(dimension, attribute_name, &issuer_pk, authority_pk);

        // Store the preimage
        let attr_key = format!("{}::{}", dimension, attribute_name);
        let stored = StoredPreimage {
            authority_pk: *authority_pk,
            blinded,
            preimage,
        };

        self.attribute_preimages.entry(attr_key).or_insert_with(Vec::new).push(stored);

        Ok(blinded)
    }

    /// Create a blinded attribute with deterministic salt.
    ///
    /// Useful when the same attribute needs to produce the same commitment
    /// (e.g., for updates or re-registration).
    pub fn create_blinded_attribute_deterministic(
        &mut self,
        dimension: &str,
        attribute_name: &str,
        authority_pk: &Word,
        salt: Word,
    ) -> Result<BlindedAttribute, Error> {
        if !self.is_registered_with(authority_pk) {
            return Err(Error::OperationNotPermitted(
                "Issuer not registered with this authority".into(),
            ));
        }

        let issuer_pk = self.identity.commitment();
        let (blinded, preimage) = BlindedAttribute::commit_with_salt(
            dimension,
            attribute_name,
            &issuer_pk,
            authority_pk,
            salt,
        );

        let attr_key = format!("{}::{}", dimension, attribute_name);
        let stored = StoredPreimage {
            authority_pk: *authority_pk,
            blinded,
            preimage,
        };

        self.attribute_preimages.entry(attr_key).or_insert_with(Vec::new).push(stored);

        Ok(blinded)
    }

    /// Get the preimage for an attribute (for a specific authority).
    pub fn get_preimage(
        &self,
        dimension: &str,
        attribute_name: &str,
        authority_pk: &Word,
    ) -> Option<&AttributePreimage> {
        let attr_key = format!("{}::{}", dimension, attribute_name);
        self.attribute_preimages.get(&attr_key).and_then(|preimages| {
            preimages.iter().find(|p| &p.authority_pk == authority_pk).map(|p| &p.preimage)
        })
    }

    /// Get an existing blinded attribute, or create a new one if none exists.
    ///
    /// This is useful for consistent attribute references - if you've already
    /// created a blinded attribute for (dimension, name, authority), this will
    /// return the same one instead of creating a new one with a different salt.
    pub fn get_or_create_blinded_attribute(
        &mut self,
        dimension: &str,
        attribute_name: &str,
        authority_pk: &Word,
    ) -> Result<BlindedAttribute, Error> {
        // Verify registration
        if !self.is_registered_with(authority_pk) {
            return Err(Error::OperationNotPermitted(
                "Issuer not registered with this authority".into(),
            ));
        }

        let attr_key = format!("{}::{}", dimension, attribute_name);

        // Check if we already have a preimage for this attribute
        if let Some(preimages) = self.attribute_preimages.get(&attr_key) {
            if let Some(stored) = preimages.iter().find(|p| &p.authority_pk == authority_pk) {
                return Ok(stored.blinded);
            }
        }

        // Create a new one
        let issuer_pk = self.identity.commitment();
        let (blinded, preimage) =
            BlindedAttribute::commit(dimension, attribute_name, &issuer_pk, authority_pk);

        let stored = StoredPreimage {
            authority_pk: *authority_pk,
            blinded,
            preimage,
        };

        self.attribute_preimages.entry(attr_key).or_insert_with(Vec::new).push(stored);

        Ok(blinded)
    }

    /// Get an existing blinded attribute (if one exists).
    ///
    /// Returns `None` if no attribute has been created for this combination yet.
    pub fn get_existing_blinded_attribute(
        &self,
        dimension: &str,
        attribute_name: &str,
        authority_pk: &Word,
    ) -> Option<BlindedAttribute> {
        let attr_key = format!("{}::{}", dimension, attribute_name);
        self.attribute_preimages.get(&attr_key).and_then(|preimages| {
            preimages.iter().find(|p| &p.authority_pk == authority_pk).map(|p| p.blinded)
        })
    }

    /// Create an ownership proof for a blinded attribute.
    pub fn prove_ownership(
        &self,
        dimension: &str,
        attribute_name: &str,
        authority_pk: &Word,
    ) -> Result<AttributeOwnershipProof, Error> {
        let preimage = self
            .get_preimage(dimension, attribute_name, authority_pk)
            .ok_or_else(|| Error::OperationNotPermitted("Preimage not found".into()))?;

        let blinded = BlindedAttribute::from_commitment(preimage.compute_commitment());

        Ok(AttributeOwnershipProof::create(blinded, preimage.clone(), &self.identity))
    }

    /// Create the registration message for signing.
    fn registration_message(issuer_pk: &Word, authority_pk: &Word, timestamp: u64) -> Word {
        let mut data = Vec::new();
        data.extend_from_slice(b"COLOSSUS-ISSUER-REGISTRATION-V1");

        let issuer_felts: [Felt; 4] = (*issuer_pk).into();
        for felt in &issuer_felts {
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        let authority_felts: [Felt; 4] = (*authority_pk).into();
        for felt in &authority_felts {
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        data.extend_from_slice(&timestamp.to_le_bytes());

        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }
}

impl Default for IssuerBlindingKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Registration of an issuer with a capability authority.
#[derive(Clone, Debug, PartialEq)]
pub struct IssuerRegistration {
    /// Issuer's public key commitment
    pub issuer_pk: Word,
    /// Authority's public key commitment
    pub authority_pk: Word,
    /// Registration timestamp
    pub timestamp: u64,
    /// Issuer's signature over the registration
    pub signature: crate::crypto::Falcon512Signature,
}

impl IssuerRegistration {
    /// Verify this registration.
    pub fn verify(&self, issuer_public_key: &crate::crypto::Falcon512PublicKey) -> bool {
        let message = IssuerBlindingKey::registration_message(
            &self.issuer_pk,
            &self.authority_pk,
            self.timestamp,
        );
        issuer_public_key.verify(&message, &self.signature)
    }
}

// ============================================================================
// AttributeOwnershipProof - ZK proof of attribute ownership
// ============================================================================

/// Proof that an issuer owns a blinded attribute.
///
/// This proof demonstrates knowledge of the preimage without revealing:
/// - The actual attribute value (dimension::name)
/// - The salt used
///
/// The proof includes:
/// - The blinded attribute commitment (public)
/// - A signature binding the proof to the issuer (public)
/// - Commitment to the salt (for binding, prevents proof reuse)
///
/// # STARK Proof (Future)
///
/// In a full implementation, this would include a STARK proof verifiable
/// in the Miden VM. For now, we use a Falcon512 signature-based proof
/// that can be verified off-chain.
#[derive(Clone)]
pub struct AttributeOwnershipProof {
    /// The blinded attribute being proven
    pub attribute: BlindedAttribute,
    /// Issuer's public key commitment
    pub issuer_pk: Word,
    /// Commitment to the preimage (for binding)
    pub preimage_commitment: Word,
    /// Issuer's signature over (attribute || preimage_commitment)
    pub signature: crate::crypto::Falcon512Signature,
}

impl AttributeOwnershipProof {
    /// Create an ownership proof.
    pub fn create(
        attribute: BlindedAttribute,
        preimage: AttributePreimage,
        issuer_identity: &IssuerIdentity,
    ) -> Self {
        let issuer_pk = issuer_identity.commitment();

        // Create commitment to preimage (hides the actual values)
        let preimage_commitment = Self::compute_preimage_commitment(&preimage);

        // Sign (attribute || preimage_commitment)
        let message = Self::compute_proof_message(&attribute, &preimage_commitment);
        let signature = issuer_identity.sign(&message);

        Self {
            attribute,
            issuer_pk,
            preimage_commitment,
            signature,
        }
    }

    /// Verify the ownership proof.
    ///
    /// This verifies:
    /// 1. The signature is valid for the claimed issuer
    /// 2. The proof binds the issuer to the attribute
    ///
    /// Note: This does NOT verify that the preimage actually produces the commitment.
    /// That requires either:
    /// - The verifier having the preimage (breaks privacy)
    /// - A STARK proof (future enhancement)
    pub fn verify(&self, issuer_public_key: &crate::crypto::Falcon512PublicKey) -> bool {
        // Verify issuer PK matches
        if issuer_public_key.commitment() != self.issuer_pk {
            return false;
        }

        let message = Self::compute_proof_message(&self.attribute, &self.preimage_commitment);
        issuer_public_key.verify(&message, &self.signature)
    }

    /// Verify with full preimage verification.
    ///
    /// This additionally verifies that the preimage produces the commitment.
    /// Use this when the verifier has access to the preimage.
    pub fn verify_with_preimage(
        &self,
        issuer_public_key: &crate::crypto::Falcon512PublicKey,
        preimage: &AttributePreimage,
    ) -> bool {
        // Basic signature verification
        if !self.verify(issuer_public_key) {
            return false;
        }

        // Verify preimage produces the commitment
        if !preimage.verify_attribute(&self.attribute) {
            return false;
        }

        // Verify preimage commitment matches
        let expected_commitment = Self::compute_preimage_commitment(preimage);
        self.preimage_commitment == expected_commitment
    }

    /// Compute commitment to the preimage.
    fn compute_preimage_commitment(preimage: &AttributePreimage) -> Word {
        // Hash all preimage components
        let preimage_bytes = preimage.to_bytes();
        Poseidon2Hash::hash_bytes(&preimage_bytes).as_word().clone()
    }

    /// Compute the message to sign.
    fn compute_proof_message(attribute: &BlindedAttribute, preimage_commitment: &Word) -> Word {
        let mut data = Vec::new();
        data.extend_from_slice(b"COLOSSUS-ATTR-OWNERSHIP-PROOF-V1");
        data.extend_from_slice(&attribute.to_bytes());

        let commit_felts: [Felt; 4] = (*preimage_commitment).into();
        for felt in &commit_felts {
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }
}

impl fmt::Debug for AttributeOwnershipProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttributeOwnershipProof")
            .field("attribute", &self.attribute)
            .field("issuer_pk", &"[COMMITMENT]")
            .field("preimage_commitment", &"[COMMITMENT]")
            .finish()
    }
}

// ============================================================================
// BlindedAccessStructure - Privacy-preserving access structure
// ============================================================================

/// A privacy-preserving access structure using blinded attributes.
///
/// This replaces the standard `AccessStructure` with one that:
/// - Hides attribute values (only commitments are stored)
/// - Binds attributes to their issuer
/// - Enables ZK verification of attribute membership
///
/// # Structure
///
/// ```text
/// BlindedAccessStructure
/// ├── authority_pk: Word (owner's commitment)
/// ├── epoch: u64 (version for rotation)
/// └── dimensions: HashMap<DimensionCommitment, BlindedDimension>
///     └── BlindedDimension
///         ├── dim_type: DimensionType
///         ├── attributes: HashMap<Word, BlindedAttributeMetadata>
///         └── ordering: Option<BlindedOrdering> (for hierarchies)
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct BlindedAccessStructure {
    /// Authority that owns this structure
    pub authority_pk: Word,
    /// Version/epoch for key rotation
    pub epoch: u64,
    /// Blinded dimensions (key is dimension commitment)
    dimensions: std::collections::HashMap<[u8; 32], BlindedDimension>,
    /// Attribute ID counter
    next_id: usize,
    /// Registered issuers (issuer_pk -> registration)
    registered_issuers: std::collections::HashMap<[u8; 32], IssuerRegistration>,
    /// Name registry: maps "DIMENSION::ATTRIBUTE" -> attribute commitment
    /// This enables AccessPolicy resolution while keeping attribute values blinded.
    /// The registry stores the plaintext names but NOT the preimages.
    name_registry: std::collections::HashMap<String, Word>,
    /// Dimension names: maps dimension commitment -> dimension name
    dimension_names: std::collections::HashMap<[u8; 32], String>,
}

/// Type of dimension organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DimensionType {
    /// Unordered, independent attributes
    Anarchy,
    /// Ordered, hierarchical attributes
    Hierarchy,
}

/// A blinded dimension containing blinded attributes.
#[derive(Clone, Debug, PartialEq)]
pub struct BlindedDimension {
    /// Dimension type
    pub dim_type: DimensionType,
    /// Blinded commitment to the dimension name
    pub name_commitment: DimensionCommitment,
    /// Attributes in this dimension (key is attribute commitment bytes)
    /// Stores both the BlindedAttribute and its metadata
    pub attributes:
        std::collections::HashMap<[u8; 32], (BlindedAttribute, BlindedAttributeMetadata)>,
    /// For hierarchy: ordering information
    pub ordering: Option<BlindedOrdering>,
}

/// Metadata for a blinded attribute.
#[derive(Clone, Debug, PartialEq)]
pub struct BlindedAttributeMetadata {
    /// Unique ID within the access structure
    pub id: usize,
    /// Write status (EncryptDecrypt or DecryptOnly)
    pub status: super::AttributeStatus,
    /// Issuer who owns this attribute
    pub issuer_pk: Word,
    /// When the attribute was added
    pub added_at: u64,
}

/// Ordering information for hierarchical dimensions.
#[derive(Clone, Debug, PartialEq)]
pub struct BlindedOrdering {
    /// Parent relationships: child_commitment -> parent_commitment
    pub parents: std::collections::HashMap<[u8; 32], [u8; 32]>,
}

impl BlindedAccessStructure {
    /// Create a new blinded access structure.
    pub fn new(authority_pk: Word) -> Self {
        Self {
            authority_pk,
            epoch: 0,
            dimensions: std::collections::HashMap::new(),
            next_id: 0,
            registered_issuers: std::collections::HashMap::new(),
            name_registry: std::collections::HashMap::new(),
            dimension_names: std::collections::HashMap::new(),
        }
    }

    /// Register an issuer with this structure.
    pub fn register_issuer(&mut self, registration: IssuerRegistration) -> Result<(), Error> {
        // Verify the registration is for this authority
        if registration.authority_pk != self.authority_pk {
            return Err(Error::OperationNotPermitted(
                "Registration is for different authority".into(),
            ));
        }

        let key = word_to_bytes(&registration.issuer_pk);
        self.registered_issuers.insert(key, registration);
        Ok(())
    }

    /// Check if an issuer is registered.
    pub fn is_issuer_registered(&self, issuer_pk: &Word) -> bool {
        let key = word_to_bytes(issuer_pk);
        self.registered_issuers.contains_key(&key)
    }

    /// Add a blinded dimension.
    pub fn add_dimension(
        &mut self,
        dimension_name: &str,
        dim_type: DimensionType,
    ) -> DimensionCommitment {
        let name_commitment = DimensionCommitment::commit(dimension_name, &self.authority_pk);

        let dim = BlindedDimension {
            dim_type,
            name_commitment,
            attributes: std::collections::HashMap::new(),
            ordering: if dim_type == DimensionType::Hierarchy {
                Some(BlindedOrdering {
                    parents: std::collections::HashMap::new(),
                })
            } else {
                None
            },
        };

        let key = word_to_bytes(name_commitment.commitment());
        self.dimensions.insert(key, dim);

        // Store the dimension name mapping
        self.dimension_names.insert(key, dimension_name.to_string());

        name_commitment
    }

    /// Add a blinded attribute to a dimension.
    ///
    /// Requires:
    /// - The issuer must be registered
    /// - A valid ownership proof
    pub fn add_attribute(
        &mut self,
        dimension_commitment: &DimensionCommitment,
        blinded_attr: BlindedAttribute,
        proof: &AttributeOwnershipProof,
        issuer_public_key: &crate::crypto::Falcon512PublicKey,
        timestamp: u64,
    ) -> Result<usize, Error> {
        // Verify issuer is registered
        if !self.is_issuer_registered(&proof.issuer_pk) {
            return Err(Error::OperationNotPermitted("Issuer not registered".into()));
        }

        // Verify ownership proof
        if !proof.verify(issuer_public_key) {
            return Err(Error::OperationNotPermitted("Invalid ownership proof".into()));
        }

        // Verify the proof is for this attribute
        if proof.attribute.commitment() != blinded_attr.commitment() {
            return Err(Error::OperationNotPermitted("Proof does not match attribute".into()));
        }

        // Find the dimension
        let dim_key = word_to_bytes(dimension_commitment.commitment());
        let dim = self
            .dimensions
            .get_mut(&dim_key)
            .ok_or_else(|| Error::OperationNotPermitted("Dimension not found".into()))?;

        // Add the attribute
        let id = self.next_id;
        self.next_id += 1;

        let attr_key = word_to_bytes(blinded_attr.commitment());
        let metadata = BlindedAttributeMetadata {
            id,
            status: super::AttributeStatus::EncryptDecrypt,
            issuer_pk: proof.issuer_pk,
            added_at: timestamp,
        };
        dim.attributes.insert(attr_key, (blinded_attr, metadata));

        Ok(id)
    }

    /// Add a blinded attribute with name registration for AccessPolicy resolution.
    ///
    /// This is the hybrid mode version that allows both privacy-preserving
    /// attribute storage AND AccessPolicy-based encryption.
    ///
    /// # Arguments
    ///
    /// * `dimension_commitment` - The dimension's commitment
    /// * `dimension_name` - The dimension name (e.g., "AGE")
    /// * `attribute_name` - The attribute name (e.g., "ADULT")
    /// * `blinded_attr` - The blinded attribute from the issuer
    /// * `proof` - Ownership proof from the issuer
    /// * `issuer_public_key` - The issuer's public key for proof verification
    /// * `timestamp` - Timestamp for when the attribute was added
    pub fn add_attribute_with_name(
        &mut self,
        dimension_commitment: &DimensionCommitment,
        dimension_name: &str,
        attribute_name: &str,
        blinded_attr: BlindedAttribute,
        proof: &AttributeOwnershipProof,
        issuer_public_key: &crate::crypto::Falcon512PublicKey,
        timestamp: u64,
    ) -> Result<usize, Error> {
        // Add the attribute using the regular method
        let id = self.add_attribute(
            dimension_commitment,
            blinded_attr.clone(),
            proof,
            issuer_public_key,
            timestamp,
        )?;

        // Register the name mapping
        let key = format!("{}::{}", dimension_name, attribute_name);
        self.name_registry.insert(key, *blinded_attr.commitment());

        Ok(id)
    }

    /// Get the attribute commitment for a "DIMENSION::ATTRIBUTE" key.
    pub fn get_attribute_commitment(&self, dimension: &str, attribute: &str) -> Option<&Word> {
        let key = format!("{}::{}", dimension, attribute);
        self.name_registry.get(&key)
    }

    /// Get the attribute by "DIMENSION::ATTRIBUTE" key.
    pub fn get_attribute_by_name(
        &self,
        dimension: &str,
        attribute: &str,
    ) -> Option<&BlindedAttribute> {
        self.get_attribute_commitment(dimension, attribute)
            .and_then(|commitment| self.get_attribute(commitment))
    }

    /// Resolve an AccessPolicy to a set of Rights.
    ///
    /// This converts a human-readable policy like "AGE::ADULT && LOC::INNER_CITY"
    /// into the set of cryptographic rights needed for encryption.
    pub fn resolve_policy(
        &self,
        policy: &super::AccessPolicy,
    ) -> Result<std::collections::HashSet<super::Right>, Error> {
        if policy.is_broadcast() {
            // Broadcast: return omega (all rights)
            return self.omega_as_rights().map(|m| m.into_keys().collect());
        }

        // Get all DNF clauses from the policy
        let dnf = policy.to_dnf();

        // For each clause, find the corresponding blinded attributes
        let mut all_rights = std::collections::HashSet::new();

        for clause in dnf {
            if clause.is_empty() {
                // Empty clause means broadcast for this disjunction
                let omega_rights: std::collections::HashSet<_> =
                    self.omega_as_rights()?.into_keys().collect();
                all_rights.extend(omega_rights);
                continue;
            }

            // Collect blinded attributes for this clause
            let mut clause_attrs = Vec::new();
            for term in &clause {
                let attr = self
                    .get_attribute_by_name(&term.dimension, &term.name)
                    .ok_or_else(|| {
                        Error::InvalidAttribute(format!(
                            "Attribute {}::{} not found in access structure",
                            term.dimension, term.name
                        ))
                    })?
                    .clone();
                clause_attrs.push(attr);
            }

            // Get the access rights for these attributes
            let clause_rights = self.get_access_rights_as_rights(&clause_attrs)?;
            all_rights.extend(clause_rights);
        }

        Ok(all_rights)
    }

    /// Check if a blinded attribute exists in the structure.
    pub fn contains_attribute(&self, commitment: &Word) -> bool {
        let attr_key = word_to_bytes(commitment);
        self.dimensions.values().any(|dim| dim.attributes.contains_key(&attr_key))
    }

    /// Get metadata for a blinded attribute.
    pub fn get_attribute_metadata(&self, commitment: &Word) -> Option<&BlindedAttributeMetadata> {
        let attr_key = word_to_bytes(commitment);
        self.dimensions
            .values()
            .find_map(|dim| dim.attributes.get(&attr_key).map(|(_, m)| m))
    }

    /// Get the blinded attribute by commitment.
    pub fn get_attribute(&self, commitment: &Word) -> Option<&BlindedAttribute> {
        let attr_key = word_to_bytes(commitment);
        self.dimensions
            .values()
            .find_map(|dim| dim.attributes.get(&attr_key).map(|(a, _)| a))
    }

    /// Get the dimension containing an attribute.
    pub fn get_attribute_dimension(&self, commitment: &Word) -> Option<&BlindedDimension> {
        let attr_key = word_to_bytes(commitment);
        self.dimensions.values().find(|dim| dim.attributes.contains_key(&attr_key))
    }

    /// Disable an attribute (set to DecryptOnly).
    pub fn disable_attribute(&mut self, commitment: &Word) -> Result<(), Error> {
        let attr_key = word_to_bytes(commitment);
        for dim in self.dimensions.values_mut() {
            if let Some((_, metadata)) = dim.attributes.get_mut(&attr_key) {
                metadata.status = super::AttributeStatus::DecryptOnly;
                return Ok(());
            }
        }
        Err(Error::OperationNotPermitted("Attribute not found".into()))
    }

    /// Get the number of attributes.
    pub fn attribute_count(&self) -> usize {
        self.dimensions.values().map(|d| d.attributes.len()).sum()
    }

    /// Get the number of dimensions.
    pub fn dimension_count(&self) -> usize {
        self.dimensions.len()
    }

    /// Get the number of registered issuers.
    pub fn issuer_count(&self) -> usize {
        self.registered_issuers.len()
    }

    /// Increment the epoch (for key rotation).
    pub fn increment_epoch(&mut self) {
        self.epoch += 1;
    }

    /// Generate all possible access rights (omega) for this structure.
    ///
    /// This computes all combinations of attributes across dimensions,
    /// similar to `AccessStructure::omega()` but using blinded attributes.
    ///
    /// Returns a map of `BlindedRight` to `AttributeStatus`.
    pub fn omega(
        &self,
    ) -> Result<std::collections::HashMap<BlindedRight, super::AttributeStatus>, Error> {
        let dimensions: Vec<_> = self.dimensions.values().collect();
        let combinations = self.combine_dimensions(&dimensions);

        combinations
            .into_iter()
            .map(|(commitments, status)| {
                let right = BlindedRight::from_commitments(commitments);
                Ok((right, status))
            })
            .collect()
    }

    /// Generate omega as standard Rights for compatibility with CapabilityAuthority.
    ///
    /// This converts blinded rights to the `Right` type used by the capability system.
    pub fn omega_as_rights(
        &self,
    ) -> Result<std::collections::HashMap<super::Right, super::AttributeStatus>, Error> {
        self.omega()?.into_iter().map(|(br, status)| Ok((br.into(), status))).collect()
    }

    /// Generate access rights from a set of claimed blinded attributes.
    ///
    /// This computes all "complementary" rights for the given attributes,
    /// similar to `AccessStructure::generate_complementary_rights`.
    pub fn get_access_rights(
        &self,
        claimed_attributes: &[BlindedAttribute],
    ) -> Result<std::collections::HashSet<BlindedRight>, Error> {
        // Group claimed attributes by dimension
        let mut claimed_by_dim: std::collections::HashMap<[u8; 32], Vec<&BlindedAttribute>> =
            std::collections::HashMap::new();

        for attr in claimed_attributes {
            if let Some(dim) = self.get_attribute_dimension(attr.commitment()) {
                let dim_key = word_to_bytes(dim.name_commitment.commitment());
                claimed_by_dim.entry(dim_key).or_default().push(attr);
            } else {
                return Err(Error::OperationNotPermitted(
                    "Claimed attribute not in access structure".into(),
                ));
            }
        }

        // For each dimension, collect semantic points (attributes in claimed dimensions)
        // and complementary points (all attributes in unclaimed dimensions)
        let mut semantic_attrs: Vec<Vec<&Word>> = vec![vec![]];
        let mut complementary_attrs: Vec<Vec<&Word>> = vec![vec![]];

        for (dim_key, dim) in &self.dimensions {
            if let Some(claimed) = claimed_by_dim.get(dim_key) {
                // For claimed dimensions: include the claimed attributes
                let mut new_semantic = Vec::new();
                for existing in &semantic_attrs {
                    for attr in claimed {
                        let mut combined = existing.clone();
                        combined.push(attr.commitment());
                        new_semantic.push(combined);
                    }
                }
                semantic_attrs = new_semantic;
            } else {
                // For unclaimed dimensions: include all attributes + empty (UNKNOWN)
                let mut new_complementary = Vec::new();
                for existing in &complementary_attrs {
                    // Add empty (represents UNKNOWN)
                    new_complementary.push(existing.clone());

                    // Add each attribute in this dimension
                    for (blinded_attr, _metadata) in dim.attributes.values() {
                        let mut combined = existing.clone();
                        combined.push(blinded_attr.commitment());
                        new_complementary.push(combined);
                    }
                }
                complementary_attrs = new_complementary;
            }
        }

        // Combine semantic and complementary points
        let mut rights = std::collections::HashSet::new();
        for semantic in &semantic_attrs {
            for complementary in &complementary_attrs {
                let mut combined = semantic.clone();
                combined.extend(complementary.iter());
                let right = BlindedRight::from_commitments(combined);
                rights.insert(right);
            }
        }

        Ok(rights)
    }

    /// Generate access rights as standard Rights for compatibility.
    pub fn get_access_rights_as_rights(
        &self,
        claimed_attributes: &[BlindedAttribute],
    ) -> Result<std::collections::HashSet<super::Right>, Error> {
        self.get_access_rights(claimed_attributes)?
            .into_iter()
            .map(|br| Ok(br.into()))
            .collect()
    }

    /// Get all attributes in this structure.
    pub fn all_attributes(&self) -> Vec<&BlindedAttribute> {
        self.dimensions
            .values()
            .flat_map(|dim| dim.attributes.values().map(|(attr, _)| attr))
            .collect()
    }

    /// Get dimensions as an iterator.
    pub fn dimensions_iter(&self) -> impl Iterator<Item = &BlindedDimension> {
        self.dimensions.values()
    }

    /// Internal method to combine all dimensions into attribute combinations.
    fn combine_dimensions<'a>(
        &'a self,
        dimensions: &[&'a BlindedDimension],
    ) -> Vec<(Vec<&'a Word>, super::AttributeStatus)> {
        if dimensions.is_empty() {
            return vec![(vec![], super::AttributeStatus::EncryptDecrypt)];
        }

        let current_dim = dimensions[0];
        let partial = self.combine_dimensions(&dimensions[1..]);

        let mut result = Vec::new();

        // Include empty case (no attribute selected from this dimension)
        for (attrs, status) in &partial {
            result.push((attrs.clone(), *status));
        }

        // Include each attribute in this dimension
        for (blinded_attr, metadata) in current_dim.attributes.values() {
            for (existing_attrs, existing_status) in &partial {
                let mut combined = existing_attrs.clone();
                combined.push(blinded_attr.commitment());
                let combined_status = *existing_status | metadata.status;
                result.push((combined, combined_status));
            }
        }

        result
    }
}

// ============================================================================
// BlindedAccessClaim - For credential verification with blinded attributes
// ============================================================================

/// A claim with blinded attributes for capability token requests.
///
/// This is the privacy-preserving version of `AccessClaim` that uses
/// blinded attributes instead of plaintext ones.
#[derive(Clone)]
pub struct BlindedAccessClaim {
    /// Issuer's public key commitment
    pub issuer_pk: Word,
    /// The blinded attributes being claimed
    pub attributes: Vec<BlindedAttribute>,
    /// Ownership proofs for each attribute
    pub proofs: Vec<AttributeOwnershipProof>,
}

impl BlindedAccessClaim {
    /// Create a new blinded access claim.
    pub fn new(issuer_pk: Word) -> Self {
        Self {
            issuer_pk,
            attributes: Vec::new(),
            proofs: Vec::new(),
        }
    }

    /// Add an attribute with its proof.
    pub fn add_attribute(&mut self, attribute: BlindedAttribute, proof: AttributeOwnershipProof) {
        self.attributes.push(attribute);
        self.proofs.push(proof);
    }

    /// Verify all proofs in the claim.
    pub fn verify_proofs(&self, issuer_public_key: &crate::crypto::Falcon512PublicKey) -> bool {
        // All proofs must be from the same issuer
        for proof in &self.proofs {
            if proof.issuer_pk != self.issuer_pk {
                return false;
            }
            if !proof.verify(issuer_public_key) {
                return false;
            }
        }
        true
    }
}

impl fmt::Debug for BlindedAccessClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindedAccessClaim")
            .field("issuer_pk", &"[COMMITMENT]")
            .field("num_attributes", &self.attributes.len())
            .finish()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a Word to a fixed-size byte array (for HashMap keys).
fn word_to_bytes(word: &Word) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let felts: [Felt; 4] = (*word).into();
    for (i, felt) in felts.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
    }
    bytes
}

// ============================================================================
// Serialization
// ============================================================================

impl Serializable for BlindedAttribute {
    type Error = Error;

    fn length(&self) -> usize {
        32 // 4 field elements * 8 bytes each
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let bytes = self.to_bytes();
        ser.write_array(&bytes).map_err(Into::into)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = de.read_array()?;
        Self::from_bytes(&bytes)
    }
}

impl Serializable for AttributePreimage {
    type Error = Error;

    fn length(&self) -> usize {
        104 // 1 + 4 + 4 + 4 field elements * 8 bytes each
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let bytes = self.to_bytes();
        let arr: [u8; 104] = bytes.try_into().map_err(|_| {
            Error::ConversionFailed("Failed to convert preimage bytes to array".into())
        })?;
        ser.write_array(&arr).map_err(Into::into)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes: [u8; 104] = de.read_array()?;
        Self::from_bytes(&bytes)
    }
}

impl Serializable for DimensionCommitment {
    type Error = Error;

    fn length(&self) -> usize {
        32
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let bytes: Vec<u8> = self
            .commitment
            .iter()
            .flat_map(|f| f.as_canonical_u64().to_le_bytes())
            .collect();
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::ConversionFailed("Failed to convert dimension bytes to array".into())
        })?;
        ser.write_array(&arr).map_err(Into::into)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = de.read_array()?;
        let mut felts = [Felt::ZERO; 4];
        for i in 0..4 {
            let offset = i * 8;
            felts[i] = Felt::new(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()));
        }
        Ok(Self { commitment: Word::new(felts) })
    }
}

// ============================================================================
// Attribute Creation Utilities
// ============================================================================

/// Utilities for creating blinded attributes.
pub mod conversion {
    use super::*;

    /// Create a blinded attribute from dimension and name strings.
    ///
    /// This is the primary way to create blinded attributes for use in the
    /// privacy-preserving access control system.
    ///
    /// # Arguments
    ///
    /// * `dimension` - The dimension name (e.g., "Security", "Department")
    /// * `name` - The attribute name (e.g., "TopSecret", "Engineering")
    /// * `issuer_pk` - Issuer's public key commitment
    /// * `authority_pk` - Authority's public key commitment
    ///
    /// # Returns
    ///
    /// A tuple of (BlindedAttribute, AttributePreimage) where the preimage
    /// contains the secret information needed to prove ownership.
    pub fn blind_attribute(
        dimension: &str,
        name: &str,
        issuer_pk: &Word,
        authority_pk: &Word,
    ) -> (BlindedAttribute, AttributePreimage) {
        BlindedAttribute::commit(dimension, name, issuer_pk, authority_pk)
    }

    /// Create a blinded attribute with a deterministic salt.
    ///
    /// Use this when you need reproducible commitments (e.g., for testing
    /// or when the same attribute must produce the same commitment).
    pub fn blind_attribute_deterministic(
        dimension: &str,
        name: &str,
        issuer_pk: &Word,
        authority_pk: &Word,
        salt: Word,
    ) -> (BlindedAttribute, AttributePreimage) {
        BlindedAttribute::commit_with_salt(dimension, name, issuer_pk, authority_pk, salt)
    }

    /// Verify that a preimage matches the specified dimension and attribute name.
    ///
    /// This checks that the attr_scalar in the preimage corresponds to
    /// the specified dimension and attribute name.
    pub fn preimage_matches(
        preimage: &AttributePreimage,
        dimension: &str,
        attribute_name: &str,
    ) -> bool {
        let expected_scalar = BlindedAttribute::derive_attr_scalar(dimension, attribute_name);
        preimage.attr_scalar == expected_scalar
    }

    /// Batch create blinded attributes.
    ///
    /// Returns a vector of (BlindedAttribute, AttributePreimage) pairs.
    pub fn batch_blind_attributes(
        attributes: &[(&str, &str)], // (dimension, name)
        issuer_pk: &Word,
        authority_pk: &Word,
    ) -> Vec<(BlindedAttribute, AttributePreimage)> {
        attributes
            .iter()
            .map(|(dimension, name)| blind_attribute(dimension, name, issuer_pk, authority_pk))
            .collect()
    }
}

// ============================================================================
// Batch Ownership Proof Aggregation
// ============================================================================

/// Domain separator for batch proof aggregation
const BATCH_PROOF_DOMAIN: &[u8] = b"COLOSSUS-BATCH-PROOF-V1";

/// Aggregated proof for multiple blinded attributes.
///
/// Instead of creating individual `AttributeOwnershipProof` for each attribute,
/// this structure combines multiple proofs into a single aggregate that:
///
/// - Reduces proof size (single signature covers all attributes)
/// - Improves verification efficiency
/// - Maintains the same security guarantees
///
/// # Security
///
/// The batch proof commits to all individual attributes and their preimage
/// commitments, then signs the aggregate. This ensures:
/// - All attributes are from the same issuer
/// - No individual attribute can be selectively removed
/// - The proof is bound to the specific set of attributes
///
/// # Example
///
/// ```ignore
/// let batch_proof = BatchOwnershipProof::create(
///     vec![attr1, attr2, attr3],
///     vec![preimage1, preimage2, preimage3],
///     &issuer_identity,
/// )?;
///
/// assert!(batch_proof.verify(&issuer_public_key));
/// ```
#[derive(Clone)]
pub struct BatchOwnershipProof {
    /// The blinded attributes being proven (in order)
    pub attributes: Vec<BlindedAttribute>,
    /// Issuer's public key commitment
    pub issuer_pk: Word,
    /// Aggregated commitment to all preimages
    pub aggregate_preimage_commitment: Word,
    /// Number of attributes in this batch
    pub count: usize,
    /// Single signature covering all attributes
    pub signature: crate::crypto::Falcon512Signature,
}

impl BatchOwnershipProof {
    /// Create a batch ownership proof for multiple attributes.
    ///
    /// # Arguments
    ///
    /// * `attributes` - Vector of blinded attributes to prove
    /// * `preimages` - Vector of preimages (must match attributes in order)
    /// * `issuer_identity` - Issuer's identity for signing
    ///
    /// # Errors
    ///
    /// Returns error if attributes and preimages have different lengths.
    pub fn create(
        attributes: Vec<BlindedAttribute>,
        preimages: Vec<AttributePreimage>,
        issuer_identity: &IssuerIdentity,
    ) -> Result<Self, Error> {
        if attributes.len() != preimages.len() {
            return Err(Error::OperationNotPermitted(
                "Attributes and preimages must have same length".into(),
            ));
        }

        if attributes.is_empty() {
            return Err(Error::OperationNotPermitted("Cannot create empty batch proof".into()));
        }

        // Verify all preimages match their attributes
        for (attr, preimage) in attributes.iter().zip(preimages.iter()) {
            if !preimage.verify_attribute(attr) {
                return Err(Error::OperationNotPermitted(
                    "Preimage does not match attribute".into(),
                ));
            }
        }

        let issuer_pk = issuer_identity.commitment();
        let count = attributes.len();

        // Compute aggregate preimage commitment
        let aggregate_preimage_commitment =
            Self::compute_aggregate_commitment(&attributes, &preimages);

        // Sign the aggregate
        let message =
            Self::compute_batch_message(&attributes, &aggregate_preimage_commitment, count);
        let signature = issuer_identity.sign(&message);

        Ok(Self {
            attributes,
            issuer_pk,
            aggregate_preimage_commitment,
            count,
            signature,
        })
    }

    /// Verify the batch ownership proof.
    ///
    /// This verifies:
    /// 1. The signature is valid for the claimed issuer
    /// 2. The count matches the number of attributes
    ///
    /// Note: Does NOT verify preimages (requires knowledge of secrets).
    pub fn verify(&self, issuer_public_key: &crate::crypto::Falcon512PublicKey) -> bool {
        // Verify issuer PK matches
        if issuer_public_key.commitment() != self.issuer_pk {
            return false;
        }

        // Verify count matches
        if self.attributes.len() != self.count {
            return false;
        }

        let message = Self::compute_batch_message(
            &self.attributes,
            &self.aggregate_preimage_commitment,
            self.count,
        );
        issuer_public_key.verify(&message, &self.signature)
    }

    /// Verify with full preimage verification.
    ///
    /// This additionally verifies that all preimages produce their commitments.
    pub fn verify_with_preimages(
        &self,
        issuer_public_key: &crate::crypto::Falcon512PublicKey,
        preimages: &[AttributePreimage],
    ) -> bool {
        // Basic verification
        if !self.verify(issuer_public_key) {
            return false;
        }

        // Verify preimage count
        if preimages.len() != self.attributes.len() {
            return false;
        }

        // Verify each preimage produces its attribute
        for (attr, preimage) in self.attributes.iter().zip(preimages.iter()) {
            if !preimage.verify_attribute(attr) {
                return false;
            }
        }

        // Verify aggregate commitment matches
        let expected_aggregate = Self::compute_aggregate_commitment(&self.attributes, preimages);
        self.aggregate_preimage_commitment == expected_aggregate
    }

    /// Compute aggregated commitment to all preimages.
    fn compute_aggregate_commitment(
        attributes: &[BlindedAttribute],
        preimages: &[AttributePreimage],
    ) -> Word {
        let mut data = Vec::new();
        data.extend_from_slice(BATCH_PROOF_DOMAIN);

        for (attr, preimage) in attributes.iter().zip(preimages.iter()) {
            data.extend_from_slice(&attr.to_bytes());
            data.extend_from_slice(&preimage.to_bytes());
        }

        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }

    /// Compute the message to sign for batch verification.
    fn compute_batch_message(
        attributes: &[BlindedAttribute],
        aggregate_commitment: &Word,
        count: usize,
    ) -> Word {
        let mut data = Vec::new();
        data.extend_from_slice(b"COLOSSUS-BATCH-OWNERSHIP-PROOF-V1");
        data.extend_from_slice(&(count as u64).to_le_bytes());

        for attr in attributes {
            data.extend_from_slice(&attr.to_bytes());
        }

        let commit_felts: [Felt; 4] = (*aggregate_commitment).into();
        for felt in &commit_felts {
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }

    /// Get the number of attributes in this batch.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get an iterator over the attributes.
    pub fn iter(&self) -> impl Iterator<Item = &BlindedAttribute> {
        self.attributes.iter()
    }

    /// Check if this batch contains a specific attribute.
    pub fn contains(&self, commitment: &Word) -> bool {
        self.attributes.iter().any(|a| a.commitment() == commitment)
    }
}

impl fmt::Debug for BatchOwnershipProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchOwnershipProof")
            .field("count", &self.count)
            .field("issuer_pk", &"[COMMITMENT]")
            .finish()
    }
}

// ============================================================================
// DAC Credential Integration
// ============================================================================

/// Integration utilities for connecting BlindedAccessClaim with DAC credentials.
///
/// This module provides the bridge between:
/// - DAC credentials (SPSEQ-UC based)
/// - Blinded access claims (Poseidon2 based, using `BlindedAttribute`)
///
/// # Flow
///
/// ```text
/// ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
/// │  DAC Credential │────▶│ BlindedAttribute │────▶│ BlindedAccessClaim  │
/// │   (dimension,   │     │   + Preimages    │     │                     │
/// │     name)       │     │                  │     │                     │
/// └─────────────────┘     └──────────────────┘     └─────────────────────┘
/// ```
pub mod dac_integration {
    use super::*;

    /// Builder for creating `BlindedAccessClaim` from attribute specifications.
    ///
    /// This builder collects attributes by dimension and name, then converts them
    /// to blinded attributes, automatically managing the preimages and proofs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let claim = BlindedClaimBuilder::new(&issuer, authority_pk)
    ///     .add_attribute("Security", "TopSecret")
    ///     .add_attribute("Department", "Engineering")
    ///     .build()?;
    /// ```
    pub struct BlindedClaimBuilder<'a> {
        issuer: &'a mut IssuerBlindingKey,
        authority_pk: Word,
        attributes: Vec<(String, String)>, // (dimension, name)
    }

    impl<'a> BlindedClaimBuilder<'a> {
        /// Create a new builder for a specific authority.
        pub fn new(issuer: &'a mut IssuerBlindingKey, authority_pk: Word) -> Self {
            Self {
                issuer,
                authority_pk,
                attributes: Vec::new(),
            }
        }

        /// Add an attribute by dimension and name.
        pub fn add_attribute(mut self, dimension: &str, name: &str) -> Self {
            self.attributes.push((dimension.to_string(), name.to_string()));
            self
        }

        /// Build the `BlindedAccessClaim`.
        ///
        /// This creates blinded attributes and ownership proofs for all
        /// added attributes. Uses `get_or_create_blinded_attribute` to ensure
        /// consistent commitments when attributes are reused.
        pub fn build(self) -> Result<BlindedAccessClaim, Error> {
            // Ensure issuer is registered
            if !self.issuer.is_registered_with(&self.authority_pk) {
                return Err(Error::OperationNotPermitted(
                    "Issuer not registered with authority".into(),
                ));
            }

            let mut claim = BlindedAccessClaim::new(self.issuer.commitment());

            for (dimension, name) in self.attributes {
                // Use get_or_create to return existing attribute if already created
                let blinded = self.issuer.get_or_create_blinded_attribute(
                    &dimension,
                    &name,
                    &self.authority_pk,
                )?;

                let proof = self.issuer.prove_ownership(&dimension, &name, &self.authority_pk)?;

                claim.add_attribute(blinded, proof);
            }

            Ok(claim)
        }

        /// Build a `BlindedAccessClaim` with a `BatchOwnershipProof`.
        ///
        /// This is more efficient when claiming many attributes.
        /// Uses `get_or_create_blinded_attribute` to ensure consistent commitments.
        pub fn build_batched(self) -> Result<BlindedAccessClaimBatched, Error> {
            if !self.issuer.is_registered_with(&self.authority_pk) {
                return Err(Error::OperationNotPermitted(
                    "Issuer not registered with authority".into(),
                ));
            }

            let mut attributes = Vec::new();
            let mut preimages = Vec::new();

            for (dimension, name) in &self.attributes {
                // Use get_or_create to return existing attribute if already created
                let blinded = self.issuer.get_or_create_blinded_attribute(
                    dimension,
                    name,
                    &self.authority_pk,
                )?;

                let preimage = self
                    .issuer
                    .get_preimage(dimension, name, &self.authority_pk)
                    .ok_or_else(|| Error::OperationNotPermitted("Preimage not found".into()))?
                    .clone();

                attributes.push(blinded);
                preimages.push(preimage);
            }

            let batch_proof =
                BatchOwnershipProof::create(attributes.clone(), preimages, self.issuer.identity())?;

            Ok(BlindedAccessClaimBatched {
                issuer_pk: self.issuer.commitment(),
                batch_proof,
            })
        }
    }

    /// A blinded access claim using batch proof aggregation.
    ///
    /// This is more efficient than `BlindedAccessClaim` when claiming
    /// multiple attributes, as it uses a single aggregated proof.
    #[derive(Clone)]
    pub struct BlindedAccessClaimBatched {
        /// Issuer's public key commitment
        pub issuer_pk: Word,
        /// Aggregated proof for all attributes
        pub batch_proof: BatchOwnershipProof,
    }

    impl BlindedAccessClaimBatched {
        /// Verify the batched claim.
        pub fn verify(&self, issuer_public_key: &crate::crypto::Falcon512PublicKey) -> bool {
            // Verify issuer PK matches
            if issuer_public_key.commitment() != self.issuer_pk {
                return false;
            }

            self.batch_proof.verify(issuer_public_key)
        }

        /// Get the attributes in this claim.
        pub fn attributes(&self) -> &[BlindedAttribute] {
            &self.batch_proof.attributes
        }

        /// Get the number of attributes.
        pub fn len(&self) -> usize {
            self.batch_proof.len()
        }

        /// Check if empty.
        pub fn is_empty(&self) -> bool {
            self.batch_proof.is_empty()
        }

        /// Check if a specific attribute is claimed.
        pub fn contains(&self, commitment: &Word) -> bool {
            self.batch_proof.contains(commitment)
        }
    }

    impl fmt::Debug for BlindedAccessClaimBatched {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("BlindedAccessClaimBatched")
                .field("issuer_pk", &"[COMMITMENT]")
                .field("num_attributes", &self.batch_proof.len())
                .finish()
        }
    }

    /// Convert a `BlindedAccessClaim` to `BlindedAccessClaimBatched`.
    ///
    /// This requires the preimages to create the batch proof.
    pub fn claim_to_batched(
        claim: &BlindedAccessClaim,
        preimages: Vec<AttributePreimage>,
        issuer_identity: &IssuerIdentity,
    ) -> Result<BlindedAccessClaimBatched, Error> {
        let batch_proof =
            BatchOwnershipProof::create(claim.attributes.clone(), preimages, issuer_identity)?;

        Ok(BlindedAccessClaimBatched { issuer_pk: claim.issuer_pk, batch_proof })
    }
}

// Re-export integration types at module level
pub use dac_integration::{BlindedAccessClaimBatched, BlindedClaimBuilder};

// ============================================================================
// BlindedRight - Access right derived from blinded attributes
// ============================================================================

/// Domain separator for blinded right derivation
const BLINDED_RIGHT_DOMAIN: &[u8] = b"COLOSSUS-BLINDED-RIGHT-V1";

/// An access right derived from blinded attribute commitments.
///
/// Unlike `Right` which is computed from sequential attribute IDs,
/// `BlindedRight` is derived from the Poseidon2 commitments of blinded attributes.
/// This ensures that:
///
/// - Rights are deterministic given the same set of attribute commitments
/// - No information about the underlying attributes is leaked
/// - Rights are compatible with the capability token system
///
/// # Derivation
///
/// ```text
/// BlindedRight = Poseidon2(domain || sorted(commitment_1, ..., commitment_n))
/// ```
///
/// Where commitments are sorted lexicographically for deterministic output.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct BlindedRight(pub(crate) Vec<u8>);

impl BlindedRight {
    /// Create a blinded right from a set of blinded attribute commitments.
    ///
    /// The commitments are sorted to ensure deterministic output regardless
    /// of the order they are provided.
    pub fn from_commitments(mut commitments: Vec<&Word>) -> Self {
        // Sort commitments for determinism
        commitments.sort_by(|a, b| {
            let a_bytes: [u8; 32] = word_to_bytes(a);
            let b_bytes: [u8; 32] = word_to_bytes(b);
            a_bytes.cmp(&b_bytes)
        });

        // Build input for hashing
        let mut data = Vec::new();
        data.extend_from_slice(BLINDED_RIGHT_DOMAIN);

        for commitment in commitments {
            let bytes = word_to_bytes(commitment);
            data.extend_from_slice(&bytes);
        }

        // Compute Poseidon2 hash
        let hash = Poseidon2Hash::hash_bytes(&data);
        let hash_bytes: Vec<u8> = hash
            .elements()
            .iter()
            .flat_map(|f| f.as_canonical_u64().to_le_bytes())
            .collect();

        Self(hash_bytes)
    }

    /// Create a blinded right from blinded attributes.
    pub fn from_attributes(attributes: &[BlindedAttribute]) -> Self {
        let commitments: Vec<&Word> = attributes.iter().map(|a| a.commitment()).collect();
        Self::from_commitments(commitments)
    }

    /// Create an empty blinded right (for dimension combinations where no attributes are selected).
    pub fn empty() -> Self {
        let hash = Poseidon2Hash::hash_bytes(BLINDED_RIGHT_DOMAIN);
        let hash_bytes: Vec<u8> = hash
            .elements()
            .iter()
            .flat_map(|f| f.as_canonical_u64().to_le_bytes())
            .collect();

        Self(hash_bytes)
    }

    /// Get the bytes representation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a `Right` for compatibility with existing capability system.
    ///
    /// This allows `BlindedRight` to be used wherever `Right` is expected.
    pub fn to_right(&self) -> super::Right {
        super::Right(self.0.clone())
    }
}

impl std::ops::Deref for BlindedRight {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<BlindedRight> for super::Right {
    fn from(blinded: BlindedRight) -> Self {
        super::Right(blinded.0)
    }
}

impl From<&BlindedRight> for super::Right {
    fn from(blinded: &BlindedRight) -> Self {
        super::Right(blinded.0.clone())
    }
}

// ============================================================================
// IssuerBlindingKey Extensions for Batch Proofs
// ============================================================================

impl IssuerBlindingKey {
    /// Create a batch ownership proof for multiple attributes.
    ///
    /// All attributes must have been created by this issuer for the same authority.
    pub fn prove_ownership_batch(
        &self,
        attributes: &[(&str, &str)], // (dimension, name) pairs
        authority_pk: &Word,
    ) -> Result<BatchOwnershipProof, Error> {
        let mut blinded_attrs = Vec::new();
        let mut preimages = Vec::new();

        for (dimension, name) in attributes {
            let preimage = self.get_preimage(dimension, name, authority_pk).ok_or_else(|| {
                Error::OperationNotPermitted(format!(
                    "Preimage not found for {}::{}",
                    dimension, name
                ))
            })?;

            let blinded = BlindedAttribute::from_commitment(preimage.compute_commitment());

            blinded_attrs.push(blinded);
            preimages.push(preimage.clone());
        }

        BatchOwnershipProof::create(blinded_attrs, preimages, &self.identity)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AttributeStatus;

    fn test_issuer_pk() -> Word {
        Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)])
    }

    fn test_authority_pk() -> Word {
        Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)])
    }

    #[test]
    fn test_blinded_attribute_creation() {
        let (blinded, preimage) = BlindedAttribute::commit(
            "Security",
            "TopSecret",
            &test_issuer_pk(),
            &test_authority_pk(),
        );

        // Verify the preimage produces the correct commitment
        assert!(preimage.verify_attribute(&blinded));
        assert!(preimage.verify(blinded.commitment()));
    }

    #[test]
    fn test_same_attribute_different_salt_produces_different_commitment() {
        let issuer_pk = test_issuer_pk();
        let authority_pk = test_authority_pk();

        let (blinded1, _) =
            BlindedAttribute::commit("Security", "TopSecret", &issuer_pk, &authority_pk);

        let (blinded2, _) =
            BlindedAttribute::commit("Security", "TopSecret", &issuer_pk, &authority_pk);

        // Different salts should produce different commitments (unlinkability)
        assert_ne!(blinded1.commitment(), blinded2.commitment());
    }

    #[test]
    fn test_deterministic_with_same_salt() {
        let issuer_pk = test_issuer_pk();
        let authority_pk = test_authority_pk();
        let salt = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

        let (blinded1, preimage1) = BlindedAttribute::commit_with_salt(
            "Security",
            "TopSecret",
            &issuer_pk,
            &authority_pk,
            salt,
        );

        let (blinded2, preimage2) = BlindedAttribute::commit_with_salt(
            "Security",
            "TopSecret",
            &issuer_pk,
            &authority_pk,
            salt,
        );

        // Same inputs should produce same commitment
        assert_eq!(blinded1.commitment(), blinded2.commitment());
        assert_eq!(preimage1.attr_scalar(), preimage2.attr_scalar());
    }

    #[test]
    fn test_different_issuer_produces_different_commitment() {
        let issuer_pk1 = test_issuer_pk();
        let issuer_pk2 = Word::new([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]);
        let authority_pk = test_authority_pk();
        let salt = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

        let (blinded1, _) = BlindedAttribute::commit_with_salt(
            "Security",
            "TopSecret",
            &issuer_pk1,
            &authority_pk,
            salt,
        );

        let (blinded2, _) = BlindedAttribute::commit_with_salt(
            "Security",
            "TopSecret",
            &issuer_pk2,
            &authority_pk,
            salt,
        );

        // Different issuers should produce different commitments (issuer-binding)
        assert_ne!(blinded1.commitment(), blinded2.commitment());
    }

    #[test]
    fn test_different_authority_produces_different_commitment() {
        let issuer_pk = test_issuer_pk();
        let authority_pk1 = test_authority_pk();
        let authority_pk2 = Word::new([Felt::new(50), Felt::new(60), Felt::new(70), Felt::new(80)]);
        let salt = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

        let (blinded1, _) = BlindedAttribute::commit_with_salt(
            "Security",
            "TopSecret",
            &issuer_pk,
            &authority_pk1,
            salt,
        );

        let (blinded2, _) = BlindedAttribute::commit_with_salt(
            "Security",
            "TopSecret",
            &issuer_pk,
            &authority_pk2,
            salt,
        );

        // Different authorities should produce different commitments (authority-binding)
        assert_ne!(blinded1.commitment(), blinded2.commitment());
    }

    #[test]
    fn test_different_attribute_produces_different_commitment() {
        let issuer_pk = test_issuer_pk();
        let authority_pk = test_authority_pk();
        let salt = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

        let (blinded1, _) = BlindedAttribute::commit_with_salt(
            "Security",
            "TopSecret",
            &issuer_pk,
            &authority_pk,
            salt,
        );

        let (blinded2, _) = BlindedAttribute::commit_with_salt(
            "Security",
            "Secret", // Different attribute
            &issuer_pk,
            &authority_pk,
            salt,
        );

        // Different attributes should produce different commitments
        assert_ne!(blinded1.commitment(), blinded2.commitment());
    }

    #[test]
    fn test_different_dimension_produces_different_commitment() {
        let issuer_pk = test_issuer_pk();
        let authority_pk = test_authority_pk();
        let salt = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

        let (blinded1, _) = BlindedAttribute::commit_with_salt(
            "Security",
            "TopSecret",
            &issuer_pk,
            &authority_pk,
            salt,
        );

        let (blinded2, _) = BlindedAttribute::commit_with_salt(
            "Department", // Different dimension
            "TopSecret",
            &issuer_pk,
            &authority_pk,
            salt,
        );

        // Different dimensions should produce different commitments
        assert_ne!(blinded1.commitment(), blinded2.commitment());
    }

    #[test]
    fn test_blinded_attribute_serialization_roundtrip() {
        let (blinded, _) = BlindedAttribute::commit(
            "Security",
            "TopSecret",
            &test_issuer_pk(),
            &test_authority_pk(),
        );

        let bytes = blinded.to_bytes();
        assert_eq!(bytes.len(), 32);

        let restored = BlindedAttribute::from_bytes(&bytes).unwrap();
        assert_eq!(blinded.commitment(), restored.commitment());
    }

    #[test]
    fn test_attribute_preimage_serialization_roundtrip() {
        let (_, preimage) = BlindedAttribute::commit(
            "Security",
            "TopSecret",
            &test_issuer_pk(),
            &test_authority_pk(),
        );

        let bytes = preimage.to_bytes();
        assert_eq!(bytes.len(), 104);

        let restored = AttributePreimage::from_bytes(&bytes).unwrap();

        // Verify restored preimage produces same commitment
        assert_eq!(preimage.compute_commitment(), restored.compute_commitment());
    }

    #[test]
    fn test_dimension_commitment() {
        let authority_pk = test_authority_pk();

        let dim_commit = DimensionCommitment::commit("Security", &authority_pk);

        // Verify with correct inputs
        assert!(dim_commit.verify("Security", &authority_pk));

        // Verify fails with wrong dimension
        assert!(!dim_commit.verify("Department", &authority_pk));

        // Verify fails with wrong authority
        let other_authority =
            Word::new([Felt::new(99), Felt::new(98), Felt::new(97), Felt::new(96)]);
        assert!(!dim_commit.verify("Security", &other_authority));
    }

    #[test]
    fn test_preimage_verification_fails_with_wrong_commitment() {
        let (blinded1, preimage1) = BlindedAttribute::commit(
            "Security",
            "TopSecret",
            &test_issuer_pk(),
            &test_authority_pk(),
        );

        let (blinded2, _) = BlindedAttribute::commit(
            "Security",
            "Secret", // Different attribute
            &test_issuer_pk(),
            &test_authority_pk(),
        );

        // Preimage1 should verify against blinded1
        assert!(preimage1.verify_attribute(&blinded1));

        // Preimage1 should NOT verify against blinded2
        assert!(!preimage1.verify_attribute(&blinded2));
    }

    #[test]
    fn test_attr_scalar_is_deterministic() {
        let scalar1 = BlindedAttribute::derive_attr_scalar("Security", "TopSecret");
        let scalar2 = BlindedAttribute::derive_attr_scalar("Security", "TopSecret");

        assert_eq!(scalar1, scalar2);
    }

    #[test]
    fn test_attr_scalar_different_for_different_inputs() {
        let scalar1 = BlindedAttribute::derive_attr_scalar("Security", "TopSecret");
        let scalar2 = BlindedAttribute::derive_attr_scalar("Security", "Secret");
        let scalar3 = BlindedAttribute::derive_attr_scalar("Department", "TopSecret");

        assert_ne!(scalar1, scalar2);
        assert_ne!(scalar1, scalar3);
        assert_ne!(scalar2, scalar3);
    }

    #[test]
    fn test_cosmian_serializable_blinded_attribute() {
        let (blinded, _) = BlindedAttribute::commit(
            "Security",
            "TopSecret",
            &test_issuer_pk(),
            &test_authority_pk(),
        );

        // Use Serializable trait
        let bytes = blinded.serialize().expect("serialization failed");
        let restored = BlindedAttribute::deserialize(&bytes).expect("deserialization failed");

        assert_eq!(blinded.commitment(), restored.commitment());
    }

    #[test]
    fn test_cosmian_serializable_attribute_preimage() {
        let (_, preimage) = BlindedAttribute::commit(
            "Security",
            "TopSecret",
            &test_issuer_pk(),
            &test_authority_pk(),
        );

        // Use Serializable trait
        let bytes = preimage.serialize().expect("serialization failed");
        let restored = AttributePreimage::deserialize(&bytes).expect("deserialization failed");

        assert_eq!(preimage.compute_commitment(), restored.compute_commitment());
    }

    // ========================================================================
    // IssuerBlindingKey Tests
    // ========================================================================

    #[test]
    fn test_issuer_blinding_key_creation() {
        let issuer = IssuerBlindingKey::new();

        // Should have a valid commitment
        let commitment = issuer.commitment();
        assert_ne!(commitment, Word::default());
    }

    #[test]
    fn test_issuer_registration() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        // Initially not registered
        assert!(!issuer.is_registered_with(&authority_pk));

        // Register
        let registration = issuer.register_with_authority(authority_pk, 1000);

        // Now registered
        assert!(issuer.is_registered_with(&authority_pk));
        assert_eq!(registration.authority_pk, authority_pk);
        assert_eq!(registration.timestamp, 1000);
    }

    #[test]
    fn test_issuer_create_blinded_attribute() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        // Must register first
        issuer.register_with_authority(authority_pk, 1000);

        // Create blinded attribute
        let blinded = issuer
            .create_blinded_attribute("Security", "TopSecret", &authority_pk)
            .expect("should succeed after registration");

        // Verify preimage was stored
        let preimage = issuer
            .get_preimage("Security", "TopSecret", &authority_pk)
            .expect("preimage should be stored");

        // Verify preimage produces correct commitment
        assert!(preimage.verify_attribute(&blinded));
    }

    #[test]
    fn test_issuer_create_blinded_attribute_requires_registration() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        // Should fail without registration
        let result = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_issuer_multiple_authorities() {
        let mut issuer = IssuerBlindingKey::new();
        let authority1 = test_authority_pk();
        let authority2 = Word::new([Felt::new(50), Felt::new(60), Felt::new(70), Felt::new(80)]);

        // Register with both
        issuer.register_with_authority(authority1, 1000);
        issuer.register_with_authority(authority2, 1001);

        // Create same attribute for both
        let blinded1 =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority1).unwrap();
        let blinded2 =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority2).unwrap();

        // Should be different (authority-bound)
        assert_ne!(blinded1.commitment(), blinded2.commitment());
    }

    // ========================================================================
    // AttributeOwnershipProof Tests
    // ========================================================================

    #[test]
    fn test_ownership_proof_creation_and_verification() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);
        issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();

        // Create ownership proof
        let proof = issuer
            .prove_ownership("Security", "TopSecret", &authority_pk)
            .expect("should create proof");

        // Verify proof
        let issuer_pk = issuer.identity().public_key();
        assert!(proof.verify(&issuer_pk));
    }

    #[test]
    fn test_ownership_proof_fails_with_wrong_key() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);
        issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();

        let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();

        // Verify with wrong key should fail
        let other_issuer = IssuerBlindingKey::new();
        let other_pk = other_issuer.identity().public_key();
        assert!(!proof.verify(&other_pk));
    }

    #[test]
    fn test_ownership_proof_with_preimage_verification() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);
        issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();

        let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();

        let preimage = issuer.get_preimage("Security", "TopSecret", &authority_pk).unwrap();

        // Full verification with preimage
        let issuer_pk = issuer.identity().public_key();
        assert!(proof.verify_with_preimage(&issuer_pk, preimage));
    }

    // ========================================================================
    // BlindedAccessStructure Tests
    // ========================================================================

    #[test]
    fn test_blinded_access_structure_creation() {
        let authority_pk = test_authority_pk();
        let structure = BlindedAccessStructure::new(authority_pk);

        assert_eq!(structure.authority_pk, authority_pk);
        assert_eq!(structure.epoch, 0);
        assert_eq!(structure.dimension_count(), 0);
        assert_eq!(structure.attribute_count(), 0);
    }

    #[test]
    fn test_blinded_access_structure_add_dimension() {
        let authority_pk = test_authority_pk();
        let mut structure = BlindedAccessStructure::new(authority_pk);

        let dim_commit = structure.add_dimension("Security", DimensionType::Hierarchy);

        assert_eq!(structure.dimension_count(), 1);
        assert!(dim_commit.verify("Security", &authority_pk));
    }

    #[test]
    fn test_blinded_access_structure_register_issuer() {
        let authority_pk = test_authority_pk();
        let mut structure = BlindedAccessStructure::new(authority_pk);
        let mut issuer = IssuerBlindingKey::new();

        // Register issuer
        let registration = issuer.register_with_authority(authority_pk, 1000);
        structure.register_issuer(registration).unwrap();

        assert_eq!(structure.issuer_count(), 1);
        assert!(structure.is_issuer_registered(&issuer.commitment()));
    }

    #[test]
    fn test_blinded_access_structure_add_attribute() {
        let authority_pk = test_authority_pk();
        let mut structure = BlindedAccessStructure::new(authority_pk);
        let mut issuer = IssuerBlindingKey::new();

        // Setup
        let registration = issuer.register_with_authority(authority_pk, 1000);
        structure.register_issuer(registration).unwrap();
        let dim_commit = structure.add_dimension("Security", DimensionType::Anarchy);

        // Create blinded attribute
        let blinded =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();

        // Create ownership proof
        let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();

        // Add to structure
        let issuer_pk = issuer.identity().public_key();
        let id = structure
            .add_attribute(&dim_commit, blinded, &proof, &issuer_pk, 2000)
            .expect("should add attribute");

        assert_eq!(id, 0);
        assert_eq!(structure.attribute_count(), 1);
        assert!(structure.contains_attribute(blinded.commitment()));
    }

    #[test]
    fn test_blinded_access_structure_requires_registered_issuer() {
        let authority_pk = test_authority_pk();
        let mut structure = BlindedAccessStructure::new(authority_pk);
        let mut issuer = IssuerBlindingKey::new();

        // Register with authority but NOT with structure
        issuer.register_with_authority(authority_pk, 1000);
        let dim_commit = structure.add_dimension("Security", DimensionType::Anarchy);

        let blinded =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();

        // Should fail - issuer not registered with structure
        let issuer_pk = issuer.identity().public_key();
        let result = structure.add_attribute(&dim_commit, blinded, &proof, &issuer_pk, 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_blinded_access_structure_get_metadata() {
        let authority_pk = test_authority_pk();
        let mut structure = BlindedAccessStructure::new(authority_pk);
        let mut issuer = IssuerBlindingKey::new();

        // Setup
        let registration = issuer.register_with_authority(authority_pk, 1000);
        structure.register_issuer(registration).unwrap();
        let dim_commit = structure.add_dimension("Security", DimensionType::Anarchy);

        let blinded =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();

        let issuer_pk = issuer.identity().public_key();
        structure.add_attribute(&dim_commit, blinded, &proof, &issuer_pk, 2000).unwrap();

        // Get metadata
        let metadata = structure
            .get_attribute_metadata(blinded.commitment())
            .expect("should find metadata");

        assert_eq!(metadata.id, 0);
        assert_eq!(metadata.issuer_pk, issuer.commitment());
        assert_eq!(metadata.added_at, 2000);
        assert_eq!(metadata.status, AttributeStatus::EncryptDecrypt);
    }

    #[test]
    fn test_blinded_access_structure_disable_attribute() {
        let authority_pk = test_authority_pk();
        let mut structure = BlindedAccessStructure::new(authority_pk);
        let mut issuer = IssuerBlindingKey::new();

        // Setup
        let registration = issuer.register_with_authority(authority_pk, 1000);
        structure.register_issuer(registration).unwrap();
        let dim_commit = structure.add_dimension("Security", DimensionType::Anarchy);

        let blinded =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();

        let issuer_pk = issuer.identity().public_key();
        structure.add_attribute(&dim_commit, blinded, &proof, &issuer_pk, 2000).unwrap();

        // Disable
        structure.disable_attribute(blinded.commitment()).expect("should disable");

        // Verify status changed
        let metadata = structure.get_attribute_metadata(blinded.commitment()).unwrap();
        assert_eq!(metadata.status, AttributeStatus::DecryptOnly);
    }

    // ========================================================================
    // BlindedAccessClaim Tests
    // ========================================================================

    #[test]
    fn test_blinded_access_claim_creation() {
        let issuer_pk = test_issuer_pk();
        let claim = BlindedAccessClaim::new(issuer_pk);

        assert_eq!(claim.issuer_pk, issuer_pk);
        assert!(claim.attributes.is_empty());
        assert!(claim.proofs.is_empty());
    }

    #[test]
    fn test_blinded_access_claim_with_attributes() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);

        let blinded1 =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        let proof1 = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();

        let blinded2 = issuer
            .create_blinded_attribute("Department", "Engineering", &authority_pk)
            .unwrap();
        let proof2 = issuer.prove_ownership("Department", "Engineering", &authority_pk).unwrap();

        let mut claim = BlindedAccessClaim::new(issuer.commitment());
        claim.add_attribute(blinded1, proof1);
        claim.add_attribute(blinded2, proof2);

        assert_eq!(claim.attributes.len(), 2);
        assert_eq!(claim.proofs.len(), 2);

        // Verify all proofs
        let issuer_pk = issuer.identity().public_key();
        assert!(claim.verify_proofs(&issuer_pk));
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn test_full_workflow() {
        // 1. Authority creates blinded access structure
        let authority_pk = test_authority_pk();
        let mut structure = BlindedAccessStructure::new(authority_pk);

        // 2. Authority adds dimensions
        let security_dim = structure.add_dimension("Security", DimensionType::Hierarchy);
        let dept_dim = structure.add_dimension("Department", DimensionType::Anarchy);

        // 3. Issuer creates identity and registers
        let mut issuer = IssuerBlindingKey::new();
        let registration = issuer.register_with_authority(authority_pk, 1000);
        structure.register_issuer(registration).unwrap();

        // 4. Issuer creates blinded attributes
        let top_secret =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        let engineering = issuer
            .create_blinded_attribute("Department", "Engineering", &authority_pk)
            .unwrap();

        // 5. Issuer provides ownership proofs
        let proof1 = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();
        let proof2 = issuer.prove_ownership("Department", "Engineering", &authority_pk).unwrap();

        // 6. Authority adds attributes to structure
        let issuer_pk = issuer.identity().public_key();
        structure
            .add_attribute(&security_dim, top_secret, &proof1, &issuer_pk, 2000)
            .unwrap();
        structure
            .add_attribute(&dept_dim, engineering, &proof2, &issuer_pk, 2000)
            .unwrap();

        // 7. Verify structure state
        assert_eq!(structure.dimension_count(), 2);
        assert_eq!(structure.attribute_count(), 2);
        assert!(structure.contains_attribute(top_secret.commitment()));
        assert!(structure.contains_attribute(engineering.commitment()));

        // 8. User creates claim with both attributes
        let mut claim = BlindedAccessClaim::new(issuer.commitment());
        claim.add_attribute(top_secret, proof1.clone());
        claim.add_attribute(engineering, proof2.clone());

        // 9. Authority verifies claim
        assert!(claim.verify_proofs(&issuer_pk));

        // 10. Verify each attribute exists in structure
        for attr in &claim.attributes {
            assert!(structure.contains_attribute(attr.commitment()));
            let metadata = structure.get_attribute_metadata(attr.commitment()).unwrap();
            assert_eq!(metadata.issuer_pk, issuer.commitment());
        }
    }

    #[test]
    fn test_cross_authority_unlinkability() {
        // Two authorities
        let authority1 = test_authority_pk();
        let authority2 = Word::new([Felt::new(50), Felt::new(60), Felt::new(70), Felt::new(80)]);

        let mut issuer = IssuerBlindingKey::new();

        // Register with both
        issuer.register_with_authority(authority1, 1000);
        issuer.register_with_authority(authority2, 1001);

        // Create same attribute for both
        let blinded1 =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority1).unwrap();
        let blinded2 =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority2).unwrap();

        // Even though it's the same issuer and attribute,
        // the commitments should be different (unlinkable across authorities)
        assert_ne!(blinded1.commitment(), blinded2.commitment());

        // Both should verify correctly
        let preimage1 = issuer.get_preimage("Security", "TopSecret", &authority1).unwrap();
        let preimage2 = issuer.get_preimage("Security", "TopSecret", &authority2).unwrap();

        assert!(preimage1.verify_attribute(&blinded1));
        assert!(preimage2.verify_attribute(&blinded2));

        // But preimages should not cross-verify
        assert!(!preimage1.verify_attribute(&blinded2));
        assert!(!preimage2.verify_attribute(&blinded1));
    }

    // ========================================================================
    // Conversion Utility Tests
    // ========================================================================

    #[test]
    fn test_conversion_blind_attribute() {
        let issuer_pk = test_issuer_pk();
        let authority_pk = test_authority_pk();

        let (blinded, preimage) =
            conversion::blind_attribute("Security", "TopSecret", &issuer_pk, &authority_pk);

        // Verify preimage produces correct commitment
        assert!(preimage.verify_attribute(&blinded));

        // Verify preimage matches
        assert!(conversion::preimage_matches(&preimage, "Security", "TopSecret"));

        // Wrong attribute name should not match
        assert!(!conversion::preimage_matches(&preimage, "Security", "Secret"));
    }

    #[test]
    fn test_conversion_deterministic() {
        let issuer_pk = test_issuer_pk();
        let authority_pk = test_authority_pk();
        let salt = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

        let (blinded1, _) = conversion::blind_attribute_deterministic(
            "Security",
            "TopSecret",
            &issuer_pk,
            &authority_pk,
            salt,
        );

        let (blinded2, _) = conversion::blind_attribute_deterministic(
            "Security",
            "TopSecret",
            &issuer_pk,
            &authority_pk,
            salt,
        );

        // Same salt should produce same commitment
        assert_eq!(blinded1.commitment(), blinded2.commitment());
    }

    #[test]
    fn test_conversion_batch() {
        let attrs =
            vec![("Security", "TopSecret"), ("Department", "Engineering"), ("Role", "Developer")];

        let issuer_pk = test_issuer_pk();
        let authority_pk = test_authority_pk();

        let results = conversion::batch_blind_attributes(&attrs, &issuer_pk, &authority_pk);

        assert_eq!(results.len(), 3);

        // All should be different
        assert_ne!(results[0].0.commitment(), results[1].0.commitment());
        assert_ne!(results[1].0.commitment(), results[2].0.commitment());

        // All preimages should verify
        for (blinded, preimage) in &results {
            assert!(preimage.verify_attribute(blinded));
        }
    }

    // ========================================================================
    // Batch Ownership Proof Tests
    // ========================================================================

    #[test]
    fn test_batch_proof_creation_and_verification() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);

        // Create multiple attributes
        issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        issuer
            .create_blinded_attribute("Department", "Engineering", &authority_pk)
            .unwrap();
        issuer.create_blinded_attribute("Role", "Developer", &authority_pk).unwrap();

        // Create batch proof
        let batch_proof = issuer
            .prove_ownership_batch(
                &[("Security", "TopSecret"), ("Department", "Engineering"), ("Role", "Developer")],
                &authority_pk,
            )
            .expect("should create batch proof");

        assert_eq!(batch_proof.len(), 3);
        assert!(!batch_proof.is_empty());

        // Verify
        let issuer_pk = issuer.identity().public_key();
        assert!(batch_proof.verify(&issuer_pk));
    }

    #[test]
    fn test_batch_proof_fails_with_wrong_key() {
        let mut issuer1 = IssuerBlindingKey::new();
        let issuer2 = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer1.register_with_authority(authority_pk, 1000);
        issuer1
            .create_blinded_attribute("Security", "TopSecret", &authority_pk)
            .unwrap();

        let batch_proof = issuer1
            .prove_ownership_batch(&[("Security", "TopSecret")], &authority_pk)
            .unwrap();

        // Verify with wrong key should fail
        let wrong_pk = issuer2.identity().public_key();
        assert!(!batch_proof.verify(&wrong_pk));
    }

    #[test]
    fn test_batch_proof_with_preimage_verification() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);

        let blinded1 =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        let blinded2 = issuer
            .create_blinded_attribute("Department", "Engineering", &authority_pk)
            .unwrap();

        let preimage1 =
            issuer.get_preimage("Security", "TopSecret", &authority_pk).unwrap().clone();
        let preimage2 =
            issuer.get_preimage("Department", "Engineering", &authority_pk).unwrap().clone();

        let batch_proof = BatchOwnershipProof::create(
            vec![blinded1, blinded2],
            vec![preimage1.clone(), preimage2.clone()],
            issuer.identity(),
        )
        .unwrap();

        let issuer_pk = issuer.identity().public_key();

        // Full verification with preimages
        assert!(batch_proof.verify_with_preimages(&issuer_pk, &[preimage1, preimage2]));
    }

    #[test]
    fn test_batch_proof_contains() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);

        let blinded1 =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        let blinded2 = issuer
            .create_blinded_attribute("Department", "Engineering", &authority_pk)
            .unwrap();

        let batch_proof = issuer
            .prove_ownership_batch(
                &[("Security", "TopSecret"), ("Department", "Engineering")],
                &authority_pk,
            )
            .unwrap();

        // Check contains
        assert!(batch_proof.contains(blinded1.commitment()));
        assert!(batch_proof.contains(blinded2.commitment()));

        // Non-existent should not be contained
        let (other, _) =
            BlindedAttribute::commit("Other", "Attribute", &test_issuer_pk(), &authority_pk);
        assert!(!batch_proof.contains(other.commitment()));
    }

    #[test]
    fn test_batch_proof_empty_fails() {
        let issuer = IssuerBlindingKey::new();

        let result = BatchOwnershipProof::create(vec![], vec![], issuer.identity());
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_proof_mismatched_lengths_fails() {
        let issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        let (blinded, preimage) =
            BlindedAttribute::commit("Security", "TopSecret", &issuer.commitment(), &authority_pk);

        // One attribute but no preimages
        let result = BatchOwnershipProof::create(vec![blinded.clone()], vec![], issuer.identity());
        assert!(result.is_err());

        // No attributes but one preimage
        let result = BatchOwnershipProof::create(vec![], vec![preimage], issuer.identity());
        assert!(result.is_err());
    }

    // ========================================================================
    // DAC Integration Tests
    // ========================================================================

    #[test]
    fn test_blinded_claim_builder() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);

        let claim = dac_integration::BlindedClaimBuilder::new(&mut issuer, authority_pk)
            .add_attribute("Security", "TopSecret")
            .add_attribute("Department", "Engineering")
            .add_attribute("Role", "Developer")
            .build()
            .expect("should build claim");

        assert_eq!(claim.attributes.len(), 3);
        assert_eq!(claim.proofs.len(), 3);

        // Verify all proofs
        let issuer_pk = issuer.identity().public_key();
        assert!(claim.verify_proofs(&issuer_pk));
    }

    #[test]
    fn test_blinded_claim_builder_batched() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);

        let claim = dac_integration::BlindedClaimBuilder::new(&mut issuer, authority_pk)
            .add_attribute("Security", "TopSecret")
            .add_attribute("Department", "Engineering")
            .add_attribute("Role", "Developer")
            .build_batched()
            .expect("should build batched claim");

        assert_eq!(claim.len(), 3);
        assert!(!claim.is_empty());

        // Verify
        let issuer_pk = issuer.identity().public_key();
        assert!(claim.verify(&issuer_pk));

        // Check contains
        for attr in claim.attributes() {
            assert!(claim.contains(attr.commitment()));
        }
    }

    #[test]
    fn test_blinded_claim_builder_with_attribute() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);

        let claim = dac_integration::BlindedClaimBuilder::new(&mut issuer, authority_pk)
            .add_attribute("Security", "TopSecret")
            .build()
            .expect("should build claim");

        assert_eq!(claim.attributes.len(), 1);

        let issuer_pk = issuer.identity().public_key();
        assert!(claim.verify_proofs(&issuer_pk));
    }

    #[test]
    fn test_claim_to_batched_conversion() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        issuer.register_with_authority(authority_pk, 1000);

        // Create regular claim
        let blinded1 =
            issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk).unwrap();
        let proof1 = issuer.prove_ownership("Security", "TopSecret", &authority_pk).unwrap();
        let preimage1 =
            issuer.get_preimage("Security", "TopSecret", &authority_pk).unwrap().clone();

        let blinded2 = issuer
            .create_blinded_attribute("Department", "Engineering", &authority_pk)
            .unwrap();
        let proof2 = issuer.prove_ownership("Department", "Engineering", &authority_pk).unwrap();
        let preimage2 =
            issuer.get_preimage("Department", "Engineering", &authority_pk).unwrap().clone();

        let mut claim = BlindedAccessClaim::new(issuer.commitment());
        claim.add_attribute(blinded1, proof1);
        claim.add_attribute(blinded2, proof2);

        // Convert to batched
        let batched = dac_integration::claim_to_batched(
            &claim,
            vec![preimage1, preimage2],
            issuer.identity(),
        )
        .expect("should convert");

        assert_eq!(batched.len(), 2);

        let issuer_pk = issuer.identity().public_key();
        assert!(batched.verify(&issuer_pk));
    }

    #[test]
    fn test_blinded_claim_builder_requires_registration() {
        let mut issuer = IssuerBlindingKey::new();
        let authority_pk = test_authority_pk();

        // NOT registered
        let result = dac_integration::BlindedClaimBuilder::new(&mut issuer, authority_pk)
            .add_attribute("Security", "TopSecret")
            .build();

        assert!(result.is_err());
    }
}
