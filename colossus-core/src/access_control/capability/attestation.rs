//! Authority Attestation using Falcon512-Poseidon2 Post-Quantum Signatures
//!
//! This module provides attestation types for capability authorities using post-quantum
//! Falcon512 signatures. These attestations enable:
//!
//! - **Authority Identity**: Self-signed attestations proving control of an authority key
//! - **Authority Delegation**: Certificates allowing one authority to delegate powers to another
//! - **Cross-System Verification**: Proofs verifiable on-chain in the Miden rollup
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Authority Attestation System                      │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────┐   │
//! │  │              AuthorityIdentity                               │   │
//! │  │   - Falcon512 keypair for authority                         │   │
//! │  │   - Self-attestation (identity proof)                       │   │
//! │  │   - Poseidon2 commitment for on-chain verification          │   │
//! │  └─────────────────────────────────────────────────────────────┘   │
//! │                           │                                         │
//! │                           ▼                                         │
//! │  ┌─────────────────────────────────────────────────────────────┐   │
//! │  │              DelegationCertificate                           │   │
//! │  │   - Delegator signs delegatee's public key                  │   │
//! │  │   - Scoped access rights                                    │   │
//! │  │   - Optional expiration                                     │   │
//! │  └─────────────────────────────────────────────────────────────┘   │
//! │                           │                                         │
//! │                           ▼                                         │
//! │  ┌─────────────────────────────────────────────────────────────┐   │
//! │  │              CapabilityAttestation                           │   │
//! │  │   - Authority signs capability token commitment             │   │
//! │  │   - Binds token to authority for external verification      │   │
//! │  └─────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Model
//!
//! - Falcon512 provides post-quantum security (NIST Level 1)
//! - Poseidon2 hashing enables efficient STARK verification
//! - Attestations are self-contained and independently verifiable
//! - Delegation chains can be verified without contacting the root authority

use crate::crypto::{Falcon512Keypair, Falcon512PublicKey, Falcon512Signature, Poseidon2Hash};
use crate::policy::{Error, Right};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer, to_leb128_len};
use miden_crypto::Word;
use miden_crypto::field::{PrimeCharacteristicRing, PrimeField64};
use std::collections::HashSet;

/// Domain separator for authority identity attestations
const IDENTITY_DOMAIN: &[u8] = b"COLOSSUS-AUTHORITY-IDENTITY-V1";

/// Domain separator for delegation certificates
const DELEGATION_DOMAIN: &[u8] = b"COLOSSUS-AUTHORITY-DELEGATION-V1";

/// Domain separator for capability attestations
const CAPABILITY_DOMAIN: &[u8] = b"COLOSSUS-CAPABILITY-ATTESTATION-V1";

/// An authority identity with Falcon512 post-quantum signing capability.
///
/// This represents a capability authority's cryptographic identity, separate from
/// the KMAC-based internal token signing. The Falcon512 keypair is used for:
///
/// - Self-attestation (proving control of the authority key)
/// - Signing delegation certificates
/// - Creating on-chain commitments
#[derive(Clone)]
pub struct AuthorityIdentity {
    /// The Falcon512 keypair for this authority
    keypair: Falcon512Keypair,
    /// Optional metadata (e.g., authority name, organization)
    metadata: Vec<u8>,
    /// Self-signed attestation proving control of the key
    self_attestation: Option<Falcon512Signature>,
}

impl AuthorityIdentity {
    /// Create a new authority identity with a fresh Falcon512 keypair.
    pub fn new() -> Self {
        Self {
            keypair: Falcon512Keypair::new(),
            metadata: Vec::new(),
            self_attestation: None,
        }
    }

    /// Create a new authority identity with the provided RNG.
    pub fn with_rng<R: rand::Rng>(rng: &mut R) -> Self {
        Self {
            keypair: Falcon512Keypair::with_rng(rng),
            metadata: Vec::new(),
            self_attestation: None,
        }
    }

    /// Create from an existing Falcon512 keypair.
    pub fn from_keypair(keypair: Falcon512Keypair) -> Self {
        Self {
            keypair,
            metadata: Vec::new(),
            self_attestation: None,
        }
    }

    /// Set metadata for this authority.
    pub fn with_metadata(mut self, metadata: impl Into<Vec<u8>>) -> Self {
        self.metadata = metadata.into();
        self
    }

    /// Get the metadata.
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Get the public key for this authority.
    pub fn public_key(&self) -> Falcon512PublicKey {
        self.keypair.public_key()
    }

    /// Get the Poseidon2 commitment to the public key.
    ///
    /// This commitment can be stored on-chain in the Miden rollup.
    pub fn commitment(&self) -> Word {
        self.keypair.public_key_commitment()
    }

    /// Create a self-attestation proving control of this authority key.
    ///
    /// The attestation binds the public key commitment to a timestamp,
    /// proving the authority was active at that time.
    pub fn create_self_attestation(&mut self, timestamp: u64) {
        let message = self.self_attestation_message(timestamp);
        self.self_attestation = Some(self.keypair.sign(&message));
    }

    /// Verify a self-attestation.
    pub fn verify_self_attestation(&self, timestamp: u64) -> bool {
        match &self.self_attestation {
            Some(sig) => {
                let message = self.self_attestation_message(timestamp);
                self.keypair.verify(&message, sig)
            },
            None => false,
        }
    }

    /// Get the self-attestation if it exists.
    pub fn self_attestation(&self) -> Option<&Falcon512Signature> {
        self.self_attestation.as_ref()
    }

    /// Create the message to sign for self-attestation.
    fn self_attestation_message(&self, timestamp: u64) -> Word {
        let mut data = Vec::with_capacity(IDENTITY_DOMAIN.len() + 32 + 8 + self.metadata.len());
        data.extend_from_slice(IDENTITY_DOMAIN);
        data.extend_from_slice(&self.commitment()[0].as_canonical_u64().to_le_bytes());
        data.extend_from_slice(&self.commitment()[1].as_canonical_u64().to_le_bytes());
        data.extend_from_slice(&self.commitment()[2].as_canonical_u64().to_le_bytes());
        data.extend_from_slice(&self.commitment()[3].as_canonical_u64().to_le_bytes());
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&self.metadata);
        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }

    /// Sign arbitrary data with this authority's key.
    pub fn sign(&self, message: &Word) -> Falcon512Signature {
        self.keypair.sign(message)
    }

    /// Verify a signature against this authority's public key.
    pub fn verify(&self, message: &Word, signature: &Falcon512Signature) -> bool {
        self.keypair.verify(message, signature)
    }

    /// Create a delegation certificate to another authority.
    pub fn delegate(
        &self,
        delegatee: &Falcon512PublicKey,
        scope: DelegationScope,
        valid_until: Option<u64>,
    ) -> DelegationCertificate {
        DelegationCertificate::create(self, delegatee, scope, valid_until)
    }
}

impl Default for AuthorityIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AuthorityIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityIdentity")
            .field("commitment", &self.commitment())
            .field("metadata_len", &self.metadata.len())
            .field("has_self_attestation", &self.self_attestation.is_some())
            .finish()
    }
}

impl PartialEq for AuthorityIdentity {
    /// Two AuthorityIdentity instances are equal if they have the same public key commitment.
    ///
    /// This allows comparison without exposing or comparing secret key material.
    fn eq(&self, other: &Self) -> bool {
        self.commitment() == other.commitment()
            && self.metadata == other.metadata
            && self.self_attestation == other.self_attestation
    }
}

impl Eq for AuthorityIdentity {}

/// The scope of a delegation - what powers are being delegated.
#[derive(Debug, Clone)]
pub enum DelegationScope {
    /// Full authority - delegatee can do anything the delegator can do
    Full,
    /// Limited to specific access rights
    Rights(HashSet<Right>),
}

impl DelegationScope {
    /// Serialize the scope to bytes for signing and hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DelegationScope::Full => vec![0u8],
            DelegationScope::Rights(rights) => {
                let mut bytes = vec![1u8];
                for right in rights {
                    bytes.extend_from_slice(&**right);
                    bytes.push(0); // separator
                }
                bytes
            },
        }
    }
}

/// A certificate allowing one authority to delegate powers to another.
///
/// The certificate is signed by the delegator and can be verified by anyone
/// who knows the delegator's public key (or commitment).
#[derive(Debug, Clone)]
pub struct DelegationCertificate {
    /// The delegator's public key
    pub delegator_pk: Falcon512PublicKey,
    /// The delegatee's public key
    pub delegatee_pk: Falcon512PublicKey,
    /// What powers are being delegated
    pub scope: DelegationScope,
    /// Optional expiration timestamp
    pub valid_until: Option<u64>,
    /// The delegator's signature over the certificate data
    pub signature: Falcon512Signature,
}

impl DelegationCertificate {
    /// Create a new delegation certificate.
    fn create(
        delegator: &AuthorityIdentity,
        delegatee: &Falcon512PublicKey,
        scope: DelegationScope,
        valid_until: Option<u64>,
    ) -> Self {
        let delegator_pk = delegator.public_key();
        let message = Self::compute_message(&delegator_pk, delegatee, &scope, valid_until);
        let signature = delegator.sign(&message);

        Self {
            delegator_pk,
            delegatee_pk: delegatee.clone(),
            scope,
            valid_until,
            signature,
        }
    }

    /// Verify this certificate is valid.
    ///
    /// Returns `true` if:
    /// - The signature is valid
    /// - The certificate hasn't expired (if `current_time` is provided)
    pub fn verify(&self, current_time: Option<u64>) -> bool {
        // Check expiration
        if let (Some(valid_until), Some(now)) = (self.valid_until, current_time) {
            if now > valid_until {
                return false;
            }
        }

        // Verify signature
        let message = Self::compute_message(
            &self.delegator_pk,
            &self.delegatee_pk,
            &self.scope,
            self.valid_until,
        );
        self.delegator_pk.verify(&message, &self.signature)
    }

    /// Verify this certificate against an expected delegator commitment.
    ///
    /// This is useful when you only have the on-chain commitment, not the full public key.
    pub fn verify_against_commitment(
        &self,
        expected_delegator_commitment: &Word,
        current_time: Option<u64>,
    ) -> bool {
        // First check the commitment matches
        if &self.delegator_pk.commitment() != expected_delegator_commitment {
            return false;
        }
        self.verify(current_time)
    }

    /// Get the delegatee's commitment for on-chain verification.
    pub fn delegatee_commitment(&self) -> Word {
        self.delegatee_pk.commitment()
    }

    /// Compute the message to sign for the certificate.
    fn compute_message(
        delegator_pk: &Falcon512PublicKey,
        delegatee_pk: &Falcon512PublicKey,
        scope: &DelegationScope,
        valid_until: Option<u64>,
    ) -> Word {
        let mut data = Vec::new();
        data.extend_from_slice(DELEGATION_DOMAIN);

        // Include delegator commitment
        let delegator_commitment = delegator_pk.commitment();
        for felt in delegator_commitment.iter() {
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        // Include delegatee commitment
        let delegatee_commitment = delegatee_pk.commitment();
        for felt in delegatee_commitment.iter() {
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        // Include scope
        data.extend_from_slice(&scope.to_bytes());

        // Include expiration
        match valid_until {
            Some(ts) => {
                data.push(1);
                data.extend_from_slice(&ts.to_le_bytes());
            },
            None => data.push(0),
        }

        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }
}

/// An attestation binding a capability token to an authority.
///
/// This allows external parties to verify that a capability token was
/// issued by a specific authority without having access to the authority's
/// internal KMAC key.
#[derive(Debug, Clone)]
pub struct CapabilityAttestation {
    /// The authority's public key that issued this attestation
    pub authority_pk: Falcon512PublicKey,
    /// Commitment to the capability token (hash of token data)
    pub token_commitment: Word,
    /// When this attestation was created
    pub timestamp: u64,
    /// The authority's signature
    pub signature: Falcon512Signature,
}

impl CapabilityAttestation {
    /// Create a new capability attestation.
    ///
    /// The `token_commitment` should be a Poseidon2 hash of the capability token's
    /// identifying data (id, access rights, etc.).
    pub fn create(authority: &AuthorityIdentity, token_commitment: Word, timestamp: u64) -> Self {
        let authority_pk = authority.public_key();
        let message = Self::compute_message(&authority_pk, &token_commitment, timestamp);
        let signature = authority.sign(&message);

        Self {
            authority_pk,
            token_commitment,
            timestamp,
            signature,
        }
    }

    /// Verify this attestation.
    pub fn verify(&self) -> bool {
        let message =
            Self::compute_message(&self.authority_pk, &self.token_commitment, self.timestamp);
        self.authority_pk.verify(&message, &self.signature)
    }

    /// Verify this attestation against an expected authority commitment.
    pub fn verify_against_commitment(&self, expected_authority_commitment: &Word) -> bool {
        if &self.authority_pk.commitment() != expected_authority_commitment {
            return false;
        }
        self.verify()
    }

    /// Compute the message to sign.
    fn compute_message(
        authority_pk: &Falcon512PublicKey,
        token_commitment: &Word,
        timestamp: u64,
    ) -> Word {
        let mut data = Vec::new();
        data.extend_from_slice(CAPABILITY_DOMAIN);

        // Authority commitment
        let auth_commitment = authority_pk.commitment();
        for felt in auth_commitment.iter() {
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        // Token commitment
        for felt in token_commitment.iter() {
            data.extend_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }

        // Timestamp
        data.extend_from_slice(&timestamp.to_le_bytes());

        Poseidon2Hash::hash_bytes(&data).as_word().clone()
    }
}

/// A chain of delegation certificates forming a trust path.
///
/// This allows verification that an authority has been delegated powers
/// through a chain of certificates back to a root authority.
#[derive(Debug, Clone)]
pub struct DelegationChain {
    /// The root authority's public key (or commitment)
    pub root_commitment: Word,
    /// The chain of certificates from root to leaf
    pub certificates: Vec<DelegationCertificate>,
}

impl DelegationChain {
    /// Create a new delegation chain starting from a root commitment.
    pub fn new(root_commitment: Word) -> Self {
        Self {
            root_commitment,
            certificates: Vec::new(),
        }
    }

    /// Add a certificate to the chain.
    pub fn add_certificate(&mut self, cert: DelegationCertificate) {
        self.certificates.push(cert);
    }

    /// Verify the entire chain.
    ///
    /// Returns `true` if:
    /// - The first certificate's delegator matches the root commitment
    /// - Each certificate's delegatee matches the next certificate's delegator
    /// - All certificates are valid (signatures check out, not expired)
    pub fn verify(&self, current_time: Option<u64>) -> bool {
        if self.certificates.is_empty() {
            return true; // Empty chain is trivially valid
        }

        // First certificate must be from the root
        let first = &self.certificates[0];
        if first.delegator_pk.commitment() != self.root_commitment {
            return false;
        }
        if !first.verify(current_time) {
            return false;
        }

        // Each subsequent certificate must chain properly
        for i in 1..self.certificates.len() {
            let prev = &self.certificates[i - 1];
            let curr = &self.certificates[i];

            // Delegator of current must be delegatee of previous
            if curr.delegator_pk.commitment() != prev.delegatee_pk.commitment() {
                return false;
            }
            if !curr.verify(current_time) {
                return false;
            }
        }

        true
    }

    /// Get the final delegatee's commitment (the leaf of the chain).
    pub fn leaf_commitment(&self) -> Option<Word> {
        self.certificates.last().map(|c| c.delegatee_commitment())
    }

    /// Get the length of the chain.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }
}

// ================================================================================================
// SERIALIZATION
// ================================================================================================

/// Helper to serialize a Word (4 field elements) to bytes
fn write_word(ser: &mut Serializer, word: &Word) -> Result<usize, Error> {
    let mut n = 0;
    for felt in word.iter() {
        n += ser.write_leb128_u64(felt.as_canonical_u64())?;
    }
    Ok(n)
}

/// Helper to deserialize a Word from bytes
fn read_word(de: &mut Deserializer) -> Result<Word, Error> {
    use miden_crypto::Felt;
    let mut felts = [Felt::ZERO; 4];
    for i in 0..4 {
        felts[i] = Felt::new(de.read_leb128_u64()?);
    }
    Ok(Word::new(felts))
}

/// Helper to get the length of a serialized Word
fn word_length() -> usize {
    // Each Felt is at most 8 bytes when LEB128 encoded (for 64-bit values)
    // Average case is around 5-6 bytes each
    4 * 10 // Conservative estimate
}

impl Serializable for DelegationScope {
    type Error = Error;

    fn length(&self) -> usize {
        match self {
            DelegationScope::Full => 1,
            DelegationScope::Rights(rights) => {
                1 + to_leb128_len(rights.len())
                    + rights.iter().map(|r| to_leb128_len(r.len()) + r.len()).sum::<usize>()
            },
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            DelegationScope::Full => ser.write_leb128_u64(0).map_err(Into::into),
            DelegationScope::Rights(rights) => {
                let mut n = ser.write_leb128_u64(1)?;
                n += ser.write_leb128_u64(rights.len() as u64)?;
                for right in rights {
                    n += ser.write_vec(&**right)?;
                }
                Ok(n)
            },
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let tag = de.read_leb128_u64()?;
        match tag {
            0 => Ok(DelegationScope::Full),
            1 => {
                let n_rights = de.read_leb128_u64()? as usize;
                let mut rights = HashSet::with_capacity(n_rights);
                for _ in 0..n_rights {
                    let bytes = de.read_vec()?;
                    rights.insert(Right::from(bytes.as_slice()));
                }
                Ok(DelegationScope::Rights(rights))
            },
            _ => Err(Error::ConversionFailed(format!("invalid DelegationScope tag: {}", tag))),
        }
    }
}

impl Serializable for CapabilityAttestation {
    type Error = Error;

    fn length(&self) -> usize {
        let pk_bytes = self.authority_pk.to_bytes();
        let sig_bytes = self.signature.to_bytes();
        to_leb128_len(pk_bytes.len())
            + pk_bytes.len()
            + word_length()
            + 8 // timestamp
            + to_leb128_len(sig_bytes.len())
            + sig_bytes.len()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let pk_bytes = self.authority_pk.to_bytes();
        let sig_bytes = self.signature.to_bytes();

        let mut n = ser.write_vec(&pk_bytes)?;
        n += write_word(ser, &self.token_commitment)?;
        n += ser.write_leb128_u64(self.timestamp)?;
        n += ser.write_vec(&sig_bytes)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let pk_bytes = de.read_vec()?;
        let authority_pk = Falcon512PublicKey::from_bytes(&pk_bytes).map_err(|e| {
            Error::ConversionFailed(format!("failed to deserialize authority public key: {}", e))
        })?;

        let token_commitment = read_word(de)?;
        let timestamp = de.read_leb128_u64()?;

        let sig_bytes = de.read_vec()?;
        let signature = Falcon512Signature::from_bytes(&sig_bytes).map_err(|e| {
            Error::ConversionFailed(format!("failed to deserialize signature: {}", e))
        })?;

        Ok(Self {
            authority_pk,
            token_commitment,
            timestamp,
            signature,
        })
    }
}

impl Serializable for DelegationCertificate {
    type Error = Error;

    fn length(&self) -> usize {
        let delegator_pk_bytes = self.delegator_pk.to_bytes();
        let delegatee_pk_bytes = self.delegatee_pk.to_bytes();
        let sig_bytes = self.signature.to_bytes();

        to_leb128_len(delegator_pk_bytes.len())
            + delegator_pk_bytes.len()
            + to_leb128_len(delegatee_pk_bytes.len())
            + delegatee_pk_bytes.len()
            + self.scope.length()
            + 1  // has_expiration flag
            + if self.valid_until.is_some() { 8 } else { 0 }
            + to_leb128_len(sig_bytes.len())
            + sig_bytes.len()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let delegator_pk_bytes = self.delegator_pk.to_bytes();
        let delegatee_pk_bytes = self.delegatee_pk.to_bytes();
        let sig_bytes = self.signature.to_bytes();

        let mut n = ser.write_vec(&delegator_pk_bytes)?;
        n += ser.write_vec(&delegatee_pk_bytes)?;
        n += self.scope.write(ser)?;

        match self.valid_until {
            Some(ts) => {
                n += ser.write_leb128_u64(1)?;
                n += ser.write_leb128_u64(ts)?;
            },
            None => {
                n += ser.write_leb128_u64(0)?;
            },
        }

        n += ser.write_vec(&sig_bytes)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let delegator_pk_bytes = de.read_vec()?;
        let delegator_pk = Falcon512PublicKey::from_bytes(&delegator_pk_bytes).map_err(|e| {
            Error::ConversionFailed(format!("failed to deserialize delegator public key: {}", e))
        })?;

        let delegatee_pk_bytes = de.read_vec()?;
        let delegatee_pk = Falcon512PublicKey::from_bytes(&delegatee_pk_bytes).map_err(|e| {
            Error::ConversionFailed(format!("failed to deserialize delegatee public key: {}", e))
        })?;

        let scope = DelegationScope::read(de)?;

        let has_expiration = de.read_leb128_u64()? != 0;
        let valid_until = if has_expiration {
            Some(de.read_leb128_u64()?)
        } else {
            None
        };

        let sig_bytes = de.read_vec()?;
        let signature = Falcon512Signature::from_bytes(&sig_bytes).map_err(|e| {
            Error::ConversionFailed(format!("failed to deserialize signature: {}", e))
        })?;

        Ok(Self {
            delegator_pk,
            delegatee_pk,
            scope,
            valid_until,
            signature,
        })
    }
}

impl Serializable for DelegationChain {
    type Error = Error;

    fn length(&self) -> usize {
        word_length()
            + to_leb128_len(self.certificates.len())
            + self.certificates.iter().map(|c| c.length()).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = write_word(ser, &self.root_commitment)?;
        n += ser.write_leb128_u64(self.certificates.len() as u64)?;
        for cert in &self.certificates {
            n += cert.write(ser)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let root_commitment = read_word(de)?;
        let n_certs = de.read_leb128_u64()? as usize;
        let mut certificates = Vec::with_capacity(n_certs);
        for _ in 0..n_certs {
            certificates.push(DelegationCertificate::read(de)?);
        }
        Ok(Self { root_commitment, certificates })
    }
}

impl Serializable for AuthorityIdentity {
    type Error = Error;

    fn length(&self) -> usize {
        let sk_bytes = self.keypair.secret_key_bytes();
        let sig_bytes = self.self_attestation.as_ref().map(|s| s.to_bytes());

        to_leb128_len(sk_bytes.len())
            + sk_bytes.len()
            + to_leb128_len(self.metadata.len())
            + self.metadata.len()
            + 1  // has_attestation flag
            + sig_bytes.map_or(0, |s| to_leb128_len(s.len()) + s.len())
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let sk_bytes = self.keypair.secret_key_bytes();

        let mut n = ser.write_vec(&sk_bytes)?;
        n += ser.write_vec(&self.metadata)?;

        match &self.self_attestation {
            Some(sig) => {
                let sig_bytes = sig.to_bytes();
                n += ser.write_leb128_u64(1)?;
                n += ser.write_vec(&sig_bytes)?;
            },
            None => {
                n += ser.write_leb128_u64(0)?;
            },
        }

        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let sk_bytes = de.read_vec()?;
        let keypair = Falcon512Keypair::from_secret_key_bytes(&sk_bytes).map_err(|e| {
            Error::ConversionFailed(format!("failed to deserialize authority keypair: {}", e))
        })?;

        let metadata = de.read_vec()?;

        let has_attestation = de.read_leb128_u64()? != 0;
        let self_attestation = if has_attestation {
            let sig_bytes = de.read_vec()?;
            Some(Falcon512Signature::from_bytes(&sig_bytes).map_err(|e| {
                Error::ConversionFailed(format!("failed to deserialize self-attestation: {}", e))
            })?)
        } else {
            None
        };

        Ok(Self { keypair, metadata, self_attestation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([42u8; 32])
    }

    #[test]
    fn test_authority_identity_creation() {
        let mut rng = test_rng();
        let authority = AuthorityIdentity::with_rng(&mut rng);

        // Should have a valid commitment
        let commitment = authority.commitment();
        assert_ne!(commitment, Word::default());

        // Should not have self-attestation yet
        assert!(authority.self_attestation().is_none());
    }

    #[test]
    fn test_self_attestation() {
        let mut rng = test_rng();
        let mut authority = AuthorityIdentity::with_rng(&mut rng);
        let timestamp = 1234567890u64;

        // Create self-attestation
        authority.create_self_attestation(timestamp);
        assert!(authority.self_attestation().is_some());

        // Verify with correct timestamp
        assert!(authority.verify_self_attestation(timestamp));

        // Verify with wrong timestamp should fail
        assert!(!authority.verify_self_attestation(timestamp + 1));
    }

    #[test]
    fn test_authority_with_metadata() {
        let mut rng = test_rng();
        let authority = AuthorityIdentity::with_rng(&mut rng).with_metadata(b"Test Authority");

        assert_eq!(authority.metadata(), b"Test Authority");
    }

    #[test]
    fn test_delegation_certificate() {
        let mut rng = test_rng();
        let delegator = AuthorityIdentity::with_rng(&mut rng);
        let delegatee = AuthorityIdentity::with_rng(&mut rng);

        let cert =
            delegator.delegate(&delegatee.public_key(), DelegationScope::Full, Some(1000000));

        // Should verify with current time before expiration
        assert!(cert.verify(Some(500000)));

        // Should fail after expiration
        assert!(!cert.verify(Some(2000000)));

        // Should verify against correct commitment
        assert!(cert.verify_against_commitment(&delegator.commitment(), Some(500000)));

        // Should fail against wrong commitment
        let wrong_commitment = delegatee.commitment();
        assert!(!cert.verify_against_commitment(&wrong_commitment, Some(500000)));
    }

    #[test]
    fn test_delegation_chain() {
        let mut rng = test_rng();
        let root = AuthorityIdentity::with_rng(&mut rng);
        let intermediate = AuthorityIdentity::with_rng(&mut rng);
        let leaf = AuthorityIdentity::with_rng(&mut rng);

        // Root delegates to intermediate
        let cert1 = root.delegate(&intermediate.public_key(), DelegationScope::Full, None);

        // Intermediate delegates to leaf
        let cert2 = intermediate.delegate(&leaf.public_key(), DelegationScope::Full, None);

        // Build and verify chain
        let mut chain = DelegationChain::new(root.commitment());
        chain.add_certificate(cert1);
        chain.add_certificate(cert2);

        assert!(chain.verify(None));
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.leaf_commitment(), Some(leaf.commitment()));
    }

    #[test]
    fn test_invalid_delegation_chain() {
        let mut rng = test_rng();
        let root = AuthorityIdentity::with_rng(&mut rng);
        let intermediate = AuthorityIdentity::with_rng(&mut rng);
        let unrelated = AuthorityIdentity::with_rng(&mut rng);
        let leaf = AuthorityIdentity::with_rng(&mut rng);

        // Root delegates to intermediate
        let cert1 = root.delegate(&intermediate.public_key(), DelegationScope::Full, None);

        // Unrelated (not intermediate!) delegates to leaf - this breaks the chain
        let cert2 = unrelated.delegate(&leaf.public_key(), DelegationScope::Full, None);

        let mut chain = DelegationChain::new(root.commitment());
        chain.add_certificate(cert1);
        chain.add_certificate(cert2);

        // Chain should not verify because cert2's delegator is not cert1's delegatee
        assert!(!chain.verify(None));
    }

    #[test]
    fn test_capability_attestation() {
        let mut rng = test_rng();
        let authority = AuthorityIdentity::with_rng(&mut rng);

        // Create a mock token commitment
        let token_commitment =
            Poseidon2Hash::hash_bytes(b"test-capability-token").as_word().clone();

        let timestamp = 1234567890u64;
        let attestation = CapabilityAttestation::create(&authority, token_commitment, timestamp);

        // Should verify
        assert!(attestation.verify());

        // Should verify against correct commitment
        assert!(attestation.verify_against_commitment(&authority.commitment()));

        // Should fail against wrong commitment
        let other_authority = AuthorityIdentity::with_rng(&mut rng);
        assert!(!attestation.verify_against_commitment(&other_authority.commitment()));
    }

    #[test]
    fn test_scoped_delegation() {
        let mut rng = test_rng();
        let delegator = AuthorityIdentity::with_rng(&mut rng);
        let delegatee = AuthorityIdentity::with_rng(&mut rng);

        let mut rights = HashSet::new();
        rights.insert(Right::from("Department::Engineering".as_bytes()));
        rights.insert(Right::from("Level::Senior".as_bytes()));

        let cert =
            delegator.delegate(&delegatee.public_key(), DelegationScope::Rights(rights), None);

        assert!(cert.verify(None));
    }

    // ============================================================================
    // Serialization Tests
    // ============================================================================

    #[test]
    fn test_authority_identity_serialization() {
        let mut rng = test_rng();
        let mut authority = AuthorityIdentity::with_rng(&mut rng).with_metadata(b"Test Authority");
        let timestamp = 1234567890u64;
        authority.create_self_attestation(timestamp);

        // Serialize
        let bytes = authority.serialize().expect("serialization failed");
        assert!(!bytes.is_empty());

        // Deserialize
        let restored = AuthorityIdentity::deserialize(&bytes).expect("deserialization failed");

        // Verify same commitment
        assert_eq!(authority.commitment(), restored.commitment());

        // Verify metadata preserved
        assert_eq!(authority.metadata(), restored.metadata());

        // Verify self-attestation works
        assert!(restored.verify_self_attestation(timestamp));
    }

    #[test]
    fn test_delegation_scope_serialization() {
        // Test Full scope
        let full = DelegationScope::Full;
        let bytes = full.serialize().expect("serialization failed");
        let restored = DelegationScope::deserialize(&bytes).expect("deserialization failed");
        assert!(matches!(restored, DelegationScope::Full));

        // Test Rights scope
        let mut rights = HashSet::new();
        rights.insert(Right::from("test::right1".as_bytes()));
        rights.insert(Right::from("test::right2".as_bytes()));
        let rights_scope = DelegationScope::Rights(rights.clone());
        let bytes = rights_scope.serialize().expect("serialization failed");
        let restored = DelegationScope::deserialize(&bytes).expect("deserialization failed");
        if let DelegationScope::Rights(restored_rights) = restored {
            assert_eq!(restored_rights.len(), 2);
        } else {
            panic!("expected DelegationScope::Rights");
        }
    }

    #[test]
    fn test_delegation_certificate_serialization() {
        let mut rng = test_rng();
        let delegator = AuthorityIdentity::with_rng(&mut rng);
        let delegatee = AuthorityIdentity::with_rng(&mut rng);

        let cert =
            delegator.delegate(&delegatee.public_key(), DelegationScope::Full, Some(2000000));

        // Serialize
        let bytes = cert.serialize().expect("serialization failed");
        assert!(!bytes.is_empty());

        // Deserialize
        let restored = DelegationCertificate::deserialize(&bytes).expect("deserialization failed");

        // Verify same commitments
        assert_eq!(cert.delegator_pk.commitment(), restored.delegator_pk.commitment());
        assert_eq!(cert.delegatee_pk.commitment(), restored.delegatee_pk.commitment());

        // Verify still valid
        assert!(restored.verify(Some(1000000)));
        assert!(!restored.verify(Some(3000000))); // expired
    }

    #[test]
    fn test_delegation_chain_serialization() {
        let mut rng = test_rng();
        let root = AuthorityIdentity::with_rng(&mut rng);
        let intermediate = AuthorityIdentity::with_rng(&mut rng);
        let leaf = AuthorityIdentity::with_rng(&mut rng);

        let cert1 = root.delegate(&intermediate.public_key(), DelegationScope::Full, None);
        let cert2 = intermediate.delegate(&leaf.public_key(), DelegationScope::Full, None);

        let mut chain = DelegationChain::new(root.commitment());
        chain.add_certificate(cert1);
        chain.add_certificate(cert2);

        // Serialize
        let bytes = chain.serialize().expect("serialization failed");
        assert!(!bytes.is_empty());

        // Deserialize
        let restored = DelegationChain::deserialize(&bytes).expect("deserialization failed");

        // Verify same structure
        assert_eq!(chain.root_commitment, restored.root_commitment);
        assert_eq!(chain.len(), restored.len());

        // Verify chain still validates
        assert!(restored.verify(None));
        assert_eq!(restored.leaf_commitment(), Some(leaf.commitment()));
    }

    #[test]
    fn test_capability_attestation_serialization() {
        let mut rng = test_rng();
        let authority = AuthorityIdentity::with_rng(&mut rng);

        let token_commitment =
            Poseidon2Hash::hash_bytes(b"test-capability-token").as_word().clone();

        let attestation =
            CapabilityAttestation::create(&authority, token_commitment.clone(), 1234567890);

        // Serialize
        let bytes = attestation.serialize().expect("serialization failed");
        assert!(!bytes.is_empty());

        // Deserialize
        let restored = CapabilityAttestation::deserialize(&bytes).expect("deserialization failed");

        // Verify same data
        assert_eq!(attestation.token_commitment, restored.token_commitment);
        assert_eq!(attestation.timestamp, restored.timestamp);
        assert_eq!(attestation.authority_pk.commitment(), restored.authority_pk.commitment());

        // Verify still valid
        assert!(restored.verify());
    }

    #[test]
    fn test_serialized_authority_retains_functionality() {
        let mut rng = test_rng();
        let mut authority = AuthorityIdentity::with_rng(&mut rng);
        let timestamp = 1234567890u64;
        authority.create_self_attestation(timestamp);

        // Serialize and deserialize
        let bytes = authority.serialize().expect("serialization failed");
        let restored = AuthorityIdentity::deserialize(&bytes).expect("deserialization failed");

        // Restored authority should have same commitment
        assert_eq!(authority.commitment(), restored.commitment());

        // Self-attestation should still verify
        assert!(restored.verify_self_attestation(timestamp));

        // Should be able to sign and verify new messages
        let message = Poseidon2Hash::hash_bytes(b"test message").as_word().clone();
        let sig = restored.sign(&message);
        assert!(restored.verify(&message, &sig));

        // Original should also be able to verify the restored's signature
        assert!(authority.verify(&message, &sig));
    }
}
