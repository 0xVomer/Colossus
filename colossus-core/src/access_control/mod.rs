//! Access Control Module
//!
//! This module provides capability-based access control with privacy-preserving
//! blinded attributes. The authority never sees actual attribute values, only
//! Poseidon2 commitments verified through Falcon512 signatures.
//!
//! # Architecture
//!
//! The access control system consists of:
//!
//! - **Capability Authority**: Issues and manages access capabilities using blinded mode
//! - **Access Capabilities**: Tokens that grant access to protected resources
//! - **Blinded Attributes**: Privacy-preserving attribute commitments
//! - **Encrypted Headers**: Encrypted metadata attached to protected content
//!
//! # Usage
//!
//! ```ignore
//! use colossus_core::access_control::{AccessControl, CapabilityAuthority};
//!
//! // Create an access control instance
//! let ac = AccessControl::default();
//!
//! // Setup a capability authority with blinded mode
//! let auth = ac.setup_blinded_authority()?;
//!
//! // Grant capabilities based on blinded claims
//! let capability = ac.grant_blinded_capability(&mut auth, &claims)?;
//! ```
//!
//! # Security Model
//!
//! - All attributes are stored as Poseidon2 commitments (authority never sees values)
//! - Issuers vouch for attributes through Falcon512 post-quantum signatures
//! - Same attributes can have different commitments (unlinkable)
//! - Tracing capabilities allow auditing without compromising anonymity

pub mod capability;
/// Cryptographic primitives for access control (Poseidon2 AEAD, ML-KEM, ElGamal NIKE)
pub mod cryptography;
pub mod encrypted_header;
/// SMT-based revocation registry for ZK-compatible capability revocation
pub mod revocation;
mod test_utils;

use crate::{
    access_control::cryptography::{MIN_TRACING_LEVEL, SHARED_SECRET_LENGTH, XEnc},
    policy::Error,
};
pub use capability::{
    AccessCapabilityId, AccessCapabilityToken, AccessRightPublicKey, AccessRightSecretKey,
    AuthorityIdentity, BlindedCapabilityClaim, CapabilityAttestation, CapabilityAuthority,
    CapabilityAuthorityPublicKey, DelegationCertificate, DelegationChain, DelegationScope,
    TracingPublicKey, create_blinded_capability_token, create_unsafe_capability_token,
    prune_capability_authority, refresh_capability_authority, refresh_capability_token,
    update_capability_authority,
};
use cosmian_crypto_core::{CsRng, Secret, reexport::rand_core::SeedableRng};
pub use encrypted_header::EncryptedHeader;
pub use revocation::{
    AttestedRevocationProof, CapabilityId, RevocationAttestation, RevocationProof,
    RevocationRegistry,
};
use std::sync::{Mutex, MutexGuard};

/// Main entry point for access control operations.
///
/// `AccessControl` provides a thread-safe interface for managing capability-based
/// access control. It wraps a cryptographically secure random number generator
/// and provides methods for:
///
/// - Setting up capability authorities
/// - Granting access capabilities
/// - Encrypting and decrypting content with access policies
///
/// # Thread Safety
///
/// All methods are thread-safe. The internal RNG is protected by a mutex.
///
/// # Example
///
/// ```ignore
/// use colossus_core::access_control::AccessControl;
///
/// let ac = AccessControl::default();
/// let (authority, public_key) = ac.setup_capability_authority()?;
/// ```
#[derive(Debug)]
pub struct AccessControl {
    rng: Mutex<CsRng>,
}

impl Default for AccessControl {
    fn default() -> Self {
        Self { rng: Mutex::new(CsRng::from_entropy()) }
    }
}

impl AccessControl {
    /// Acquires the RNG mutex lock.
    ///
    /// # Errors
    /// Returns `Error::MutexPoisoned` if the mutex has been poisoned.
    fn lock_rng(&self) -> Result<MutexGuard<'_, CsRng>, Error> {
        self.rng.lock().map_err(|_| Error::MutexPoisoned)
    }

    /// Sets up a new capability authority for blinded mode.
    ///
    /// Creates a new `CapabilityAuthority` with tracing capabilities enabled.
    /// The authority must then be initialized with `init_blinded_structure()`
    /// before registering issuers and granting capabilities.
    ///
    /// # Returns
    ///
    /// A new `CapabilityAuthority` ready for blinded mode initialization.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The RNG mutex is poisoned
    /// - Key generation fails
    pub fn setup_blinded_authority(&self) -> Result<CapabilityAuthority, Error> {
        let mut rng = self.lock_rng()?;
        CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut *rng)
    }

    /// Grants a capability token based on blinded access claims.
    ///
    /// This is the privacy-preserving equivalent of `grant_capability`. Instead of
    /// verifying DAC credential proofs with visible attributes, it verifies
    /// ownership proofs for blinded attribute commitments.
    ///
    /// # Privacy Properties
    ///
    /// - Authority never sees actual attribute values (only Poseidon2 commitments)
    /// - Issuers vouch for attributes through Falcon512 signatures
    /// - Same attribute can have different commitments (unlinkable)
    ///
    /// # Arguments
    ///
    /// * `auth` - Mutable reference to the capability authority (must be in blinded mode)
    /// * `claims` - Slice of blinded capability claims with ownership proofs
    ///
    /// # Returns
    ///
    /// An `AccessCapabilityToken` that can be used to decrypt protected content.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The authority is not in blinded mode (call `init_blinded_structure` first)
    /// - The ownership proofs are invalid
    /// - The issuer is not registered
    /// - The RNG mutex is poisoned
    pub fn grant_blinded_capability(
        &self,
        auth: &mut CapabilityAuthority,
        claims: &[BlindedCapabilityClaim],
    ) -> Result<AccessCapabilityToken, Error> {
        create_blinded_capability_token(&mut *self.lock_rng()?, auth, claims)
    }

    /// Registers a blinded issuer with the capability authority.
    ///
    /// This is the privacy-preserving equivalent of `register_issuer`. Instead of
    /// registering an `IssuerPublic` with a plaintext access structure, it registers
    /// an `IssuerRegistration` that only contains the issuer's Falcon512 public key.
    ///
    /// # Arguments
    ///
    /// * `auth` - Mutable reference to the capability authority (must be in blinded mode)
    /// * `registration` - The issuer's registration with this authority
    /// * `issuer_public_key` - The issuer's Falcon512 public key for verification
    ///
    /// # Returns
    ///
    /// The issuer ID (1-indexed) for use in `BlindedCapabilityClaim`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The authority is not in blinded mode
    /// - The registration signature is invalid
    /// - The registration is for a different authority
    pub fn register_blinded_issuer(
        &self,
        auth: &mut CapabilityAuthority,
        registration: crate::policy::IssuerRegistration,
        issuer_public_key: crate::crypto::Falcon512PublicKey,
    ) -> Result<usize, Error> {
        auth.register_blinded_issuer(registration, issuer_public_key, &mut *self.lock_rng()?)
    }

    /// Adds a blinded attribute to the authority's structure.
    ///
    /// This is called during setup to populate the blinded access structure with
    /// attributes provided by registered issuers. The authority sees only the
    /// Poseidon2 commitment, never the actual attribute value.
    ///
    /// # Arguments
    ///
    /// * `auth` - Mutable reference to the capability authority (must be in blinded mode)
    /// * `dimension_commitment` - The dimension to add the attribute to
    /// * `blinded_attr` - The blinded attribute commitment
    /// * `proof` - Ownership proof from the issuer
    /// * `timestamp` - When the attribute was added
    ///
    /// # Returns
    ///
    /// The attribute ID within the structure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The authority is not in blinded mode
    /// - The issuer is not registered
    /// - The ownership proof is invalid
    pub fn add_blinded_attribute(
        &self,
        auth: &mut CapabilityAuthority,
        dimension_commitment: &crate::policy::DimensionCommitment,
        blinded_attr: crate::policy::BlindedAttribute,
        proof: &crate::policy::AttributeOwnershipProof,
        timestamp: u64,
    ) -> Result<usize, Error> {
        auth.add_blinded_attribute(
            dimension_commitment,
            blinded_attr,
            proof,
            timestamp,
            &mut *self.lock_rng()?,
        )
    }

    pub fn refresh_capability(
        &self,
        auth: &mut CapabilityAuthority,
        cap_token: &mut AccessCapabilityToken,
        keep_old_secrets: bool,
    ) -> Result<(), Error> {
        refresh_capability_token(&mut *self.lock_rng()?, auth, cap_token, keep_old_secrets)
    }

    /// Re-encapsulates a shared secret for a new recipient.
    ///
    /// Given an existing encapsulation, this method decapsulates it using the authority's
    /// secret key and re-encapsulates for the same set of rights using the provided
    /// public key.
    ///
    /// # Arguments
    ///
    /// * `auth` - The capability authority with decryption capability
    /// * `pk` - The public key to re-encapsulate for
    /// * `encapsulation` - The existing encapsulation to transform
    ///
    /// # Returns
    ///
    /// A tuple of the new shared secret and new encapsulation.
    pub fn recaps(
        &self,
        auth: &CapabilityAuthority,
        pk: &CapabilityAuthorityPublicKey,
        encapsulation: &XEnc,
    ) -> Result<(Secret<32>, XEnc), Error> {
        let (_ss, rights) = auth.decapsulate(encapsulation)?;
        pk.encapsulate(&mut *self.lock_rng()?, &rights)
    }

    /// Encapsulates a shared secret for a set of access rights.
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to encapsulate for
    /// * `rights` - The set of access rights to encrypt for
    ///
    /// # Returns
    ///
    /// A tuple of the shared secret and encapsulation.
    pub fn encapsulate_for_rights(
        &self,
        pk: &CapabilityAuthorityPublicKey,
        rights: &std::collections::HashSet<crate::policy::Right>,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
        pk.encapsulate(&mut *self.lock_rng()?, rights)
    }

    /// Decapsulates a shared secret using a capability token.
    ///
    /// # Arguments
    ///
    /// * `token` - The capability token with decryption rights
    /// * `encapsulation` - The encapsulation to open
    ///
    /// # Returns
    ///
    /// The shared secret if the token has matching rights, None otherwise.
    pub fn decapsulate(
        &self,
        token: &AccessCapabilityToken,
        encapsulation: &XEnc,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        token.decapsulate(&mut *self.lock_rng()?, encapsulation)
    }
}
