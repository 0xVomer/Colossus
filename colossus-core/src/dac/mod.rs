//! Delegatable Anonymous Credentials (DAC) Module
//!
//! This module implements a privacy-preserving credential system based on
//! Structure-Preserving Signatures on Equivalence Classes (SPSEQ-UC).
//!
//! # Features
//!
//! - **Anonymous credentials**: Users can prove attributes without revealing identity
//! - **Selective disclosure**: Reveal only the attributes needed for a specific context
//! - **Delegation**: Credentials can be delegated to create sub-credentials
//! - **Unlinkability**: Multiple uses of the same credential cannot be linked
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │   Issuer    │────▶│ Credential  │────▶│   Verifier  │
//! │             │     │   Holder    │     │             │
//! └─────────────┘     └─────────────┘     └─────────────┘
//!       │                    │                   │
//!       │   Issue cred       │   Present proof   │
//!       └────────────────────┴───────────────────┘
//! ```
//!
//! # Cryptographic Primitives
//!
//! - **BLS12-381**: Pairing-friendly elliptic curve
//! - **Set Commitments**: Commit to sets of attributes
//! - **Zero-Knowledge Proofs**: Prove knowledge without revealing values
//!
//! # Privacy Model
//!
//! All attributes in this module are **blinded** using Poseidon2 commitments.
//! The system never processes plaintext attribute values - only cryptographic
//! commitments that hide the actual values while allowing zero-knowledge proofs.
//!
//! # Security Notes
//!
//! - The underlying BLS12-381 curve provides 128-bit classical security
//! - BLS12-381 is NOT post-quantum secure (vulnerable to Shor's algorithm)
//! - Attribute blinding uses Poseidon2 which is believed to be PQ-secure
//! - See `docs/POST_QUANTUM_MIGRATION.md` for the migration strategy

pub mod builder;
pub mod ec;
pub mod entry;
pub mod error;
pub mod keypair;
pub mod keys;
pub mod set_commits;
pub mod utils;
pub mod zkp;

/// Default maximum number of attribute entries in a credential.
pub const DEFAULT_MAX_ENTRIES: usize = 6;

/// Default maximum number of attributes per entry (cardinality).
pub const DEFAULT_MAX_CARDINALITY: usize = 8;

/// Name for the Schnorr challenge state in ZKP protocols.
pub const CHALLENGE_STATE_NAME: &str = "schnorr";

/// A set of blinded attributes for credential issuance.
///
/// Blinded attributes are Poseidon2 commitments to (dimension, name, issuer_pk, authority_pk, salt)
/// tuples. The actual attribute values are never revealed - only the cryptographic commitments.
pub type Attributes = entry::Entry<crate::policy::BlindedAttribute>;

/// A set of access rights derived from blinded attributes.
///
/// Access rights are computed from blinded attribute commitments and are used
/// for capability-based access control.
pub type AccessRights = entry::Entry<crate::policy::Right>;

impl entry::Attribute for crate::policy::BlindedAttribute {
    fn digest(&self) -> &[u8] {
        self.commitment_bytes()
    }
}

impl entry::Attribute for crate::policy::Right {
    fn digest(&self) -> &[u8] {
        &self.0
    }
}
