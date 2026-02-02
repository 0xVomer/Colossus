//! # Colossus Core
//!
//! Privacy-aware capability-based security framework.
//!
//! Colossus provides a comprehensive security framework combining:
//!
//! - **Delegatable Anonymous Credentials (DAC)**: Privacy-preserving identity verification
//! - **Capability-Based Access Control**: Fine-grained permission management
//! - **Attribute-Based Encryption**: Content encryption based on user attributes
//!
//! # Quick Start
//!
//! ```ignore
//! use colossus_core::prelude::*;
//!
//! // 1. Create an access control instance
//! let ac = AccessControl::default();
//!
//! // 2. Setup a capability authority
//! let (auth, public_key) = ac.setup_capability_authority()?;
//!
//! // 3. Issue credentials to users (via DAC module)
//! // 4. Grant capabilities based on verified credentials
//! // 5. Encrypt content with access policies
//! ```
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Colossus Core                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
//! │  │    DAC      │  │   Access    │  │   Policy    │             │
//! │  │ Credentials │  │   Control   │  │  Framework  │             │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
//! │         │                │                │                     │
//! │         └────────────────┼────────────────┘                     │
//! │                          │                                      │
//! │  ┌───────────────────────┴───────────────────────┐             │
//! │  │              Crypto Layer                      │             │
//! │  │  ┌─────────────────┐  ┌──────────────────┐    │             │
//! │  │  │ Poseidon2 AEAD  │  │   BLS12-381      │    │             │
//! │  │  │ (miden-crypto)  │  │   Pairings       │    │             │
//! │  │  └─────────────────┘  └──────────────────┘    │             │
//! │  │  ┌─────────────────┐  ┌──────────────────┐    │             │
//! │  │  │    ML-KEM       │  │   R25519/ElGamal │    │             │
//! │  │  │  (Post-Quantum) │  │      NIKE        │    │             │
//! │  │  └─────────────────┘  └──────────────────┘    │             │
//! │  └───────────────────────────────────────────────┘             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - [`access_control`]: Capability-based access control system
//! - [`dac`]: Delegatable Anonymous Credentials
//! - [`policy`]: Access policy and structure definitions
//! - [`crypto`]: Cryptographic provider abstraction
//!
//! # Security Considerations
//!
//! - The system uses BLS12-381 which provides 128-bit classical security
//! - BLS12-381 is NOT post-quantum secure; see `docs/POST_QUANTUM_MIGRATION.md`
//! - Metadata encryption uses **Poseidon2 AEAD** (miden-crypto), which is optimized
//!   for zero-knowledge proof systems (STARKs) while providing 128-bit security
//! - ML-KEM (Kyber) provides post-quantum key encapsulation for session keys
//! - All secret keys should be protected and zeroized when no longer needed

extern crate alloc;
extern crate rand;

// ============================================================================
// Public API Modules
// ============================================================================

/// Access control with capability-based security and attribute-based encryption
pub mod access_control;

/// Cryptographic provider abstraction layer
///
/// Provides algorithm-agile cryptographic primitives for Colossus,
/// enabling future migration to post-quantum algorithms.
///
/// # Components
///
/// - [`crypto::HashProvider`] - Unified hash interface (BLAKE3, SHA3-256)
/// - [`crypto::PairingProvider`] - Bilinear pairing abstraction (BLS12-381)
/// - [`crypto::CryptoProvider`] - Unified provider combining all primitives
///
/// See `docs/POST_QUANTUM_MIGRATION.md` for the migration strategy.
pub mod crypto;

/// Decentralized Anonymous Credentials (DAC)
///
/// Privacy-preserving credential system with selective disclosure and
/// zero-knowledge proofs.
pub mod dac;

/// Access policy definitions and attribute structures
pub mod policy;

/// Miden integration module for on-chain note types
///
/// Provides types for representing Colossus access control primitives
/// in a format suitable for Polygon Miden's STARK-based verification.
pub mod miden;

/// Re-exported logging macros from tracing
pub mod log {
    pub use tracing::{debug, error, info, trace, warn};
}

/// Prelude module for convenient imports.
///
/// Import everything commonly needed with:
/// ```ignore
/// use colossus_core::prelude::*;
/// ```
pub mod prelude {
    // Access Control types
    pub use crate::access_control::{
        AccessCapabilityToken, AccessControl, BlindedCapabilityClaim, CapabilityAuthority,
        CapabilityAuthorityPublicKey, EncryptedHeader,
    };

    // DAC types
    pub use crate::dac::{
        AccessRights, Attributes,
        keypair::{Issuer, IssuerError, IssuerPublic},
        zkp::Nonce,
    };

    // Policy types
    pub use crate::policy::{
        AccessPolicy, BlindedAccessClaim, BlindedAccessStructure, BlindedAttribute,
        Error as PolicyError, IssuerBlindingKey, IssuerRegistration, PolicyTerm,
    };

    // Crypto types
    pub use crate::crypto::{CryptoProvider, DefaultCryptoProvider};
}

#[cfg(test)]
mod test;
