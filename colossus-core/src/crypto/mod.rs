//! Crypto Provider Abstraction Layer
//!
//! This module provides algorithm-agile cryptographic primitives for Colossus.
//! It enables future migration to post-quantum algorithms while maintaining
//! backward compatibility with existing code.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Application Layer                            │
//! │              (Uses CryptoProvider trait)                        │
//! └─────────────────────────────────────────────────────────────────┘
//!                               │
//!                               ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   CryptoProvider Trait                          │
//! │   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
//! │   │  Pairing    │ │    Hash     │ │  Signature  │              │
//! │   │  Provider   │ │  Provider   │ │  Provider   │              │
//! │   └─────────────┘ └─────────────┘ └─────────────┘              │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use colossus_core::crypto::{CryptoProvider, DefaultCryptoProvider};
//!
//! // Use the default provider
//! let hash = DefaultCryptoProvider::hash(b"data");
//!
//! // Or use a specific provider
//! use colossus_core::crypto::Blake3Hash;
//! let hash = Blake3Hash::hash(b"data");
//! ```

pub mod error;
pub mod hash;
pub mod pairing;
pub mod provider;
pub mod signature;

pub use error::CryptoError;
pub use hash::{Blake3Hash, Hash256, HashProvider, Poseidon2Digest, Poseidon2Hash, Sha3_256Hash};
pub use pairing::{Bls12_381Pairing, PairingProvider};
pub use provider::{CryptoProvider, DefaultCryptoProvider};
pub use signature::{
    FALCON512_PUBLIC_KEY_LEN, FALCON512_SECRET_KEY_LEN, Falcon512Keypair, Falcon512PublicKey,
    Falcon512Signable, Falcon512Signature,
};

// Re-export miden-crypto types for convenience
pub use miden_crypto::{Felt, Word};
