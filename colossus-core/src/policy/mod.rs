//! Access Policy and Structure Module
//!
//! This module defines the policy framework for privacy-preserving attribute-based
//! access control using blinded attributes.
//!
//! # Key Concepts
//!
//! ## Blinded Access Structure
//!
//! A `BlindedAccessStructure` defines the universe of possible attributes organized
//! into dimensions. Unlike plaintext access structures, attributes are stored as
//! Poseidon2 commitments - the authority never sees actual attribute values.
//!
//! Dimensions can be:
//! - **Hierarchical**: Attributes have parent-child relationships (e.g., security levels)
//! - **Anarchical**: Attributes are independent (e.g., department membership)
//!
//! ## Blinded Attributes
//!
//! A `BlindedAttribute` is a privacy-preserving commitment to a dimension-value pair.
//! The actual values are hidden from the authority through Poseidon2 hashing with salt.
//!
//! ## Access Rights
//!
//! A `Right` is a cryptographic identifier derived from blinded attributes that can
//! be used for encryption and access control.
//!
//! # Example
//!
//! ```ignore
//! use colossus_core::policy::{BlindedAccessStructure, DimensionType, IssuerBlindingKey};
//!
//! // Create an authority with blinded structure
//! let mut structure = BlindedAccessStructure::new(authority_pk);
//!
//! // Add dimensions
//! let security_dim = structure.add_dimension("Security", DimensionType::Hierarchy);
//! let dept_dim = structure.add_dimension("Department", DimensionType::Anarchy);
//!
//! // Issuers create blinded attributes
//! let mut issuer = IssuerBlindingKey::new();
//! let blinded = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
//! ```

mod access_policy;
mod attribute;
pub mod blinded;
mod data_struct;
mod dimension;
mod errors;
mod rights;

pub use access_policy::{AccessPolicy, PolicyTerm};
pub use attribute::ATTRIBUTE;
pub use blinded::{
    AttributeOwnershipProof, AttributePreimage, AuthorityBinding, BatchOwnershipProof,
    BlindedAccessClaim, BlindedAccessClaimBatched, BlindedAccessStructure, BlindedAttribute,
    BlindedAttributeMetadata, BlindedClaimBuilder, BlindedDimension, BlindedRight,
    DimensionCommitment, DimensionType, IssuerBlindingKey, IssuerIdentity, IssuerRegistration,
    StoredPreimage, conversion, dac_integration,
};
pub use data_struct::{Dict, RevisionMap, RevisionVec};
pub use dimension::{Attribute, AttributeStatus, Dimension};
pub use errors::PolicyError as Error;
pub use rights::Right;
