//! Integration tests for privacy-preserving blinded attributes.
//!
//! These tests demonstrate the Poseidon2-based blinded attribute system that provides:
//! - Privacy-preserving attribute commitments
//! - Issuer-bound and authority-bound attributes
//! - Zero-knowledge ownership proofs (individual and batched)
//! - Cross-authority unlinkability
//! - QualifiedAttribute conversion utilities
//! - DAC credential integration
//!
//! # Architecture Tested
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                   Blinded Attribute Integration Tests                    │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  1. IssuerBlindingKey                                                    │
//! │     • Identity creation and management                                   │
//! │     • Authority registration                                             │
//! │     • Blinded attribute creation                                         │
//! │     • Batch ownership proofs                                             │
//! │                                                                          │
//! │  2. BlindedAccessStructure                                               │
//! │     • Dimension management                                               │
//! │     • Attribute registration with proofs                                 │
//! │     • Issuer verification                                                │
//! │                                                                          │
//! │  3. AttributeOwnershipProof & BatchOwnershipProof                        │
//! │     • Individual proof creation and verification                         │
//! │     • Batch proof aggregation                                            │
//! │     • Cross-verification with preimages                                  │
//! │                                                                          │
//! │  4. BlindedAccessClaim & BlindedAccessClaimBatched                       │
//! │     • Claim construction with multiple attributes                        │
//! │     • Individual and batched proof bundling                              │
//! │                                                                          │
//! │  5. Conversion Utilities                                                 │
//! │     • QualifiedAttribute to BlindedAttribute                             │
//! │     • Batch conversions                                                  │
//! │     • Preimage verification against qualified attributes                 │
//! │                                                                          │
//! │  6. DAC Integration (BlindedClaimBuilder)                                │
//! │     • Building claims from DAC credentials                               │
//! │     • Individual and batched claim construction                          │
//! │                                                                          │
//! │  7. Privacy Properties                                                   │
//! │     • Cross-authority unlinkability                                      │
//! │     • Cross-issuer unlinkability                                         │
//! │     • Same-attribute different-commitment property                       │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use crate::crypto::{Felt, Word};
use crate::policy::{
    AttributeStatus, BatchOwnershipProof, BlindedAccessClaim, BlindedAccessStructure,
    BlindedAttribute, BlindedClaimBuilder, DimensionType, IssuerBlindingKey, conversion,
    dac_integration,
};
use anyhow::Result;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test authority public key commitment
fn test_authority_pk() -> Word {
    Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)])
}

/// Create a second test authority public key commitment
fn test_authority_pk_2() -> Word {
    Word::new([Felt::new(500), Felt::new(600), Felt::new(700), Felt::new(800)])
}

// ============================================================================
// IssuerBlindingKey Tests
// ============================================================================

/// Test basic issuer creation and identity management.
#[test]
fn test_issuer_blinding_key_lifecycle() -> Result<()> {
    // Create a new issuer
    let issuer = IssuerBlindingKey::new();

    // Verify identity is created with valid commitment
    let commitment = issuer.commitment();
    assert_ne!(commitment, Word::default(), "commitment should not be zero");

    // Verify issuer identity can sign and verify
    let identity = issuer.identity();
    let test_message = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let signature = identity.sign(&test_message);
    assert!(
        identity.verify(&test_message, &signature),
        "issuer should verify own signatures"
    );

    Ok(())
}

/// Test issuer registration with multiple authorities.
#[test]
fn test_issuer_multi_authority_registration() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority1 = test_authority_pk();
    let authority2 = test_authority_pk_2();

    // Initially not registered with any authority
    assert!(!issuer.is_registered_with(&authority1));
    assert!(!issuer.is_registered_with(&authority2));

    // Register with first authority
    let reg1 = issuer.register_with_authority(authority1, 1000);
    assert!(issuer.is_registered_with(&authority1));
    assert!(!issuer.is_registered_with(&authority2));
    assert_eq!(reg1.timestamp, 1000);

    // Register with second authority
    let reg2 = issuer.register_with_authority(authority2, 2000);
    assert!(issuer.is_registered_with(&authority1));
    assert!(issuer.is_registered_with(&authority2));
    assert_eq!(reg2.timestamp, 2000);

    // Both registrations should have same issuer PK
    assert_eq!(reg1.issuer_pk, reg2.issuer_pk);
    assert_eq!(reg1.issuer_pk, issuer.commitment());

    Ok(())
}

/// Test registration verification using public key.
#[test]
fn test_issuer_registration_verification() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    let registration = issuer.register_with_authority(authority_pk, 1000);

    // Verify with correct public key
    let issuer_pk = issuer.identity().public_key();
    assert!(registration.verify(&issuer_pk), "registration should verify with correct key");

    // Verify fails with different issuer's key
    let other_issuer = IssuerBlindingKey::new();
    let other_pk = other_issuer.identity().public_key();
    assert!(!registration.verify(&other_pk), "registration should fail with wrong key");

    Ok(())
}

// ============================================================================
// BlindedAttribute Tests
// ============================================================================

/// Test that same attribute with different salts produces different commitments.
#[test]
fn test_blinded_attribute_unlinkability() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    // Create same attribute multiple times
    let blinded1 = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let blinded2 = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let blinded3 = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;

    // All should have different commitments (due to random salt)
    assert_ne!(blinded1.commitment(), blinded2.commitment());
    assert_ne!(blinded2.commitment(), blinded3.commitment());
    assert_ne!(blinded1.commitment(), blinded3.commitment());

    // But all should have valid preimages
    let preimage1 = issuer.get_preimage("Security", "TopSecret", &authority_pk);
    assert!(preimage1.is_some(), "preimage should exist");

    Ok(())
}

/// Test deterministic attribute creation with explicit salt.
#[test]
fn test_blinded_attribute_deterministic() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();
    let salt = Word::new([Felt::new(42), Felt::new(43), Felt::new(44), Felt::new(45)]);

    issuer.register_with_authority(authority_pk, 1000);

    // Create with explicit salt
    let blinded1 = issuer.create_blinded_attribute_deterministic(
        "Security",
        "TopSecret",
        &authority_pk,
        salt,
    )?;

    // Create another issuer and do the same
    let mut issuer2 = IssuerBlindingKey::new();
    issuer2.register_with_authority(authority_pk, 1000);
    let blinded2 = issuer2.create_blinded_attribute_deterministic(
        "Security",
        "TopSecret",
        &authority_pk,
        salt,
    )?;

    // Different issuers should still produce different commitments
    // (because issuer_pk is part of the hash)
    assert_ne!(blinded1.commitment(), blinded2.commitment());

    Ok(())
}

/// Test cross-authority attribute isolation.
#[test]
fn test_blinded_attribute_cross_authority_isolation() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority1 = test_authority_pk();
    let authority2 = test_authority_pk_2();

    // Register with both authorities
    issuer.register_with_authority(authority1, 1000);
    issuer.register_with_authority(authority2, 1001);

    // Create same attribute for both authorities
    let blinded1 = issuer.create_blinded_attribute("Security", "TopSecret", &authority1)?;
    let blinded2 = issuer.create_blinded_attribute("Security", "TopSecret", &authority2)?;

    // Commitments should be different (authority-bound)
    assert_ne!(blinded1.commitment(), blinded2.commitment());

    // Preimages should exist for both
    let preimage1 = issuer.get_preimage("Security", "TopSecret", &authority1).unwrap();
    let preimage2 = issuer.get_preimage("Security", "TopSecret", &authority2).unwrap();

    // Each preimage should only verify its own attribute
    assert!(preimage1.verify_attribute(&blinded1));
    assert!(!preimage1.verify_attribute(&blinded2));
    assert!(preimage2.verify_attribute(&blinded2));
    assert!(!preimage2.verify_attribute(&blinded1));

    Ok(())
}

// ============================================================================
// AttributeOwnershipProof Tests
// ============================================================================

/// Test ownership proof creation and verification flow.
#[test]
fn test_ownership_proof_flow() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    // Create attribute
    let blinded = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;

    // Create ownership proof
    let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk)?;

    // Verify the proof
    let issuer_pk = issuer.identity().public_key();
    assert!(proof.verify(&issuer_pk), "proof should verify with correct key");

    // Proof should reference the correct attribute
    assert_eq!(proof.attribute.commitment(), blinded.commitment());
    assert_eq!(proof.issuer_pk, issuer.commitment());

    Ok(())
}

/// Test that ownership proofs are bound to the issuer.
#[test]
fn test_ownership_proof_issuer_binding() -> Result<()> {
    let mut issuer1 = IssuerBlindingKey::new();
    let mut issuer2 = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer1.register_with_authority(authority_pk, 1000);
    issuer2.register_with_authority(authority_pk, 1001);

    // Issuer1 creates attribute and proof
    issuer1.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let proof1 = issuer1.prove_ownership("Security", "TopSecret", &authority_pk)?;

    // Issuer2 creates same attribute
    issuer2.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let proof2 = issuer2.prove_ownership("Security", "TopSecret", &authority_pk)?;

    // Each proof should only verify with its own issuer's key
    let pk1 = issuer1.identity().public_key();
    let pk2 = issuer2.identity().public_key();

    assert!(proof1.verify(&pk1));
    assert!(!proof1.verify(&pk2));
    assert!(proof2.verify(&pk2));
    assert!(!proof2.verify(&pk1));

    Ok(())
}

/// Test ownership proof with full preimage verification.
#[test]
fn test_ownership_proof_with_preimage() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);
    issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;

    let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk)?;
    let preimage = issuer.get_preimage("Security", "TopSecret", &authority_pk).unwrap();
    let issuer_pk = issuer.identity().public_key();

    // Full verification with preimage
    assert!(proof.verify_with_preimage(&issuer_pk, preimage));

    // Should fail with wrong preimage
    let (_, wrong_preimage) = BlindedAttribute::commit(
        "Security",
        "Secret", // Different attribute
        &issuer.commitment(),
        &authority_pk,
    );
    assert!(!proof.verify_with_preimage(&issuer_pk, &wrong_preimage));

    Ok(())
}

// ============================================================================
// BatchOwnershipProof Tests
// ============================================================================

/// Test batch ownership proof creation and verification.
#[test]
fn test_batch_ownership_proof_flow() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    // Create multiple attributes
    issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    issuer.create_blinded_attribute("Department", "Engineering", &authority_pk)?;
    issuer.create_blinded_attribute("Role", "Developer", &authority_pk)?;

    // Create batch proof
    let batch_proof = issuer.prove_ownership_batch(
        &[("Security", "TopSecret"), ("Department", "Engineering"), ("Role", "Developer")],
        &authority_pk,
    )?;

    assert_eq!(batch_proof.len(), 3);
    assert!(!batch_proof.is_empty());

    // Verify the batch proof
    let issuer_pk = issuer.identity().public_key();
    assert!(batch_proof.verify(&issuer_pk), "batch proof should verify");

    Ok(())
}

/// Test batch proof with full preimage verification.
#[test]
fn test_batch_proof_with_preimage_verification() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    let blinded1 = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let blinded2 = issuer.create_blinded_attribute("Department", "Engineering", &authority_pk)?;

    let preimage1 = issuer.get_preimage("Security", "TopSecret", &authority_pk).unwrap().clone();
    let preimage2 =
        issuer.get_preimage("Department", "Engineering", &authority_pk).unwrap().clone();

    let batch_proof = BatchOwnershipProof::create(
        vec![blinded1, blinded2],
        vec![preimage1.clone(), preimage2.clone()],
        issuer.identity(),
    )?;

    let issuer_pk = issuer.identity().public_key();

    // Full verification with preimages
    assert!(batch_proof.verify_with_preimages(&issuer_pk, &[preimage1, preimage2]));

    Ok(())
}

/// Test batch proof contains functionality.
#[test]
fn test_batch_proof_contains() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    let blinded1 = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let blinded2 = issuer.create_blinded_attribute("Department", "Engineering", &authority_pk)?;

    let batch_proof = issuer.prove_ownership_batch(
        &[("Security", "TopSecret"), ("Department", "Engineering")],
        &authority_pk,
    )?;

    // Check contains
    assert!(batch_proof.contains(blinded1.commitment()));
    assert!(batch_proof.contains(blinded2.commitment()));

    // Non-existent should not be contained
    let (other, _) =
        BlindedAttribute::commit("Other", "Attribute", &issuer.commitment(), &authority_pk);
    assert!(!batch_proof.contains(other.commitment()));

    Ok(())
}

// ============================================================================
// BlindedAccessStructure Tests
// ============================================================================

/// Test blinded access structure setup and dimension management.
#[test]
fn test_blinded_access_structure_setup() -> Result<()> {
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);

    assert_eq!(structure.authority_pk, authority_pk);
    assert_eq!(structure.epoch, 0);
    assert_eq!(structure.dimension_count(), 0);
    assert_eq!(structure.attribute_count(), 0);
    assert_eq!(structure.issuer_count(), 0);

    // Add dimensions
    let security_dim = structure.add_dimension("Security", DimensionType::Hierarchy);
    let dept_dim = structure.add_dimension("Department", DimensionType::Anarchy);

    assert_eq!(structure.dimension_count(), 2);

    // Verify dimension commitments
    assert!(security_dim.verify("Security", &authority_pk));
    assert!(dept_dim.verify("Department", &authority_pk));
    assert!(!security_dim.verify("Department", &authority_pk));

    Ok(())
}

/// Test issuer registration with blinded access structure.
#[test]
fn test_blinded_access_structure_issuer_registration() -> Result<()> {
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);

    let mut issuer1 = IssuerBlindingKey::new();
    let mut issuer2 = IssuerBlindingKey::new();

    // Register first issuer
    let reg1 = issuer1.register_with_authority(authority_pk, 1000);
    structure.register_issuer(reg1)?;

    assert_eq!(structure.issuer_count(), 1);
    assert!(structure.is_issuer_registered(&issuer1.commitment()));
    assert!(!structure.is_issuer_registered(&issuer2.commitment()));

    // Register second issuer
    let reg2 = issuer2.register_with_authority(authority_pk, 1001);
    structure.register_issuer(reg2)?;

    assert_eq!(structure.issuer_count(), 2);
    assert!(structure.is_issuer_registered(&issuer1.commitment()));
    assert!(structure.is_issuer_registered(&issuer2.commitment()));

    Ok(())
}

/// Test adding blinded attributes to the structure.
#[test]
fn test_blinded_access_structure_add_attributes() -> Result<()> {
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);
    let mut issuer = IssuerBlindingKey::new();

    // Setup
    let registration = issuer.register_with_authority(authority_pk, 1000);
    structure.register_issuer(registration)?;
    let security_dim = structure.add_dimension("Security", DimensionType::Hierarchy);

    // Create and add attributes
    let top_secret = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let secret = issuer.create_blinded_attribute("Security", "Secret", &authority_pk)?;
    let public = issuer.create_blinded_attribute("Security", "Public", &authority_pk)?;

    let proof1 = issuer.prove_ownership("Security", "TopSecret", &authority_pk)?;
    let proof2 = issuer.prove_ownership("Security", "Secret", &authority_pk)?;
    let proof3 = issuer.prove_ownership("Security", "Public", &authority_pk)?;

    let issuer_pk = issuer.identity().public_key();

    // Add to structure
    let id1 = structure.add_attribute(&security_dim, top_secret, &proof1, &issuer_pk, 2000)?;
    let id2 = structure.add_attribute(&security_dim, secret, &proof2, &issuer_pk, 2001)?;
    let id3 = structure.add_attribute(&security_dim, public, &proof3, &issuer_pk, 2002)?;

    // Verify IDs are sequential
    assert_eq!(id1, 0);
    assert_eq!(id2, 1);
    assert_eq!(id3, 2);

    // Verify attributes exist
    assert_eq!(structure.attribute_count(), 3);
    assert!(structure.contains_attribute(top_secret.commitment()));
    assert!(structure.contains_attribute(secret.commitment()));
    assert!(structure.contains_attribute(public.commitment()));

    // Verify metadata
    let metadata = structure.get_attribute_metadata(top_secret.commitment()).unwrap();
    assert_eq!(metadata.id, 0);
    assert_eq!(metadata.issuer_pk, issuer.commitment());
    assert_eq!(metadata.status, AttributeStatus::EncryptDecrypt);

    Ok(())
}

/// Test that unregistered issuers cannot add attributes.
#[test]
fn test_blinded_access_structure_requires_registered_issuer() -> Result<()> {
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);
    let mut issuer = IssuerBlindingKey::new();

    // Register with authority but NOT with structure
    issuer.register_with_authority(authority_pk, 1000);
    let security_dim = structure.add_dimension("Security", DimensionType::Anarchy);

    // Create attribute and proof
    let blinded = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk)?;
    let issuer_pk = issuer.identity().public_key();

    // Should fail - issuer not registered with structure
    let result = structure.add_attribute(&security_dim, blinded, &proof, &issuer_pk, 2000);
    assert!(result.is_err());

    Ok(())
}

/// Test attribute disabling functionality.
#[test]
fn test_blinded_access_structure_disable_attribute() -> Result<()> {
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);
    let mut issuer = IssuerBlindingKey::new();

    // Setup
    let registration = issuer.register_with_authority(authority_pk, 1000);
    structure.register_issuer(registration)?;
    let dim = structure.add_dimension("Security", DimensionType::Anarchy);

    // Add attribute
    let blinded = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let proof = issuer.prove_ownership("Security", "TopSecret", &authority_pk)?;
    let issuer_pk = issuer.identity().public_key();
    structure.add_attribute(&dim, blinded, &proof, &issuer_pk, 2000)?;

    // Initially EncryptDecrypt
    let metadata = structure.get_attribute_metadata(blinded.commitment()).unwrap();
    assert_eq!(metadata.status, AttributeStatus::EncryptDecrypt);

    // Disable
    structure.disable_attribute(blinded.commitment())?;

    // Now DecryptOnly
    let metadata = structure.get_attribute_metadata(blinded.commitment()).unwrap();
    assert_eq!(metadata.status, AttributeStatus::DecryptOnly);

    Ok(())
}

// ============================================================================
// BlindedAccessClaim Tests
// ============================================================================

/// Test creating claims with multiple blinded attributes.
#[test]
fn test_blinded_access_claim_creation() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    // Create multiple attributes
    let attr1 = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let attr2 = issuer.create_blinded_attribute("Department", "Engineering", &authority_pk)?;
    let attr3 = issuer.create_blinded_attribute("Role", "Developer", &authority_pk)?;

    let proof1 = issuer.prove_ownership("Security", "TopSecret", &authority_pk)?;
    let proof2 = issuer.prove_ownership("Department", "Engineering", &authority_pk)?;
    let proof3 = issuer.prove_ownership("Role", "Developer", &authority_pk)?;

    // Create claim
    let mut claim = BlindedAccessClaim::new(issuer.commitment());
    claim.add_attribute(attr1, proof1);
    claim.add_attribute(attr2, proof2);
    claim.add_attribute(attr3, proof3);

    assert_eq!(claim.attributes.len(), 3);
    assert_eq!(claim.proofs.len(), 3);
    assert_eq!(claim.issuer_pk, issuer.commitment());

    // Verify all proofs
    let issuer_pk = issuer.identity().public_key();
    assert!(claim.verify_proofs(&issuer_pk));

    Ok(())
}

/// Test that claims fail verification with wrong issuer key.
#[test]
fn test_blinded_access_claim_wrong_issuer_fails() -> Result<()> {
    let mut issuer1 = IssuerBlindingKey::new();
    let issuer2 = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer1.register_with_authority(authority_pk, 1000);

    let attr = issuer1.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let proof = issuer1.prove_ownership("Security", "TopSecret", &authority_pk)?;

    let mut claim = BlindedAccessClaim::new(issuer1.commitment());
    claim.add_attribute(attr, proof);

    // Should fail with wrong issuer's key
    let wrong_pk = issuer2.identity().public_key();
    assert!(!claim.verify_proofs(&wrong_pk));

    Ok(())
}

// ============================================================================
// Conversion Utilities Tests
// ============================================================================

/// Test blinded attribute creation and verification.
#[test]
fn test_blinded_attribute_conversion() -> Result<()> {
    let issuer_pk = test_authority_pk();
    let authority_pk = test_authority_pk_2();

    // Create blinded attribute directly using conversion utilities
    let (blinded, preimage) =
        conversion::blind_attribute("Security", "TopSecret", &issuer_pk, &authority_pk);

    // Verify preimage produces correct commitment
    assert!(preimage.verify_attribute(&blinded));

    // Verify preimage matches the expected values
    assert!(conversion::preimage_matches(&preimage, "Security", "TopSecret"));

    // Wrong attribute name should not match
    assert!(!conversion::preimage_matches(&preimage, "Security", "Secret"));

    Ok(())
}

/// Test batch creation of blinded attributes.
#[test]
fn test_batch_blinded_conversion() -> Result<()> {
    let issuer_pk = test_authority_pk();
    let authority_pk = test_authority_pk_2();

    let attrs =
        vec![("Security", "TopSecret"), ("Department", "Engineering"), ("Role", "Developer")];

    let results = conversion::batch_blind_attributes(&attrs, &issuer_pk, &authority_pk);

    assert_eq!(results.len(), 3);

    // All should be different
    assert_ne!(results[0].0.commitment(), results[1].0.commitment());
    assert_ne!(results[1].0.commitment(), results[2].0.commitment());

    // All preimages should verify
    for (blinded, preimage) in &results {
        assert!(preimage.verify_attribute(blinded));
    }

    Ok(())
}

// ============================================================================
// DAC Integration Tests
// ============================================================================

/// Test BlindedClaimBuilder for creating claims.
#[test]
fn test_blinded_claim_builder() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("Security", "TopSecret")
        .add_attribute("Department", "Engineering")
        .add_attribute("Role", "Developer")
        .build()?;

    assert_eq!(claim.attributes.len(), 3);
    assert_eq!(claim.proofs.len(), 3);

    // Verify all proofs
    let issuer_pk = issuer.identity().public_key();
    assert!(claim.verify_proofs(&issuer_pk));

    Ok(())
}

/// Test BlindedClaimBuilder for creating batched claims.
#[test]
fn test_blinded_claim_builder_batched() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("Security", "TopSecret")
        .add_attribute("Department", "Engineering")
        .add_attribute("Role", "Developer")
        .build_batched()?;

    assert_eq!(claim.len(), 3);
    assert!(!claim.is_empty());

    // Verify
    let issuer_pk = issuer.identity().public_key();
    assert!(claim.verify(&issuer_pk));

    // Check contains
    for attr in claim.attributes() {
        assert!(claim.contains(attr.commitment()));
    }

    Ok(())
}

/// Test claim_to_batched conversion.
#[test]
fn test_claim_to_batched_conversion() -> Result<()> {
    let mut issuer = IssuerBlindingKey::new();
    let authority_pk = test_authority_pk();

    issuer.register_with_authority(authority_pk, 1000);

    // Create regular claim
    let blinded1 = issuer.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let proof1 = issuer.prove_ownership("Security", "TopSecret", &authority_pk)?;
    let preimage1 = issuer.get_preimage("Security", "TopSecret", &authority_pk).unwrap().clone();

    let blinded2 = issuer.create_blinded_attribute("Department", "Engineering", &authority_pk)?;
    let proof2 = issuer.prove_ownership("Department", "Engineering", &authority_pk)?;
    let preimage2 =
        issuer.get_preimage("Department", "Engineering", &authority_pk).unwrap().clone();

    let mut claim = BlindedAccessClaim::new(issuer.commitment());
    claim.add_attribute(blinded1, proof1);
    claim.add_attribute(blinded2, proof2);

    // Convert to batched
    let batched =
        dac_integration::claim_to_batched(&claim, vec![preimage1, preimage2], issuer.identity())?;

    assert_eq!(batched.len(), 2);

    let issuer_pk = issuer.identity().public_key();
    assert!(batched.verify(&issuer_pk));

    Ok(())
}

// ============================================================================
// Full Integration Tests
// ============================================================================

/// Test the complete workflow from issuer setup to claim verification.
#[test]
fn test_full_blinded_attribute_workflow() -> Result<()> {
    // 1. Authority creates blinded access structure
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);

    // 2. Add dimensions
    let security_dim = structure.add_dimension("Security", DimensionType::Hierarchy);
    let dept_dim = structure.add_dimension("Department", DimensionType::Anarchy);
    let role_dim = structure.add_dimension("Role", DimensionType::Anarchy);

    // 3. Multiple issuers register
    let mut issuer_gov = IssuerBlindingKey::new(); // Government issuer
    let mut issuer_corp = IssuerBlindingKey::new(); // Corporate issuer

    let reg_gov = issuer_gov.register_with_authority(authority_pk, 1000);
    let reg_corp = issuer_corp.register_with_authority(authority_pk, 1001);

    structure.register_issuer(reg_gov)?;
    structure.register_issuer(reg_corp)?;

    // 4. Government issuer provides security clearance
    let clearance = issuer_gov.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let clearance_proof = issuer_gov.prove_ownership("Security", "TopSecret", &authority_pk)?;

    structure.add_attribute(
        &security_dim,
        clearance,
        &clearance_proof,
        &issuer_gov.identity().public_key(),
        2000,
    )?;

    // 5. Corporate issuer provides department and role
    let dept = issuer_corp.create_blinded_attribute("Department", "Engineering", &authority_pk)?;
    let role = issuer_corp.create_blinded_attribute("Role", "SeniorDev", &authority_pk)?;

    let dept_proof = issuer_corp.prove_ownership("Department", "Engineering", &authority_pk)?;
    let role_proof = issuer_corp.prove_ownership("Role", "SeniorDev", &authority_pk)?;

    structure.add_attribute(
        &dept_dim,
        dept,
        &dept_proof,
        &issuer_corp.identity().public_key(),
        2001,
    )?;
    structure.add_attribute(
        &role_dim,
        role,
        &role_proof,
        &issuer_corp.identity().public_key(),
        2002,
    )?;

    // 6. Verify structure state
    assert_eq!(structure.dimension_count(), 3);
    assert_eq!(structure.attribute_count(), 3);
    assert_eq!(structure.issuer_count(), 2);

    // 7. User creates claim for access (combining gov and corp attributes)
    // In real flow, user would have credentials from both issuers
    // Here we simulate by having the issuers create claims

    let mut claim_gov = BlindedAccessClaim::new(issuer_gov.commitment());
    claim_gov.add_attribute(clearance, clearance_proof.clone());

    let mut claim_corp = BlindedAccessClaim::new(issuer_corp.commitment());
    claim_corp.add_attribute(dept, dept_proof.clone());
    claim_corp.add_attribute(role, role_proof.clone());

    // 8. Authority verifies claims
    assert!(claim_gov.verify_proofs(&issuer_gov.identity().public_key()));
    assert!(claim_corp.verify_proofs(&issuer_corp.identity().public_key()));

    // 9. Authority verifies attributes exist in structure
    for attr in &claim_gov.attributes {
        assert!(structure.contains_attribute(attr.commitment()));
        let meta = structure.get_attribute_metadata(attr.commitment()).unwrap();
        assert_eq!(meta.issuer_pk, issuer_gov.commitment());
    }

    for attr in &claim_corp.attributes {
        assert!(structure.contains_attribute(attr.commitment()));
        let meta = structure.get_attribute_metadata(attr.commitment()).unwrap();
        assert_eq!(meta.issuer_pk, issuer_corp.commitment());
    }

    Ok(())
}

/// Test that the same logical attribute from different issuers is unlinkable.
#[test]
fn test_cross_issuer_unlinkability() -> Result<()> {
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);

    // Two issuers that both issue "Security::TopSecret"
    let mut issuer1 = IssuerBlindingKey::new();
    let mut issuer2 = IssuerBlindingKey::new();

    let reg1 = issuer1.register_with_authority(authority_pk, 1000);
    let reg2 = issuer2.register_with_authority(authority_pk, 1001);

    structure.register_issuer(reg1)?;
    structure.register_issuer(reg2)?;

    let dim = structure.add_dimension("Security", DimensionType::Hierarchy);

    // Both issuers create "TopSecret" attribute
    let attr1 = issuer1.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;
    let attr2 = issuer2.create_blinded_attribute("Security", "TopSecret", &authority_pk)?;

    // The commitments should be different (unlinkable)
    assert_ne!(attr1.commitment(), attr2.commitment());

    // Add both to structure
    let proof1 = issuer1.prove_ownership("Security", "TopSecret", &authority_pk)?;
    let proof2 = issuer2.prove_ownership("Security", "TopSecret", &authority_pk)?;

    structure.add_attribute(&dim, attr1, &proof1, &issuer1.identity().public_key(), 2000)?;
    structure.add_attribute(&dim, attr2, &proof2, &issuer2.identity().public_key(), 2001)?;

    // Both exist independently
    assert!(structure.contains_attribute(attr1.commitment()));
    assert!(structure.contains_attribute(attr2.commitment()));

    // Metadata correctly identifies different issuers
    let meta1 = structure.get_attribute_metadata(attr1.commitment()).unwrap();
    let meta2 = structure.get_attribute_metadata(attr2.commitment()).unwrap();

    assert_eq!(meta1.issuer_pk, issuer1.commitment());
    assert_eq!(meta2.issuer_pk, issuer2.commitment());
    assert_ne!(meta1.issuer_pk, meta2.issuer_pk);

    Ok(())
}

/// Test that the same issuer's attributes across different authorities are unlinkable.
#[test]
fn test_cross_authority_unlinkability() -> Result<()> {
    let authority1 = test_authority_pk();
    let authority2 = test_authority_pk_2();

    let mut issuer = IssuerBlindingKey::new();

    // Register with both authorities
    issuer.register_with_authority(authority1, 1000);
    issuer.register_with_authority(authority2, 1001);

    // Create same attribute for both authorities
    let attr1 = issuer.create_blinded_attribute("Security", "TopSecret", &authority1)?;
    let attr2 = issuer.create_blinded_attribute("Security", "TopSecret", &authority2)?;

    // Commitments should be different
    assert_ne!(attr1.commitment(), attr2.commitment());

    // Each preimage only verifies its own attribute
    let preimage1 = issuer.get_preimage("Security", "TopSecret", &authority1).unwrap();
    let preimage2 = issuer.get_preimage("Security", "TopSecret", &authority2).unwrap();

    assert!(preimage1.verify_attribute(&attr1));
    assert!(!preimage1.verify_attribute(&attr2));
    assert!(preimage2.verify_attribute(&attr2));
    assert!(!preimage2.verify_attribute(&attr1));

    // Proofs are also distinct
    let proof1 = issuer.prove_ownership("Security", "TopSecret", &authority1)?;
    let proof2 = issuer.prove_ownership("Security", "TopSecret", &authority2)?;

    assert_ne!(proof1.attribute.commitment(), proof2.attribute.commitment());

    Ok(())
}

/// Test epoch management for key rotation.
#[test]
fn test_blinded_access_structure_epoch() -> Result<()> {
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);

    assert_eq!(structure.epoch, 0);

    structure.increment_epoch();
    assert_eq!(structure.epoch, 1);

    structure.increment_epoch();
    structure.increment_epoch();
    assert_eq!(structure.epoch, 3);

    Ok(())
}

/// Test that registrations for wrong authority are rejected.
#[test]
fn test_blinded_access_structure_rejects_wrong_authority_registration() -> Result<()> {
    let authority1 = test_authority_pk();
    let authority2 = test_authority_pk_2();

    let mut structure = BlindedAccessStructure::new(authority1);
    let mut issuer = IssuerBlindingKey::new();

    // Register issuer with authority2
    let registration = issuer.register_with_authority(authority2, 1000);

    // Try to add to structure owned by authority1
    let result = structure.register_issuer(registration);
    assert!(result.is_err());

    Ok(())
}

// ============================================================================
// Batched Claim Integration Tests
// ============================================================================

/// Test full workflow with batched claims for efficiency.
#[test]
fn test_full_workflow_with_batched_claims() -> Result<()> {
    let authority_pk = test_authority_pk();
    let mut structure = BlindedAccessStructure::new(authority_pk);

    // Setup dimensions
    let security_dim = structure.add_dimension("Security", DimensionType::Hierarchy);
    let dept_dim = structure.add_dimension("Department", DimensionType::Anarchy);
    let role_dim = structure.add_dimension("Role", DimensionType::Anarchy);

    // Setup issuer
    let mut issuer = IssuerBlindingKey::new();
    let registration = issuer.register_with_authority(authority_pk, 1000);
    structure.register_issuer(registration)?;

    // Create attributes using builder pattern
    let batched_claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("Security", "TopSecret")
        .add_attribute("Department", "Engineering")
        .add_attribute("Role", "Developer")
        .build_batched()?;

    // Add attributes to structure (need to create individual proofs for structure)
    // This shows how batched claims can be verified efficiently but attributes
    // still need individual proofs for structure registration
    let issuer_pk = issuer.identity().public_key();

    for attr in batched_claim.attributes() {
        // Need to retrieve the proof for each attribute
        // In a real scenario, you'd keep track of these during creation
        assert!(structure.contains_attribute(attr.commitment()) == false);
    }

    // Verify the batched claim (efficient - single signature verification)
    assert!(batched_claim.verify(&issuer_pk));
    assert_eq!(batched_claim.len(), 3);

    Ok(())
}
