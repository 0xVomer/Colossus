//! Integration tests for Falcon512-based authority attestations.
//!
//! These tests demonstrate the post-quantum attestation layer that provides:
//! - Authority identity proofs using Falcon512 signatures
//! - Capability token attestations for external verification
//! - Delegation chains between authorities
//! - Revocation state attestations for on-chain commitments

use crate::access_control::{
    AttestedRevocationProof, AuthorityIdentity, CapabilityAuthority, DelegationScope,
    RevocationAttestation, RevocationRegistry,
    capability::{create_unsafe_capability_token, update_capability_authority},
    cryptography::MIN_TRACING_LEVEL,
    revocation::CapabilityId,
};
use crate::policy::{AttributeStatus, Right};
use anyhow::Result;
use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
use std::collections::{HashMap, HashSet};

// ============================================================================
// Authority Identity Tests
// ============================================================================

/// Test that an authority can be created with a Falcon512 identity
/// and can create self-attestations proving control of the key.
#[test]
fn test_authority_identity_self_attestation() -> Result<()> {
    let mut rng = CsRng::from_entropy();

    // Create authority with identity
    let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng)?.with_identity();

    // Verify identity is present
    let identity = auth.identity().expect("authority should have identity");
    let initial_commitment = identity.commitment();

    // Create self-attestation
    let timestamp = 1234567890u64;
    auth.identity_mut()
        .expect("should have identity")
        .create_self_attestation(timestamp);

    // Verify self-attestation
    let identity = auth.identity().unwrap();
    assert!(
        identity.verify_self_attestation(timestamp),
        "self-attestation should verify with correct timestamp"
    );
    assert!(
        !identity.verify_self_attestation(timestamp + 1),
        "self-attestation should fail with wrong timestamp"
    );

    // Commitment should remain the same
    assert_eq!(
        identity.commitment(),
        initial_commitment,
        "commitment should not change after self-attestation"
    );

    Ok(())
}

/// Test the full capability token attestation flow where an authority
/// issues a capability and then creates a verifiable attestation for it.
#[test]
fn test_capability_token_attestation_flow() -> Result<()> {
    let mut rng = CsRng::from_entropy();

    // Create two access rights
    let right1 = Right::random(&mut rng);
    let right2 = Right::random(&mut rng);

    // Create authority with identity
    let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng)?.with_identity();

    // Setup access rights
    update_capability_authority(
        &mut rng,
        &mut auth,
        HashMap::from([
            (right1.clone(), AttributeStatus::EncryptDecrypt),
            (right2.clone(), AttributeStatus::EncryptDecrypt),
        ]),
    )?;

    // Issue a capability token
    let cap_token = create_unsafe_capability_token(
        &mut rng,
        &mut auth,
        HashSet::from([right1.clone(), right2.clone()]),
    )?;

    // Create attestation for the token
    let timestamp = 1700000000u64; // Example timestamp
    let attestation = auth
        .attest_token(&cap_token, timestamp)?
        .expect("attestation should be created");

    // Verify the attestation
    assert!(attestation.verify(), "attestation signature should be valid");
    assert_eq!(attestation.timestamp, timestamp);

    // Verify the attestation is from the expected authority
    let authority_pk = auth.identity().unwrap().public_key();
    assert_eq!(
        attestation.authority_pk.commitment(),
        authority_pk.commitment(),
        "attestation should be from the authority"
    );

    // Token commitment should be deterministic
    let commitment1 = CapabilityAuthority::compute_token_commitment(&cap_token)?;
    let commitment2 = CapabilityAuthority::compute_token_commitment(&cap_token)?;
    assert_eq!(commitment1, commitment2, "token commitment should be deterministic");

    // Attestation should cover the correct token commitment
    assert_eq!(
        attestation.token_commitment, commitment1,
        "attestation should cover the correct token"
    );

    Ok(())
}

// ============================================================================
// Delegation Chain Tests
// ============================================================================

/// Test delegation from one authority to another with scoped permissions.
#[test]
fn test_authority_delegation_chain() -> Result<()> {
    let mut rng = CsRng::from_entropy();

    // Create a hierarchy of authorities:
    // Root -> Intermediate -> Leaf
    let root_auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng)?.with_identity();

    let intermediate_auth =
        CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng)?.with_identity();

    let leaf_auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng)?.with_identity();

    // Root delegates full authority to intermediate
    let cert1 = root_auth
        .delegate_to(
            &intermediate_auth.identity().unwrap().public_key(),
            DelegationScope::Full,
            Some(2000000000), // Expires far in future
        )
        .expect("delegation should succeed");

    assert!(cert1.verify(Some(1000000000)), "certificate should be valid before expiration");
    assert!(
        !cert1.verify(Some(3000000000)),
        "certificate should be invalid after expiration"
    );

    // Intermediate delegates limited rights to leaf
    let limited_rights: HashSet<Right> = (0..3).map(|_| Right::random(&mut rng)).collect();

    let cert2 = intermediate_auth
        .delegate_to(
            &leaf_auth.identity().unwrap().public_key(),
            DelegationScope::Rights(limited_rights.clone()),
            None, // No expiration
        )
        .expect("delegation should succeed");

    assert!(cert2.verify(None), "certificate without expiration should always be valid");

    // Verify the chain of trust
    assert_eq!(
        cert1.delegator_pk.commitment(),
        root_auth.identity().unwrap().public_key().commitment()
    );
    assert_eq!(
        cert1.delegatee_pk.commitment(),
        intermediate_auth.identity().unwrap().public_key().commitment()
    );
    assert_eq!(
        cert2.delegator_pk.commitment(),
        intermediate_auth.identity().unwrap().public_key().commitment()
    );
    assert_eq!(
        cert2.delegatee_pk.commitment(),
        leaf_auth.identity().unwrap().public_key().commitment()
    );

    Ok(())
}

// ============================================================================
// Revocation Attestation Tests
// ============================================================================

/// Test the revocation attestation flow where an authority creates
/// a signed commitment to the revocation registry state.
#[test]
fn test_revocation_attestation_flow() -> Result<()> {
    // Create a revocation registry
    let mut registry = RevocationRegistry::new();
    let initial_root = registry.root();

    // Create authority identity for signing
    let authority = AuthorityIdentity::new();

    // Create initial attestation (empty registry)
    let attestation1 = RevocationAttestation::create(&registry, &authority, 1000);

    assert!(attestation1.verify(), "initial attestation should verify");
    assert_eq!(attestation1.root, initial_root);
    assert_eq!(attestation1.revocation_count, 0);
    assert!(attestation1.is_fresh(1000, 100));
    assert!(!attestation1.is_fresh(1200, 100));

    // Revoke some capabilities
    let cap_ids: Vec<CapabilityId> = (0..5)
        .map(|i| CapabilityId::new(format!("capability-{}", i).into_bytes()))
        .collect();

    for cap_id in &cap_ids {
        registry.revoke(cap_id)?;
    }

    // Create new attestation after revocations
    let attestation2 = RevocationAttestation::create(&registry, &authority, 2000);

    assert!(attestation2.verify(), "attestation after revocations should verify");
    assert_ne!(attestation2.root, initial_root, "root should change after revocations");
    assert_eq!(attestation2.revocation_count, 5);

    // Verify attestation is from expected authority
    assert!(attestation2.verify_for_authority(&authority.public_key()));

    // Verify fails for different authority
    let other_authority = AuthorityIdentity::new();
    assert!(!attestation2.verify_for_authority(&other_authority.public_key()));

    Ok(())
}

/// Test attested revocation proofs that bundle a proof with an authority signature.
#[test]
fn test_attested_revocation_proof() -> Result<()> {
    let mut registry = RevocationRegistry::new();
    let authority = AuthorityIdentity::new();

    // Create some capabilities
    let active_cap = CapabilityId::new(b"active-capability".to_vec());
    let revoked_cap = CapabilityId::new(b"revoked-capability".to_vec());

    // Revoke one capability
    registry.revoke(&revoked_cap)?;

    // Create attested proof that active_cap is NOT revoked
    let proof_not_revoked =
        AttestedRevocationProof::prove_not_revoked(&registry, &active_cap, &authority, 1000)?;

    assert!(proof_not_revoked.verify_not_revoked()?, "should verify as not revoked");
    assert!(!proof_not_revoked.verify_revoked()?, "should not verify as revoked");

    // Verify against specific authority
    assert!(
        proof_not_revoked.verify_not_revoked_for_authority(&authority.public_key())?,
        "should verify for correct authority"
    );

    // Create attested proof that revoked_cap IS revoked
    let proof_revoked =
        AttestedRevocationProof::prove_revoked(&registry, &revoked_cap, &authority, 1000)?;

    assert!(proof_revoked.verify_revoked()?, "should verify as revoked");
    assert!(!proof_revoked.verify_not_revoked()?, "should not verify as not revoked");

    Ok(())
}

// ============================================================================
// Full Integration Tests
// ============================================================================

/// Test the complete flow of:
/// 1. Authority setup with identity
/// 2. Issuing capabilities
/// 3. Creating attestations
/// 4. Managing revocations with signed proofs
#[test]
fn test_full_attestation_integration() -> Result<()> {
    let mut rng = CsRng::from_entropy();

    // Step 1: Create authority with identity
    let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng)?.with_identity();

    // Create self-attestation for identity proof
    let setup_time = 1000u64;
    auth.identity_mut().unwrap().create_self_attestation(setup_time);

    // Step 2: Setup access rights
    let rights: Vec<Right> = (0..5).map(|_| Right::random(&mut rng)).collect();
    update_capability_authority(
        &mut rng,
        &mut auth,
        rights.iter().map(|r| (r.clone(), AttributeStatus::EncryptDecrypt)).collect(),
    )?;

    // Step 3: Issue capabilities and create attestations
    let mut issued_tokens = Vec::new();
    let mut attestations = Vec::new();

    for i in 0..3 {
        let token = create_unsafe_capability_token(
            &mut rng,
            &mut auth,
            HashSet::from([rights[i].clone()]),
        )?;

        let attestation = auth.attest_token(&token, setup_time + (i as u64 * 100))?.unwrap();

        assert!(attestation.verify(), "attestation {} should verify", i);

        issued_tokens.push(token);
        attestations.push(attestation);
    }

    // Step 4: Setup revocation registry
    let mut registry = RevocationRegistry::new();
    let authority_identity = auth.identity().unwrap();

    // Create initial revocation state attestation
    let initial_rev_attestation =
        RevocationAttestation::create(&registry, authority_identity, setup_time + 500);
    assert!(initial_rev_attestation.verify());
    assert_eq!(initial_rev_attestation.revocation_count, 0);

    // Step 5: Revoke one capability and create proof
    let token_commitment = CapabilityAuthority::compute_token_commitment(&issued_tokens[1])?;
    let cap_id = CapabilityId::from_word(&token_commitment);

    registry.revoke(&cap_id)?;

    // Create attested proof of revocation
    let revocation_proof = AttestedRevocationProof::prove_revoked(
        &registry,
        &cap_id,
        authority_identity,
        setup_time + 600,
    )?;

    assert!(revocation_proof.verify_revoked()?);

    // Create attested proof that other tokens are still valid
    for (i, token) in issued_tokens.iter().enumerate() {
        if i == 1 {
            continue; // Skip revoked token
        }

        let commitment = CapabilityAuthority::compute_token_commitment(token)?;
        let cap_id = CapabilityId::from_word(&commitment);

        let valid_proof = AttestedRevocationProof::prove_not_revoked(
            &registry,
            &cap_id,
            authority_identity,
            setup_time + 700,
        )?;

        assert!(
            valid_proof.verify_not_revoked()?,
            "token {} should be verified as not revoked",
            i
        );
    }

    // Step 6: Verify all attestations are from same authority
    let expected_commitment = authority_identity.public_key().commitment();

    for attestation in &attestations {
        assert_eq!(
            attestation.authority_pk.commitment(),
            expected_commitment,
            "all attestations should be from same authority"
        );
    }

    Ok(())
}

/// Test authority serialization preserves identity and attestation capability.
#[test]
fn test_authority_serialization_preserves_attestation() -> Result<()> {
    use cosmian_crypto_core::bytes_ser_de::Serializable;

    let mut rng = CsRng::from_entropy();

    // Create authority with identity and access rights
    let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng)?.with_identity();

    let right = Right::random(&mut rng);
    update_capability_authority(
        &mut rng,
        &mut auth,
        HashMap::from([(right.clone(), AttributeStatus::EncryptDecrypt)]),
    )?;

    // Create self-attestation
    auth.identity_mut().unwrap().create_self_attestation(1000);

    // Issue a token
    let token = create_unsafe_capability_token(&mut rng, &mut auth, HashSet::from([right]))?;

    // Create attestation before serialization
    let original_attestation = auth.attest_token(&token, 2000)?.unwrap();
    let original_commitment = auth.identity().unwrap().commitment();

    // Serialize and deserialize
    let serialized = auth.serialize()?;
    let restored = CapabilityAuthority::deserialize(&serialized)?;

    // Verify identity survived
    assert!(restored.identity().is_some(), "identity should survive serialization");

    let restored_commitment = restored.identity().unwrap().commitment();
    assert_eq!(original_commitment, restored_commitment, "commitment should be preserved");

    // Verify self-attestation still works
    assert!(
        restored.identity().unwrap().verify_self_attestation(1000),
        "self-attestation should survive serialization"
    );

    // Create new attestation from restored authority
    let restored_attestation = restored.attest_token(&token, 3000)?.unwrap();
    assert!(
        restored_attestation.verify(),
        "restored authority should be able to create valid attestations"
    );

    // Both attestations should be from same key
    assert_eq!(
        original_attestation.authority_pk.commitment(),
        restored_attestation.authority_pk.commitment(),
        "attestations should be from same authority"
    );

    Ok(())
}
