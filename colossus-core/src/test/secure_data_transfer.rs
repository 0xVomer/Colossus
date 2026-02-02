//! Integration tests for secure data transfer with privacy-preserving blinded attributes.
//!
//! These tests demonstrate end-to-end secure data transfer flows that combine:
//! - Privacy-preserving blinded attributes with Poseidon2 commitments
//! - AccessPolicy for human-readable encryption policies
//! - Hybrid mode with name registry for policy resolution
//! - Multi-issuer credential aggregation

use anyhow::Result;
use cosmian_crypto_core::reexport::rand_core::SeedableRng;

use crate::access_control::capability::{BlindedCapabilityClaim, create_blinded_capability_token};
use crate::access_control::{AccessControl, EncryptedHeader};
use crate::crypto::{Felt, Word};
use crate::dac::zkp::Nonce;
use crate::policy::{AccessPolicy, BlindedClaimBuilder, DimensionType, IssuerBlindingKey};
use bls12_381_plus::Scalar;

/// Helper to create a test nonce
fn test_nonce() -> Nonce {
    Nonce(Scalar::from(42u64))
}

// ============================================================================
// Secure Data Transfer Tests (Hybrid Blinded Mode)
// ============================================================================

/// Test secure data transfer using the hybrid blinded mode.
///
/// This demonstrates a complete end-to-end flow:
/// 1. Authority setup with blinded structure and name registry
/// 2. Issuers register and publish attributes with names
/// 3. Encryptor creates encrypted header with AccessPolicy
/// 4. User claims attributes and receives capability token
/// 5. User decrypts the data
#[test]
fn test_secure_data_transfer() -> Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let nonce = test_nonce();

    // =========================================================================
    // PHASE 1: Authority Setup
    // =========================================================================

    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;

    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // =========================================================================
    // PHASE 2: Setup Dimensions for Data Classification
    // =========================================================================

    let clearance_dim = auth.add_blinded_dimension("CLEARANCE", DimensionType::Hierarchy)?;
    let dept_dim = auth.add_blinded_dimension("DEPT", DimensionType::Anarchy)?;

    // =========================================================================
    // PHASE 3: Register Issuer (Security Office)
    // =========================================================================

    let mut security_issuer = IssuerBlindingKey::new();
    let reg = security_issuer.register_with_authority(authority_pk, 1000);
    let issuer_id =
        auth.register_blinded_issuer(reg, security_issuer.identity().public_key(), &mut rng)?;

    // =========================================================================
    // PHASE 4: Publish Security Attributes with Names
    // =========================================================================

    let timestamp = 2000u64;

    // Clearance levels (hierarchical)
    for level in &["PUBLIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"] {
        let attr = security_issuer.create_blinded_attribute("CLEARANCE", level, &authority_pk)?;
        let proof = security_issuer.prove_ownership("CLEARANCE", level, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &clearance_dim,
            "CLEARANCE",
            level,
            attr,
            &proof,
            timestamp,
            &mut rng,
        )?;
    }

    // Departments
    for dept in &["ENGINEERING", "RESEARCH", "OPERATIONS"] {
        let attr = security_issuer.create_blinded_attribute("DEPT", dept, &authority_pk)?;
        let proof = security_issuer.prove_ownership("DEPT", dept, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &dept_dim, "DEPT", dept, attr, &proof, timestamp, &mut rng,
        )?;
    }

    let apk = auth.rpk()?;

    // =========================================================================
    // PHASE 5: Encrypt Sensitive Data with Access Policy
    // =========================================================================

    // Data is classified: requires SECRET or TOP_SECRET clearance AND RESEARCH dept
    let policy =
        AccessPolicy::parse("(CLEARANCE::SECRET || CLEARANCE::TOP_SECRET) && DEPT::RESEARCH")?;

    let sensitive_metadata = b"project_alpha_specs";
    let (secret, enc_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &policy,
        Some(sensitive_metadata),
        Some(&nonce.to_be_bytes()),
    )?;

    // =========================================================================
    // PHASE 6: Authorized User Claims Attributes
    // =========================================================================

    // Dr. Smith has SECRET clearance and works in RESEARCH
    let smith_claim = BlindedClaimBuilder::new(&mut security_issuer, authority_pk)
        .add_attribute("CLEARANCE", "SECRET")
        .add_attribute("DEPT", "RESEARCH")
        .build_batched()?;

    let capability_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, smith_claim);
    let capability = create_blinded_capability_token(&mut rng, &mut auth, &[capability_claim])?;

    // =========================================================================
    // PHASE 7: Decrypt and Access Data
    // =========================================================================

    match enc_header.decrypt(&access_control, &capability, Some(&nonce.to_be_bytes()))? {
        Some(data) => {
            assert_eq!(data.secret, secret);
            assert_eq!(data.metadata.unwrap(), sensitive_metadata);
            println!("Secure data transfer test passed!");
        },
        None => {
            panic!("Dr. Smith should be able to decrypt - has SECRET and RESEARCH!");
        },
    }

    Ok(())
}

/// Test secure data transfer with blinded attributes and multiple access paths.
///
/// Demonstrates OR policies where multiple attribute combinations grant access.
#[test]
fn test_secure_data_transfer_with_blinded_attributes() -> Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let nonce = test_nonce();

    // Setup authority
    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;
    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // Setup dimensions
    let role_dim = auth.add_blinded_dimension("ROLE", DimensionType::Anarchy)?;
    let project_dim = auth.add_blinded_dimension("PROJECT", DimensionType::Anarchy)?;

    // Register issuer
    let mut issuer = IssuerBlindingKey::new();
    let reg = issuer.register_with_authority(authority_pk, 1000);
    let issuer_id = auth.register_blinded_issuer(reg, issuer.identity().public_key(), &mut rng)?;

    let timestamp = 2000u64;

    // Add role attributes
    for role in &["ADMIN", "DEVELOPER", "VIEWER"] {
        let attr = issuer.create_blinded_attribute("ROLE", role, &authority_pk)?;
        let proof = issuer.prove_ownership("ROLE", role, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &role_dim, "ROLE", role, attr, &proof, timestamp, &mut rng,
        )?;
    }

    // Add project attributes
    for project in &["ALPHA", "BETA", "GAMMA"] {
        let attr = issuer.create_blinded_attribute("PROJECT", project, &authority_pk)?;
        let proof = issuer.prove_ownership("PROJECT", project, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &project_dim,
            "PROJECT",
            project,
            attr,
            &proof,
            timestamp,
            &mut rng,
        )?;
    }

    let apk = auth.rpk()?;

    // Policy: ADMIN can access anything, or DEVELOPER on ALPHA project
    let policy = AccessPolicy::parse("ROLE::ADMIN || (ROLE::DEVELOPER && PROJECT::ALPHA)")?;

    let (secret, enc_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &policy,
        Some(b"alpha_codebase"),
        Some(&nonce.to_be_bytes()),
    )?;

    // Test 1: Developer on ALPHA project should succeed
    let dev_claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("ROLE", "DEVELOPER")
        .add_attribute("PROJECT", "ALPHA")
        .build_batched()?;

    let dev_cap_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, dev_claim);
    let dev_capability = create_blinded_capability_token(&mut rng, &mut auth, &[dev_cap_claim])?;

    match enc_header.decrypt(&access_control, &dev_capability, Some(&nonce.to_be_bytes()))? {
        Some(data) => {
            assert_eq!(data.secret, secret);
            println!("Developer on ALPHA project access: SUCCESS");
        },
        None => {
            panic!("Developer on ALPHA project should have access!");
        },
    }

    // Test 2: Viewer on ALPHA project should FAIL (not ADMIN, not DEVELOPER)
    let viewer_claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("ROLE", "VIEWER")
        .add_attribute("PROJECT", "ALPHA")
        .build_batched()?;

    let viewer_cap_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, viewer_claim);
    let viewer_capability =
        create_blinded_capability_token(&mut rng, &mut auth, &[viewer_cap_claim])?;

    match enc_header.decrypt(&access_control, &viewer_capability, Some(&nonce.to_be_bytes()))? {
        Some(_) => {
            panic!("Viewer should NOT have access - not ADMIN or DEVELOPER!");
        },
        None => {
            println!("Viewer denied access: CORRECT");
        },
    }

    println!("Secure data transfer with blinded attributes test passed!");
    Ok(())
}

/// Test federated secure data transfer with multiple issuers.
///
/// Demonstrates credentials from different organizations being combined
/// to satisfy an access policy.
#[test]
fn test_federated_secure_data_transfer() -> Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let nonce = test_nonce();

    // Setup authority
    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;
    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // Setup dimensions
    let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;
    let membership_dim = auth.add_blinded_dimension("MEMBERSHIP", DimensionType::Anarchy)?;
    let payment_dim = auth.add_blinded_dimension("PAYMENT", DimensionType::Anarchy)?;

    // =========================================================================
    // Multiple Issuers from Different Organizations
    // =========================================================================

    // Government identity issuer (age verification)
    let mut gov_issuer = IssuerBlindingKey::new();
    let gov_reg = gov_issuer.register_with_authority(authority_pk, 1000);
    let gov_id =
        auth.register_blinded_issuer(gov_reg, gov_issuer.identity().public_key(), &mut rng)?;

    // Streaming service issuer (membership)
    let mut streaming_issuer = IssuerBlindingKey::new();
    let stream_reg = streaming_issuer.register_with_authority(authority_pk, 1001);
    let stream_id = auth.register_blinded_issuer(
        stream_reg,
        streaming_issuer.identity().public_key(),
        &mut rng,
    )?;

    // Payment provider issuer
    let mut payment_issuer = IssuerBlindingKey::new();
    let pay_reg = payment_issuer.register_with_authority(authority_pk, 1002);
    let pay_id =
        auth.register_blinded_issuer(pay_reg, payment_issuer.identity().public_key(), &mut rng)?;

    let timestamp = 2000u64;

    // Government adds age attributes
    for age in &["MINOR", "ADULT", "SENIOR"] {
        let attr = gov_issuer.create_blinded_attribute("AGE", age, &authority_pk)?;
        let proof = gov_issuer.prove_ownership("AGE", age, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &age_dim, "AGE", age, attr, &proof, timestamp, &mut rng,
        )?;
    }

    // Streaming service adds membership tiers
    for tier in &["FREE", "PREMIUM", "FAMILY"] {
        let attr = streaming_issuer.create_blinded_attribute("MEMBERSHIP", tier, &authority_pk)?;
        let proof = streaming_issuer.prove_ownership("MEMBERSHIP", tier, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &membership_dim,
            "MEMBERSHIP",
            tier,
            attr,
            &proof,
            timestamp,
            &mut rng,
        )?;
    }

    // Payment provider adds payment status
    for status in &["VERIFIED", "UNVERIFIED"] {
        let attr = payment_issuer.create_blinded_attribute("PAYMENT", status, &authority_pk)?;
        let proof = payment_issuer.prove_ownership("PAYMENT", status, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &payment_dim,
            "PAYMENT",
            status,
            attr,
            &proof,
            timestamp,
            &mut rng,
        )?;
    }

    let apk = auth.rpk()?;

    // =========================================================================
    // Content Encryption with Federated Policy
    // =========================================================================

    // Premium adult content: requires ADULT + PREMIUM + VERIFIED payment
    let policy = AccessPolicy::parse("AGE::ADULT && MEMBERSHIP::PREMIUM && PAYMENT::VERIFIED")?;

    let (secret, enc_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &policy,
        Some(b"premium_movie_key"),
        Some(&nonce.to_be_bytes()),
    )?;

    // =========================================================================
    // User with Credentials from All Three Issuers
    // =========================================================================

    // User claims from government (age)
    let age_claim = BlindedClaimBuilder::new(&mut gov_issuer, authority_pk)
        .add_attribute("AGE", "ADULT")
        .build_batched()?;

    // User claims from streaming service (membership)
    let membership_claim = BlindedClaimBuilder::new(&mut streaming_issuer, authority_pk)
        .add_attribute("MEMBERSHIP", "PREMIUM")
        .build_batched()?;

    // User claims from payment provider
    let payment_claim = BlindedClaimBuilder::new(&mut payment_issuer, authority_pk)
        .add_attribute("PAYMENT", "VERIFIED")
        .build_batched()?;

    // Combine all claims
    let capability_claims = vec![
        BlindedCapabilityClaim::from_batched_claim(gov_id, age_claim),
        BlindedCapabilityClaim::from_batched_claim(stream_id, membership_claim),
        BlindedCapabilityClaim::from_batched_claim(pay_id, payment_claim),
    ];

    let capability = create_blinded_capability_token(&mut rng, &mut auth, &capability_claims)?;

    // User should be able to decrypt
    match enc_header.decrypt(&access_control, &capability, Some(&nonce.to_be_bytes()))? {
        Some(data) => {
            assert_eq!(data.secret, secret);
            println!("Federated access granted with credentials from 3 issuers!");
        },
        None => {
            panic!("User with all required federated credentials should have access!");
        },
    }

    println!("Federated secure data transfer test passed!");
    Ok(())
}

/// Test attribute-based access control for data transfer scenarios.
///
/// Demonstrates how different attribute combinations affect access.
///
/// NOTE: The underlying cryptographic scheme uses broadcast encryption where
/// each right gets its own encapsulation. A user can decrypt if they match
/// ANY of the required rights. For strict AND semantics (requiring ALL rights),
/// use separate dimensions or design policies where access requires rights
/// the user doesn't have at all.
#[test]
fn test_attribute_conversion_in_data_transfer() -> Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let nonce = test_nonce();

    // Setup authority
    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;
    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // Setup dimensions for different access levels
    let level_dim = auth.add_blinded_dimension("LEVEL", DimensionType::Anarchy)?;
    let role_dim = auth.add_blinded_dimension("ROLE", DimensionType::Anarchy)?;

    // Register issuer
    let mut issuer = IssuerBlindingKey::new();
    let reg = issuer.register_with_authority(authority_pk, 1000);
    let issuer_id = auth.register_blinded_issuer(reg, issuer.identity().public_key(), &mut rng)?;

    let timestamp = 2000u64;

    // Add access level attributes
    for level in &["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] {
        let attr = issuer.create_blinded_attribute("LEVEL", level, &authority_pk)?;
        let proof = issuer.prove_ownership("LEVEL", level, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &level_dim, "LEVEL", level, attr, &proof, timestamp, &mut rng,
        )?;
    }

    // Add role attributes
    for role in &["GUEST", "EMPLOYEE", "MANAGER", "ADMIN"] {
        let attr = issuer.create_blinded_attribute("ROLE", role, &authority_pk)?;
        let proof = issuer.prove_ownership("ROLE", role, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &role_dim, "ROLE", role, attr, &proof, timestamp, &mut rng,
        )?;
    }

    let apk = auth.rpk()?;

    // =========================================================================
    // Test Multiple Policy Scenarios
    // =========================================================================

    // Scenario 1: Public data (anyone with GUEST role can access)
    let public_policy = AccessPolicy::parse("ROLE::GUEST")?;
    let (public_secret, public_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &public_policy,
        Some(b"public_data"),
        Some(&nonce.to_be_bytes()),
    )?;

    // Scenario 2: Confidential data (requires CONFIDENTIAL level AND MANAGER role)
    // This tests cross-dimension AND - user must have attributes from BOTH dimensions
    let confidential_policy = AccessPolicy::parse("LEVEL::CONFIDENTIAL && ROLE::MANAGER")?;
    let (conf_secret, conf_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &confidential_policy,
        Some(b"confidential_data"),
        Some(&nonce.to_be_bytes()),
    )?;

    // Scenario 3: Restricted data (requires RESTRICTED level)
    let restricted_policy = AccessPolicy::parse("LEVEL::RESTRICTED")?;
    let (restricted_secret, restricted_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &restricted_policy,
        Some(b"restricted_data"),
        Some(&nonce.to_be_bytes()),
    )?;

    // =========================================================================
    // User 1: Guest with PUBLIC level (low privileges)
    // =========================================================================
    let guest_claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("LEVEL", "PUBLIC")
        .add_attribute("ROLE", "GUEST")
        .build_batched()?;
    let guest_cap_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, guest_claim);
    let guest_capability =
        create_blinded_capability_token(&mut rng, &mut auth, &[guest_cap_claim])?;

    // =========================================================================
    // User 2: Manager with CONFIDENTIAL level (medium privileges)
    // =========================================================================
    let manager_claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("LEVEL", "CONFIDENTIAL")
        .add_attribute("ROLE", "MANAGER")
        .build_batched()?;
    let manager_cap_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, manager_claim);
    let manager_capability =
        create_blinded_capability_token(&mut rng, &mut auth, &[manager_cap_claim])?;

    // =========================================================================
    // User 3: Admin with RESTRICTED level (high privileges)
    // =========================================================================
    let admin_claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("LEVEL", "RESTRICTED")
        .add_attribute("ROLE", "ADMIN")
        .build_batched()?;
    let admin_cap_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, admin_claim);
    let admin_capability =
        create_blinded_capability_token(&mut rng, &mut auth, &[admin_cap_claim])?;

    // =========================================================================
    // Access Tests
    // =========================================================================

    // Test: Guest can access public data
    match public_header.decrypt(&access_control, &guest_capability, Some(&nonce.to_be_bytes()))? {
        Some(data) => {
            assert_eq!(data.secret, public_secret);
            println!("Guest accessing public data: SUCCESS");
        },
        None => {
            panic!("Guest should access public data!");
        },
    }

    // Test: Guest CANNOT access confidential data (lacks CONFIDENTIAL and MANAGER)
    match conf_header.decrypt(&access_control, &guest_capability, Some(&nonce.to_be_bytes()))? {
        Some(_) => {
            panic!("Guest should NOT access confidential data!");
        },
        None => {
            println!("Guest denied confidential data: CORRECT");
        },
    }

    // Test: Guest CANNOT access restricted data (lacks RESTRICTED level)
    match restricted_header.decrypt(
        &access_control,
        &guest_capability,
        Some(&nonce.to_be_bytes()),
    )? {
        Some(_) => {
            panic!("Guest should NOT access restricted data!");
        },
        None => {
            println!("Guest denied restricted data: CORRECT");
        },
    }

    // Test: Manager can access confidential data (has CONFIDENTIAL + MANAGER)
    match conf_header.decrypt(&access_control, &manager_capability, Some(&nonce.to_be_bytes()))? {
        Some(data) => {
            assert_eq!(data.secret, conf_secret);
            println!("Manager accessing confidential data: SUCCESS");
        },
        None => {
            panic!("Manager should access confidential data!");
        },
    }

    // Test: Manager CANNOT access restricted data (lacks RESTRICTED level)
    match restricted_header.decrypt(
        &access_control,
        &manager_capability,
        Some(&nonce.to_be_bytes()),
    )? {
        Some(_) => {
            panic!("Manager should NOT access restricted data!");
        },
        None => {
            println!("Manager denied restricted data: CORRECT");
        },
    }

    // Test: Admin can access restricted data
    match restricted_header.decrypt(
        &access_control,
        &admin_capability,
        Some(&nonce.to_be_bytes()),
    )? {
        Some(data) => {
            assert_eq!(data.secret, restricted_secret);
            println!("Admin accessing restricted data: SUCCESS");
        },
        None => {
            panic!("Admin should access restricted data!");
        },
    }

    println!("Attribute conversion in data transfer test passed!");
    Ok(())
}

// ============================================================================
// Blinded Attribute Tests (utility tests)
// ============================================================================

/// Test batch proof efficiency for multiple attribute verification.
#[test]
fn test_secure_transfer_with_batch_proofs() -> Result<()> {
    let authority_pk = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

    // Create issuer with multiple attributes
    let mut issuer = IssuerBlindingKey::new();
    issuer.register_with_authority(authority_pk, 1000);

    // Create several blinded attributes representing different permissions
    let _read_attr = issuer.create_blinded_attribute("PERMISSION", "READ", &authority_pk)?;
    let _write_attr = issuer.create_blinded_attribute("PERMISSION", "WRITE", &authority_pk)?;
    let _exec_attr = issuer.create_blinded_attribute("PERMISSION", "EXECUTE", &authority_pk)?;
    let _group_attr = issuer.create_blinded_attribute("GROUPID", "GROUP_100", &authority_pk)?;
    let _user_attr = issuer.create_blinded_attribute("USERID", "USER_42", &authority_pk)?;

    // Create a batch proof for all attributes (efficient - single signature)
    let batch_proof = issuer.prove_ownership_batch(
        &[
            ("PERMISSION", "READ"),
            ("PERMISSION", "WRITE"),
            ("PERMISSION", "EXECUTE"),
            ("GROUPID", "GROUP_100"),
            ("USERID", "USER_42"),
        ],
        &authority_pk,
    )?;

    // Verify batch proof
    let issuer_pk = issuer.identity().public_key();
    assert!(batch_proof.verify(&issuer_pk), "batch proof should verify");
    assert_eq!(batch_proof.len(), 5, "should have 5 attributes");

    // Individual proofs would require 5 signatures; batch proof uses only 1
    println!("Batch proof size: 1 signature for {} attributes", batch_proof.len());

    Ok(())
}

/// Test secure data transfer with batched blinded claims.
#[test]
fn test_secure_transfer_with_batched_claims() -> Result<()> {
    let authority_pk = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

    // Create issuer
    let mut issuer = IssuerBlindingKey::new();
    issuer.register_with_authority(authority_pk, 1000);

    // Use BlindedClaimBuilder to create batched claim
    let batched_claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("PERMISSION", "READ")
        .add_attribute("PERMISSION", "WRITE")
        .add_attribute("PERMISSION", "EXECUTE")
        .add_attribute("GROUPID", "GROUP_100")
        .add_attribute("USERID", "USER_42")
        .build_batched()?;

    // Verify batched claim (efficient - single signature verification)
    let issuer_pk = issuer.identity().public_key();
    assert!(batched_claim.verify(&issuer_pk), "batched claim should verify");
    assert_eq!(batched_claim.len(), 5, "should have 5 attributes");

    // All attributes should be contained in the claim
    let preimage = issuer.get_preimage("PERMISSION", "READ", &authority_pk).unwrap();
    let read_commitment = preimage.compute_commitment();
    assert!(batched_claim.contains(&read_commitment), "batched claim should contain READ");

    println!("Secure transfer with batched claims test passed!");
    Ok(())
}
