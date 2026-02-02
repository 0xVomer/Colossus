use crate::access_control::capability::{BlindedCapabilityClaim, create_blinded_capability_token};
use crate::access_control::{AccessControl, EncryptedHeader};
use crate::crypto::{Felt, Word};
use crate::dac::zkp::Nonce;
use crate::policy::{
    AccessPolicy, BlindedAccessClaim, BlindedAccessStructure, BlindedClaimBuilder, DimensionType,
    IssuerBlindingKey,
};
use anyhow::Result;
use bls12_381_plus::Scalar;
use cosmian_crypto_core::reexport::rand_core::SeedableRng;

// =============================================================================
// HYBRID MODE ACCESS CONTROL TESTS
// =============================================================================
// These tests demonstrate the hybrid approach:
// - Blinded attributes for privacy (issuers' attribute values hidden from authority)
// - AccessPolicy for encryption (human-readable policy strings)
// - Name registry for mapping policy terms to blinded commitments

/// Helper to create a test nonce
fn test_nonce() -> Nonce {
    Nonce(Scalar::from(42u64))
}

/// Test the complete access control flow using hybrid blinded mode.
///
/// This is the equivalent of the original test_access_control_flow but uses:
/// - Blinded attributes instead of QualifiedAttribute
/// - AccessPolicy for encryption policy specification
/// - add_blinded_attribute_with_name for policy resolution
#[test]
fn test_access_control_flow() -> Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let nonce = test_nonce();

    // =========================================================================
    // PHASE 1: Authority Setup with Hybrid Blinded Mode
    // =========================================================================

    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;

    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // =========================================================================
    // PHASE 2: Setup Dimensions
    // =========================================================================

    // Add dimensions - authority knows dimension names
    let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;
    let sex_dim = auth.add_blinded_dimension("SEX", DimensionType::Anarchy)?;
    let loc_dim = auth.add_blinded_dimension("LOC", DimensionType::Anarchy)?;
    let device_dim = auth.add_blinded_dimension("DEVICE", DimensionType::Hierarchy)?;

    // =========================================================================
    // PHASE 3: Register Issuers
    // =========================================================================

    // Issuer A manages Age + Sex credentials
    let mut issuer_a = IssuerBlindingKey::new();
    let reg_a = issuer_a.register_with_authority(authority_pk, 1000);
    let issuer_a_id =
        auth.register_blinded_issuer(reg_a, issuer_a.identity().public_key(), &mut rng)?;

    // Issuer B manages Location + Device credentials
    let mut issuer_b = IssuerBlindingKey::new();
    let reg_b = issuer_b.register_with_authority(authority_pk, 1001);
    let issuer_b_id =
        auth.register_blinded_issuer(reg_b, issuer_b.identity().public_key(), &mut rng)?;

    // =========================================================================
    // PHASE 4: Issuers Publish Attributes (with names for policy resolution)
    // =========================================================================

    let timestamp = 2000u64;

    // Issuer A's attributes (Age hierarchy)
    for attr_name in &["YOUTH", "ADULT", "SENIOR"] {
        let attr = issuer_a.create_blinded_attribute("AGE", attr_name, &authority_pk)?;
        let proof = issuer_a.prove_ownership("AGE", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &age_dim, "AGE", attr_name, attr, &proof, timestamp, &mut rng,
        )?;
    }

    // Issuer A's Sex attributes
    for attr_name in &["MALE", "FEMALE"] {
        let attr = issuer_a.create_blinded_attribute("SEX", attr_name, &authority_pk)?;
        let proof = issuer_a.prove_ownership("SEX", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &sex_dim, "SEX", attr_name, attr, &proof, timestamp, &mut rng,
        )?;
    }

    // Issuer B's Location attributes
    for attr_name in &["INNER_CITY", "EAST_SYDNEY", "WEST_SYDNEY"] {
        let attr = issuer_b.create_blinded_attribute("LOC", attr_name, &authority_pk)?;
        let proof = issuer_b.prove_ownership("LOC", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &loc_dim, "LOC", attr_name, attr, &proof, timestamp, &mut rng,
        )?;
    }

    // Issuer B's Device attributes
    for attr_name in &["MOBILE", "LAPTOP"] {
        let attr = issuer_b.create_blinded_attribute("DEVICE", attr_name, &authority_pk)?;
        let proof = issuer_b.prove_ownership("DEVICE", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &device_dim,
            "DEVICE",
            attr_name,
            attr,
            &proof,
            timestamp,
            &mut rng,
        )?;
    }

    // Get authority public key for encryption
    let apk = auth.rpk()?;

    // =========================================================================
    // PHASE 5: Alice Creates Encrypted Header with Access Policy
    // =========================================================================

    // Alice encrypts using a policy: (ADULT or SENIOR) AND INNER_CITY AND MOBILE
    let policy =
        AccessPolicy::parse("(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY && DEVICE::MOBILE")?;

    let (secret, enc_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &policy,
        Some(b"alice_metadata"),
        Some(&nonce.to_be_bytes()),
    )?;

    // =========================================================================
    // PHASE 6: Bob Claims Attributes and Gets Capability Token
    // =========================================================================

    // Bob claims: ADULT (age 25), INNER_CITY, MOBILE
    // Note: Bob does NOT claim SEX attribute (for privacy)

    // Bob's claim from Issuer A (Age)
    let claim_a = BlindedClaimBuilder::new(&mut issuer_a, authority_pk)
        .add_attribute("AGE", "ADULT")
        .build_batched()?;

    // Bob's claim from Issuer B (Location + Device)
    let claim_b = BlindedClaimBuilder::new(&mut issuer_b, authority_pk)
        .add_attribute("LOC", "INNER_CITY")
        .add_attribute("DEVICE", "MOBILE")
        .build_batched()?;

    // Convert to BlindedCapabilityClaims
    let capability_claims = vec![
        BlindedCapabilityClaim::from_batched_claim(issuer_a_id, claim_a),
        BlindedCapabilityClaim::from_batched_claim(issuer_b_id, claim_b),
    ];

    // Authority grants capability token
    let capability = create_blinded_capability_token(&mut rng, &mut auth, &capability_claims)?;

    // =========================================================================
    // PHASE 7: Bob Decrypts Content
    // =========================================================================

    match enc_header.decrypt(&access_control, &capability, Some(&nonce.to_be_bytes()))? {
        Some(data) => {
            assert_eq!(data.secret, secret);
            assert_eq!(data.metadata.unwrap(), b"alice_metadata");
            println!("Access control flow test passed!");
        },
        None => {
            panic!("Bob should be able to decrypt - he has matching attributes!");
        },
    }

    Ok(())
}

/// Test that access is denied when user lacks required attributes.
/// Policy requires YOUTH and WEST_SYDNEY, but Bob has ADULT and INNER_CITY.
#[test]
fn test_access_denied_flow_a() -> Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let nonce = test_nonce();

    // Setup authority
    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;
    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // Add dimensions
    let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;
    let loc_dim = auth.add_blinded_dimension("LOC", DimensionType::Anarchy)?;

    // Register issuers
    let mut issuer_a = IssuerBlindingKey::new();
    let reg_a = issuer_a.register_with_authority(authority_pk, 1000);
    let issuer_a_id =
        auth.register_blinded_issuer(reg_a, issuer_a.identity().public_key(), &mut rng)?;

    let mut issuer_b = IssuerBlindingKey::new();
    let reg_b = issuer_b.register_with_authority(authority_pk, 1001);
    let issuer_b_id =
        auth.register_blinded_issuer(reg_b, issuer_b.identity().public_key(), &mut rng)?;

    // Add attributes with names
    let timestamp = 2000u64;

    for attr_name in &["YOUTH", "ADULT", "SENIOR"] {
        let attr = issuer_a.create_blinded_attribute("AGE", attr_name, &authority_pk)?;
        let proof = issuer_a.prove_ownership("AGE", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &age_dim, "AGE", attr_name, attr, &proof, timestamp, &mut rng,
        )?;
    }

    for attr_name in &["INNER_CITY", "WEST_SYDNEY"] {
        let attr = issuer_b.create_blinded_attribute("LOC", attr_name, &authority_pk)?;
        let proof = issuer_b.prove_ownership("LOC", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &loc_dim, "LOC", attr_name, attr, &proof, timestamp, &mut rng,
        )?;
    }

    let apk = auth.rpk()?;

    // Alice encrypts for YOUTH and WEST_SYDNEY only
    let policy = AccessPolicy::parse("AGE::YOUTH && LOC::WEST_SYDNEY")?;
    let (_secret, enc_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &policy,
        Some(b"alice_metadata"),
        Some(&nonce.to_be_bytes()),
    )?;

    // Bob has ADULT (not YOUTH) and INNER_CITY (not WEST_SYDNEY)
    let claim_a = BlindedClaimBuilder::new(&mut issuer_a, authority_pk)
        .add_attribute("AGE", "ADULT")
        .build_batched()?;

    let claim_b = BlindedClaimBuilder::new(&mut issuer_b, authority_pk)
        .add_attribute("LOC", "INNER_CITY")
        .build_batched()?;

    let capability_claims = vec![
        BlindedCapabilityClaim::from_batched_claim(issuer_a_id, claim_a),
        BlindedCapabilityClaim::from_batched_claim(issuer_b_id, claim_b),
    ];

    let capability = create_blinded_capability_token(&mut rng, &mut auth, &capability_claims)?;

    // Bob should NOT be able to decrypt
    match enc_header.decrypt(&access_control, &capability, Some(&nonce.to_be_bytes()))? {
        Some(_) => {
            panic!("Bob should NOT be able to decrypt - he lacks required attributes!");
        },
        None => {
            println!("Access denied flow A test passed - Bob correctly denied!");
        },
    }

    Ok(())
}

/// Test that access is denied when user omits a required attribute.
/// Policy requires FEMALE, but Bob is MALE and omits Sex attribute.
#[test]
fn test_access_denied_flow_b() -> Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let nonce = test_nonce();

    // Setup authority
    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;
    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // Add dimensions
    let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;
    let sex_dim = auth.add_blinded_dimension("SEX", DimensionType::Anarchy)?;
    let loc_dim = auth.add_blinded_dimension("LOC", DimensionType::Anarchy)?;
    let device_dim = auth.add_blinded_dimension("DEVICE", DimensionType::Anarchy)?;

    // Register issuers
    let mut issuer_a = IssuerBlindingKey::new();
    let reg_a = issuer_a.register_with_authority(authority_pk, 1000);
    let issuer_a_id =
        auth.register_blinded_issuer(reg_a, issuer_a.identity().public_key(), &mut rng)?;

    let mut issuer_b = IssuerBlindingKey::new();
    let reg_b = issuer_b.register_with_authority(authority_pk, 1001);
    let issuer_b_id =
        auth.register_blinded_issuer(reg_b, issuer_b.identity().public_key(), &mut rng)?;

    // Add attributes
    let timestamp = 2000u64;

    for attr_name in &["ADULT"] {
        let attr = issuer_a.create_blinded_attribute("AGE", attr_name, &authority_pk)?;
        let proof = issuer_a.prove_ownership("AGE", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &age_dim, "AGE", attr_name, attr, &proof, timestamp, &mut rng,
        )?;
    }

    for attr_name in &["MALE", "FEMALE"] {
        let attr = issuer_a.create_blinded_attribute("SEX", attr_name, &authority_pk)?;
        let proof = issuer_a.prove_ownership("SEX", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &sex_dim, "SEX", attr_name, attr, &proof, timestamp, &mut rng,
        )?;
    }

    for attr_name in &["INNER_CITY"] {
        let attr = issuer_b.create_blinded_attribute("LOC", attr_name, &authority_pk)?;
        let proof = issuer_b.prove_ownership("LOC", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &loc_dim, "LOC", attr_name, attr, &proof, timestamp, &mut rng,
        )?;
    }

    for attr_name in &["MOBILE"] {
        let attr = issuer_b.create_blinded_attribute("DEVICE", attr_name, &authority_pk)?;
        let proof = issuer_b.prove_ownership("DEVICE", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &device_dim,
            "DEVICE",
            attr_name,
            attr,
            &proof,
            timestamp,
            &mut rng,
        )?;
    }

    let apk = auth.rpk()?;

    // Alice encrypts for FEMALE ADULT in INNER_CITY or with MOBILE
    let policy =
        AccessPolicy::parse("AGE::ADULT && SEX::FEMALE && (LOC::INNER_CITY || DEVICE::MOBILE)")?;

    let (_secret, enc_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &policy,
        Some(b"alice_metadata"),
        Some(&nonce.to_be_bytes()),
    )?;

    // Bob is MALE (not FEMALE), so even though he has ADULT, INNER_CITY, and MOBILE,
    // he can't decrypt because policy requires SEX::FEMALE
    let claim_a = BlindedClaimBuilder::new(&mut issuer_a, authority_pk)
        .add_attribute("AGE", "ADULT")
        .add_attribute("SEX", "MALE")  // Bob claims MALE, but policy requires FEMALE
        .build_batched()?;

    let claim_b = BlindedClaimBuilder::new(&mut issuer_b, authority_pk)
        .add_attribute("LOC", "INNER_CITY")
        .add_attribute("DEVICE", "MOBILE")
        .build_batched()?;

    let capability_claims = vec![
        BlindedCapabilityClaim::from_batched_claim(issuer_a_id, claim_a),
        BlindedCapabilityClaim::from_batched_claim(issuer_b_id, claim_b),
    ];

    let capability = create_blinded_capability_token(&mut rng, &mut auth, &capability_claims)?;

    // Bob should NOT be able to decrypt (he has MALE but policy requires FEMALE)
    match enc_header.decrypt(&access_control, &capability, Some(&nonce.to_be_bytes()))? {
        Some(_) => {
            panic!("Bob should NOT be able to decrypt - he is MALE but policy requires FEMALE!");
        },
        None => {
            println!("Access denied flow B test passed - Bob correctly denied!");
        },
    }

    Ok(())
}

#[test]
#[ignore = "TODO: Implement attestation integration with blinded mode"]
fn test_access_control_with_attestations() -> Result<()> {
    // This test needs further work to integrate attestations with blinded mode
    Ok(())
}

// ============================================================================
// Blinded Attribute Integration Tests
// ============================================================================

/// Test that blinded attributes can be created directly using IssuerBlindingKey.
#[test]
fn test_blinded_attributes_creation() -> Result<()> {
    // Create test authority key commitment
    let authority_pk = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

    // Create issuer with blinding key
    let mut issuer = IssuerBlindingKey::new();
    issuer.register_with_authority(authority_pk, 1000);

    // Create blinded attributes directly
    let blinded_age = issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
    let blinded_sex = issuer.create_blinded_attribute("SEX", "MALE", &authority_pk)?;

    // Get preimages for verification
    let preimage_age = issuer.get_preimage("AGE", "ADULT", &authority_pk).unwrap();
    let preimage_sex = issuer.get_preimage("SEX", "MALE", &authority_pk).unwrap();

    // Verify commitments are different (privacy property)
    assert_ne!(blinded_age.commitment(), blinded_sex.commitment());

    // Verify preimages correctly verify their own blinded attributes
    assert!(preimage_age.verify_attribute(&blinded_age));
    assert!(preimage_sex.verify_attribute(&blinded_sex));

    // Cross-verification should fail (binding property)
    assert!(!preimage_age.verify_attribute(&blinded_sex));
    assert!(!preimage_sex.verify_attribute(&blinded_age));

    Ok(())
}

/// Test the complete flow of using blinded attributes INTEGRATED into CapabilityAuthority.
///
/// This demonstrates the privacy-preserving access control flow where:
/// - Authority never sees actual attribute values (only Poseidon2 commitments)
/// - Issuers vouch for attributes through Falcon512 signatures
/// - Users prove attribute ownership without revealing values
///
/// ## Flow:
/// 1. Authority setup with identity (required for blinded mode)
/// 2. Authority initializes blinded structure
/// 3. Authority adds dimensions (schema)
/// 4. Issuer registers with authority
/// 5. Issuer creates blinded attributes and provides them to authority
/// 6. Authority adds blinded attributes (with ownership proofs) and generates secret keys
/// 7. User requests capability using BlindedCapabilityClaim
/// 8. Authority grants capability token (without seeing actual attribute values)
/// 9. User can decrypt content
#[test]
fn test_access_control_with_blinded_attributes() -> Result<()> {
    use crate::access_control::capability::{
        BlindedCapabilityClaim, create_blinded_capability_token,
    };
    use cosmian_crypto_core::reexport::rand_core::SeedableRng;

    let mut rng = cosmian_crypto_core::CsRng::from_entropy();

    // ============================================
    // PHASE 1: Authority Setup with Blinded Mode
    // ============================================

    let access_control = AccessControl::default();

    // Authority MUST have identity for blinded mode (provides authority_pk)
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();

    // Initialize blinded structure - this uses the authority's identity commitment as authority_pk
    auth.init_blinded_structure()?;
    assert!(auth.is_blinded_mode(), "should be in blinded mode");

    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // ============================================
    // PHASE 2: Authority Defines Access Structure Schema
    // ============================================

    // Add dimensions - the authority knows the dimension NAMES but NOT the attribute values
    let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;
    let loc_dim = auth.add_blinded_dimension("LOC", DimensionType::Anarchy)?;
    let device_dim = auth.add_blinded_dimension("DEVICE", DimensionType::Anarchy)?;

    // ============================================
    // PHASE 3: Issuer Registration
    // ============================================

    // Issuer creates their blinding key
    let mut issuer = IssuerBlindingKey::new();
    let registration = issuer.register_with_authority(authority_pk, 1000);

    // Authority registers the issuer
    let issuer_id =
        auth.register_blinded_issuer(registration, issuer.identity().public_key(), &mut rng)?;
    assert_eq!(issuer_id, 1, "first issuer should have id 1");
    assert_eq!(auth.blinded_issuer_count(), 1);

    // ============================================
    // PHASE 4: Issuer Publishes Blinded Attributes
    // ============================================

    // Issuer creates blinded attributes - the authority sees ONLY commitments, NOT values
    let adult_attr = issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
    let adult_proof = issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;

    let inner_city_attr = issuer.create_blinded_attribute("LOC", "INNER_CITY", &authority_pk)?;
    let inner_city_proof = issuer.prove_ownership("LOC", "INNER_CITY", &authority_pk)?;

    let mobile_attr = issuer.create_blinded_attribute("DEVICE", "MOBILE", &authority_pk)?;
    let mobile_proof = issuer.prove_ownership("DEVICE", "MOBILE", &authority_pk)?;

    // ============================================
    // PHASE 5: Authority Adds Blinded Attributes
    // ============================================

    let timestamp = 2000u64;

    auth.add_blinded_attribute(&age_dim, adult_attr.clone(), &adult_proof, timestamp, &mut rng)?;
    auth.add_blinded_attribute(
        &loc_dim,
        inner_city_attr.clone(),
        &inner_city_proof,
        timestamp,
        &mut rng,
    )?;
    auth.add_blinded_attribute(
        &device_dim,
        mobile_attr.clone(),
        &mobile_proof,
        timestamp,
        &mut rng,
    )?;

    // Verify the structure has the attributes
    let structure = auth.blinded_structure().expect("should have blinded structure");
    assert!(structure.contains_attribute(&adult_attr.commitment()), "should contain ADULT");
    assert!(
        structure.contains_attribute(&inner_city_attr.commitment()),
        "should contain INNER_CITY"
    );
    assert!(structure.contains_attribute(&mobile_attr.commitment()), "should contain MOBILE");

    // ============================================
    // PHASE 6: User Creates Blinded Capability Claim
    // ============================================

    // Using batched claim builder for efficiency (single signature)
    let batched_claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("AGE", "ADULT")
        .add_attribute("LOC", "INNER_CITY")
        .add_attribute("DEVICE", "MOBILE")
        .build_batched()?;

    // Convert to BlindedCapabilityClaim for the authority
    let capability_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, batched_claim);

    // ============================================
    // PHASE 7: Authority Grants Capability Token
    // ============================================

    let capability = create_blinded_capability_token(&mut rng, &mut auth, &[capability_claim])?;
    assert!(capability.count() > 0, "capability should have access rights");

    println!(
        "Capability token created successfully with {} access rights",
        capability.count()
    );

    println!("Blinded attributes integrated access control test passed!");
    Ok(())
}

/// Test batch ownership proof with access control flow.
/// Demonstrates efficient multi-attribute proof verification.
#[test]
fn test_batch_ownership_proof_integration() -> Result<()> {
    let authority_pk = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

    // Create issuer
    let mut issuer = IssuerBlindingKey::new();
    issuer.register_with_authority(authority_pk, 1000);

    // Create multiple blinded attributes
    let _attr1 = issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
    let _attr2 = issuer.create_blinded_attribute("SEX", "MALE", &authority_pk)?;
    let _attr3 = issuer.create_blinded_attribute("LOC", "INNER_CITY", &authority_pk)?;
    let _attr4 = issuer.create_blinded_attribute("DEVICE", "MOBILE", &authority_pk)?;

    // Create batch proof for all attributes (efficient - single signature)
    let batch_proof = issuer.prove_ownership_batch(
        &[("AGE", "ADULT"), ("SEX", "MALE"), ("LOC", "INNER_CITY"), ("DEVICE", "MOBILE")],
        &authority_pk,
    )?;

    // Verify batch proof
    let issuer_pk = issuer.identity().public_key();
    assert!(batch_proof.verify(&issuer_pk), "batch proof should verify");
    assert_eq!(batch_proof.len(), 4, "should have 4 attributes in batch");

    // Verify all attributes are contained
    let preimage1 = issuer.get_preimage("AGE", "ADULT", &authority_pk).unwrap();
    let commitment1 = preimage1.compute_commitment();
    assert!(batch_proof.contains(&commitment1), "batch should contain AGE::ADULT");

    println!("Batch ownership proof integration test passed!");
    Ok(())
}

/// Test privacy properties: unlinkability between different authorities.
#[test]
fn test_cross_authority_privacy() -> Result<()> {
    let authority1 = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);
    let authority2 = Word::new([Felt::new(500), Felt::new(600), Felt::new(700), Felt::new(800)]);

    // Same issuer registers with two different authorities
    let mut issuer = IssuerBlindingKey::new();
    issuer.register_with_authority(authority1, 1000);
    issuer.register_with_authority(authority2, 1001);

    // Create the same attribute for both authorities
    let attr_auth1 = issuer.create_blinded_attribute("AGE", "ADULT", &authority1)?;
    let attr_auth2 = issuer.create_blinded_attribute("AGE", "ADULT", &authority2)?;

    // Commitments should be different (unlinkability)
    assert_ne!(
        attr_auth1.commitment(),
        attr_auth2.commitment(),
        "same attribute should have different commitments for different authorities"
    );

    // Proofs should be distinct
    let proof1 = issuer.prove_ownership("AGE", "ADULT", &authority1)?;
    let proof2 = issuer.prove_ownership("AGE", "ADULT", &authority2)?;

    assert_ne!(
        proof1.attribute.commitment(),
        proof2.attribute.commitment(),
        "proofs should reference different commitments"
    );

    // Both proofs should verify with the same issuer key
    let issuer_pk = issuer.identity().public_key();
    assert!(proof1.verify(&issuer_pk), "proof1 should verify");
    assert!(proof2.verify(&issuer_pk), "proof2 should verify");

    println!("Cross-authority privacy test passed!");
    Ok(())
}

/// Test blinded access structure with multiple issuers from different organizations.
#[test]
fn test_multi_issuer_blinded_structure() -> Result<()> {
    let authority_pk = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

    // Create blinded access structure
    let mut structure = BlindedAccessStructure::new(authority_pk);
    let age_dim = structure.add_dimension("AGE", DimensionType::Hierarchy);
    let dept_dim = structure.add_dimension("DEPARTMENT", DimensionType::Anarchy);

    // Government issuer for age verification
    let mut gov_issuer = IssuerBlindingKey::new();
    let gov_reg = gov_issuer.register_with_authority(authority_pk, 1000);
    structure.register_issuer(gov_reg)?;

    // Corporate issuer for department
    let mut corp_issuer = IssuerBlindingKey::new();
    let corp_reg = corp_issuer.register_with_authority(authority_pk, 1001);
    structure.register_issuer(corp_reg)?;

    // Government issues age attribute
    let age_attr = gov_issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
    let age_proof = gov_issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;
    let gov_pk = gov_issuer.identity().public_key();
    structure.add_attribute(&age_dim, age_attr, &age_proof, &gov_pk, 2000)?;

    // Corporation issues department attribute
    let dept_attr =
        corp_issuer.create_blinded_attribute("DEPARTMENT", "ENGINEERING", &authority_pk)?;
    let dept_proof = corp_issuer.prove_ownership("DEPARTMENT", "ENGINEERING", &authority_pk)?;
    let corp_pk = corp_issuer.identity().public_key();
    structure.add_attribute(&dept_dim, dept_attr, &dept_proof, &corp_pk, 2001)?;

    // Verify structure state
    assert_eq!(structure.issuer_count(), 2);
    assert_eq!(structure.attribute_count(), 2);

    // Verify attributes are from correct issuers
    let age_meta = structure.get_attribute_metadata(age_attr.commitment()).unwrap();
    assert_eq!(age_meta.issuer_pk, gov_issuer.commitment());

    let dept_meta = structure.get_attribute_metadata(dept_attr.commitment()).unwrap();
    assert_eq!(dept_meta.issuer_pk, corp_issuer.commitment());

    // Create claims from each issuer
    let mut gov_claim = BlindedAccessClaim::new(gov_issuer.commitment());
    gov_claim.add_attribute(age_attr, age_proof.clone());

    let mut corp_claim = BlindedAccessClaim::new(corp_issuer.commitment());
    corp_claim.add_attribute(dept_attr, dept_proof.clone());

    // Verify claims
    assert!(gov_claim.verify_proofs(&gov_pk));
    assert!(corp_claim.verify_proofs(&corp_pk));

    // Combined attributes cover both issuers
    let all_claimed_attrs: Vec<_> =
        gov_claim.attributes.iter().chain(corp_claim.attributes.iter()).collect();
    assert_eq!(all_claimed_attrs.len(), 2);

    println!("Multi-issuer blinded structure test passed!");
    Ok(())
}
