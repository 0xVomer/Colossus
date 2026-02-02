// =============================================================================
// DAC Builder Tests
// =============================================================================
//
// NOTE: These tests need to be rewritten for the BlindedAttribute-based flow.
// The QualifiedAttribute flow has been removed.
//
// The original tests used:
// - Entry::new(&[QualifiedAttribute...])
// - register_issuer() with IssuerPublic containing AccessStructure
// - AccessCredentialBuilder validation against AccessStructure
//
// The new flow should use:
// - Entry::new(&[BlindedAttribute...])
// - IssuerBlindingKey for creating blinded attributes
// - register_blinded_issuer() with IssuerRegistration
// - Ownership proofs for attribute validation

use anyhow::Result;

/// Test credential building with blinded attributes.
///
/// TODO: Rewrite this test to:
/// 1. Create an IssuerBlindingKey
/// 2. Register it with the authority's blinded structure
/// 3. Create BlindedAttribute entries
/// 4. Issue credentials using the blinded attributes
#[test]
#[ignore = "Needs implementation for BlindedAttribute-based flow"]
fn test_credential_building_blinded() -> Result<()> {
    // Test body removed - needs complete rewrite
    Ok(())
}

/// Test issuer with unsupported attributes (blinded version).
///
/// TODO: Rewrite this test to verify that:
/// 1. Issuers can only create blinded attributes for registered dimensions
/// 2. Authority validates ownership proofs before accepting attributes
#[test]
#[ignore = "Needs implementation for BlindedAttribute-based flow"]
fn test_issuer_unsupported_attribute_blinded() -> Result<()> {
    // Test body removed - needs complete rewrite
    Ok(())
}
