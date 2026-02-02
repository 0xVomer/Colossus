# Blinded Attributes

This document explains Colossus's privacy-preserving blinded attribute system.

## Overview

Blinded attributes allow credential issuers to register attributes with the Capability Authority without revealing the actual attribute values. The authority only sees cryptographic commitments, preserving privacy while enabling policy-based access control.

## Key Concepts

### Traditional vs Blinded Attributes

| Aspect | Traditional | Blinded |
|--------|-------------|---------|
| Authority sees | `"AGE::ADULT"` | `0x7a3f...` (commitment) |
| Policy resolution | Direct lookup | Name registry |
| Privacy | Authority knows all values | Authority only sees commitments |
| Unlinkability | Same value everywhere | Different commitment per authority |

### Commitment Structure

A blinded attribute commitment is computed as:

```
commitment = Poseidon2(
    dimension_commitment,
    attribute_hash,
    issuer_commitment,
    authority_pk,
    salt
)
```

Where:
- `dimension_commitment` = Poseidon2(dimension_name, authority_pk)
- `attribute_hash` = Poseidon2(attribute_name)
- `issuer_commitment` = Poseidon2(issuer_secret_key)
- `salt` = Random 32-byte value

## Components

### 1. IssuerBlindingKey

The issuer's secret key for creating blinded attributes.

```rust
use colossus_core::policy::IssuerBlindingKey;

// Create a new issuer with blinding capabilities
let mut issuer = IssuerBlindingKey::new();

// Register with an authority
let authority_pk = auth.authority_pk().expect("need pk");
let registration = issuer.register_with_authority(authority_pk, timestamp);

// Create a blinded attribute
let blinded_attr = issuer.create_blinded_attribute(
    "AGE",      // dimension
    "ADULT",    // attribute name
    &authority_pk
)?;

// Create ownership proof (Falcon512 signature)
let proof = issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;
```

### 2. BlindedAttribute

A privacy-preserving attribute representation.

```rust
pub struct BlindedAttribute {
    /// The Poseidon2 commitment hiding the attribute
    commitment: Word,
    
    /// Commitment to the dimension (for structure validation)
    dimension_commitment: Word,
}
```

**Key Methods:**
- `commitment()` - Get the attribute commitment
- `dimension_commitment()` - Get the dimension commitment

### 3. AttributePreimage

The secret values that produce a commitment.

```rust
pub struct AttributePreimage {
    dimension: [u8; 32],
    attribute: [u8; 32],
    issuer: Word,
    authority: Word,
    salt: [u8; 32],
}
```

**Key Methods:**
- `verify_attribute(&BlindedAttribute)` - Verify commitment matches
- `compute_commitment()` - Recompute the commitment

### 4. BlindedAccessStructure

The authority's view of the attribute space.

```rust
pub struct BlindedAccessStructure {
    authority_pk: Word,
    dimensions: HashMap<[u8; 32], BlindedDimension>,
    issuers: HashMap<Word, BlindedIssuerRegistration>,
    
    // Name registry for policy resolution
    name_registry: HashMap<String, Word>,      // "DIM::ATTR" -> commitment
    dimension_names: HashMap<[u8; 32], String>, // commitment -> "DIM"
}
```

## Hybrid Mode: Name Registry

The key innovation in Colossus is the **name registry** that maps human-readable policy terms to blinded commitments. This enables:

1. **Encryptors** to use readable policies: `"AGE::ADULT && LOC::INNER_CITY"`
2. **Authority** to resolve these to cryptographic rights without knowing values
3. **Issuers** to maintain privacy of their attribute definitions

### How It Works

```rust
// Issuer creates blinded attribute with ownership proof
let attr = issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
let proof = issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;

// Authority adds to structure WITH the name (for policy resolution)
auth.add_blinded_attribute_with_name(
    &dimension,
    "AGE",           // dimension name
    "ADULT",         // attribute name  
    attr,
    &proof,
    timestamp,
    &mut rng
)?;

// Later, when encrypting with policy "AGE::ADULT"
// Authority looks up "AGE::ADULT" in name_registry -> gets commitment
// Uses commitment to find cryptographic rights
```

## Ownership Proofs

Issuers must prove they created an attribute using Falcon512 signatures.

### Single Attribute Proof

```rust
let proof = issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;

// Proof contains:
// - The blinded attribute
// - Falcon512 signature over the commitment
// - Issuer's public key for verification
```

### Batch Ownership Proof

For efficiency, prove multiple attributes with a single signature:

```rust
let batch_proof = issuer.prove_ownership_batch(
    &[
        ("AGE", "ADULT"),
        ("LOC", "INNER_CITY"),
        ("DEVICE", "MOBILE"),
    ],
    &authority_pk
)?;

// Single signature covering all attributes
assert!(batch_proof.verify(&issuer.identity().public_key()));
```

## Claim Building

Users build claims to request capability tokens.

### BlindedClaimBuilder

Fluent API for constructing claims:

```rust
use colossus_core::policy::BlindedClaimBuilder;

// Build a batched claim (efficient - single signature)
let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
    .add_attribute("AGE", "ADULT")
    .add_attribute("LOC", "INNER_CITY")
    .add_attribute("DEVICE", "MOBILE")
    .build_batched()?;

// Verify the claim
let issuer_pk = issuer.identity().public_key();
assert!(claim.verify(&issuer_pk));
```

### BlindedCapabilityClaim

Convert batched claims for the authority:

```rust
use colossus_core::access_control::capability::BlindedCapabilityClaim;

let capability_claim = BlindedCapabilityClaim::from_batched_claim(
    issuer_id,      // Issuer's ID from registration
    batched_claim   // The batched claim from builder
);
```

## Privacy Properties

### 1. Authority Blindness

The authority never sees:
- Actual attribute values (only commitments)
- Relationship between attributes (each is independent)
- User's selection of attributes (only claimed set)

### 2. Cross-Authority Unlinkability

The same attribute with different authorities produces different commitments:

```rust
let authority_a = Word::new([Felt::new(1), ...]);
let authority_b = Word::new([Felt::new(2), ...]);

issuer.register_with_authority(authority_a, 1000);
issuer.register_with_authority(authority_b, 1001);

let attr_a = issuer.create_blinded_attribute("AGE", "ADULT", &authority_a)?;
let attr_b = issuer.create_blinded_attribute("AGE", "ADULT", &authority_b)?;

// Different commitments - cannot be linked!
assert_ne!(attr_a.commitment(), attr_b.commitment());
```

### 3. Cross-Issuer Unlinkability

Different issuers produce different commitments for the same attribute:

```rust
let mut issuer_1 = IssuerBlindingKey::new();
let mut issuer_2 = IssuerBlindingKey::new();

issuer_1.register_with_authority(authority_pk, 1000);
issuer_2.register_with_authority(authority_pk, 1001);

let attr_1 = issuer_1.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
let attr_2 = issuer_2.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;

// Different commitments!
assert_ne!(attr_1.commitment(), attr_2.commitment());
```

### 4. Commitment Binding

It's computationally infeasible to find two different attribute values that produce the same commitment:

```rust
// Given a commitment, you cannot forge a different preimage
let attr_adult = issuer.create_blinded_attribute("AGE", "ADULT", &pk)?;
let attr_youth = issuer.create_blinded_attribute("AGE", "YOUTH", &pk)?;

// These are cryptographically different
assert_ne!(attr_adult.commitment(), attr_youth.commitment());
```

## Complete Example

```rust
use colossus_core::access_control::AccessControl;
use colossus_core::access_control::capability::{BlindedCapabilityClaim, create_blinded_capability_token};
use colossus_core::policy::{BlindedClaimBuilder, DimensionType, IssuerBlindingKey};

fn example() -> anyhow::Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();

    // Setup authority in blinded mode
    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;
    
    let authority_pk = auth.authority_pk().unwrap();

    // Add dimension
    let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;

    // Setup issuer
    let mut issuer = IssuerBlindingKey::new();
    let reg = issuer.register_with_authority(authority_pk, 1000);
    let issuer_id = auth.register_blinded_issuer(
        reg,
        issuer.identity().public_key(),
        &mut rng
    )?;

    // Issuer creates blinded attributes
    let adult_attr = issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
    let adult_proof = issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;

    // Authority adds attribute (with name for policy resolution)
    auth.add_blinded_attribute_with_name(
        &age_dim,
        "AGE",
        "ADULT",
        adult_attr,
        &adult_proof,
        2000,
        &mut rng
    )?;

    // User builds claim
    let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("AGE", "ADULT")
        .build_batched()?;

    // Convert to capability claim
    let cap_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, claim);

    // Get capability token
    let token = create_blinded_capability_token(&mut rng, &mut auth, &[cap_claim])?;

    println!("Capability token created with {} rights", token.count());
    
    Ok(())
}
```

## Security Considerations

1. **Salt Management**: Each attribute uses a unique salt. Reusing salts could leak information.

2. **Issuer Key Security**: The `IssuerBlindingKey` must be kept secret. Compromise allows forging attributes.

3. **Proof Verification**: Always verify ownership proofs before adding attributes to the structure.

4. **Timestamp Ordering**: Use monotonically increasing timestamps for registration to prevent replay.

## API Reference

| Type | Purpose |
|------|---------|
| `IssuerBlindingKey` | Issuer's secret key for creating blinded attributes |
| `BlindedAttribute` | Privacy-preserving attribute commitment |
| `AttributePreimage` | Secret values that produce a commitment |
| `AttributeOwnershipProof` | Falcon512 signed proof of attribute creation |
| `BatchOwnershipProof` | Efficient multi-attribute proof |
| `BlindedClaimBuilder` | Fluent API for building claims |
| `BatchedBlindedClaim` | Efficient batched claim with single signature |
| `BlindedAccessStructure` | Authority's view with name registry |
