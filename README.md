![](./assets/colossus.jpg)

# Colossus

Colossus is a privacy-aware capability-based security framework that cryptographically enforces Zero-Trust principles ("Never Trust, Always Verify").

## Key Features

- **Privacy-Preserving Access Control**: Attribute values are hidden from the authority using Poseidon2 cryptographic commitments
- **Hybrid Blinded Mode**: Human-readable policies (e.g., `"AGE::ADULT && LOC::INNER_CITY"`) combined with privacy-preserving blinded attributes
- **Quantum-Secure Encryption**: Post-quantum KEM with hidden access policies based on [ETSI TS 104 015](https://www.etsi.org/deliver/etsi_ts/104000_104099/104015/01.01.01_60/ts_104015v010101p.pdf)
- **Multi-Issuer Federation**: Credentials from multiple issuers can be combined to satisfy access policies
- **Capability-Based Security**: Access tokens grant specific rights without revealing underlying attributes

## Architecture

```
+------------------+     +-------------------+     +------------------+
|   Credential     |     |    Capability     |     |    Encrypted     |
|    Issuers       |---->|    Authority      |---->|     Content      |
+------------------+     +-------------------+     +------------------+
        |                        ^                        |
        |                        |                        |
        v                        |                        v
+------------------+     +-------------------+     +------------------+
|    Blinded       |     |   Capability      |     |    Decrypted     |
|   Attributes     |     |     Token         |     |     Content      |
+------------------+     +-------------------+     +------------------+
```

## Privacy Model

Colossus implements a **hybrid blinded mode** that provides:

1. **Issuer Privacy**: Issuers create blinded attributes using Poseidon2 commitments. The authority never sees actual attribute values.
2. **User Privacy**: Users can selectively disclose attributes. In the example below, Bob doesn't reveal his sex to anyone.
3. **Policy Expressiveness**: Encryptors use human-readable policies like `"AGE::ADULT && LOC::INNER_CITY"`.
4. **Cross-Authority Unlinkability**: The same attribute registered with different authorities produces different commitments.

## Quick Start

### Installation

Add Colossus to your `Cargo.toml`:

```toml
[dependencies]
colossus-core = { git = "https://github.com/FeurJak/Colossus.git" }
```

### Basic Usage

```rust
use colossus_core::prelude::*;
use colossus_core::access_control::{AccessControl, EncryptedHeader};
use colossus_core::access_control::capability::{BlindedCapabilityClaim, create_blinded_capability_token};
use colossus_core::policy::{AccessPolicy, BlindedClaimBuilder, DimensionType, IssuerBlindingKey};

fn main() -> anyhow::Result<()> {
    let mut rng = cosmian_crypto_core::CsRng::from_entropy();

    // =========================================================================
    // Phase 1: Authority Setup
    // =========================================================================
    let access_control = AccessControl::default();
    let auth = access_control.setup_blinded_authority()?;
    let mut auth = auth.with_identity();
    auth.init_blinded_structure()?;
    
    let authority_pk = auth.authority_pk().expect("authority should have pk");

    // =========================================================================
    // Phase 2: Define Dimensions (Schema)
    // =========================================================================
    let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;
    let loc_dim = auth.add_blinded_dimension("LOC", DimensionType::Anarchy)?;
    let device_dim = auth.add_blinded_dimension("DEVICE", DimensionType::Hierarchy)?;

    // =========================================================================
    // Phase 3: Register Issuers
    // =========================================================================
    
    // Issuer A manages Age credentials
    let mut issuer_a = IssuerBlindingKey::new();
    let reg_a = issuer_a.register_with_authority(authority_pk, 1000);
    let issuer_a_id = auth.register_blinded_issuer(
        reg_a, 
        issuer_a.identity().public_key(), 
        &mut rng
    )?;

    // Issuer B manages Location + Device credentials
    let mut issuer_b = IssuerBlindingKey::new();
    let reg_b = issuer_b.register_with_authority(authority_pk, 1001);
    let issuer_b_id = auth.register_blinded_issuer(
        reg_b, 
        issuer_b.identity().public_key(), 
        &mut rng
    )?;

    // =========================================================================
    // Phase 4: Publish Blinded Attributes (with names for policy resolution)
    // =========================================================================
    let timestamp = 2000u64;

    // Age attributes (hierarchical)
    for attr_name in &["YOUTH", "ADULT", "SENIOR"] {
        let attr = issuer_a.create_blinded_attribute("AGE", attr_name, &authority_pk)?;
        let proof = issuer_a.prove_ownership("AGE", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &age_dim, "AGE", attr_name, attr, &proof, timestamp, &mut rng
        )?;
    }

    // Location attributes
    for attr_name in &["INNER_CITY", "EAST_SYDNEY", "WEST_SYDNEY"] {
        let attr = issuer_b.create_blinded_attribute("LOC", attr_name, &authority_pk)?;
        let proof = issuer_b.prove_ownership("LOC", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &loc_dim, "LOC", attr_name, attr, &proof, timestamp, &mut rng
        )?;
    }

    // Device attributes
    for attr_name in &["MOBILE", "LAPTOP"] {
        let attr = issuer_b.create_blinded_attribute("DEVICE", attr_name, &authority_pk)?;
        let proof = issuer_b.prove_ownership("DEVICE", attr_name, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &device_dim, "DEVICE", attr_name, attr, &proof, timestamp, &mut rng
        )?;
    }

    let apk = auth.rpk()?;

    // =========================================================================
    // Phase 5: Alice Encrypts Data with Access Policy
    // =========================================================================
    let policy = AccessPolicy::parse(
        "(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY && DEVICE::MOBILE"
    )?;

    let (secret, enc_header) = EncryptedHeader::generate_with_policy(
        &access_control,
        &apk,
        &auth,
        &policy,
        Some(b"alice_secret_metadata"),
        Some(b"additional_auth_data"),
    )?;

    // =========================================================================
    // Phase 6: Bob Claims Attributes and Gets Capability Token
    // =========================================================================
    
    // Bob claims: ADULT, INNER_CITY, MOBILE
    let claim_a = BlindedClaimBuilder::new(&mut issuer_a, authority_pk)
        .add_attribute("AGE", "ADULT")
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

    // =========================================================================
    // Phase 7: Bob Decrypts Content
    // =========================================================================
    match enc_header.decrypt(&access_control, &capability, Some(b"additional_auth_data"))? {
        Some(data) => {
            assert_eq!(data.secret, secret);
            println!("Decrypted metadata: {:?}", data.metadata);
        }
        None => {
            println!("Access denied - insufficient attributes");
        }
    }

    Ok(())
}
```

## Access Policy Syntax

Colossus uses a simple, expressive policy syntax:

| Syntax | Description |
|--------|-------------|
| `DIM::ATTR` | Single attribute requirement |
| `A && B` | Logical AND - both required |
| `A \|\| B` | Logical OR - either sufficient |
| `(A \|\| B) && C` | Grouping with parentheses |
| `*` | Broadcast - all users can decrypt |

### Examples

```rust
// Simple: requires adult age
AccessPolicy::parse("AGE::ADULT")?;

// OR: adult or senior
AccessPolicy::parse("AGE::ADULT || AGE::SENIOR")?;

// AND: adult in inner city
AccessPolicy::parse("AGE::ADULT && LOC::INNER_CITY")?;

// Complex: (adult or senior) AND inner city AND mobile device
AccessPolicy::parse("(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY && DEVICE::MOBILE")?;

// Broadcast to everyone
AccessPolicy::broadcast();
```

## Dimension Types

| Type | Description | Use Case |
|------|-------------|----------|
| `Hierarchy` | Ordered attributes with inheritance | Age levels, security clearances |
| `Anarchy` | Independent, unordered attributes | Locations, departments |

## Multi-Issuer Federation

Colossus supports credentials from multiple independent issuers:

```rust
// Government issuer for identity
let mut gov_issuer = IssuerBlindingKey::new();
let gov_id = auth.register_blinded_issuer(...)?;

// Company issuer for employment
let mut company_issuer = IssuerBlindingKey::new();
let company_id = auth.register_blinded_issuer(...)?;

// Bank issuer for payment verification
let mut bank_issuer = IssuerBlindingKey::new();
let bank_id = auth.register_blinded_issuer(...)?;

// User combines credentials from all three
let claims = vec![
    BlindedCapabilityClaim::from_batched_claim(gov_id, age_claim),
    BlindedCapabilityClaim::from_batched_claim(company_id, role_claim),
    BlindedCapabilityClaim::from_batched_claim(bank_id, payment_claim),
];

let capability = create_blinded_capability_token(&mut rng, &mut auth, &claims)?;
```

## Documentation

See the [docs](./docs/) folder for detailed documentation:

- [Architecture Overview](./docs/architecture.md) - System design and components
- [Blinded Attributes](./docs/blinded-attributes.md) - Privacy-preserving attribute system
- [Access Policies](./docs/access-policy.md) - Policy syntax and semantics
- [API Reference](./docs/api-reference.md) - Complete API documentation

## Building & Testing

```bash
# Build the project
cargo build

# Run all tests (223 tests)
cargo test

# Run specific test
cargo test test_access_control_flow

# Build documentation
cargo doc --open
```

## Security Considerations

- **Quantum Resistance**: Uses ML-KEM for key encapsulation
- **Commitment Binding**: Poseidon2 commitments are computationally binding
- **Unlinkability**: Same attribute with different authorities produces different commitments
- **Forward Secrecy**: Session keys are derived using secure KDFs

## Acknowledgements

Colossus builds upon:
- [CoverCrypt](https://github.com/Cosmian/cover_crypt) - ETSI TS 104 015 implementation
- [Miden](https://polygon.technology/polygon-miden) - Poseidon2 hash function
- [Falcon](https://falcon-sign.info/) - Post-quantum signatures for issuer authentication

## License

[Add license information]
