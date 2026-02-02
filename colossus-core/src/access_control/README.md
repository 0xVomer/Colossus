# Access Control Module

This module implements Colossus's privacy-aware capability-based access control system.

## Overview

The access control module provides:

- **Capability Authority**: Manages access rights and issues capability tokens
- **Encrypted Headers**: KEM-based encryption with hidden access policies
- **Blinded Mode**: Privacy-preserving attribute commitments
- **Revocation**: Capability token revocation with Merkle proofs

## Module Structure

```
access_control/
├── mod.rs              # AccessControl entry point
├── capability/
│   ├── mod.rs          # Capability token types
│   ├── authority.rs    # CapabilityAuthority implementation
│   └── attestation.rs  # Authority identity and delegation
├── encrypted_header.rs # EncryptedHeader for data encryption
├── cryptography/
│   ├── ae_poseidon2.rs # Poseidon2 AEAD
│   ├── mlkem.rs        # ML-KEM post-quantum KEM
│   └── nike.rs         # Non-interactive key exchange
├── revocation/
│   └── mod.rs          # RevocationRegistry
└── root_authority.rs   # Root key management
```

## Quick Start

### Setup Authority (Blinded Mode)

```rust
use colossus_core::access_control::AccessControl;
use colossus_core::policy::DimensionType;

let access_control = AccessControl::default();
let mut auth = access_control.setup_blinded_authority()?.with_identity();
auth.init_blinded_structure()?;

// Add dimensions
let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;
let loc_dim = auth.add_blinded_dimension("LOC", DimensionType::Anarchy)?;
```

### Register Issuers

```rust
use colossus_core::policy::IssuerBlindingKey;

let mut issuer = IssuerBlindingKey::new();
let authority_pk = auth.authority_pk().unwrap();
let registration = issuer.register_with_authority(authority_pk, timestamp);

let issuer_id = auth.register_blinded_issuer(
    registration,
    issuer.identity().public_key(),
    &mut rng
)?;
```

### Add Blinded Attributes

```rust
// Issuer creates blinded attribute
let attr = issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
let proof = issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;

// Authority adds with name (for policy resolution)
auth.add_blinded_attribute_with_name(
    &age_dim,
    "AGE",
    "ADULT",
    attr,
    &proof,
    timestamp,
    &mut rng
)?;
```

### Encrypt with Policy

```rust
use colossus_core::access_control::EncryptedHeader;
use colossus_core::policy::AccessPolicy;

let policy = AccessPolicy::parse("AGE::ADULT && LOC::INNER_CITY")?;
let apk = auth.rpk()?;

let (secret, enc_header) = EncryptedHeader::generate_with_policy(
    &access_control,
    &apk,
    &auth,
    &policy,
    Some(b"metadata"),
    Some(b"aad"),
)?;
```

### Issue Capability Token

```rust
use colossus_core::access_control::capability::{
    BlindedCapabilityClaim,
    create_blinded_capability_token
};
use colossus_core::policy::BlindedClaimBuilder;

// User builds claim
let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
    .add_attribute("AGE", "ADULT")
    .add_attribute("LOC", "INNER_CITY")
    .build_batched()?;

let cap_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, claim);

// Authority issues token
let token = create_blinded_capability_token(&mut rng, &mut auth, &[cap_claim])?;
```

### Decrypt

```rust
match enc_header.decrypt(&access_control, &token, Some(b"aad"))? {
    Some(cleartext) => {
        // Access granted
        println!("Secret: {:?}", cleartext.secret);
        println!("Metadata: {:?}", cleartext.metadata);
    }
    None => {
        // Access denied
        println!("Insufficient attributes");
    }
}
```

## Key Types

| Type | Description |
|------|-------------|
| `AccessControl` | Main entry point |
| `CapabilityAuthority` | Manages access rights and issues tokens |
| `CapabilityAuthorityPublicKey` | Authority's public key for encryption |
| `AccessCapabilityToken` | Token granting decryption rights |
| `EncryptedHeader` | Encrypted metadata with access control |
| `BlindedCapabilityClaim` | User's claim for capability request |

## Cryptographic Primitives

- **KEM**: Hybrid ElGamal + ML-KEM-768 (post-quantum)
- **AEAD**: Poseidon2-based authenticated encryption
- **Signatures**: Falcon512 for issuer proofs
- **Commitments**: Poseidon2 for blinded attributes

## Security Properties

1. **Hidden Policy**: Encryption doesn't reveal the access policy
2. **Attribute Privacy**: Authority only sees commitments, not values
3. **Quantum Resistance**: ML-KEM provides PQ security
4. **Unlinkability**: Same attribute → different commitments per authority

## See Also

- [Architecture Overview](../../../docs/architecture.md)
- [Blinded Attributes](../../../docs/blinded-attributes.md)
- [Access Policies](../../../docs/access-policy.md)
- [API Reference](../../../docs/api-reference.md)
