# API Reference

Complete API reference for Colossus's core types and functions.

## Table of Contents

- [Access Control](#access-control)
- [Capability Authority](#capability-authority)
- [Encrypted Header](#encrypted-header)
- [Policy Types](#policy-types)
- [Blinded Attributes](#blinded-attributes)
- [Capability Claims](#capability-claims)
- [Cryptographic Types](#cryptographic-types)

---

## Access Control

### AccessControl

Main entry point for the access control system.

```rust
use colossus_core::access_control::AccessControl;

pub struct AccessControl { /* ... */ }
```

#### Methods

##### `default() -> Self`
Create a new AccessControl instance with default RNG.

```rust
let access_control = AccessControl::default();
```

##### `setup_blinded_authority() -> Result<CapabilityAuthority>`
Create a new capability authority for blinded mode.

```rust
let auth = access_control.setup_blinded_authority()?;
```

##### `encapsulate_for_rights(pk, rights) -> Result<(Secret, XEnc)>`
Encrypt a secret for a set of access rights.

```rust
let (secret, encapsulation) = access_control.encapsulate_for_rights(
    &authority_pk,
    &rights_set
)?;
```

##### `decapsulate(token, encapsulation) -> Result<Option<Secret>>`
Decrypt using a capability token.

```rust
let secret = access_control.decapsulate(&capability_token, &encapsulation)?;
```

---

## Capability Authority

### CapabilityAuthority

Manages the access control state and issues capability tokens.

```rust
use colossus_core::access_control::capability::CapabilityAuthority;
```

#### Methods

##### `with_identity() -> Self`
Add identity support for attestations and blinded mode.

```rust
let auth = access_control.setup_blinded_authority()?.with_identity();
```

##### `init_blinded_structure() -> Result<()>`
Initialize the blinded access structure. Required before adding dimensions/attributes.

```rust
auth.init_blinded_structure()?;
```

##### `authority_pk() -> Option<Word>`
Get the authority's public key commitment.

```rust
let pk = auth.authority_pk().expect("authority should have pk");
```

##### `add_blinded_dimension(name, dim_type) -> Result<Word>`
Add a dimension to the access structure.

```rust
use colossus_core::policy::DimensionType;

let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;
let loc_dim = auth.add_blinded_dimension("LOC", DimensionType::Anarchy)?;
```

##### `register_blinded_issuer(reg, pk, rng) -> Result<u64>`
Register a credential issuer.

```rust
let issuer_id = auth.register_blinded_issuer(
    registration,
    issuer.identity().public_key(),
    &mut rng
)?;
```

##### `add_blinded_attribute_with_name(...) -> Result<()>`
Add a blinded attribute with its name for policy resolution.

```rust
auth.add_blinded_attribute_with_name(
    &dimension,          // Dimension commitment
    "AGE",               // Dimension name
    "ADULT",             // Attribute name
    blinded_attr,        // BlindedAttribute
    &ownership_proof,    // AttributeOwnershipProof
    timestamp,           // u64
    &mut rng
)?;
```

##### `resolve_policy(policy) -> Result<HashSet<Right>>`
Convert an AccessPolicy to cryptographic rights.

```rust
let policy = AccessPolicy::parse("AGE::ADULT && LOC::INNER_CITY")?;
let rights = auth.resolve_policy(&policy)?;
```

##### `rpk() -> Result<CapabilityAuthorityPublicKey>`
Get the authority's public key for encryption.

```rust
let apk = auth.rpk()?;
```

##### `is_blinded_mode() -> bool`
Check if authority is in blinded mode.

```rust
assert!(auth.is_blinded_mode());
```

##### `blinded_issuer_count() -> usize`
Get the number of registered issuers.

```rust
println!("Registered issuers: {}", auth.blinded_issuer_count());
```

---

## Encrypted Header

### EncryptedHeader

Encapsulates encrypted metadata with access control.

```rust
use colossus_core::access_control::EncryptedHeader;

pub struct EncryptedHeader {
    pub encapsulation: XEnc,
    pub encrypted_metadata: Option<Vec<u8>>,
}
```

#### Methods

##### `generate_with_policy(...) -> Result<(Secret, Self)>`
Generate encrypted header using an access policy.

```rust
let policy = AccessPolicy::parse("AGE::ADULT && LOC::INNER_CITY")?;

let (secret, enc_header) = EncryptedHeader::generate_with_policy(
    &access_control,
    &authority_pk,
    &auth,                          // For policy resolution
    &policy,
    Some(b"metadata"),              // Optional metadata
    Some(b"additional_auth_data"),  // Optional AAD
)?;
```

##### `generate(...) -> Result<(Secret, Self)>`
Generate encrypted header using a set of rights directly.

```rust
let (secret, enc_header) = EncryptedHeader::generate(
    &access_control,
    &authority_pk,
    &rights,
    Some(b"metadata"),
    Some(b"aad"),
)?;
```

##### `decrypt(api, token, aad) -> Result<Option<CleartextHeader>>`
Decrypt using a capability token.

```rust
match enc_header.decrypt(&access_control, &capability, Some(b"aad"))? {
    Some(cleartext) => {
        println!("Secret: {:?}", cleartext.secret);
        println!("Metadata: {:?}", cleartext.metadata);
    }
    None => {
        println!("Access denied");
    }
}
```

### CleartextHeader

Decrypted content from EncryptedHeader.

```rust
pub struct CleartextHeader {
    pub secret: Secret<32>,
    pub metadata: Option<Vec<u8>>,
}
```

---

## Policy Types

### AccessPolicy

Human-readable access policy expressions.

```rust
use colossus_core::policy::AccessPolicy;

pub enum AccessPolicy {
    Term(PolicyTerm),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Broadcast,
}
```

#### Methods

##### `parse(input) -> Result<Self>`
Parse a policy from string.

```rust
let policy = AccessPolicy::parse("(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY")?;
```

##### `term(dimension, attribute) -> Self`
Create a single-term policy.

```rust
let policy = AccessPolicy::term("AGE", "ADULT");
```

##### `broadcast() -> Self`
Create a broadcast policy (everyone can decrypt).

```rust
let policy = AccessPolicy::broadcast();
```

##### `to_dnf() -> Vec<HashSet<PolicyTerm>>`
Convert to Disjunctive Normal Form.

```rust
let dnf = policy.to_dnf();
// Each inner set is a conjunction (AND)
// Outer vec is a disjunction (OR)
```

##### `is_broadcast() -> bool`
Check if this is a broadcast policy.

```rust
if policy.is_broadcast() {
    println!("Everyone can decrypt");
}
```

#### Operators

```rust
// AND
let policy = AccessPolicy::term("A", "1") & AccessPolicy::term("B", "2");

// OR
let policy = AccessPolicy::term("A", "1") | AccessPolicy::term("B", "2");
```

### PolicyTerm

A single attribute requirement.

```rust
pub struct PolicyTerm {
    pub dimension: String,
    pub name: String,
}
```

### DimensionType

Type of attribute dimension.

```rust
use colossus_core::policy::DimensionType;

pub enum DimensionType {
    /// Ordered attributes with inheritance
    Hierarchy,
    /// Independent, unordered attributes
    Anarchy,
}
```

---

## Blinded Attributes

### IssuerBlindingKey

Issuer's secret key for creating blinded attributes.

```rust
use colossus_core::policy::IssuerBlindingKey;
```

#### Methods

##### `new() -> Self`
Create a new issuer with random keys.

```rust
let mut issuer = IssuerBlindingKey::new();
```

##### `register_with_authority(pk, timestamp) -> BlindedIssuerRegistration`
Register with an authority.

```rust
let registration = issuer.register_with_authority(authority_pk, timestamp);
```

##### `create_blinded_attribute(dim, attr, pk) -> Result<BlindedAttribute>`
Create a blinded attribute.

```rust
let attr = issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
```

##### `prove_ownership(dim, attr, pk) -> Result<AttributeOwnershipProof>`
Create ownership proof for an attribute.

```rust
let proof = issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;
```

##### `prove_ownership_batch(attrs, pk) -> Result<BatchOwnershipProof>`
Create batch proof for multiple attributes.

```rust
let batch_proof = issuer.prove_ownership_batch(
    &[("AGE", "ADULT"), ("LOC", "INNER_CITY")],
    &authority_pk
)?;
```

##### `identity() -> &Falcon512Identity`
Get the issuer's signing identity.

```rust
let public_key = issuer.identity().public_key();
```

##### `commitment() -> Word`
Get the issuer's commitment (public identifier).

```rust
let issuer_id = issuer.commitment();
```

##### `get_preimage(dim, attr, pk) -> Option<&AttributePreimage>`
Get the preimage for a created attribute.

```rust
let preimage = issuer.get_preimage("AGE", "ADULT", &authority_pk)?;
```

### BlindedAttribute

Privacy-preserving attribute.

```rust
pub struct BlindedAttribute {
    commitment: Word,
    dimension_commitment: Word,
}
```

#### Methods

##### `commitment() -> &Word`
Get the attribute commitment.

##### `dimension_commitment() -> &Word`
Get the dimension commitment.

### AttributeOwnershipProof

Signed proof of attribute ownership.

```rust
pub struct AttributeOwnershipProof {
    pub attribute: BlindedAttribute,
    pub signature: Signature,
}
```

#### Methods

##### `verify(public_key) -> bool`
Verify the proof signature.

```rust
assert!(proof.verify(&issuer_pk));
```

### BatchOwnershipProof

Efficient multi-attribute proof.

```rust
pub struct BatchOwnershipProof {
    pub attributes: Vec<BlindedAttribute>,
    pub signature: Signature,
}
```

#### Methods

##### `verify(public_key) -> bool`
Verify the batch signature.

##### `len() -> usize`
Get number of attributes in batch.

##### `contains(commitment) -> bool`
Check if batch contains a specific attribute.

---

## Capability Claims

### BlindedClaimBuilder

Fluent API for building claims.

```rust
use colossus_core::policy::BlindedClaimBuilder;
```

#### Methods

##### `new(issuer, authority_pk) -> Self`
Create a new claim builder.

```rust
let builder = BlindedClaimBuilder::new(&mut issuer, authority_pk);
```

##### `add_attribute(dim, attr) -> Self`
Add an attribute to the claim.

```rust
let builder = builder.add_attribute("AGE", "ADULT");
```

##### `build_batched() -> Result<BatchedBlindedClaim>`
Build an efficient batched claim.

```rust
let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
    .add_attribute("AGE", "ADULT")
    .add_attribute("LOC", "INNER_CITY")
    .build_batched()?;
```

### BatchedBlindedClaim

Efficient claim with single signature.

```rust
pub struct BatchedBlindedClaim {
    pub issuer_commitment: Word,
    pub attributes: Vec<BlindedAttribute>,
    pub batch_proof: BatchOwnershipProof,
}
```

#### Methods

##### `verify(public_key) -> bool`
Verify the claim signature.

##### `len() -> usize`
Get number of claimed attributes.

##### `contains(commitment) -> bool`
Check if claim contains a specific attribute.

### BlindedCapabilityClaim

Claim formatted for capability token request.

```rust
use colossus_core::access_control::capability::BlindedCapabilityClaim;
```

#### Methods

##### `from_batched_claim(issuer_id, claim) -> Self`
Create from a batched claim.

```rust
let cap_claim = BlindedCapabilityClaim::from_batched_claim(
    issuer_id,
    batched_claim
);
```

### create_blinded_capability_token

Create a capability token from claims.

```rust
use colossus_core::access_control::capability::create_blinded_capability_token;

let token = create_blinded_capability_token(
    &mut rng,
    &mut auth,
    &[cap_claim1, cap_claim2]
)?;
```

### AccessCapabilityToken

Token granting decryption rights.

```rust
pub struct AccessCapabilityToken { /* ... */ }
```

#### Methods

##### `count() -> usize`
Get number of access rights in token.

##### `decapsulate(rng, enc) -> Result<Option<Secret>>`
Attempt to decrypt an encapsulation.

---

## Cryptographic Types

### Word

Poseidon2 field element array (4 x Felt).

```rust
use colossus_core::crypto::Word;

pub struct Word([Felt; 4]);
```

### Felt

Miden field element.

```rust
use colossus_core::crypto::Felt;

let felt = Felt::new(42u64);
```

### Secret<N>

Secure secret storage with automatic zeroization.

```rust
use colossus_core::access_control::Secret;

let secret: Secret<32> = Secret::random(&mut rng);
```

---

## Complete Example

```rust
use colossus_core::access_control::{AccessControl, EncryptedHeader};
use colossus_core::access_control::capability::{
    BlindedCapabilityClaim, 
    create_blinded_capability_token
};
use colossus_core::policy::{
    AccessPolicy, 
    BlindedClaimBuilder, 
    DimensionType, 
    IssuerBlindingKey
};
use cosmian_crypto_core::CsRng;
use cosmian_crypto_core::reexport::rand_core::SeedableRng;

fn main() -> anyhow::Result<()> {
    let mut rng = CsRng::from_entropy();

    // 1. Setup
    let access_control = AccessControl::default();
    let mut auth = access_control.setup_blinded_authority()?.with_identity();
    auth.init_blinded_structure()?;
    let authority_pk = auth.authority_pk().unwrap();

    // 2. Add dimensions
    let age_dim = auth.add_blinded_dimension("AGE", DimensionType::Hierarchy)?;

    // 3. Setup issuer
    let mut issuer = IssuerBlindingKey::new();
    let reg = issuer.register_with_authority(authority_pk, 1000);
    let issuer_id = auth.register_blinded_issuer(
        reg, 
        issuer.identity().public_key(), 
        &mut rng
    )?;

    // 4. Add attributes
    let attr = issuer.create_blinded_attribute("AGE", "ADULT", &authority_pk)?;
    let proof = issuer.prove_ownership("AGE", "ADULT", &authority_pk)?;
    auth.add_blinded_attribute_with_name(
        &age_dim, "AGE", "ADULT", attr, &proof, 2000, &mut rng
    )?;

    // 5. Encrypt
    let policy = AccessPolicy::parse("AGE::ADULT")?;
    let apk = auth.rpk()?;
    let (secret, enc_header) = EncryptedHeader::generate_with_policy(
        &access_control, &apk, &auth, &policy, Some(b"data"), None
    )?;

    // 6. Claim and get token
    let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("AGE", "ADULT")
        .build_batched()?;
    let cap_claim = BlindedCapabilityClaim::from_batched_claim(issuer_id, claim);
    let token = create_blinded_capability_token(&mut rng, &mut auth, &[cap_claim])?;

    // 7. Decrypt
    let result = enc_header.decrypt(&access_control, &token, None)?;
    assert!(result.is_some());
    assert_eq!(result.unwrap().secret, secret);

    Ok(())
}
```
