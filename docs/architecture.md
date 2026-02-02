# Colossus Architecture

This document describes the high-level architecture of Colossus, a privacy-aware capability-based security framework.

## Overview

Colossus implements a **hybrid blinded mode** access control system that combines:

1. **Human-readable access policies** for encryption (e.g., `"AGE::ADULT && LOC::INNER_CITY"`)
2. **Privacy-preserving blinded attributes** using Poseidon2 cryptographic commitments
3. **Capability-based security** for decryption rights

## System Components

```
+------------------------------------------------------------------+
|                         COLOSSUS SYSTEM                          |
+------------------------------------------------------------------+
|                                                                  |
|  +--------------------+          +------------------------+      |
|  |  ISSUERS           |          |  CAPABILITY AUTHORITY  |      |
|  |                    |          |                        |      |
|  |  - Create blinded  |  reg     |  - Manages dimensions  |      |
|  |    attributes      |--------->|  - Registers issuers   |      |
|  |  - Sign proofs     |          |  - Issues capability   |      |
|  |  - Issue claims    |          |    tokens              |      |
|  +--------------------+          +------------------------+      |
|          |                                  |                    |
|          | attributes                       | tokens             |
|          v                                  v                    |
|  +--------------------+          +------------------------+      |
|  |  BLINDED ACCESS    |          |  ACCESS CAPABILITY     |      |
|  |  STRUCTURE         |          |  TOKEN                 |      |
|  |                    |          |                        |      |
|  |  - Name registry   |          |  - Cryptographic keys  |      |
|  |  - Dimensions      |          |  - Access rights       |      |
|  |  - Commitments     |          |                        |      |
|  +--------------------+          +------------------------+      |
|          |                                  |                    |
|          | policy resolution                | decryption         |
|          v                                  v                    |
|  +--------------------+          +------------------------+      |
|  |  ENCRYPTED HEADER  |          |  DECRYPTED CONTENT     |      |
|  |                    |          |                        |      |
|  |  - KEM encaps      |--------->|  - Secret key          |      |
|  |  - Encrypted meta  |  decrypt |  - Metadata            |      |
|  +--------------------+          +------------------------+      |
|                                                                  |
+------------------------------------------------------------------+
```

## Core Modules

### 1. Access Control (`access_control/`)

The main entry point for the access control system.

```rust
pub struct AccessControl {
    rng: Arc<Mutex<CsRng>>,
}
```

**Key Operations:**
- `setup_blinded_authority()` - Create a new capability authority
- `encapsulate_for_rights()` - Encrypt for a set of access rights
- `decapsulate()` - Decrypt using a capability token

### 2. Capability Authority (`access_control/capability/`)

Manages the access control state and issues capability tokens.

```rust
pub struct CapabilityAuthority {
    // Core cryptographic keys
    sk: SecretKey,
    pk: PublicKey,
    
    // Blinded mode components
    blinded_structure: Option<BlindedAccessStructure>,
    identity: Option<AuthorityIdentity>,
    
    // Issuer registry
    blinded_issuers: HashMap<u64, BlindedIssuerInfo>,
}
```

**Key Operations:**
- `init_blinded_structure()` - Initialize blinded mode
- `add_blinded_dimension()` - Add a dimension (schema)
- `register_blinded_issuer()` - Register a credential issuer
- `add_blinded_attribute_with_name()` - Add attribute with policy name
- `resolve_policy()` - Convert AccessPolicy to cryptographic rights

### 3. Policy Module (`policy/`)

Defines access policies and blinded attributes.

#### AccessPolicy

Human-readable policy expressions:

```rust
pub enum AccessPolicy {
    Term(PolicyTerm),           // Single attribute: "AGE::ADULT"
    And(Box<Self>, Box<Self>),  // Conjunction: A && B
    Or(Box<Self>, Box<Self>),   // Disjunction: A || B
    Broadcast,                   // Everyone can decrypt
}
```

#### BlindedAccessStructure

Privacy-preserving attribute store:

```rust
pub struct BlindedAccessStructure {
    authority_pk: Word,
    dimensions: HashMap<[u8; 32], BlindedDimension>,
    issuers: HashMap<Word, BlindedIssuerRegistration>,
    
    // Name registry for policy resolution
    name_registry: HashMap<String, Word>,
    dimension_names: HashMap<[u8; 32], String>,
}
```

### 4. Blinded Attributes (`policy/blinded.rs`)

Privacy-preserving attribute system.

```rust
pub struct BlindedAttribute {
    commitment: Word,           // Poseidon2(dim || attr || issuer || authority || salt)
    dimension_commitment: Word, // Poseidon2(dimension || authority)
}

pub struct IssuerBlindingKey {
    secret_key: [u8; 32],
    identity: Falcon512Identity,
    attribute_cache: HashMap<(Word, String, String), AttributePreimage>,
}
```

### 5. Cryptographic Primitives (`crypto/`)

- **Poseidon2**: ZK-friendly hash function for commitments
- **Falcon512**: Post-quantum signatures for issuer proofs
- **ML-KEM**: Post-quantum key encapsulation
- **ElGamal**: Discrete log based encryption component

## Data Flow

### 1. Setup Phase

```
Authority                 Issuer
    |                        |
    |  init_blinded_structure()
    |<-----------------------|
    |                        |
    |  add_blinded_dimension("AGE", Hierarchy)
    |<-----------------------|
    |                        |
    |  register_with_authority(pk, timestamp)
    |<-----------------------+
    |                        |
    |  register_blinded_issuer(reg, issuer_pk)
    +----------------------->|
    |                        |
    |  create_blinded_attribute("AGE", "ADULT")
    |                        +---> BlindedAttribute
    |                        |
    |  prove_ownership("AGE", "ADULT")
    |                        +---> AttributeOwnershipProof
    |                        |
    |  add_blinded_attribute_with_name(...)
    |<-----------------------+
```

### 2. Encryption Phase

```
Encryptor                Authority
    |                        |
    |  AccessPolicy::parse("AGE::ADULT && LOC::INNER_CITY")
    +---> AccessPolicy       |
    |                        |
    |  EncryptedHeader::generate_with_policy(...)
    |----------------------->|
    |                        |
    |                   resolve_policy()
    |                        +---> HashSet<Right>
    |                        |
    |                   encapsulate_for_rights()
    |                        +---> XEnc
    |<-----------------------+
    |                        |
    +---> (Secret, EncryptedHeader)
```

### 3. Decryption Phase

```
User                     Issuer                Authority
  |                        |                        |
  |  BlindedClaimBuilder::new()
  +----------------------->|                        |
  |                        |                        |
  |  add_attribute("AGE", "ADULT")
  |  build_batched()       |                        |
  +----------------------->|                        |
  |                        |                        |
  |<-----------------------+                        |
  |  BatchedBlindedClaim   |                        |
  |                        |                        |
  |  BlindedCapabilityClaim::from_batched_claim()   |
  +------------------------------------------------>|
  |                        |                        |
  |  create_blinded_capability_token()              |
  |<------------------------------------------------+
  |  AccessCapabilityToken |                        |
  |                        |                        |
  |  enc_header.decrypt(token)
  +---> Decrypted content
```

## Cryptographic Design

### Commitment Scheme

Blinded attributes use Poseidon2 commitments:

```
commitment = Poseidon2(
    dimension_hash ||
    attribute_hash ||
    issuer_commitment ||
    authority_pk ||
    salt
)
```

**Properties:**
- **Binding**: Cannot find two different inputs with same commitment
- **Hiding**: Commitment reveals nothing about the input
- **Deterministic**: Same inputs always produce same commitment (with same salt)

### Key Encapsulation

Uses a hybrid KEM combining:
- **ElGamal** for discrete log security
- **ML-KEM-768** for post-quantum security

```rust
pub struct XEnc {
    tag: Secret<32>,
    c: Vec<G1Projective>,
    encapsulations: Encapsulations,
}
```

### Access Right Matching

The cryptographic scheme creates one encapsulation per access right. Decryption succeeds if the capability token contains a matching right for ANY of the encapsulations.

**Implication**: For AND policies like `A && B`, both A and B are encrypted, but a user with only A can still decrypt. To enforce strict AND, design policies where unauthorized users don't have ANY of the required attributes.

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Confidentiality** | Hybrid KEM with hidden policy |
| **Issuer Authentication** | Falcon512 signatures |
| **Attribute Privacy** | Poseidon2 commitments |
| **Cross-Authority Unlinkability** | Authority-specific salts |
| **Quantum Resistance** | ML-KEM + Falcon512 |

## Module Dependencies

```
colossus-core
├── access_control/
│   ├── mod.rs           <- Main AccessControl struct
│   ├── capability/
│   │   ├── authority.rs <- CapabilityAuthority
│   │   └── attestation.rs
│   ├── encrypted_header.rs
│   ├── cryptography/
│   │   ├── ae_poseidon2.rs
│   │   ├── mlkem.rs
│   │   └── nike.rs
│   └── revocation/
├── policy/
│   ├── mod.rs
│   ├── access_policy.rs <- AccessPolicy parser
│   ├── blinded.rs       <- BlindedAttribute system
│   ├── dimension.rs
│   └── rights.rs
├── crypto/
│   ├── hash.rs          <- Poseidon2, SHA3, Blake3
│   ├── signature.rs     <- Falcon512
│   └── pairing.rs       <- BLS12-381
├── dac/                  <- Delegatable Anonymous Credentials
└── miden/               <- Miden VM integration (future)
```

## Extension Points

1. **Custom Issuers**: Implement `IssuerBlindingKey` for domain-specific credentials
2. **Policy Languages**: Extend `AccessPolicy` for custom policy syntax
3. **Attestations**: Use `AuthorityIdentity` for authority delegation
4. **Revocation**: Use `RevocationRegistry` for capability revocation
