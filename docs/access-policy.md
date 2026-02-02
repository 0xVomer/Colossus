# Access Policies

This document describes Colossus's access policy syntax and semantics.

## Overview

Access policies define who can decrypt encrypted content. Colossus uses a simple, expressive syntax that combines:

- **Policy Terms**: Individual attribute requirements (e.g., `AGE::ADULT`)
- **Boolean Operators**: AND (`&&`) and OR (`||`) for combining terms
- **Parentheses**: For explicit grouping

## Syntax

### Policy Term

A policy term specifies a required attribute:

```
DIMENSION::ATTRIBUTE
```

Examples:
- `AGE::ADULT` - Requires the ADULT attribute from the AGE dimension
- `LOC::INNER_CITY` - Requires the INNER_CITY attribute from LOC dimension
- `CLEARANCE::TOP_SECRET` - Requires TOP_SECRET clearance

### Boolean Operators

| Operator | Syntax | Description |
|----------|--------|-------------|
| AND | `A && B` | Both A and B required |
| OR | `A \|\| B` | Either A or B sufficient |

### Grouping

Use parentheses to control evaluation order:

```
(A || B) && C    // A or B, AND C
A || (B && C)    // A, OR (B and C)
```

### Broadcast

The special broadcast policy allows everyone to decrypt:

```rust
AccessPolicy::broadcast()
```

## Parsing Policies

```rust
use colossus_core::policy::AccessPolicy;

// Simple term
let policy = AccessPolicy::parse("AGE::ADULT")?;

// OR policy
let policy = AccessPolicy::parse("AGE::ADULT || AGE::SENIOR")?;

// AND policy
let policy = AccessPolicy::parse("AGE::ADULT && LOC::INNER_CITY")?;

// Complex policy with grouping
let policy = AccessPolicy::parse(
    "(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY && DEVICE::MOBILE"
)?;
```

## Programmatic Construction

Policies can also be built programmatically:

```rust
use colossus_core::policy::AccessPolicy;

// Using the term constructor
let adult = AccessPolicy::term("AGE", "ADULT");
let senior = AccessPolicy::term("AGE", "SENIOR");
let inner_city = AccessPolicy::term("LOC", "INNER_CITY");

// Combine with operators
let age_policy = adult.clone() | senior.clone();  // OR
let location_policy = age_policy & inner_city;     // AND

// Equivalent to: "(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY"
```

## Policy Variants

```rust
pub enum AccessPolicy {
    /// A single attribute requirement
    Term(PolicyTerm),
    
    /// Conjunction (AND) of two policies
    And(Box<Self>, Box<Self>),
    
    /// Disjunction (OR) of two policies
    Or(Box<Self>, Box<Self>),
    
    /// Broadcast - everyone can decrypt
    Broadcast,
}
```

## Disjunctive Normal Form (DNF)

Internally, policies are converted to Disjunctive Normal Form for cryptographic processing:

```
DNF = Clause1 || Clause2 || ... || ClauseN
Clause = Term1 && Term2 && ... && TermM
```

### Examples

| Policy | DNF |
|--------|-----|
| `A` | `{A}` |
| `A \|\| B` | `{A}, {B}` |
| `A && B` | `{A, B}` |
| `(A \|\| B) && C` | `{A, C}, {B, C}` |
| `A && (B \|\| C)` | `{A, B}, {A, C}` |

### Accessing DNF

```rust
let policy = AccessPolicy::parse("(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY")?;
let dnf = policy.to_dnf();

// dnf = [
//   [PolicyTerm{AGE, ADULT}, PolicyTerm{LOC, INNER_CITY}],
//   [PolicyTerm{AGE, SENIOR}, PolicyTerm{LOC, INNER_CITY}]
// ]
```

## Policy Resolution

When encrypting, the policy is resolved to cryptographic rights:

```rust
// Authority resolves policy to rights using name registry
let rights = auth.resolve_policy(&policy)?;

// These rights are used for key encapsulation
let (secret, enc_header) = EncryptedHeader::generate_with_policy(
    &access_control,
    &apk,
    &auth,
    &policy,
    metadata,
    aad
)?;
```

## Access Control Semantics

### How Decryption Works

The cryptographic scheme creates one encapsulation per access right. Decryption succeeds if the capability token contains a matching right for **any** of the encapsulations.

### Implications

1. **OR Semantics**: `A || B` - User needs A or B (either works)
2. **AND Semantics**: `A && B` - Both A and B are encrypted, but user with only A can technically decrypt

### Designing Effective Policies

For strict access control, design policies where unauthorized users don't have ANY of the required attributes:

```rust
// Good: Different clearance levels don't overlap
// User with CONFIDENTIAL can't access TOP_SECRET
let policy = AccessPolicy::parse("CLEARANCE::TOP_SECRET")?;

// Good: Cross-dimension requirements
// User needs attributes from BOTH dimensions
let policy = AccessPolicy::parse("LEVEL::SECRET && DEPT::RESEARCH")?;

// Careful: Same dimension AND
// User with just READ could decrypt (has one of the rights)
let policy = AccessPolicy::parse("PERM::READ && PERM::WRITE && PERM::EXECUTE")?;
```

## Common Patterns

### Role-Based Access Control

```rust
// Only admins
let admin_only = AccessPolicy::parse("ROLE::ADMIN")?;

// Admin or manager
let management = AccessPolicy::parse("ROLE::ADMIN || ROLE::MANAGER")?;

// Any authenticated user
let authenticated = AccessPolicy::parse(
    "ROLE::ADMIN || ROLE::MANAGER || ROLE::EMPLOYEE || ROLE::GUEST"
)?;
```

### Hierarchical Access Levels

```rust
// Public data - anyone
let public = AccessPolicy::parse("LEVEL::PUBLIC")?;

// Internal data - employees and above
let internal = AccessPolicy::parse(
    "LEVEL::INTERNAL || LEVEL::CONFIDENTIAL || LEVEL::SECRET"
)?;

// Secret data - only highest clearance
let secret = AccessPolicy::parse("LEVEL::SECRET")?;
```

### Multi-Factor Requirements

```rust
// Age verification AND payment verification
let premium_content = AccessPolicy::parse(
    "AGE::ADULT && PAYMENT::VERIFIED"
)?;

// Security clearance AND department membership AND device type
let secure_access = AccessPolicy::parse(
    "CLEARANCE::SECRET && DEPT::RESEARCH && DEVICE::SECURE_TERMINAL"
)?;
```

### Geographic Restrictions

```rust
// Only specific regions
let regional = AccessPolicy::parse(
    "GEO::NORTH_AMERICA || GEO::EUROPE"
)?;

// Region AND compliance level
let compliant_regional = AccessPolicy::parse(
    "(GEO::NORTH_AMERICA || GEO::EUROPE) && COMPLIANCE::GDPR"
)?;
```

### Time-Based Access (via attributes)

```rust
// Active subscription required
let subscription = AccessPolicy::parse("STATUS::ACTIVE_SUBSCRIPTION")?;

// Trial or paid
let access = AccessPolicy::parse("STATUS::TRIAL || STATUS::PAID")?;
```

## Using with EncryptedHeader

```rust
use colossus_core::access_control::EncryptedHeader;
use colossus_core::policy::AccessPolicy;

// Parse the policy
let policy = AccessPolicy::parse(
    "(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY"
)?;

// Get the authority's public key
let apk = auth.rpk()?;

// Generate encrypted header with policy
let (secret, enc_header) = EncryptedHeader::generate_with_policy(
    &access_control,
    &apk,
    &auth,       // Authority for policy resolution
    &policy,
    Some(b"metadata"),
    Some(b"additional_auth_data"),
)?;

// secret is the symmetric key for content encryption
// enc_header is stored/transmitted with the encrypted content
```

## Display and Debugging

Policies implement `Display` for readable output:

```rust
let policy = AccessPolicy::parse("(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY")?;
println!("{}", policy);
// Output: ((AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY)
```

## Error Handling

```rust
use colossus_core::policy::AccessPolicy;

// Invalid syntax
let result = AccessPolicy::parse("AGE::"); // Missing attribute
assert!(result.is_err());

// Unknown attribute (during resolution, not parsing)
let policy = AccessPolicy::parse("UNKNOWN::VALUE")?;
let result = auth.resolve_policy(&policy);
// Error: Attribute UNKNOWN::VALUE not found in access structure
```

## Best Practices

1. **Use descriptive dimension names**: `CLEARANCE::SECRET` vs `C::S`
2. **Prefer cross-dimension AND**: More robust access control
3. **Document your policies**: Complex policies need explanation
4. **Test access patterns**: Verify authorized users can decrypt
5. **Validate before encryption**: Ensure all policy terms exist in the structure
