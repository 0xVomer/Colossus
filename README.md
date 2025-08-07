![](./assets/colossus.jpg)

# Colossus

Colossus is a privacy-aware capability-based security framework that cryptographically enforces Zero-Trust principles ("Never Trust, Always Verify").

# Motivation


# Capability-Based Access-Control:

Colossus implements an access-control system that is based on the capability-based security paradigm. This paradigm ensures that access to resources is granted only to those who have the necessary capabilities to access them.

## Capability-Authority:

### Capability-Tokens:

### Quantum-Secure KEM with Hidden-Access Policy:

Colossus adopts [ETSI TS 104 015](https://www.etsi.org/deliver/etsi_ts/104000_104099/104015/01.01.01_60/ts_104015v010101p.pdf) standard by building upon the implementation of [covercrypt](https://github.com/Cosmian/cover_crypt).

## Credential-Issuer:

### Anonymous-Credentials:


# Examples:

## Attribute-Based Access-Control:

In this example, two individuals have created an alias for themselves as "Alice" and "Bob" and there exist a Colossus Access-Control system with 2 registered credential issuers.

Alice wishes to share some data to Bob but requires that Bob must be either an adult or a senior, lives in the inner-city area and is viewing the data on a mobile device.
On the other hand, Bob wants to ensure that under no circumstances does Alice know of Bob's sex.

Using Colossus Access-Control, Alice computes a random Nonce value and generates the encrypted-header which conceals the data under the hidden-access policy: "(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY && DEVICE::MOBILE" and the random Nonce. Alice then provides the Nonce & Encrypted-Header to Bob.

Bob requests credentials (Age & Sex credential and Device & Location Credential) and computes zero-knowledge proofs which attests to these credentials claiming the following attributes:
- Age of 25 => "AGE::ADULT"
- Location area of inner-city => "LOC::INNER_CITY"
- Device UDI of 0 => "DEVICE::MOBILE"

Bob requests a capability-token from the Capability Authority given the zero-knoweledge proof & claimed attributes and Nonce. Capability-Authority verifies the proofs, grants the associated access-rights and issues the capability token to Bob.

Using the capability-token & Nonce Bob is then able to reveal the data hidden within the encrypted-header.
Under no circumstances did Bob reveal his sex to Alice or to the Capability Authority.


### Issuer A (Age + Sex):

```rust
pub struct Age(u8);

impl Age {
    pub fn claim(age: u8) -> Self {
        Self(age)
    }
    fn dimension_label() -> &'static str {
        "AGE"
    }
    fn attribute_label(&self) -> &'static str {
        match self.0 {
            0..=20 => "YOUTH",
            21..=60 => "ADULT",
            61..=100 => "SENIOR",
            _ => "UNKNOWN",
        }
    }
    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), self.attribute_label())
    }

    fn young_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), "YOUTH")
    }

    fn adult_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), "ADULT")
    }

    fn senior_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), "SENIOR")
    }

    fn unkown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Age::dimension_label(), "UNKNOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_hierarchy(Age::dimension_label().to_string())?;
        ac.add_attribute(Age::young_attribute(), None)?;
        ac.add_attribute(Age::adult_attribute(), Some("YOUTH"))?;
        ac.add_attribute(Age::senior_attribute(), Some("ADULT"))?;
        ac.add_attribute(Age::unkown_attribute(), Some("SENIOR"))?;

        Ok(ac)
    }
}

pub enum Sex {
    MALE,
    FEMALE,
    UNKNOWN,
}

impl Sex {
    fn dimension_label() -> &'static str {
        "SEX"
    }
    fn attribute_label(&self) -> &'static str {
        match self {
            Sex::MALE => "MALE",
            Sex::FEMALE => "FEMALE",
            Sex::UNKNOWN => "UNKNOWN",
        }
    }
    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Sex::dimension_label(), self.attribute_label())
    }

    fn male_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Sex::dimension_label(), "MALE")
    }

    fn female_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Sex::dimension_label(), "FEMALE")
    }
    fn unknown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Sex::dimension_label(), "UNKNOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_anarchy(Sex::dimension_label().to_string())?;
        ac.add_attribute(Sex::male_attribute(), None)?;
        ac.add_attribute(Sex::female_attribute(), None)?;
        ac.add_attribute(Sex::unknown_attribute(), None)?;

        Ok(ac)
    }
}
```

Credential Issuer A issues credentials supporting age and sex attributes:

- Anyone of 0 to 20 Years of age is considered a "YOUTH".
- Anyone of 21 to 60 Years of age is considered an "ADULT".
- Anyone of 61 to 100 Years of age is considered a "SENIOR".
- Any age exceeding 100 Years is considered "UNKNOWN".
- Only Male or Female Sex is considered or else "UNKNOWN"



### Issuer B (Device + Location)

```rust
pub struct Location(String);

impl Location {
    pub fn claim(address: String) -> Self {
        Self(address)
    }
    fn dimension_label() -> &'static str {
        "LOC"
    }
    fn attribute_label(&self) -> &'static str {
        match self.0.as_str() {
            "innercity" => "INNER_CITY",
            "eastsydney" => "EAST_SYDNEY",
            "westsydney" => "WEST_SYDNEY",
            _ => "UNKOWN",
        }
    }
    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), self.attribute_label())
    }

    fn inner_city_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), "INNER_CITY")
    }

    fn east_sydney_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), "EAST_SYDNEY")
    }

    fn west_sydney_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), "WEST_SYDNEY")
    }

    fn unkown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Location::dimension_label(), "UNKNOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_anarchy(Location::dimension_label().to_string())?;
        ac.add_attribute(Location::inner_city_attribute(), None)?;
        ac.add_attribute(Location::east_sydney_attribute(), None)?;
        ac.add_attribute(Location::west_sydney_attribute(), None)?;
        ac.add_attribute(Location::unkown_attribute(), None)?;

        Ok(ac)
    }
}


pub struct Device(u8);

impl Device {
    pub fn claim(udi: u8) -> Self {
        Self(udi)
    }
    fn dimension_label() -> &'static str {
        "DEVICE"
    }
    fn attribute_label(&self) -> &'static str {
        match self.0 {
            0..=10 => "MOBILE",
            11..=40 => "LAPTOP",
            _ => "UNKOWN",
        }
    }
    pub fn qualify(&self) -> QualifiedAttribute {
        QualifiedAttribute::new(Device::dimension_label(), self.attribute_label())
    }

    fn mobile_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Device::dimension_label(), "MOBILE")
    }

    fn laptop_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Device::dimension_label(), "LAPTOP")
    }

    fn unkown_attribute() -> QualifiedAttribute {
        QualifiedAttribute::new(Device::dimension_label(), "UNKOWN")
    }

    pub fn access_structure() -> Result<AccessStructure> {
        let mut ac = AccessStructure::new();
        ac.add_hierarchy(Device::dimension_label().to_string())?;
        ac.add_attribute(Device::mobile_attribute(), None)?;
        ac.add_attribute(Device::laptop_attribute(), None)?;
        ac.add_attribute(Device::unkown_attribute(), None)?;

        Ok(ac)
    }
}
```
Credential Issuer B issues credentials supporting device and location attributes:

- 3 location-areas are covered:
    - Inner City ("INNER_CITY")
    - East Sydney ("EAST_SYDNEY")
    - West Sydney ("WEST_SYDNEY")
- Unique Device Identifier (UDI) from 0 to 10 is considered to be a "MOBILE" device
- Unique Device Identifier (UDI) from 11 to 40 is considered to be a "LAPTOP" device
- Unique Device Identifier (UDI) exceeding 40 is considered to be an "UNKNOWN" device



### Complete Flow:

```rust
let access_control = AccessControl::default();
let (mut auth, _) = access_control.setup_capability_authority()?;

// Access-Credential A manages credentials that contains Age + Sex attributes
let mut access_structure_a = Age::access_structure().unwrap();
access_structure_a.extend(&Sex::access_structure().unwrap()).unwrap();

let issuer_a = Issuer::setup(None, &access_structure_a);
let (issuer_a_id, _) = access_control.register_issuer(&mut auth, &issuer_a.public)?;

// Access-Credential B manages credentials that contains Device & Location attributes
let mut access_structure_b = Location::access_structure().unwrap();
access_structure_b.extend(&Device::access_structure().unwrap()).unwrap();

let issuer_b = Issuer::setup(None, &access_structure_b);
let (issuer_b_id, apk) = access_control.register_issuer(&mut auth, &issuer_b.public)?;

// Alice creates encrypted header with Access Policy
// Access Policy requires Age, Location, and Device attributes but not Sex attribute
let (secret, enc_header) = EncryptedHeader::generate(
    &access_control,
    &apk,
    &AccessPolicy::parse(
        "(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY && DEVICE::MOBILE",
    )
    .unwrap(),
    Some("alice_metadata".as_bytes()),
    Some(&NONCE.to_be_bytes()),
)
.unwrap();

// Bob creates an alias
let mut bob = Alias::new();
bob = bob.randomize();

// and a proof of his alias using the verification nonce
let bob_proof = bob.alias_proof(&NONCE);

// Issuer A provides bob with age and location credential
let age_sex_cred = issuer_a
    .access_credential()
    .with_entry(Entry::new(&[Age::claim(25).qualify(), Sex::MALE.qualify()]))
    .max_entries(&MaxEntries::default())
    .issue_to(&bob_proof, Some(&NONCE))?;

// Issuer B provides bob with device credential
let device_location_cred = issuer_b
    .access_credential()
    .with_entry(Entry::new(&[
        Device::claim(0).qualify(),
        Location::claim("innercity".to_string()).qualify(),
    ]))
    .max_entries(&MaxEntries::default())
    .issue_to(&bob_proof, Some(&NONCE))?;

// bob wants to claims access rights using his age & sex credential
// Bob chooses to omit his sex attribute for privacy reasons
let (credential_proof_a, claimed_attributes_a) = bob
    .claim_builder(
        &age_sex_cred,
        vec![Entry::new(&[Age::claim(25).qualify(), Sex::MALE.qualify()])],
    )
    // Bob only selects his age attribute
    .select_attribute(Age::claim(25).qualify())
    .generate(&NONCE)
    .map_err(|e| {
        println!("Error generating credential proof: {}", e);
        e
    })?;

// bob also wants to claim access rights using his device & location credential
let (credential_proof_b, claimed_attributes_b) = bob
    .claim_builder(
        &device_location_cred,
        vec![Entry::new(&[
            Device::claim(0).qualify(),
            Location::claim("innercity".to_string()).qualify(),
        ])],
    )
    .select_attribute(Device::claim(0).qualify())
    .select_attribute(Location::claim("innercity".to_string()).qualify())
    .generate(&NONCE)?;

// capability is granted to Bob based on the set of his access claims
let capability = access_control
    .grant_capability(
        &mut auth,
        &vec![
            // Access Claim from Bob's credential whihc holds age & location attributes
            AccessClaim {
                issuer_id: issuer_a_id,
                cred_proof: credential_proof_a,
                attributes: claimed_attributes_a,
            },
            // Access Claim from Bob's credential which holds device attribute
            AccessClaim {
                issuer_id: issuer_b_id,
                cred_proof: credential_proof_b,
                attributes: claimed_attributes_b,
            },
        ],
        &NONCE,
    )
    .unwrap();

// bob is able to access the hidden metadata using his capability token
match enc_header
    .decrypt(&access_control, &capability, Some(&NONCE.to_be_bytes()))
    .unwrap()
{
    Some(data) => {
        println!("{data:#?}");
    },
    None => {
        panic!("Failed to decrypt metadata");
    },
}
Ok(())
````

## Key-Exchange Policy:

In this example, a relayer

In this example,

# Potential Applications:


# Building & Testing:

To build the project, run the following command:

```
cargo build
```
The code contains numerous tests that you can run using:

```
cargo test
```

# Acknowledgements:
