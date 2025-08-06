extern crate alloc;
extern crate rand;
pub mod access_control;
mod akd;
mod configuration;
pub mod dac;
pub mod directory;
pub mod policy;
pub mod proto;
mod storage;
pub mod log {
    pub use tracing::{debug, error, info, trace, warn};
}

use configuration::Configuration;

#[cfg(test)]
mod test {

    use crate::{
        access_control::{AccessClaim, AccessControl, EncryptedHeader},
        dac::{
            entry::{Entry, MaxEntries},
            keypair::{Alias, Issuer},
            zkp::Nonce,
        },
        policy::{AccessPolicy, AccessStructure, QualifiedAttribute},
    };
    use anyhow::Result;
    use bls12_381_plus::Scalar;
    use lazy_static::lazy_static;

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

    lazy_static! {
        static ref NONCE: Nonce = Nonce(Scalar::from(42u64));
    }

    #[test]
    fn test_access_control_flow() -> Result<()> {
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

        // bob wants to claims access rights using his age & sex credential but without considering the sex attribute
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

        println!("Claimed Attributes A: {:?}", claimed_attributes_a);

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

        println!("Claimed Attributes B: {:?}", claimed_attributes_b);

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

        // let capability = access_control
        //     .grant_unsafe_capability(
        //         &mut auth,
        //         &AccessPolicy::parse("AGE::YOUTH && DEVICE::MOBILE && LOC::INNER_CITY").unwrap(),
        //     )
        //     .unwrap();

        // bob is able to access the hidden metadata using his capability token
        match enc_header
            .decrypt(&access_control, &capability, Some(&NONCE.to_be_bytes()))
            .unwrap()
        {
            Some(data) => {
                println!("{data:#?}");

                assert_eq!(data.secret, secret);
                assert_eq!(data.metadata.unwrap(), "alice_metadata".as_bytes());
            },
            None => {
                panic!("Failed to decrypt metadata");
            },
        }
        Ok(())
    }

    #[test]
    fn test_access_denied_flow_a() -> Result<()> {
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
        // Access Policy permits only someone young living in West Sydney
        let (secret, enc_header) = EncryptedHeader::generate(
            &access_control,
            &apk,
            &AccessPolicy::parse("AGE::YOUTH && LOC::WEST_SYDNEY").unwrap(),
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

        // bob wants to claims access rights using his age & sex credential but without considering the sex attribute
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

        println!("Claimed Attributes A: {:?}", claimed_attributes_a);

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

        println!("Claimed Attributes B: {:?}", claimed_attributes_b);

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

        // bob is unable to access the hidden metadata using his capability token
        // since bob is an adult and lives in the inner city.
        match enc_header
            .decrypt(&access_control, &capability, Some(&NONCE.to_be_bytes()))
            .unwrap()
        {
            Some(data) => {
                println!("{data:#?}");

                assert_eq!(data.secret, secret);
                assert_eq!(data.metadata.unwrap(), "alice_metadata".as_bytes());
                panic!("Should not be able to decrypt metadata");
            },
            None => println!("No data decrypted"),
        }
        Ok(())
    }

    #[test]
    fn test_access_denied_flow_b() -> Result<()> {
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
        // Access Policy permits only an Female Adult living in an Inner City or using a Mobile Device
        let (secret, enc_header) = EncryptedHeader::generate(
            &access_control,
            &apk,
            &AccessPolicy::parse(
                "AGE::ADULT && SEX::FEMALE && (LOC::INNER_CITY || DEVICE::MOBILE)",
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

        // bob wants to claims access rights using his age & sex credential but without considering the sex attribute
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

        println!("Claimed Attributes A: {:?}", claimed_attributes_a);

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

        println!("Claimed Attributes B: {:?}", claimed_attributes_b);

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

        // bob is unable to access the hidden metadata using his capability token
        // since bob chose to omit his Sex attribute
        match enc_header
            .decrypt(&access_control, &capability, Some(&NONCE.to_be_bytes()))
            .unwrap()
        {
            Some(data) => {
                println!("{data:#?}");

                assert_eq!(data.secret, secret);
                assert_eq!(data.metadata.unwrap(), "alice_metadata".as_bytes());
                panic!("Should not be able to decrypt metadata");
            },
            None => println!("No data decrypted"),
        }
        Ok(())
    }
}
