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
    use std::ops::Deref;

    use crate::{
        access_control::{AccessClaim, AccessControl, EncryptedHeader},
        dac::{
            entry::{Entry, MaxEntries},
            keypair::{Alias, CBORCodec, Issuer, verify_proof},
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
                _ => "SENIOR",
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

        pub fn access_structure() -> Result<AccessStructure> {
            let mut ac = AccessStructure::new();
            ac.add_hierarchy(Age::dimension_label().to_string())?;
            ac.add_attribute(Age::young_attribute(), None)?;
            ac.add_attribute(Age::adult_attribute(), Some("YOUTH"))?;
            ac.add_attribute(Age::senior_attribute(), Some("ADULT"))?;

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
                _ => "WEST_SYDNEY",
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

        pub fn access_structure() -> Result<AccessStructure> {
            let mut ac = AccessStructure::new();
            ac.add_anarchy(Location::dimension_label().to_string())?;
            ac.add_attribute(Location::inner_city_attribute(), None)?;
            ac.add_attribute(Location::east_sydney_attribute(), None)?;
            ac.add_attribute(Location::west_sydney_attribute(), None)?;

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
    fn test_access_control() -> Result<()> {
        let access_control = AccessControl::default();
        let (mut auth, _) = access_control.setup_capability_authority()?;

        // Access-Credential A manages credentials that contains Age + Location attributes
        let mut access_structure_a = Age::access_structure().unwrap();
        let location_access_structure = Location::access_structure().unwrap();
        access_structure_a.extend(&location_access_structure).unwrap();

        let issuer_a = Issuer::setup(None, &access_structure_a);
        access_control.register_issuer(&mut auth, &issuer_a.public)?;

        // Access-Credential B manages credentials that contains Device attributes
        let issuer_b = Issuer::setup(None, &Device::access_structure().unwrap());
        let (_, apk) = access_control.register_issuer(&mut auth, &issuer_b.public)?;

        // Alice creates encrypted header with Access Policy
        let (secret, enc_header) = EncryptedHeader::generate(
            &access_control,
            &apk,
            &AccessPolicy::parse("(AGE::ADULT || AGE::SENIOR) && LOC::INNER_CITY").unwrap(),
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
        let age_location_cred = issuer_a
            .access_credential()
            .with_entry(Entry::new(&[
                Age::claim(25).qualify(),
                Location::claim("innercity".to_string()).qualify(),
            ]))
            .max_entries(&MaxEntries::default())
            .issue_to(&bob_proof, Some(&NONCE))?;

        // Issuer B provides bob with device credential
        let device_cred = issuer_b
            .access_credential()
            .with_entry(Entry::new(&[Device::claim(0).qualify()]))
            .max_entries(&MaxEntries::default())
            .issue_to(&bob_proof, Some(&NONCE))?;

        // bob claims access rights from his issued credentials, known attributes and authentication nonce
        let (credential_proof_a, claimed_attributes_a) = bob
            .claim_builder(
                &age_location_cred,
                vec![Entry::new(&[
                    Age::claim(25).qualify(),
                    Location::claim("innercity".to_string()).qualify(),
                ])],
            )
            .select_attribute(Age::claim(0).qualify())
            .select_attribute(Location::claim("innercity".to_string()).qualify())
            .generate(&NONCE)
            .map_err(|e| {
                println!("Error generating credential proof: {}", e);
                e
            })?;

        println!("claims: {claimed_attributes_a:?}");

        let (credential_proof_b, claimed_attributes_b) = bob
            .claim_builder(&device_cred, vec![Entry::new(&[Device::claim(0).qualify()])])
            .select_attribute(Device::claim(0).qualify())
            .generate(&NONCE)?;

        // verify claim against a set of access rights and the issuer's pubkey & authentication nonce
        // assert!(verify_proof(
        //     &issuer_a.public,
        //     &credential_proof_a,
        //     &claimed_attributes_a,
        //     Some(&NONCE)
        // ));
        // assert!(verify_proof(
        //     &issuer_b.public,
        //     &credential_proof_b,
        //     &claimed_attributes_b,
        //     Some(&NONCE)
        // ));

        // let claims = AccessPolicy::parse("AGE::ADULT && LOC::INNER_CITY").unwrap();

        let access_claims: Vec<AccessClaim> = vec![
            AccessClaim {
                issuer_id: 1,
                cred_proof: credential_proof_a,
                attributes: claimed_attributes_a,
            },
            AccessClaim {
                issuer_id: 2,
                cred_proof: credential_proof_b,
                attributes: claimed_attributes_b,
            },
        ];

        let capability =
            access_control.grant_capability(&mut auth, &access_claims, &NONCE).unwrap();

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
}
