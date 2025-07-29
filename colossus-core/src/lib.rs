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

// #[cfg(test)]
// mod test {
//     use std::ops::Deref;

//     use crate::{
//         access_control::{AccessControl, EncryptedHeader},
//         dac::{
//             entry::{Entry, MaxEntries},
//             keypair::{Alias, CBORCodec, Issuer, verify_proof},
//             zkp::Nonce,
//         },
//         policy::{AccessPolicy, AccessStructure, QualifiedAttribute},
//     };
//     use anyhow::Result;
//     use bls12_381_plus::Scalar;
//     use lazy_static::lazy_static;

//     pub struct Age(u8);

//     impl Age {
//         pub fn new(age: u8) -> Self {
//             Self(age)
//         }
//         fn dimension_label() -> &'static str {
//             "AGE"
//         }
//         fn attribute_label(&self) -> &'static str {
//             match self.0 {
//                 0..=20 => "YOUTH",
//                 21..=60 => "ADULT",
//                 _ => "SENIOR",
//             }
//         }
//         pub fn as_qualified_attribute(&self) -> QualifiedAttribute {
//             QualifiedAttribute::new(Age::dimension_label(), self.attribute_label())
//         }

//         fn young_attribute() -> QualifiedAttribute {
//             QualifiedAttribute::new(Age::dimension_label(), "YOUTH")
//         }

//         fn adult_attribute() -> QualifiedAttribute {
//             QualifiedAttribute::new(Age::dimension_label(), "ADULT")
//         }

//         fn senior_attribute() -> QualifiedAttribute {
//             QualifiedAttribute::new(Age::dimension_label(), "SENIOR")
//         }

//         pub fn insert_into(access_structure: &mut AccessStructure) -> Result<()> {
//             access_structure.add_hierarchy(Age::dimension_label().to_string()).unwrap();
//             access_structure.add_attribute(Age::young_attribute(), None).unwrap();
//             access_structure.add_attribute(Age::adult_attribute(), Some("YOUTH")).unwrap();
//             access_structure.add_attribute(Age::senior_attribute(), Some("ADULT")).unwrap();

//             Ok(())
//         }
//     }

//     lazy_static! {
//         static ref NONCE: Nonce = Nonce(Scalar::from(42u64));
//     }

//     #[test]
//     fn test_access_control() -> Result<()> {
//         let access_control = AccessControl::default();
//         let (mut auth, _) = access_control.setup_capability_authority()?;

//         Age::insert_into(&mut auth.access_structure)?;

//         let cred_issuer = Issuer::default();
//         let cred_issuer_public = cred_issuer.public.to_compact().to_cbor().unwrap();

//         let rpk = access_control.update_capability_authority(&mut auth)?;

//         // Alice creates encrypted header with Access Policy: "AGE::ADULT || AGE::SENIOR"
//         let ap = AccessPolicy::parse("AGE::ADULT || AGE::SENIOR").unwrap();
//         println!("{ap:#?}");

//         let (secret, enc_header) = EncryptedHeader::generate(
//             &access_control,
//             &rpk,
//             &ap,
//             Some("alice_metadata".as_bytes()),
//             Some(&NONCE.to_be_bytes()),
//         )
//         .unwrap();
//         println!("{enc_header:#?}");

//         // Bob creates an alias
//         let mut bob = Alias::new();
//         bob = bob.randomize();

//         // and a proof of his alias using the verification nonce
//         let bob_proof = bob.alias_proof(&NONCE);

//         // Bob provides her age to credential issuer
//         // Credential issuer creates a credential for bob
//         let attr_entry = Entry::new(&[Age::new(25).as_qualified_attribute()]);
//         let bob_cred = cred_issuer
//             .credential()
//             .with_entry(attr_entry.clone())
//             .max_entries(&MaxEntries::default())
//             .issue_to(&bob_proof, Some(&NONCE))?;

//         // bob creates a proof of his credential that attests to his age-attribute
//         let cred_proof = bob.prove(&bob_cred, &[attr_entry.clone()], &[attr_entry.clone()], &NONCE);

//         // Bob acquires access-right keys
//         assert!(verify_proof(&cred_issuer.public, &cred_proof, &[attr_entry], Some(&NONCE)));
//         let capability = access_control.grant_capability(&mut auth, &ap).unwrap();

//         match enc_header
//             .decrypt(&access_control, &capability, Some(&NONCE.to_be_bytes()))
//             .unwrap()
//         {
//             Some(data) => {
//                 println!("{data:#?}");

//                 assert_eq!(data.secret, secret);
//                 assert_eq!(data.metadata.unwrap(), "alice_metadata".as_bytes());
//             },
//             None => {
//                 panic!("Failed to decrypt metadata");
//             },
//         }
//         Ok(())
//     }
// }
