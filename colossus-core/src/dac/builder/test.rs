use super::*;
use anyhow::Result;
use lazy_static::lazy_static;

use crate::{
    access_control::AccessControl,
    dac::{
        entry::{Entry, MaxEntries},
        keypair::verify_proof,
    },
    policy::{AccessStructure, QualifiedAttribute},
};
use bls12_381_plus::Scalar;

lazy_static! {
    static ref NONCE: Nonce = Nonce(Scalar::from(42u64));
}

#[test]
fn test_credential_building() -> Result<()> {
    let access_control = AccessControl::default();
    let (mut auth, _) = access_control.setup_capability_authority()?;

    let age_adult = QualifiedAttribute::from(("AGE", "ADULT"));
    let age_senior = QualifiedAttribute::from(("AGE", "SENIOR"));
    let void = QualifiedAttribute::from(("VOID", "VOID"));

    let mut access_structure = AccessStructure::new();
    access_structure.add_hierarchy("AGE".to_string())?;
    access_structure.add_attribute(age_adult.clone(), None)?;
    access_structure.add_attribute(age_senior.clone(), Some("ADULT"))?;

    access_structure.add_anarchy("VOID".to_string())?;
    access_structure.add_attribute(void.clone(), None)?;

    let issuer = Issuer::setup(None, &access_structure);
    let (_, apk) = access_control.register_issuer(&mut auth, &issuer.public)?;

    let alias = Alias::new();

    let root_entry = Entry::new(&[age_adult, age_senior]);

    let cred = issuer
        .access_credential()
        .with_entry(root_entry.clone()) // adds a Root Entry
        .max_entries(&MaxEntries::default()) // set the Entry ceiling
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?; // issues to a Nym

    assert_eq!(cred.commitment_vector.len(), 1);

    let cred = AccessCredentialBuilder::new(&issuer)
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default())
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?;

    assert_eq!(cred.commitment_vector.len(), 1);

    let cred = AccessCredentialBuilder::new(&issuer)
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default())
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?;

    assert_eq!(cred.commitment_vector.len(), 1);
    assert_eq!(
        cred.update_key.as_ref().unwrap().len(),
        MaxEntries(access_structure.no_attributes())
    );

    let another_entry = Entry::new(&[void]);
    let cred = issuer
        .access_credential()
        .with_entry(root_entry.clone())
        .with_entry(another_entry)
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?;

    assert_eq!(cred.commitment_vector.len(), 2);

    assert!(cred.update_key.is_none());

    let proof = alias.prove(&cred, &[root_entry.clone()], &[root_entry.clone()], &NONCE);

    assert!(verify_proof(&issuer.public, &proof, &[root_entry], Some(&NONCE)));

    Ok(())
}

#[test]
fn test_issuer_unsupported_attribute() -> Result<()> {
    let access_control = AccessControl::default();
    let (mut auth, _) = access_control.setup_capability_authority()?;

    let mut access_structure = AccessStructure::new();

    let supported = QualifiedAttribute::from(("SUPPORT", "YES"));
    let unsupported = QualifiedAttribute::from(("UNSUPPORTED", "NO"));

    access_structure.add_anarchy("SUPPORT".to_string())?;
    access_structure.add_attribute(supported.clone(), None)?;

    let mut issuer = Issuer::setup(None, &access_structure);
    let (_, apk) = access_control.register_issuer(&mut auth, &issuer.public)?;

    let alias = Alias::new();
    let unsupported_root_entry = Entry::new(&[unsupported.clone()]);
    let supported_root_entry = Entry::new(&[supported.clone()]);
    let combined_root_entry = Entry::new(&[supported, unsupported.clone()]);

    let _ = match issuer
        .access_credential()
        .with_entry(unsupported_root_entry.clone())
        .max_entries(&MaxEntries::default())
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))
    {
        Ok(_) => Err("AccessCredential issued with unsupported attribute"),
        Err(e) => {
            println!("Error issuing credential: {}", e);
            Ok(())
        },
    };

    let cred = issuer
        .access_credential() // AccessCredentialBuilder for this Issuer
        .with_entry(supported_root_entry.clone()) // adds a Root Entry
        .max_entries(&MaxEntries::default()) // set the Entry ceiling
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?; // issues to a Nym

    assert_eq!(cred.commitment_vector.len(), 1);

    // update access structure to contain the unsupported attribute
    access_structure.add_anarchy("UNSUPPORTED".to_string())?;
    access_structure.add_attribute(unsupported, None)?;

    // issuer shouldn't be affected by this change
    // it will require for issuer to re-setup.
    let _ = match issuer
        .access_credential()
        .with_entry(unsupported_root_entry.clone())
        .max_entries(&MaxEntries::default())
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))
    {
        Ok(_) => Err("AccessCredential issued with unsupported attribute"),
        Err(e) => {
            println!("Error issuing credential: {}", e);
            Ok(())
        },
    };

    // new issuer that supports both the supported and unsupported attributes
    let issuer_2 = Issuer::setup(None, &access_structure);

    // register issuer or else apk will not contain the unsupported attribute
    access_control.register_issuer(&mut auth, &issuer_2.public)?;

    let cred = issuer_2
        .access_credential() // AccessCredentialBuilder for this Issuer
        .with_entry(combined_root_entry.clone()) // adds a Root Entry
        .max_entries(&MaxEntries::default()) // set the Entry ceiling
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?; // issues to a Nym

    assert_eq!(cred.commitment_vector.len(), 1);

    // old issuer updates its access structure;
    issuer.restruct(&access_structure);
    // old issuer should now be able to issue a credential with the unsupported attribute
    let cred = issuer
        .access_credential() // AccessCredentialBuilder for this Issuer
        .with_entry(combined_root_entry.clone()) // adds a Root Entry
        .max_entries(&MaxEntries::default()) // set the Entry ceiling
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?; // issues to a Nym

    assert_eq!(cred.commitment_vector.len(), 1);

    Ok(())
}
