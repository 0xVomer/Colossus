use super::*;
use anyhow::Result;
use lazy_static::lazy_static;

use crate::{
    dac::{entry::MaxEntries, keypair::verify_proof},
    policy::AccessStructure,
};

lazy_static! {
    static ref NONCE: Nonce = Nonce(Scalar::from(42u64));
}

#[test]
fn test_credential_building() -> Result<()> {
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
    let alias = Alias::new();

    let root_entry = Entry::new(&[age_adult, age_senior]);

    let cred = issuer
        .credential() // CredentialBuilder for this Issuer
        .with_entry(root_entry.clone()) // adds a Root Entry
        .max_entries(&MaxEntries::default()) // set the Entry ceiling
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?; // issues to a Nym

    assert_eq!(cred.commitment_vector.len(), 1);

    let cred = CredentialBuilder::new(&issuer)
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default())
        .issue_to(&alias.alias_proof(&NONCE), Some(&NONCE))?;

    assert_eq!(cred.commitment_vector.len(), 1);

    let cred = CredentialBuilder::new(&issuer)
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
        .credential()
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
fn offer_tests() -> Result<()> {
    let age_adult = QualifiedAttribute::from(("AGE", "ADULT"));
    let age_senior = QualifiedAttribute::from(("AGE", "SENIOR"));
    let void = QualifiedAttribute::from(("VOID", "VOID"));
    let ent_0 = QualifiedAttribute::from(("ENTRY", "0"));
    let ent_1 = QualifiedAttribute::from(("ENTRY", "1"));

    let handsome_attribute = QualifiedAttribute::from(("LOOK", "HANDSOME"));

    let mut access_structure = AccessStructure::new();
    access_structure.add_hierarchy("AGE".to_string())?;
    access_structure.add_attribute(age_adult.clone(), None)?;
    access_structure.add_attribute(age_senior.clone(), Some("ADULT"))?;

    access_structure.add_anarchy("VOID".to_string())?;
    access_structure.add_attribute(void.clone(), None)?;

    access_structure.add_anarchy("LOOK".to_string())?;
    access_structure.add_attribute(handsome_attribute.clone(), None)?;

    access_structure.add_hierarchy("ENTRY".to_string())?;
    access_structure.add_attribute(ent_0.clone(), None)?;
    access_structure.add_attribute(ent_1.clone(), Some("0"))?;

    let issuer = Issuer::setup(None, &access_structure);

    let alice_alias = Alias::new();
    let bobby_alias = Alias::new();
    let charlie_alias = Alias::new();
    let doug_alias = Alias::new();
    let evan_alias = Alias::new();

    let root_entry = Entry::new(&[age_adult.clone(), age_senior]);

    let cred = match issuer
        .credential()
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default()) // DEFAULT_MAX_ENTRIES: usize = 6
        .issue_to(&alice_alias.alias_proof(&NONCE), Some(&NONCE))
    {
        Ok(cred) => cred,
        Err(e) => panic!("Error issuing cred: {:?}", e),
    };

    let (offer, provable_entries) = alice_alias.offer_builder(&cred, &[root_entry]).open_offer()?;

    let bobby_cred = bobby_alias.accept(&offer)?;

    let proof = bobby_alias.prove(&bobby_cred, &provable_entries, &provable_entries, &NONCE);
    assert!(verify_proof(&issuer.public, &proof, &provable_entries, Some(&NONCE)));

    let (proof, selected_entries) = bobby_alias
        .proof_builder(&bobby_cred, &provable_entries)
        .select_attribute(age_adult)
        .prove(&NONCE);
    assert!(verify_proof(&issuer.public, &proof, &selected_entries, Some(&NONCE)));

    let additional_entry = Entry::new(&[handsome_attribute.clone()]);

    let (offer, provable_entries) = bobby_alias
        .offer_builder(&bobby_cred, &provable_entries)
        .additional_entry(additional_entry)
        .open_offer()?;

    let charlie_cred = charlie_alias.accept(&offer)?;

    let (proof, selected_entries) = charlie_alias
        .proof_builder(&charlie_cred, &provable_entries)
        .select_attribute(handsome_attribute.clone())
        .prove(&NONCE);
    assert!(verify_proof(&issuer.public, &proof, &selected_entries, Some(&NONCE)));

    let (offer, provable_entries) = charlie_alias
        .offer_builder(&charlie_cred, &provable_entries)
        .without_attribute(handsome_attribute.clone())
        .open_offer()?;

    assert_eq!(provable_entries.len(), 2); // Should be 2 Entry(s) in the provable_entries, but only 1 non-empty
    assert_eq!(provable_entries[0].len(), 2); // over_21, seniors_discount
    assert_eq!(provable_entries[1].len(), 0); // empty, redacted entry with the handsome attribute

    let doug_cred = doug_alias.accept(&offer)?;

    let (_proof, selected_entries) = doug_alias
        .proof_builder(&doug_cred, &provable_entries)
        .select_attribute(handsome_attribute.clone())
        .prove(&NONCE);

    let contains_handsome =
        selected_entries.into_iter().any(|entry| entry.contains(&handsome_attribute));

    assert!(!contains_handsome);

    let (offer, provable_entries) = doug_alias
        .offer_builder(&doug_cred, &provable_entries)
        .max_entries(3)
        .open_offer()?;

    let evan_cred = evan_alias.accept(&offer)?;

    let even_alias_2 = Alias::new();
    let (offer, provable_entries) = evan_alias
        .offer_builder(&evan_cred, &provable_entries)
        .additional_entry(Entry::new(&[ent_0]))
        .open_offer()?;

    let evan_2_cred = even_alias_2.accept(&offer)?;

    let (proof, selected_entries) = even_alias_2
        .proof_builder(&evan_2_cred, &provable_entries)
        .select_attribute(QualifiedAttribute::from(("ENTRY", "1")))
        .prove(&NONCE);
    assert!(verify_proof(&issuer.public, &proof, &selected_entries, Some(&NONCE)));

    let res = even_alias_2
        .offer_builder(&evan_2_cred, &provable_entries)
        .additional_entry(Entry::new(&[ent_1]))
        .open_offer();

    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_delegate_root_cred() -> Result<()> {
    let void = QualifiedAttribute::from(("VOID", "VOID"));
    let del = QualifiedAttribute::from(("TYPE", "DELEGGATED"));

    let mut access_structure = AccessStructure::new();
    access_structure.add_anarchy("VOID".to_string())?;
    access_structure.add_attribute(void.clone(), None)?;
    access_structure.add_anarchy("TYPE".to_string())?;
    access_structure.add_attribute(del.clone(), None)?;

    let issuer = Issuer::setup(None, &access_structure);
    let alias = Alias::new();

    let root_entry = Entry::new(&[]);
    let nonce = Nonce::default();

    let cred = match issuer
        .credential()
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default())
        .issue_to(&alias.alias_proof(&nonce), Some(&nonce))
    {
        Ok(cred) => cred,
        Err(e) => panic!("Error issuing cred: {:?}", e),
    };

    let (offer, entries) = alias
        .offer_builder(&cred, &[root_entry])
        .additional_entry(Entry::new(&[del.clone()]))
        .open_offer()?;

    let del_alias = Alias::new();
    let del_cred = del_alias.accept(&offer)?;

    let (proof, selected_entries) =
        del_alias.proof_builder(&del_cred, &entries).select_attribute(del).prove(&nonce);

    assert!(verify_proof(&issuer.public, &proof, &selected_entries, Some(&nonce)));

    Ok(())
}
