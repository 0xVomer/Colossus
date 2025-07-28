use super::*;
use anyhow::Result;
use lazy_static::lazy_static;

lazy_static! {
    static ref NONCE: Nonce = Nonce(Scalar::from(42u64));
}

#[test]
fn test_credential_building() -> Result<()> {
    let issuer = Issuer::default();
    let nym = Alias::new();

    let age_adult = QualifiedAttribute::from(("AGE", "ADULT"));
    let age_senior = QualifiedAttribute::from(("AGE", "SENIOR"));
    let root_entry = Entry::new(&[age_adult, age_senior]);

    let cred = issuer
        .credential() // CredentialBuilder for this Issuer
        .with_entry(root_entry.clone()) // adds a Root Entry
        .max_entries(&MaxEntries::default()) // set the Entry ceiling
        .issue_to(&nym.nym_proof(&NONCE), Some(&NONCE))?; // issues to a Nym

    assert_eq!(cred.commitment_vector.len(), 1);

    let cred = CredentialBuilder::new(&issuer)
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default())
        .issue_to(&nym.nym_proof(&NONCE), Some(&NONCE))?;

    assert_eq!(cred.commitment_vector.len(), 1);

    let cred = CredentialBuilder::new(&issuer)
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default())
        .issue_to(&nym.nym_proof(&NONCE), Some(&NONCE))?;

    assert_eq!(cred.commitment_vector.len(), 1);
    assert_eq!(cred.update_key.as_ref().unwrap().len(), MaxEntries::default());

    let another_entry = Entry::new(&[QualifiedAttribute::from(("another entry", ""))]);
    let cred = issuer
        .credential()
        .with_entry(root_entry.clone())
        .with_entry(another_entry)
        .issue_to(&nym.nym_proof(&NONCE), Some(&NONCE))?;

    assert_eq!(cred.commitment_vector.len(), 2);

    assert!(cred.update_key.is_none());

    let proof = nym.prove(&cred, &[root_entry.clone()], &[root_entry.clone()], &NONCE);

    assert!(verify_proof(&issuer.public, &proof, &[root_entry], Some(&NONCE)));

    Ok(())
}

#[test]
fn offer_tests() -> Result<()> {
    let issuer = Issuer::default();

    let alice_nym = Alias::new();

    let bobby_nym = Alias::new();

    let charlie_nym = Alias::new();

    let doug_nym = Alias::new();

    let evan_nym = Alias::new();

    let age_adult = QualifiedAttribute::from(("AGE", "ADULT"));
    let age_senior = QualifiedAttribute::from(("AGE", "SENIOR"));

    let root_entry = Entry::new(&[age_adult.clone(), age_senior]);

    let cred = match issuer
        .credential()
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default()) // DEFAULT_MAX_ENTRIES: usize = 6
        .issue_to(&alice_nym.nym_proof(&NONCE), Some(&NONCE))
    {
        Ok(cred) => cred,
        Err(e) => panic!("Error issuing cred: {:?}", e),
    };

    let (offer, provable_entries) = alice_nym.offer_builder(&cred, &[root_entry]).open_offer()?;

    let bobby_cred = bobby_nym.accept(&offer)?;

    let proof = bobby_nym.prove(&bobby_cred, &provable_entries, &provable_entries, &NONCE);
    assert!(verify_proof(&issuer.public, &proof, &provable_entries, Some(&NONCE)));

    let (proof, selected_entries) = bobby_nym
        .proof_builder(&bobby_cred, &provable_entries)
        .select_attribute(age_adult)
        .prove(&NONCE);
    assert!(verify_proof(&issuer.public, &proof, &selected_entries, Some(&NONCE)));

    let handsome_attribute = QualifiedAttribute::from(("LOOK", "HANDSOME"));
    let additional_entry = Entry::new(&[handsome_attribute.clone()]);

    let (offer, provable_entries) = bobby_nym
        .offer_builder(&bobby_cred, &provable_entries)
        .additional_entry(additional_entry)
        .open_offer()?;

    let charlie_cred = charlie_nym.accept(&offer)?;

    let (proof, selected_entries) = charlie_nym
        .proof_builder(&charlie_cred, &provable_entries)
        .select_attribute(handsome_attribute.clone())
        .prove(&NONCE);
    assert!(verify_proof(&issuer.public, &proof, &selected_entries, Some(&NONCE)));

    let (offer, provable_entries) = charlie_nym
        .offer_builder(&charlie_cred, &provable_entries)
        .without_attribute(handsome_attribute.clone())
        .open_offer()?;

    assert_eq!(provable_entries.len(), 2); // Should be 2 Entry(s) in the provable_entries, but only 1 non-empty
    assert_eq!(provable_entries[0].len(), 2); // over_21, seniors_discount
    assert_eq!(provable_entries[1].len(), 0); // empty, redacted entry with the handsome attribute

    let doug_cred = doug_nym.accept(&offer)?;

    let (_proof, selected_entries) = doug_nym
        .proof_builder(&doug_cred, &provable_entries)
        .select_attribute(handsome_attribute.clone())
        .prove(&NONCE);

    let contains_handsome =
        selected_entries.into_iter().any(|entry| entry.contains(&handsome_attribute));

    assert!(!contains_handsome);

    let (offer, provable_entries) = doug_nym
        .offer_builder(&doug_cred, &provable_entries)
        .max_entries(3)
        .open_offer()?;

    let evan_entry = Entry::new(&[QualifiedAttribute::from(("ENTRY", "1"))]);

    let evan_cred = evan_nym.accept(&offer)?;

    let even_nym_2 = Alias::new();
    let (offer, provable_entries) = evan_nym
        .offer_builder(&evan_cred, &provable_entries)
        .additional_entry(evan_entry)
        .open_offer()?;

    let evan_2_cred = even_nym_2.accept(&offer)?;

    let (proof, selected_entries) = even_nym_2
        .proof_builder(&evan_2_cred, &provable_entries)
        .select_attribute(QualifiedAttribute::from(("ENTRY", "1")))
        .prove(&NONCE);
    assert!(verify_proof(&issuer.public, &proof, &selected_entries, Some(&NONCE)));

    let res = even_nym_2
        .offer_builder(&evan_2_cred, &provable_entries)
        .additional_entry(Entry::new(&[QualifiedAttribute::from(("ENTRY", "MAX"))]))
        .open_offer();

    assert!(res.is_err());

    Ok(())
}

#[test]
fn test_delegate_root_cred() -> Result<()> {
    let issuer = Issuer::default();
    let nym = Alias::new();

    let root_entry = Entry::new(&[]);
    let nonce = Nonce::default();

    let cred = match issuer
        .credential()
        .with_entry(root_entry.clone())
        .max_entries(&MaxEntries::default()) // DEFAULT_MAX_ENTRIES: usize = 6
        .issue_to(&nym.nym_proof(&nonce), Some(&nonce))
    {
        Ok(cred) => cred,
        Err(e) => panic!("Error issuing cred: {:?}", e),
    };

    let del_root_entry = QualifiedAttribute::from(("TYPE", "DELEGGATED"));

    let (offer, entries) = nym
        .offer_builder(&cred, &[root_entry])
        .additional_entry(Entry::new(&[del_root_entry.clone()]))
        .open_offer()?;

    let del_nym = Alias::new();
    let del_cred = del_nym.accept(&offer)?;

    let (proof, selected_entries) = del_nym
        .proof_builder(&del_cred, &entries)
        .select_attribute(del_root_entry)
        .prove(&nonce);

    assert!(verify_proof(&issuer.public, &proof, &selected_entries, Some(&nonce)));

    Ok(())
}
