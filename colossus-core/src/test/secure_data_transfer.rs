use super::*;

#[test]
fn test_secure_data_transfer() -> Result<()> {
    let access_control = AccessControl::default();
    let (mut auth, _) = access_control.setup_capability_authority()?;

    // Issuer of credentials that contains data-permissions
    let permission_issuer = Issuer::setup(None, &Permission::access_structure().unwrap());
    let (permission_issuer_id, _) =
        access_control.register_issuer(&mut auth, &permission_issuer.public)?;

    // Issuer of credentials that contain userid
    let userid_issuer = Issuer::setup(None, &UserID::access_structure().unwrap());
    let (userid_issuer_id, _) = access_control.register_issuer(&mut auth, &userid_issuer.public)?;

    // Issuer of crednetials that contains groupid
    let groupid_issuer = Issuer::setup(None, &GroupID::access_structure().unwrap());
    let (groupid_issuer_id, apk) =
        access_control.register_issuer(&mut auth, &groupid_issuer.public)?;

    // Alice creates encrypted header with Access Policy
    let (secret, enc_header) = EncryptedHeader::generate(
        &access_control,
        &apk,
        &AccessPolicy::try_from(
            vec![Permission::WRITE.to_string(), Challenge::HasGroupID.to_string()].as_slice(),
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

    // Bob is issued a user id
    let bob_userid = userid_issuer
        .access_credential()
        .with_entry(Entry::new(&[UserID::claim(12).qualify()]))
        .max_entries(&MaxEntries::default())
        .issue_to(&bob_proof, Some(&NONCE))?;

    // Bbob is issued a group id
    let bob_groupid = groupid_issuer
        .access_credential()
        .with_entry(Entry::new(&[GroupID::claim(24).qualify()]))
        .max_entries(&MaxEntries::default())
        .issue_to(&bob_proof, Some(&NONCE))?;

    // Bob is given Read, Write, Execute and Search permission for the requested datapoint
    let bob_permissions = permission_issuer
        .access_credential()
        .with_entry(Entry::new(&[
            Permission::READ.qualify(),
            Permission::WRITE.qualify(),
            Permission::EXECUTE.qualify(),
            Permission::SEARCH.qualify(),
        ]))
        .max_entries(&MaxEntries::default())
        .issue_to(&bob_proof, Some(&NONCE))?;

    let (permission_proof, claimed_permissions) = bob
            .claim_builder(
                &bob_permissions,
                vec![Entry::new(&[
                    Permission::READ.qualify(),
                    Permission::WRITE.qualify(),
                    Permission::EXECUTE.qualify(),
                    Permission::SEARCH.qualify(),
                ])],
            )
            // Bob only selects his read & write permission
            .select_attribute(Permission::READ.qualify())
            .select_attribute(Permission::WRITE.qualify())
            .generate(&NONCE)
            .map_err(|e| {
                println!("Error generating credential proof: {}", e);
                e
            })?;

    println!("Permission Claims: {:?}", claimed_permissions);

    // bob also wants to claim access rights using his device & location credential
    let (groupid_proof, has_groupid_claim) = bob
        .claim_builder(&bob_groupid, vec![Entry::new(&[GroupID::claim(24).qualify()])])
        .select_attribute(GroupID::claim(24).qualify())
        .generate(&NONCE)?;

    println!("GroupID Claim: {:?}", has_groupid_claim);

    // capability is granted to Bob based on the set of his access claims
    let capability = access_control
        .grant_capability(
            &mut auth,
            &vec![
                // Access Claim from Bob's credential whihc holds age & location attributes
                AccessClaim {
                    issuer_id: permission_issuer_id,
                    cred_proof: permission_proof,
                    attributes: claimed_permissions,
                },
                // Access Claim from Bob's credential which holds device attribute
                AccessClaim {
                    issuer_id: groupid_issuer_id,
                    cred_proof: groupid_proof,
                    attributes: has_groupid_claim,
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

            assert_eq!(data.secret, secret);
            assert_eq!(data.metadata.unwrap(), "alice_metadata".as_bytes());
        },
        None => {
            panic!("Failed to decrypt metadata");
        },
    }
    Ok(())
}
