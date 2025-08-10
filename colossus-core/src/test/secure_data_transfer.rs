use super::*;
use bls12_381_plus::{Scalar, ff::Field};
use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};

#[test]
fn test_secure_data_transfer() -> Result<()> {
    // Generate a fixed nonce for the test (but make it consistent)
    let rng = CsRng::seed_from_u64(42);
    let nonce = Nonce(Scalar::random(rng));

    let access_control = AccessControl::default();
    let (mut auth, _) = access_control.setup_capability_authority()?;

    // Access-Structures
    let permission_access_structure = &Permission::access_structure().unwrap();
    let userid_access_structure = &UserID::access_structure().unwrap();
    let groupid_access_structure = &GroupID::access_structure().unwrap();

    // Credential Issuers
    let permission_issuer = Issuer::setup(None, &permission_access_structure);
    let userid_issuer = Issuer::setup(None, &userid_access_structure);
    let groupid_issuer = Issuer::setup(None, &groupid_access_structure);

    // Register Credential Issuers
    let (permission_issuer_id, _) =
        access_control.register_issuer(&mut auth, &permission_issuer.public)?;
    let (_, _) = access_control.register_issuer(&mut auth, &userid_issuer.public)?;
    let (groupid_issuer_id, apk) =
        access_control.register_issuer(&mut auth, &groupid_issuer.public)?;

    //Alice creates encrypted header with Access Policy
    let (secret, enc_header) = EncryptedHeader::generate(
        &access_control,
        &apk,
        &AccessPolicy::try_from(
            vec![
                Permission::WRITE("host::domain::path::subpath::user::item_id".to_string()).label(),
                Permission::READ("host::domain::path::subpath::user::item_id".to_string()).label(),
                Challenge::HasGroupID.label(),
            ]
            .as_slice(),
        )
        .unwrap(),
        Some("host::domain::path::subpath::user::item_id".as_bytes()),
        Some(&nonce.to_be_bytes()),
    )
    .unwrap();

    // Bob creates an alias
    let bob = Alias::new().randomize();
    // and a proof of his alias using the verification nonce
    let bob_proof = bob.alias_proof(&nonce);

    // Bob is issued a user id
    let bob_userid = userid_issuer
        .access_credential()
        .with_entry(Entry::new(&[UserID::claim(12).qualify()]))
        .max_entries(&MaxEntries::default())
        .issue_to(&bob_proof, Some(&nonce))?;

    // Bbob is issued a group id
    let bob_groupid = groupid_issuer
        .access_credential()
        .with_entry(Entry::new(&[GroupID::claim(24).qualify()]))
        .max_entries(&MaxEntries::default())
        .issue_to(&bob_proof, Some(&nonce))?;

    // Bob is given Read, Write, Execute and Search permission for the requested datapoint
    let bob_permissions = permission_issuer
        .access_credential()
        .with_entry(Entry::new(&[
            Permission::WRITE("host::domain::path::subpath::user::item_id".to_string()).qualify(),
            Permission::READ("host::domain::path::subpath::user::item_id".to_string()).qualify(),
            Permission::EXECUTE("host::domain::path::subpath::user::item_id".to_string()).qualify(),
            Permission::SEARCH("host::domain::path::subpath::user::item_id".to_string()).qualify(),
        ]))
        .max_entries(&MaxEntries::default())
        .issue_to(&bob_proof, Some(&nonce))?;

    let (permission_proof, claimed_permissions) = bob
            .claim_builder(
                &bob_permissions,
                vec![Entry::new(&[
                    Permission::WRITE("host::domain::path::subpath::user::item_id".to_string()).qualify(),
                    Permission::READ("host::domain::path::subpath::user::item_id".to_string()).qualify(),
                    Permission::EXECUTE("host::domain::path::subpath::user::item_id".to_string()).qualify(),
                    Permission::SEARCH("host::domain::path::subpath::user::item_id".to_string()).qualify(),
                ])],
            )
            // Bob only selects his read & write permission
            .select_attribute(Permission::WRITE("host::domain::path::subpath::user::item_id".to_string()).qualify())
            .select_attribute(Permission::READ("host::domain::path::subpath::user::item_id".to_string()).qualify())
            .generate(&nonce)
            .map_err(|e| {
                println!("Error generating credential proof: {}", e);
                e
            })?;

    println!("Permission Claims: {:?}", claimed_permissions);

    // bob also wants to claim access rights using his device & location credential
    let (groupid_proof, has_groupid_claim) = bob
        .claim_builder(&bob_groupid, vec![Entry::new(&[GroupID::claim(24).qualify()])])
        .select_attribute(GroupID::claim(24).qualify())
        .generate(&nonce)?;

    println!("GroupID Claim: {:?}", has_groupid_claim);

    // capability is granted to Bob based on the set of his access claims
    let capability = access_control
        .grant_capability(
            &mut auth,
            &vec![
                AccessClaim {
                    issuer_id: permission_issuer_id,
                    cred_proof: permission_proof,
                    attributes: claimed_permissions,
                },
                AccessClaim {
                    issuer_id: groupid_issuer_id,
                    cred_proof: groupid_proof,
                    attributes: has_groupid_claim,
                },
            ],
            &nonce,
        )
        .unwrap();

    // bob is able to access the hidden metadata using his capability token
    match enc_header
        .decrypt(&access_control, &capability, Some(&nonce.to_be_bytes()))
        .unwrap()
    {
        Some(data) => {
            println!("{data:#?}");

            assert_eq!(data.secret, secret);
            assert_eq!(
                data.metadata.unwrap(),
                "host::domain::path::subpath::user::item_id".as_bytes()
            );
        },
        None => {
            panic!("Failed to decrypt metadata");
        },
    }
    Ok(())
}
