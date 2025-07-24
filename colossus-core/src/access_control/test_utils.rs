use crate::{
    access_control::{Root, RootAuthority, RootPublicKey},
    policy::{AccessStructure, Error},
};

pub fn gen_structure(policy: &mut AccessStructure, complete: bool) -> Result<(), Error> {
    policy.add_hierarchy("SEC".to_string())?;

    policy.add_attribute(crate::policy::QualifiedAttribute::from(("SEC", "LOW")), None)?;
    policy.add_attribute(crate::policy::QualifiedAttribute::from(("SEC", "TOP")), Some("LOW"))?;

    policy.add_anarchy("DPT".to_string())?;
    ["RD", "HR", "MKG", "FIN", "DEV"].into_iter().try_for_each(|attrib| {
        policy.add_attribute(crate::policy::QualifiedAttribute::from(("DPT", attrib)), None)
    })?;

    if complete {
        policy.add_anarchy("CTR".to_string())?;
        ["EN", "DE", "IT", "FR", "SP"].into_iter().try_for_each(|attrib| {
            policy.add_attribute(crate::policy::QualifiedAttribute::from(("CTR", attrib)), None)
        })?;
    }

    Ok(())
}

pub fn gen_auth(api: &Root, complete: bool) -> Result<(RootAuthority, RootPublicKey), Error> {
    let (mut auth, _) = api.setup()?;
    gen_structure(&mut auth.access_structure, complete)?;
    let rpk = api.update_auth(&mut auth)?;
    Ok((auth, rpk))
}
