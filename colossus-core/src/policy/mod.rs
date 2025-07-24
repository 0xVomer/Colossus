mod access_policy;
mod access_structure;
mod attribute;
mod data_struct;
mod dimension;
mod errors;
mod rights;

pub use access_policy::AccessPolicy;
pub use access_structure::AccessStructure;
pub use attribute::{ATTRIBUTE, QualifiedAttribute};
pub use data_struct::{Dict, RevisionMap, RevisionVec};
pub use dimension::{Attribute, AttributeStatus, Dimension};
pub use errors::PolicyError as Error;
pub use rights::Right;

#[cfg(test)]
mod tests;

fn gen_test_structure(policy: &mut AccessStructure, complete: bool) -> Result<(), Error> {
    policy.add_hierarchy("SEC".to_string())?;
    policy.add_attribute(QualifiedAttribute::from(("SEC", "LOW")), None)?;
    policy.add_attribute(QualifiedAttribute::from(("SEC", "TOP")), Some("LOW"))?;

    policy.add_anarchy("DPT".to_string())?;
    [("RD"), ("HR"), ("MKG"), ("FIN"), ("DEV")]
        .into_iter()
        .try_for_each(|attribute| {
            policy.add_attribute(QualifiedAttribute::from(("DPT", attribute)), None)
        })?;

    if complete {
        policy.add_anarchy("CTR".to_string())?;
        [("EN"), ("DE"), ("IT"), ("FR"), ("SP")].into_iter().try_for_each(|attribute| {
            policy.add_attribute(QualifiedAttribute::from(("CTR", attribute)), None)
        })?;
    }

    Ok(())
}
