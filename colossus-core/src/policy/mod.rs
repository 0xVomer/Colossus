mod access_policy;
mod access_structure;
mod attribute;
mod data_struct;
mod dimension;
mod errors;
mod rights;

pub use access_policy::AccessPolicy;
pub use access_structure::AccessStructure;
pub use attribute::{Attribute, AttributeStatus, QualifiedAttribute};
pub use data_struct::{Dict, RevisionMap, RevisionVec};
pub use dimension::Dimension;
pub use errors::PolicyError as Error;
pub use rights::Right;

#[cfg(test)]
mod tests;

type Name = String;

fn gen_test_structure(policy: &mut AccessStructure, complete: bool) -> Result<(), Error> {
    policy.add_hierarchy("SEC".to_string())?;

    policy.add_attribute(
        QualifiedAttribute {
            dimension: "SEC".to_string(),
            name: "LOW".to_string(),
        },
        None,
    )?;
    policy.add_attribute(
        QualifiedAttribute {
            dimension: "SEC".to_string(),
            name: "TOP".to_string(),
        },
        Some("LOW"),
    )?;

    policy.add_anarchy("DPT".to_string())?;
    [("RD"), ("HR"), ("MKG"), ("FIN"), ("DEV")]
        .into_iter()
        .try_for_each(|attribute| {
            policy.add_attribute(
                QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: attribute.to_string(),
                },
                None,
            )
        })?;

    if complete {
        policy.add_anarchy("CTR".to_string())?;
        [("EN"), ("DE"), ("IT"), ("FR"), ("SP")].into_iter().try_for_each(|attribute| {
            policy.add_attribute(
                QualifiedAttribute {
                    dimension: "CTR".to_string(),
                    name: attribute.to_string(),
                },
                None,
            )
        })?;
    }

    Ok(())
}
