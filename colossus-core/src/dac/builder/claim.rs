use super::*;
use crate::policy::QualifiedAttribute;

pub struct ClaimBuilder<'a, Stage> {
    alias: &'a Alias<Stage>,
    cred: &'a AccessCredential,
    all_attributes: Vec<Attributes>,
    selected_attributes: Vec<QualifiedAttribute>,
}

impl<'a, Stage> ClaimBuilder<'a, Stage> {
    pub fn new(
        alias: &'a Alias<Stage>,
        cred: &'a AccessCredential,
        all_attributes: Vec<Attributes>,
    ) -> Self {
        Self {
            alias,
            cred,
            all_attributes,
            selected_attributes: Vec::new(),
        }
    }

    pub fn select_attribute(&mut self, attribute: QualifiedAttribute) -> &mut Self {
        self.selected_attributes.push(attribute);
        self
    }

    pub fn generate(&self, nonce: &Nonce) -> Result<(CredProof, Vec<Attributes>), IssuerError> {
        // check selected attributes were covered by the credential issuer
        for attr in &self.selected_attributes {
            if !self.cred.issuer_public.access_structure.contains_attribute(attr.bytes()) {
                return Err(IssuerError::AttributesNotCovered);
            }
        }

        let selected_attr = self
            .all_attributes
            .iter()
            .map(|entry| {
                entry
                    .iter()
                    .filter(|attr| self.selected_attributes.contains(attr))
                    .cloned()
                    .collect::<Attributes>()
            })
            .collect::<Vec<Attributes>>();

        let proof = self.alias.prove(self.cred, &self.all_attributes, &selected_attr, nonce);

        Ok((proof, selected_attr))
    }
}
