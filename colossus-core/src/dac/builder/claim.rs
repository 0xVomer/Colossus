use super::*;
use crate::policy::BlindedAttribute;

pub struct ClaimBuilder<'a, Stage> {
    alias: &'a Alias<Stage>,
    cred: &'a AccessCredential,
    all_attributes: Vec<Attributes>,
    selected_attributes: Vec<BlindedAttribute>,
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

    pub fn select_attribute(&mut self, attribute: BlindedAttribute) -> &mut Self {
        self.selected_attributes.push(attribute);
        self
    }

    pub fn generate(&self, nonce: &Nonce) -> Result<(CredProof, Vec<Attributes>), IssuerError> {
        // Note: With blinded attributes, we trust the issuer's proofs instead of
        // validating against an access structure. The access_structure validation
        // is removed in favor of ownership proof verification at the authority level.

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
