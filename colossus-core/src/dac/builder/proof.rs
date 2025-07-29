use super::*;

pub struct ProofBuilder<'a, Stage> {
    alias: &'a Alias<Stage>,
    cred: &'a Credential,
    all_attributes: Vec<Entry>,
    selected_attributes: Vec<QualifiedAttribute>,
}

impl<'a, Stage> ProofBuilder<'a, Stage> {
    pub fn new(alias: &'a Alias<Stage>, cred: &'a Credential, all_attributes: &[Entry]) -> Self {
        Self {
            alias,
            cred,
            all_attributes: all_attributes.to_vec(),
            selected_attributes: Vec::new(),
        }
    }

    pub fn select_attribute(&mut self, attribute: QualifiedAttribute) -> &mut Self {
        self.selected_attributes.push(attribute);
        self
    }

    pub fn prove(&self, nonce: &Nonce) -> (CredProof, Vec<Entry>) {
        let selected_attr = self
            .all_attributes
            .iter()
            .map(|entry| {
                entry
                    .iter()
                    .filter(|attr| self.selected_attributes.contains(attr))
                    .cloned()
                    .collect::<Entry>()
            })
            .collect::<Vec<Entry>>();

        let proof = self.alias.prove(self.cred, &self.all_attributes, &selected_attr, nonce);

        (proof, selected_attr)
    }
}
