use super::*;

pub struct CredentialBuilder<'a> {
    entries: Vec<Entry>,
    extendable: usize,
    issuer: &'a Issuer,
}

impl<'a> CredentialBuilder<'a> {
    pub fn new(issuer: &'a Issuer) -> Self {
        Self {
            issuer,
            entries: Vec::new(),
            extendable: 0,
        }
    }

    pub fn with_entry(&mut self, entry: Entry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    pub fn max_entries(&mut self, extendable: &usize) -> &mut Self {
        self.extendable = *extendable;
        self
    }

    pub fn issue_to(
        &self,
        alias_proof: &AliasProof,
        nonce: Option<&Nonce>,
    ) -> Result<Credential, IssuerError> {
        let k_prime = self.extendable.checked_sub(0);
        self.issuer.issue_cred(&self.entries, k_prime, alias_proof, nonce)
    }
}
