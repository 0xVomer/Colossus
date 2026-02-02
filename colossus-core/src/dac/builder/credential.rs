use super::*;

pub struct AccessCredentialBuilder<'a> {
    entries: Vec<Attributes>,
    extendable: usize,
    issuer: &'a Issuer,
}

impl<'a> AccessCredentialBuilder<'a> {
    pub fn new(issuer: &'a Issuer) -> Self {
        Self {
            issuer,
            entries: Vec::new(),
            extendable: 0,
        }
    }

    pub fn with_entry(&mut self, entry: Attributes) -> &mut Self {
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
    ) -> Result<AccessCredential, IssuerError> {
        // Note: With blinded attributes, attribute validation happens through
        // ownership proofs at the authority level. The issuer trusts the
        // BlindedAttribute commitments provided in the entries.
        // Legacy access_structure containment check has been removed.

        let k_prime = self.extendable.checked_sub(0);
        self.issuer.issue_access_cred(&self.entries, k_prime, alias_proof, nonce)
    }
}
