use super::*;

pub struct OfferBuilder<'a, Stage> {
    our_nym: &'a Alias<Stage>,
    credential: &'a Credential,
    unprovable_attributes: Vec<QualifiedAttribute>,
    current_entries: Vec<Entry>,
    additional_entry: Option<Entry>,
    max_entries: usize,
}

impl<'a, Stage> OfferBuilder<'a, Stage> {
    pub fn new(
        our_nym: &'a Alias<Stage>,
        credential: &'a Credential,
        current_entries: &[Entry],
    ) -> Self {
        Self {
            our_nym,
            credential,
            unprovable_attributes: Vec::new(),
            current_entries: current_entries.to_vec(),
            additional_entry: None,

            max_entries: credential.update_key.as_ref().map_or(0, |k| k.len()),
        }
    }

    pub fn without_attribute(&mut self, redacted: QualifiedAttribute) -> &mut Self {
        self.unprovable_attributes.push(redacted);
        self
    }

    pub fn additional_entry(&mut self, entry: Entry) -> &mut Self {
        self.additional_entry = Some(entry);
        self
    }

    pub fn max_entries(&mut self, limit: usize) -> &mut Self {
        self.max_entries =
            std::cmp::min(limit, self.credential.update_key.as_ref().map_or(0, |k| k.len()));
        self
    }

    pub fn open_offer(&self) -> Result<(Offer, Vec<Entry>), Error> {
        let mut cred_redacted = self.credential.clone();
        let mut provable_entries = self.current_entries.clone();

        if !self.unprovable_attributes.is_empty() {
            let mut opening_vector_restricted = self.credential.opening_vector.clone();
            for unprovable_attribute in &self.unprovable_attributes {
                for (index, entry) in self.current_entries.iter().enumerate() {
                    if entry.contains(unprovable_attribute) {
                        opening_vector_restricted[index] = Scalar::ZERO;

                        provable_entries[index] = Entry::new(&[]);
                    }
                }
            }

            cred_redacted = Credential {
                opening_vector: opening_vector_restricted,
                ..cred_redacted
            };
        }

        if let Some(entry) = &self.additional_entry {
            provable_entries.push(entry.clone());
        }

        cred_redacted.update_key = match self.max_entries {
            0 => None,
            _ => Some(
                self.credential
                    .update_key
                    .as_ref()
                    .unwrap()
                    .iter()
                    .take(self.max_entries)
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
        };

        let offer = self.our_nym.offer(&cred_redacted, &self.additional_entry)?;

        Ok((offer, provable_entries))
    }
}
