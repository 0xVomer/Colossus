use super::DEFAULT_MAX_ENTRIES;
use bls12_381_plus::{Scalar, elliptic_curve::bigint};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

pub trait Attribute: Clone {
    fn digest(&self) -> &[u8];
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry<A: Attribute>(pub Vec<A>);

impl<A: Attribute> Entry<A> {
    pub fn new(attributes: &[A]) -> Self {
        Entry(attributes.to_vec())
    }
    pub fn attributes(&'_ self) -> impl '_ + Iterator<Item = A> {
        self.0.iter().cloned()
    }
}

impl<A: Attribute> Deref for Entry<A> {
    type Target = Vec<A>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<A: Attribute> IntoIterator for Entry<A> {
    type Item = A;
    type IntoIter = ::std::vec::IntoIter<A>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<A: Attribute> std::iter::FromIterator<A> for Entry<A> {
    fn from_iter<I: IntoIterator<Item = A>>(iter: I) -> Self {
        Entry(iter.into_iter().collect())
    }
}

impl<A: Attribute> From<Vec<A>> for Entry<A> {
    fn from(item: Vec<A>) -> Self {
        Entry(item)
    }
}

impl<A: Attribute> From<&[A]> for Entry<A> {
    fn from(item: &[A]) -> Self {
        Entry(item.to_vec())
    }
}

pub fn entry_to_scalar<A: Attribute>(input: &Entry<A>) -> Vec<Scalar> {
    input
        .iter()
        .map(|attr| bigint::U256::from_be_slice(attr.digest()).into())
        .collect()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaxEntries(pub usize);

impl From<usize> for MaxEntries {
    fn from(item: usize) -> Self {
        MaxEntries(item)
    }
}

impl From<u8> for MaxEntries {
    fn from(item: u8) -> Self {
        MaxEntries(item as usize)
    }
}

impl From<MaxEntries> for usize {
    fn from(item: MaxEntries) -> Self {
        item.0
    }
}

impl From<MaxEntries> for u8 {
    fn from(item: MaxEntries) -> Self {
        item.0 as u8
    }
}

impl Deref for MaxEntries {
    type Target = usize;
    fn deref(&self) -> &usize {
        &self.0
    }
}

impl Default for MaxEntries {
    fn default() -> Self {
        MaxEntries(DEFAULT_MAX_ENTRIES)
    }
}

impl MaxEntries {
    pub fn new(item: usize) -> Self {
        MaxEntries(item)
    }
}

impl std::cmp::PartialEq<MaxEntries> for usize {
    fn eq(&self, other: &MaxEntries) -> bool {
        self == &other.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{Felt, Word};
    use crate::policy::BlindedAttribute;

    #[test]
    fn test_entry() {
        let entry = Entry::<BlindedAttribute>(vec![]);
        assert!(entry.is_empty());
    }

    #[test]
    fn test_convert_entry_to_big() {
        // Create a test BlindedAttribute using a deterministic commitment
        let test_commitment =
            Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);
        let blinded_attr = BlindedAttribute::from_commitment(test_commitment);

        let entry = Entry::<BlindedAttribute>::new(&[blinded_attr]);
        let scalars = entry_to_scalar(&entry);
        assert_eq!(scalars.len(), 1);
    }
}
