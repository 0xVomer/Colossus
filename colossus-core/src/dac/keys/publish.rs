use super::VKCompressed;
use cid::CidGeneric;
use cid::multibase;
use cid::multihash;
use tiny_keccak::{Hasher, Sha3};

const SHA2_256: u64 = 0x12;

#[derive(serde::Serialize, Debug)]
pub struct PublishingKey<'a, T> {
    preimages: &'a OfferedPreimages<'a, T>,
    issuer_key: &'a IssuerKey<'a>,
}

#[derive(serde::Serialize, Debug)]
pub struct OfferedPreimages<'a, T>(pub &'a Vec<T>);

#[derive(serde::Serialize, Debug)]
pub struct IssuerKey<'a>(pub &'a Vec<VKCompressed>);

impl<'a, T> PublishingKey<'a, T>
where
    T: serde::Serialize,
{
    pub fn new(preimages: &'a OfferedPreimages<T>, issuer_key: &'a IssuerKey) -> Self {
        Self { preimages, issuer_key }
    }

    pub fn cid(&self) -> CidGeneric<32> {
        let mut hasher = Sha3::v256();
        let mut hash = [0u8; 32];

        const RAW: u64 = 0x55;
        let bytes = serde_json::to_vec(&self).unwrap_or_default();

        hasher.update(&bytes);
        hasher.finalize(&mut hash);

        let mhash = multihash::Multihash::wrap(SHA2_256, &hash).unwrap();
        CidGeneric::new_v1(RAW, mhash)
    }

    pub fn to_string_of_base(
        &self,
        base: multibase::Base,
    ) -> core::result::Result<String, cid::Error> {
        self.cid().to_string_of_base(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_with() {
        let attrs = vec![b"a".to_vec(), "b".as_bytes().to_vec()];
        let entry = vec![attrs.clone()];
        let issuer_key = vec![VKCompressed::G1(vec![1, 2, 3]), VKCompressed::G2(vec![4, 5, 6])];
        let cid = PublishingKey::new(&OfferedPreimages(&entry), &IssuerKey(&issuer_key)).cid();

        assert_eq!(cid.to_string(), "bafkreifqnsshobbrw2wbt4zajhteazbsvu5shd6cju2udfjghde6xyut5q");
    }
}
