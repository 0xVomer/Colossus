use super::{
    AkdLabel, AkdValue, AzksValue, AzksValueWithEpoch, Configuration, DIGEST_BYTES, Digest,
    DomainLabel, NamedConfiguration, NodeLabel, VersionFreshness, i2osp_array,
};
use alloc::vec::Vec;
use core::marker::PhantomData;

#[derive(Clone)]
pub struct ColossusConfiguration<L>(PhantomData<L>);

unsafe impl<L> Send for ColossusConfiguration<L> {}
unsafe impl<L> Sync for ColossusConfiguration<L> {}

impl<L: DomainLabel> ColossusConfiguration<L> {
    fn generate_commitment_from_nonce_client(
        value: &crate::akd::AkdValue,
        nonce: &[u8],
    ) -> AzksValue {
        AzksValue(<Self as Configuration>::hash(
            &[i2osp_array(value), i2osp_array(nonce)].concat(),
        ))
    }
}

impl<L: DomainLabel> Configuration for ColossusConfiguration<L> {
    fn hash(item: &[u8]) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(L::domain_label());
        hasher.update(item);
        hasher.finalize().into()
    }

    fn empty_root_value() -> AzksValue {
        AzksValue([0u8; 32])
    }

    fn empty_node_hash() -> AzksValue {
        AzksValue([0u8; 32])
    }

    fn hash_leaf_with_value(
        value: &crate::akd::AkdValue,
        epoch: u64,
        nonce: &[u8],
    ) -> AzksValueWithEpoch {
        let commitment = Self::generate_commitment_from_nonce_client(value, nonce);
        Self::hash_leaf_with_commitment(commitment, epoch)
    }

    fn hash_leaf_with_commitment(commitment: AzksValue, epoch: u64) -> AzksValueWithEpoch {
        let mut data = [0; DIGEST_BYTES + 8];
        data[..DIGEST_BYTES].copy_from_slice(&commitment.0);
        data[DIGEST_BYTES..].copy_from_slice(&epoch.to_be_bytes());
        AzksValueWithEpoch(Self::hash(&data))
    }

    fn get_commitment_nonce(
        commitment_key: &[u8],
        label: &NodeLabel,
        _version: u64,
        _value: &AkdValue,
    ) -> Digest {
        Self::hash(&[commitment_key, &label.to_bytes()].concat())
    }

    fn compute_fresh_azks_value(
        commitment_key: &[u8],
        label: &NodeLabel,
        version: u64,
        value: &AkdValue,
    ) -> AzksValue {
        let nonce = Self::get_commitment_nonce(commitment_key, label, version, value);
        AzksValue(Self::hash(&[i2osp_array(value), i2osp_array(&nonce)].concat()))
    }

    fn get_hash_from_label_input(
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Vec<u8> {
        let freshness_bytes = [freshness as u8];
        let hashed_label = Self::hash(
            &[
                &crate::akd::utils::i2osp_array(label)[..],
                &freshness_bytes,
                &version.to_be_bytes(),
            ]
            .concat(),
        );
        hashed_label.to_vec()
    }

    fn compute_parent_hash_from_children(
        left_val: &AzksValue,
        left_label: &[u8],
        right_val: &AzksValue,
        right_label: &[u8],
    ) -> AzksValue {
        AzksValue(Self::hash(&[&left_val.0, left_label, &right_val.0, right_label].concat()))
    }

    fn compute_root_hash_from_val(root_val: &AzksValue) -> Digest {
        root_val.0
    }

    fn stale_azks_value() -> AzksValue {
        AzksValue(crate::akd::EMPTY_DIGEST)
    }

    fn compute_node_label_value(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    fn empty_label() -> NodeLabel {
        NodeLabel {
            label_val: [
                1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            ],
            label_len: 0,
        }
    }
}

impl<L: DomainLabel> NamedConfiguration for ColossusConfiguration<L> {
    fn name() -> &'static str {
        "colossus"
    }
}
