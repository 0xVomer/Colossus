mod colossus;

use super::akd::{
    AkdLabel, AkdValue, AzksValue, AzksValueWithEpoch, DIGEST_BYTES, Digest, NodeLabel,
    VersionFreshness, utils::i2osp_array,
};
use alloc::vec::Vec;
pub use colossus::ColossusConfiguration;

pub trait DomainLabel: Clone + 'static {
    fn domain_label() -> &'static [u8];
}

#[derive(Clone)]
pub struct ExampleLabel;

impl DomainLabel for ExampleLabel {
    fn domain_label() -> &'static [u8] {
        "ExampleLabel".as_bytes()
    }
}

pub trait Configuration: Clone + Send + Sync + 'static {
    fn hash(item: &[u8]) -> crate::akd::Digest;

    fn empty_root_value() -> AzksValue;

    fn empty_node_hash() -> AzksValue;

    fn hash_leaf_with_value(
        value: &crate::akd::AkdValue,
        epoch: u64,
        nonce: &[u8],
    ) -> AzksValueWithEpoch;

    fn hash_leaf_with_commitment(commitment: AzksValue, epoch: u64) -> AzksValueWithEpoch;

    fn get_commitment_nonce(
        commitment_key: &[u8],
        label: &NodeLabel,
        version: u64,
        value: &AkdValue,
    ) -> Digest;

    fn compute_fresh_azks_value(
        commitment_key: &[u8],
        label: &NodeLabel,
        version: u64,
        value: &AkdValue,
    ) -> AzksValue;

    fn get_hash_from_label_input(
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Vec<u8>;

    fn compute_parent_hash_from_children(
        left_val: &AzksValue,
        left_label: &[u8],
        right_val: &AzksValue,
        right_label: &[u8],
    ) -> AzksValue;

    fn compute_root_hash_from_val(root_val: &AzksValue) -> Digest;

    fn stale_azks_value() -> AzksValue;

    fn compute_node_label_value(bytes: &[u8]) -> Vec<u8>;

    fn empty_label() -> NodeLabel;
}

pub trait NamedConfiguration: Configuration {
    fn name() -> &'static str;
}
