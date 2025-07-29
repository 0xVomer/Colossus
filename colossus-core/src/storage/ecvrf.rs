use crate::{
    Configuration,
    akd::{
        AkdLabel, AkdValue, NodeLabel, VersionFreshness,
        ecvrf::{Output, Proof, VRFExpandedPrivateKey, VRFPrivateKey, VRFPublicKey},
        errors::VrfError,
    },
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::convert::TryInto;

#[async_trait]
pub trait VRFKeyStorage: Clone + Sync + Send {
    /* ======= To be implemented ====== */

    async fn retrieve(&self) -> Result<Vec<u8>, VrfError>;

    /* ======= Common trait functionality ====== */

    async fn get_vrf_private_key(&self) -> Result<VRFPrivateKey, VrfError> {
        match self.retrieve().await {
            Ok(bytes) => {
                let pk_ref: &[u8] = &bytes;
                pk_ref.try_into()
            },
            Err(other) => Err(other),
        }
    }

    async fn get_vrf_public_key(&self) -> Result<VRFPublicKey, VrfError> {
        self.get_vrf_private_key().await.map(|key| (&key).into())
    }

    async fn get_node_label<TC: Configuration>(
        &self,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Result<NodeLabel, VrfError> {
        let key = self.get_vrf_private_key().await?;
        let expanded_key = VRFExpandedPrivateKey::from(&key);
        let pk = VRFPublicKey::from(&key);
        Ok(Self::get_node_label_with_expanded_key::<TC>(
            &expanded_key,
            &pk,
            label,
            freshness,
            version,
        ))
    }

    fn get_node_label_with_expanded_key<TC: Configuration>(
        expanded_private_key: &VRFExpandedPrivateKey,
        pk: &VRFPublicKey,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> NodeLabel {
        let output = Self::get_label_with_key_helper::<TC>(
            expanded_private_key,
            pk,
            label,
            freshness,
            version,
        );
        NodeLabel::new(output.to_truncated_bytes(), 256)
    }

    async fn get_node_label_from_vrf_proof(&self, proof: Proof) -> NodeLabel {
        let output: Output = (&proof).into();
        NodeLabel::new(output.to_truncated_bytes(), 256)
    }

    async fn get_label_proof<TC: Configuration>(
        &self,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Result<Proof, VrfError> {
        let key = self.get_vrf_private_key().await?;
        Ok(Self::get_label_proof_with_key::<TC>(&key, label, freshness, version))
    }

    fn get_label_proof_with_key<TC: Configuration>(
        key: &VRFPrivateKey,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Proof {
        let hashed_label = TC::get_hash_from_label_input(label, freshness, version);
        key.prove(&hashed_label)
    }

    fn get_label_with_key_helper<TC: Configuration>(
        expanded_private_key: &VRFExpandedPrivateKey,
        pk: &VRFPublicKey,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Output {
        let hashed_label = TC::get_hash_from_label_input(label, freshness, version);
        expanded_private_key.evaluate(pk, &hashed_label)
    }

    async fn get_node_labels<TC: Configuration>(
        &self,
        labels: &[(AkdLabel, VersionFreshness, u64, AkdValue)],
    ) -> Result<Vec<((AkdLabel, VersionFreshness, u64, AkdValue), NodeLabel)>, VrfError> {
        let key = self.get_vrf_private_key().await?;
        let expanded_key = VRFExpandedPrivateKey::from(&key);
        let pk = VRFPublicKey::from(&key);

        let mut results = Vec::new();
        for (label, freshness, version, value) in labels {
            let node_label = Self::get_node_label_with_expanded_key::<TC>(
                &expanded_key,
                &pk,
                label,
                *freshness,
                *version,
            );
            results.push(((label.clone(), *freshness, *version, value.clone()), node_label));
        }
        Ok(results)
    }
}
