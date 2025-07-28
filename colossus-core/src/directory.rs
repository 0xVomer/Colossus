use super::{
    akd::{
        AkdLabel, AkdValue, Azks, AzksElement, AzksParallelismConfig, Digest, EpochHash,
        InsertMode, LookupInfo, VersionFreshness,
        ecvrf::VRFPublicKey,
        errors::{AkdError, DirectoryError, StorageError},
        proofs::{AppendOnlyProof, HistoryProof, LookupProof, UpdateProof},
        utils::get_marker_versions,
        verify::HistoryParams,
    },
    configuration::Configuration,
    storage::{
        ecvrf::VRFKeyStorage,
        manager::StorageManager,
        traits::Database,
        types::{DbRecord, ValueState, ValueStateRetrievalFlag},
    },
};
use crate::log::{error, info};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::Instrument;

pub struct Directory<TC, S: Database, V> {
    storage: StorageManager<S>,
    vrf: V,
    parallelism_config: AzksParallelismConfig,

    cache_lock: Arc<RwLock<()>>,
    tc: PhantomData<TC>,
}

impl<TC, S: Database, V: VRFKeyStorage> Clone for Directory<TC, S, V> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            vrf: self.vrf.clone(),
            parallelism_config: self.parallelism_config,
            cache_lock: self.cache_lock.clone(),
            tc: PhantomData,
        }
    }
}

impl<TC, S, V> Directory<TC, S, V>
where
    TC: Configuration,
    S: Database + 'static,
    V: VRFKeyStorage,
{
    #[tracing::instrument(skip_all)]
    pub async fn new(
        storage: StorageManager<S>,
        vrf: V,
        parallelism_config: AzksParallelismConfig,
    ) -> Result<Self, AkdError> {
        let azks = Directory::<TC, S, V>::get_azks_from_storage(&storage, false).await;

        if let Err(AkdError::Storage(StorageError::NotFound(e))) = azks {
            info!("No aZKS was found in storage: {e}. Creating a new aZKS!");

            let new_azks = Azks::new::<TC, _>(&storage).await?;
            storage.set(DbRecord::Azks(new_azks)).await?;
        } else {
            let _res = azks?;
        }

        Ok(Directory {
            storage,
            vrf,
            parallelism_config,
            cache_lock: Arc::new(RwLock::new(())),
            tc: PhantomData,
        })
    }

    #[tracing::instrument(skip_all, fields(num_updates = updates.len()))]
    pub async fn publish(&self, updates: Vec<(AkdLabel, AkdValue)>) -> Result<EpochHash, AkdError> {
        let _guard = self.cache_lock.read().await;

        let distinct_set: HashSet<AkdLabel> =
            updates.iter().map(|(label, _)| label.clone()).collect();
        if distinct_set.len() != updates.len() {
            return Err(AkdError::Directory(DirectoryError::Publish(
                "Cannot publish with a set of entries that contain duplicate labels".to_string(),
            )));
        }

        let mut update_set = Vec::<AzksElement>::new();
        let mut user_data_update_set = Vec::<ValueState>::new();

        let mut current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let next_epoch = current_epoch + 1;

        let mut keys: Vec<AkdLabel> =
            updates.iter().map(|(akd_label, _val)| akd_label.clone()).collect();

        keys.sort();

        let all_user_versions_retrieved = self
            .storage
            .get_user_state_versions(&keys, ValueStateRetrievalFlag::LeqEpoch(current_epoch))
            .await?;

        info!(
            "Retrieved {} previous user versions of {} requested",
            all_user_versions_retrieved.len(),
            keys.len()
        );

        let vrf_computations = updates
            .iter()
            .flat_map(|(akd_label, akd_value)| match all_user_versions_retrieved.get(akd_label) {
                None => vec![(akd_label.clone(), VersionFreshness::Fresh, 1u64, akd_value.clone())],
                Some((latest_version, existing_akd_value)) => {
                    if existing_akd_value == akd_value {
                        return vec![];
                    }
                    vec![
                        (
                            akd_label.clone(),
                            VersionFreshness::Stale,
                            *latest_version,
                            akd_value.clone(),
                        ),
                        (
                            akd_label.clone(),
                            VersionFreshness::Fresh,
                            *latest_version + 1,
                            akd_value.clone(),
                        ),
                    ]
                },
            })
            .collect::<Vec<_>>();

        let vrf_map = self
            .vrf
            .get_node_labels::<TC>(&vrf_computations)
            .await?
            .into_iter()
            .collect::<HashMap<_, _>>();

        let commitment_key = self.derive_commitment_key().await?;

        for ((akd_label, freshness, version, akd_value), node_label) in vrf_map {
            let azks_value = match freshness {
                VersionFreshness::Stale => TC::stale_azks_value(),
                VersionFreshness::Fresh => {
                    TC::compute_fresh_azks_value(&commitment_key, &node_label, version, &akd_value)
                },
            };
            update_set.push(AzksElement { label: node_label, value: azks_value });

            if freshness == VersionFreshness::Fresh {
                let latest_state =
                    ValueState::new(akd_label, akd_value, version, node_label, next_epoch);
                user_data_update_set.push(latest_state);
            }
        }

        if update_set.is_empty() {
            info!(
                "After filtering for duplicated user information, there is no publish which is necessary (0 updates)"
            );

            let root_hash = current_azks.get_root_hash::<TC, _>(&self.storage).await?;
            return Ok(EpochHash(current_epoch, root_hash));
        }

        if !self.storage.begin_transaction() {
            error!("Transaction is already active");
            return Err(AkdError::Storage(StorageError::Transaction(
                "Transaction is already active".to_string(),
            )));
        }
        info!("Starting inserting new leaves");

        if let Err(err) = current_azks
            .batch_insert_nodes::<TC, _>(
                &self.storage,
                update_set,
                InsertMode::Directory,
                self.parallelism_config,
            )
            .await
        {
            let _ = self.storage.rollback_transaction();

            return Err(err);
        }

        let mut updates = vec![DbRecord::Azks(current_azks.clone())];
        for update in user_data_update_set.into_iter() {
            updates.push(DbRecord::ValueState(update));
        }
        self.storage.batch_set(updates).await?;

        info!("Committing transaction");
        match self.storage.commit_transaction().await {
            Ok(num_records) => {
                info!("Transaction committed ({} records)", num_records);
            },
            Err(err) => {
                error!("Failed to commit transaction, rolling back");
                let _ = self.storage.rollback_transaction();
                return Err(AkdError::Storage(err));
            },
        };

        let root_hash = current_azks.get_root_hash_safe::<TC, _>(&self.storage, next_epoch).await?;

        Ok(EpochHash(next_epoch, root_hash))
    }

    #[tracing::instrument(skip_all)]
    pub async fn lookup(&self, akd_label: AkdLabel) -> Result<(LookupProof, EpochHash), AkdError> {
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let lookup_info = self.get_lookup_info(akd_label, current_epoch).await?;

        let root_hash =
            EpochHash(current_epoch, current_azks.get_root_hash::<TC, _>(&self.storage).await?);
        let proof = self.lookup_with_info(&current_azks, lookup_info, false).await?;
        Ok((proof, root_hash))
    }

    #[tracing::instrument(skip_all)]
    async fn lookup_with_info(
        &self,
        current_azks: &Azks,
        lookup_info: LookupInfo,
        skip_preload: bool,
    ) -> Result<LookupProof, AkdError> {
        if !skip_preload {
            current_azks
                .preload_lookup_nodes(&self.storage, &vec![lookup_info.clone()], None)
                .await?;
        }
        let label = &lookup_info.value_state.username;
        let current_version = lookup_info.value_state.version;
        let commitment_key = self.derive_commitment_key().await?;
        let plaintext_value = lookup_info.value_state.value;
        let existence_vrf = self
            .vrf
            .get_label_proof::<TC>(label, VersionFreshness::Fresh, current_version)
            .await?;
        let commitment_label = self.vrf.get_node_label_from_vrf_proof(existence_vrf).await;
        let lookup_proof = LookupProof {
            epoch: lookup_info.value_state.epoch,
            value: plaintext_value.clone(),
            version: lookup_info.value_state.version,
            existence_vrf_proof: existence_vrf.to_bytes().to_vec(),
            existence_proof: current_azks
                .get_membership_proof::<TC, _>(&self.storage, lookup_info.existent_label)
                .await?,
            marker_vrf_proof: self
                .vrf
                .get_label_proof::<TC>(label, VersionFreshness::Fresh, lookup_info.marker_version)
                .await?
                .to_bytes()
                .to_vec(),
            marker_proof: current_azks
                .get_membership_proof::<TC, _>(&self.storage, lookup_info.marker_label)
                .await?,
            freshness_vrf_proof: self
                .vrf
                .get_label_proof::<TC>(label, VersionFreshness::Stale, current_version)
                .await?
                .to_bytes()
                .to_vec(),
            freshness_proof: current_azks
                .get_non_membership_proof::<TC, _>(&self.storage, lookup_info.non_existent_label)
                .await?,
            commitment_nonce: TC::get_commitment_nonce(
                &commitment_key,
                &commitment_label,
                lookup_info.value_state.version,
                &plaintext_value,
            )
            .to_vec(),
        };

        Ok(lookup_proof)
    }

    #[tracing::instrument(skip_all)]
    pub async fn batch_lookup(
        &self,
        akd_labels: &[AkdLabel],
    ) -> Result<(Vec<LookupProof>, EpochHash), AkdError> {
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        let mut lookup_infos = Vec::new();
        for akd_label in akd_labels {
            let lookup_info = self.get_lookup_info(akd_label.clone(), current_epoch).await?;
            lookup_infos.push(lookup_info.clone());
        }

        current_azks.preload_lookup_nodes(&self.storage, &lookup_infos, None).await?;

        assert_eq!(akd_labels.len(), lookup_infos.len());

        let root_hash =
            EpochHash(current_epoch, current_azks.get_root_hash::<TC, _>(&self.storage).await?);

        let mut lookup_proofs = Vec::new();
        for info in lookup_infos.into_iter() {
            lookup_proofs.push(self.lookup_with_info(&current_azks, info, true).await?);
        }

        Ok((lookup_proofs, root_hash))
    }

    #[tracing::instrument(skip_all)]
    async fn build_lookup_info(&self, latest_st: &ValueState) -> Result<LookupInfo, AkdError> {
        let akd_label = &latest_st.username;

        let version = latest_st.version;
        let marker_version = 1 << get_marker_version(version);
        let existent_label = self
            .vrf
            .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, version)
            .await?;
        let marker_label = self
            .vrf
            .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, marker_version)
            .await?;
        let non_existent_label = self
            .vrf
            .get_node_label::<TC>(akd_label, VersionFreshness::Stale, version)
            .await?;
        Ok(LookupInfo {
            value_state: latest_st.clone(),
            marker_version,
            existent_label,
            marker_label,
            non_existent_label,
        })
    }

    #[tracing::instrument(skip_all)]
    async fn get_lookup_info(
        &self,
        akd_label: AkdLabel,
        epoch: u64,
    ) -> Result<LookupInfo, AkdError> {
        match self
            .storage
            .get_user_state(&akd_label, ValueStateRetrievalFlag::LeqEpoch(epoch))
            .await
        {
            Err(_) => match std::str::from_utf8(&akd_label) {
                Ok(name) => Err(AkdError::Storage(StorageError::NotFound(format!(
                    "User {name} at epoch {epoch}"
                )))),
                _ => Err(AkdError::Storage(StorageError::NotFound(format!(
                    "User {akd_label:?} at epoch {epoch}"
                )))),
            },
            Ok(latest_st) => self.build_lookup_info(&latest_st).await,
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn key_history(
        &self,
        akd_label: &AkdLabel,
        params: HistoryParams,
    ) -> Result<(HistoryProof, EpochHash), AkdError> {
        let _guard = self.cache_lock.read().await;
        let _guard =
            self.cache_lock.read().instrument(tracing::info_span!("cache_lock.read")).await;

        let current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let mut user_data = self.storage.get_user_data(akd_label).await?.states;

        user_data.retain(|vs| vs.epoch <= current_epoch);

        user_data.sort_by(|a, b| b.epoch.cmp(&a.epoch));

        user_data = match params {
            HistoryParams::Complete => user_data,
            HistoryParams::MostRecent(n) => user_data.into_iter().take(n).collect::<Vec<_>>(),
        };

        if user_data.is_empty() {
            let msg = if let Ok(username_str) = std::str::from_utf8(akd_label) {
                format!("User {username_str}")
            } else {
                format!("User {akd_label:?}")
            };
            return Err(AkdError::Storage(StorageError::NotFound(msg)));
        }

        let mut start_version = user_data[0].version;
        let mut end_version = user_data[0].version;
        for user_state in &user_data {
            start_version = std::cmp::min(user_state.version, start_version);
            end_version = std::cmp::max(user_state.version, end_version);
        }

        if start_version == 0 || end_version == 0 {
            return Err(AkdError::Directory(DirectoryError::InvalidVersion(
                "Computed start and end versions for the key history should be non-zero"
                    .to_string(),
            )));
        }

        let (past_marker_versions, future_marker_versions) =
            get_marker_versions(start_version, end_version, current_epoch);

        let mut update_proofs = Vec::<UpdateProof>::new();
        for user_state in &user_data {
            let proof = self.create_single_update_proof(akd_label, user_state).await?;
            update_proofs.push(proof);
        }

        let mut past_marker_vrf_proofs = vec![];
        let mut existence_of_past_marker_proofs = vec![];

        for version in past_marker_versions {
            let node_label = self
                .vrf
                .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, version)
                .await?;
            let existence_vrf = self
                .vrf
                .get_label_proof::<TC>(akd_label, VersionFreshness::Fresh, version)
                .await?;
            past_marker_vrf_proofs.push(existence_vrf.to_bytes().to_vec());
            existence_of_past_marker_proofs
                .push(current_azks.get_membership_proof::<TC, _>(&self.storage, node_label).await?);
        }

        let mut future_marker_vrf_proofs = vec![];
        let mut non_existence_of_future_marker_proofs = vec![];

        for version in future_marker_versions {
            let node_label = self
                .vrf
                .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, version)
                .await?;
            non_existence_of_future_marker_proofs.push(
                current_azks
                    .get_non_membership_proof::<TC, _>(&self.storage, node_label)
                    .await?,
            );
            future_marker_vrf_proofs.push(
                self.vrf
                    .get_label_proof::<TC>(akd_label, VersionFreshness::Fresh, version)
                    .await?
                    .to_bytes()
                    .to_vec(),
            );
        }

        let root_hash =
            EpochHash(current_epoch, current_azks.get_root_hash::<TC, _>(&self.storage).await?);

        Ok((
            HistoryProof {
                update_proofs,
                past_marker_vrf_proofs,
                existence_of_past_marker_proofs,
                future_marker_vrf_proofs,
                non_existence_of_future_marker_proofs,
            },
            root_hash,
        ))
    }

    pub async fn poll_for_azks_changes(
        &self,
        period: tokio::time::Duration,
        change_detected: Option<tokio::sync::mpsc::Sender<()>>,
    ) -> Result<(), AkdError> {
        let mut last = Directory::<TC, S, V>::get_azks_from_storage(&self.storage, false).await?;

        loop {
            tokio::time::sleep(period).await;

            let latest = Directory::<TC, S, V>::get_azks_from_storage(&self.storage, true).await?;
            if latest.latest_epoch > last.latest_epoch {
                {
                    let _guard = self.cache_lock.write().await;
                    let _guard = self
                        .cache_lock
                        .write()
                        .instrument(tracing::info_span!("cache_lock.write"))
                        .await;

                    self.storage.flush_cache().await;
                    self.storage.flush_cache().instrument(tracing::info_span!("flush_cache")).await;

                    last =
                        Directory::<TC, S, V>::get_azks_from_storage(&self.storage, false).await?;

                    if let Some(channel) = &change_detected {
                        channel.send(()).await.map_err(|send_err| {
                            AkdError::Storage(StorageError::Connection(format!(
                                "Tokio MPSC sender failed to publish notification with error {send_err:?}"
                            )))
                        })?;
                    }
                }
            }
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(start_epoch = audit_start_ep, end_epoch = audit_end_ep))]
    pub async fn audit(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
    ) -> Result<AppendOnlyProof, AkdError> {
        let _guard = self.cache_lock.read().await;
        let _guard =
            self.cache_lock.read().instrument(tracing::info_span!("cache_lock.read")).await;

        let current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        if audit_start_ep >= audit_end_ep {
            Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "Start epoch {audit_start_ep} is greater than or equal the end epoch {audit_end_ep}"
            ))))
        } else if current_epoch < audit_end_ep {
            Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "End epoch {audit_end_ep} is greater than the current epoch {current_epoch}"
            ))))
        } else {
            self.storage.disable_cache_cleaning();
            let result = current_azks
                .get_append_only_proof::<TC, _>(
                    &self.storage,
                    audit_start_ep,
                    audit_end_ep,
                    self.parallelism_config,
                )
                .await;
            self.storage.enable_cache_cleaning();
            result
        }
    }

    #[tracing::instrument(skip_all)]
    pub(crate) async fn retrieve_azks(&self) -> Result<Azks, crate::akd::errors::AkdError> {
        Directory::<TC, S, V>::get_azks_from_storage(&self.storage, false).await
    }

    #[tracing::instrument(skip_all, fields(ignore_cache = ignore_cache))]
    async fn get_azks_from_storage(
        storage: &StorageManager<S>,
        ignore_cache: bool,
    ) -> Result<Azks, crate::akd::errors::AkdError> {
        let got = if ignore_cache {
            storage.get_direct::<Azks>(&crate::akd::DEFAULT_AZKS_KEY).await?
        } else {
            storage.get::<Azks>(&crate::akd::DEFAULT_AZKS_KEY).await?
        };
        match got {
            DbRecord::Azks(azks) => Ok(azks),
            _ => {
                error!(
                    "No AZKS can be found. You should re-initialize the directory to create a new one"
                );
                Err(AkdError::Storage(StorageError::NotFound("AZKS not found".to_string())))
            },
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn get_public_key(&self) -> Result<VRFPublicKey, AkdError> {
        Ok(self.vrf.get_vrf_public_key().await?)
    }

    #[tracing::instrument(skip_all)]
    async fn create_single_update_proof(
        &self,
        akd_label: &AkdLabel,
        user_state: &ValueState,
    ) -> Result<UpdateProof, AkdError> {
        let epoch = user_state.epoch;
        let value = &user_state.value;
        let version = user_state.version;

        let label_at_ep = self
            .vrf
            .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, version)
            .await?;

        let current_azks = self.retrieve_azks().await?;
        let existence_vrf = self
            .vrf
            .get_label_proof::<TC>(akd_label, VersionFreshness::Fresh, version)
            .await?;
        let existence_vrf_proof = existence_vrf.to_bytes().to_vec();
        let existence_label = self.vrf.get_node_label_from_vrf_proof(existence_vrf).await;
        let existence_proof =
            current_azks.get_membership_proof::<TC, _>(&self.storage, label_at_ep).await?;
        let mut previous_version_proof = Option::None;
        let mut previous_version_vrf_proof = Option::None;
        if version > 1 {
            let prev_label_at_ep = self
                .vrf
                .get_node_label::<TC>(akd_label, VersionFreshness::Stale, version - 1)
                .await?;
            previous_version_proof = Option::Some(
                current_azks
                    .get_membership_proof::<TC, _>(&self.storage, prev_label_at_ep)
                    .await?,
            );
            previous_version_vrf_proof = Option::Some(
                self.vrf
                    .get_label_proof::<TC>(akd_label, VersionFreshness::Stale, version - 1)
                    .await?
                    .to_bytes()
                    .to_vec(),
            );
        }

        let commitment_key = self.derive_commitment_key().await?;
        let commitment_nonce =
            TC::get_commitment_nonce(&commitment_key, &existence_label, version, value).to_vec();

        Ok(UpdateProof {
            epoch,
            version,
            value: value.clone(),
            existence_vrf_proof,
            existence_proof,
            previous_version_vrf_proof,
            previous_version_proof,
            commitment_nonce,
        })
    }

    #[tracing::instrument(skip_all)]
    pub async fn get_epoch_hash(&self) -> Result<EpochHash, AkdError> {
        let current_azks = self.retrieve_azks().await?;
        let latest_epoch = current_azks.get_latest_epoch();
        let root_hash = current_azks.get_root_hash::<TC, _>(&self.storage).await?;
        Ok(EpochHash(latest_epoch, root_hash))
    }

    async fn derive_commitment_key(&self) -> Result<Digest, AkdError> {
        let raw_key = self.vrf.retrieve().await?;
        let commitment_key = TC::hash(&raw_key);
        Ok(commitment_key)
    }
}

#[derive(Clone)]
pub struct ReadOnlyDirectory<TC, S, V>(Directory<TC, S, V>)
where
    TC: Configuration,
    S: Database + Sync + Send,
    V: VRFKeyStorage;

impl<TC, S, V> ReadOnlyDirectory<TC, S, V>
where
    TC: Configuration,
    S: Database + 'static,
    V: VRFKeyStorage,
{
    pub async fn new(
        storage: StorageManager<S>,
        vrf: V,
        parallelism_config: AzksParallelismConfig,
    ) -> Result<Self, AkdError> {
        let azks = Directory::<TC, S, V>::get_azks_from_storage(&storage, false).await;

        if azks.is_err() {
            return Err(AkdError::Directory(DirectoryError::ReadOnlyDirectory(format!(
                "Cannot start directory in read-only mode when AZKS is missing, error: {:?}",
                azks.err()
            ))));
        }

        Ok(Self(Directory {
            storage,
            vrf,
            parallelism_config,
            cache_lock: Arc::new(RwLock::new(())),
            tc: PhantomData,
        }))
    }

    #[tracing::instrument(skip_all)]
    pub async fn lookup(&self, uname: AkdLabel) -> Result<(LookupProof, EpochHash), AkdError> {
        self.0.lookup(uname).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn batch_lookup(
        &self,
        unames: &[AkdLabel],
    ) -> Result<(Vec<LookupProof>, EpochHash), AkdError> {
        self.0.batch_lookup(unames).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn key_history(
        &self,
        uname: &AkdLabel,
        params: HistoryParams,
    ) -> Result<(HistoryProof, EpochHash), AkdError> {
        self.0.key_history(uname, params).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn poll_for_azks_changes(
        &self,
        period: tokio::time::Duration,
        change_detected: Option<tokio::sync::mpsc::Sender<()>>,
    ) -> Result<(), AkdError> {
        self.0.poll_for_azks_changes(period, change_detected).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn audit(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
    ) -> Result<AppendOnlyProof, AkdError> {
        self.0.audit(audit_start_ep, audit_end_ep).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn get_epoch_hash(&self) -> Result<EpochHash, AkdError> {
        self.0.get_epoch_hash().await
    }

    #[tracing::instrument(skip_all)]
    pub async fn get_public_key(&self) -> Result<VRFPublicKey, AkdError> {
        self.0.get_public_key().await
    }
}

pub(crate) fn get_marker_version(version: u64) -> u64 {
    (64 - version.leading_zeros() - 1).into()
}

#[derive(Debug, Clone)]
pub enum PublishCorruption {
    UnmarkedStaleVersion(AkdLabel),

    MarkVersionStale(AkdLabel, u64),
}

#[cfg(test)]
impl<TC: Configuration, S: Database + 'static, V: VRFKeyStorage> Directory<TC, S, V> {
    pub(crate) async fn publish_malicious_update(
        &self,
        updates: Vec<(AkdLabel, AkdValue)>,
        corruption: PublishCorruption,
    ) -> Result<EpochHash, AkdError> {
        let _guard = self.cache_lock.read().await;

        let mut update_set = Vec::<AzksElement>::new();

        if let PublishCorruption::MarkVersionStale(ref akd_label, version_number) = corruption {
            let stale_label = self
                .vrf
                .get_node_label::<TC>(akd_label, VersionFreshness::Stale, version_number)
                .await?;
            let stale_value_to_add = TC::stale_azks_value();
            update_set.push(AzksElement {
                label: stale_label,
                value: stale_value_to_add,
            })
        };

        let mut user_data_update_set = Vec::<ValueState>::new();

        let mut current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let next_epoch = current_epoch + 1;

        let mut keys: Vec<AkdLabel> =
            updates.iter().map(|(akd_label, _val)| akd_label.clone()).collect();

        keys.sort();

        let all_user_versions_retrieved = self
            .storage
            .get_user_state_versions(&keys, ValueStateRetrievalFlag::LeqEpoch(current_epoch))
            .await?;

        info!(
            "Retrieved {} previous user versions of {} requested",
            all_user_versions_retrieved.len(),
            keys.len()
        );

        let commitment_key = self.derive_commitment_key().await?;

        for (akd_label, val) in updates {
            match all_user_versions_retrieved.get(&akd_label) {
                None => {
                    let latest_version = 1;
                    let label = self
                        .vrf
                        .get_node_label::<TC>(&akd_label, VersionFreshness::Fresh, latest_version)
                        .await?;

                    let value_to_add =
                        TC::compute_fresh_azks_value(&commitment_key, &label, latest_version, &val);
                    update_set.push(AzksElement { label, value: value_to_add });
                    let latest_state =
                        ValueState::new(akd_label, val, latest_version, label, next_epoch);
                    user_data_update_set.push(latest_state);
                },
                Some((_, previous_value)) if val == *previous_value => {},
                Some((previous_version, _)) => {
                    let latest_version = *previous_version + 1;
                    let stale_label = self
                        .vrf
                        .get_node_label::<TC>(
                            &akd_label,
                            VersionFreshness::Stale,
                            *previous_version,
                        )
                        .await?;
                    let fresh_label = self
                        .vrf
                        .get_node_label::<TC>(&akd_label, VersionFreshness::Fresh, latest_version)
                        .await?;
                    let stale_value_to_add = TC::stale_azks_value();
                    let fresh_value_to_add = TC::compute_fresh_azks_value(
                        &commitment_key,
                        &fresh_label,
                        latest_version,
                        &val,
                    );
                    match &corruption {
                        PublishCorruption::UnmarkedStaleVersion(target_akd_label) => {
                            if *target_akd_label != akd_label {
                                update_set.push(AzksElement {
                                    label: stale_label,
                                    value: stale_value_to_add,
                                })
                            }
                        },
                        _ => update_set.push(AzksElement {
                            label: stale_label,
                            value: stale_value_to_add,
                        }),
                    };

                    update_set.push(AzksElement {
                        label: fresh_label,
                        value: fresh_value_to_add,
                    });
                    let new_state =
                        ValueState::new(akd_label, val, latest_version, fresh_label, next_epoch);
                    user_data_update_set.push(new_state);
                },
            }
        }
        let azks_element_set: Vec<AzksElement> = update_set.to_vec();

        if azks_element_set.is_empty() {
            info!(
                "After filtering for duplicated user information, there is no publish which is necessary (0 updates)"
            );

            let root_hash = current_azks.get_root_hash::<TC, _>(&self.storage).await?;
            return Ok(EpochHash(current_epoch, root_hash));
        }

        if !self.storage.begin_transaction() {
            error!("Transaction is already active");
            return Err(AkdError::Storage(StorageError::Transaction(
                "Transaction is already active".to_string(),
            )));
        }
        info!("Starting database insertion");

        current_azks
            .batch_insert_nodes::<TC, _>(
                &self.storage,
                azks_element_set,
                InsertMode::Directory,
                self.parallelism_config,
            )
            .await?;

        let mut updates = vec![DbRecord::Azks(current_azks.clone())];
        for update in user_data_update_set.into_iter() {
            updates.push(DbRecord::ValueState(update));
        }
        self.storage.batch_set(updates).await?;

        if let Err(err) = self.storage.commit_transaction().await {
            let _ = self.storage.rollback_transaction();
            return Err(AkdError::Storage(err));
        }

        let root_hash = current_azks.get_root_hash_safe::<TC, _>(&self.storage, next_epoch).await?;

        Ok(EpochHash(next_epoch, root_hash))
    }
}
