use crate::akd::{AkdLabel, AkdValue, errors::StorageError};
use crate::log::debug;
use crate::log::info;
use crate::storage::cache::TimedCache;
use crate::storage::traits::Database;
use crate::storage::traits::DbSetState;
use crate::storage::traits::Storable;
use crate::storage::transaction::Transaction;
use crate::storage::types::DbRecord;
use crate::storage::types::KeyData;
use crate::storage::types::ValueState;

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::types::ValueStateRetrievalFlag;

type Metric = usize;

const METRIC_GET: Metric = 0;
const METRIC_BATCH_GET: Metric = 1;
const METRIC_SET: Metric = 2;
const METRIC_BATCH_SET: Metric = 3;
const METRIC_READ_TIME: Metric = 4;
const METRIC_WRITE_TIME: Metric = 5;
const METRIC_TOMBSTONE: Metric = 6;
const METRIC_GET_USER_STATE: Metric = 7;
const METRIC_GET_USER_DATA: Metric = 8;
const METRIC_GET_USER_STATE_VERSIONS: Metric = 9;

const NUM_METRICS: usize = 10;

#[cfg(test)]
mod tests;

pub struct StorageManager<Db: Database> {
    cache: Option<TimedCache>,
    transaction: Transaction,

    db: Arc<Db>,
    metrics: [Arc<AtomicU64>; NUM_METRICS],
}

impl<Db: Database> Clone for StorageManager<Db> {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
            transaction: self.transaction.clone(),
            db: self.db.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

unsafe impl<Db: Database> Sync for StorageManager<Db> {}
unsafe impl<Db: Database> Send for StorageManager<Db> {}

impl<Db: Database> StorageManager<Db> {
    pub fn new_no_cache(db: Db) -> Self {
        Self {
            cache: None,
            transaction: Transaction::new(),
            db: Arc::new(db),
            metrics: [0; NUM_METRICS].map(|_| Arc::new(AtomicU64::new(0))),
        }
    }

    pub fn new(
        db: Db,
        cache_item_lifetime: Option<Duration>,
        cache_limit_bytes: Option<usize>,
        cache_clean_frequency: Option<Duration>,
    ) -> Self {
        Self {
            cache: Some(TimedCache::new(
                cache_item_lifetime,
                cache_limit_bytes,
                cache_clean_frequency,
            )),
            transaction: Transaction::new(),
            db: Arc::new(db),
            metrics: [0; NUM_METRICS].map(|_| Arc::new(AtomicU64::new(0))),
        }
    }

    pub fn get_db(&self) -> Arc<Db> {
        self.db.clone()
    }

    pub fn has_cache(&self) -> bool {
        self.cache.is_some()
    }

    pub async fn log_metrics(&self) {
        if let Some(cache) = &self.cache {
            cache.log_metrics()
        }

        self.transaction.log_metrics();

        let snapshot = self
            .metrics
            .iter()
            .map(|metric| metric.swap(0, Ordering::Relaxed))
            .collect::<Vec<_>>();

        let msg = format!(
            "
===================================================
============ Database operation counts ============
===================================================
    SET {},
    BATCH SET {},
    GET {},
    BATCH GET {}
    TOMBSTONE {}
    GET USER STATE {}
    GET USER DATA {}
    GET USER STATE VERSIONS {}
===================================================
============ Database operation timing ============
===================================================
    TIME READ {} ms
    TIME WRITE {} ms",
            snapshot[METRIC_SET],
            snapshot[METRIC_BATCH_SET],
            snapshot[METRIC_GET],
            snapshot[METRIC_BATCH_GET],
            snapshot[METRIC_TOMBSTONE],
            snapshot[METRIC_GET_USER_STATE],
            snapshot[METRIC_GET_USER_DATA],
            snapshot[METRIC_GET_USER_STATE_VERSIONS],
            snapshot[METRIC_READ_TIME],
            snapshot[METRIC_WRITE_TIME]
        );

        info!("{msg}");
    }

    pub fn begin_transaction(&self) -> bool {
        let started = self.transaction.begin_transaction();

        if let Some(cache) = &self.cache {
            cache.disable_clean();
        }

        started
    }

    pub async fn commit_transaction(&self) -> Result<u64, StorageError> {
        let records = self.transaction.commit_transaction()?;
        let num_records = records.len();

        if let Some(cache) = &self.cache {
            cache.enable_clean();
        }

        if records.is_empty() {
            return Ok(0);
        }

        let _epoch = match records.last() {
            Some(DbRecord::Azks(azks)) => Ok(azks.latest_epoch),
            other => Err(StorageError::Transaction(format!(
                "The last record in the transaction log is NOT an Azks record {other:?}"
            ))),
        }?;

        if let Some(cache) = &self.cache {
            cache.batch_put(&records).await;
        }

        self.tic_toc(METRIC_WRITE_TIME, self.db.batch_set(records, DbSetState::TransactionCommit))
            .await?;
        self.increment_metric(METRIC_BATCH_SET);
        Ok(num_records as u64)
    }

    pub fn rollback_transaction(&self) -> Result<(), StorageError> {
        self.transaction.rollback_transaction()?;

        if let Some(cache) = &self.cache {
            cache.enable_clean();
        }
        Ok(())
    }

    pub fn is_transaction_active(&self) -> bool {
        self.transaction.is_transaction_active()
    }

    pub fn disable_cache_cleaning(&self) {
        if let Some(cache) = &self.cache {
            cache.disable_clean();
        }
    }

    pub fn enable_cache_cleaning(&self) {
        if let Some(cache) = &self.cache {
            cache.enable_clean();
        }
    }

    pub async fn set(&self, record: DbRecord) -> Result<(), StorageError> {
        if self.is_transaction_active() {
            self.transaction.set(&record);
            return Ok(());
        }

        if let Some(cache) = &self.cache {
            cache.put(&record).await;
        }

        self.tic_toc(METRIC_WRITE_TIME, self.db.set(record)).await?;
        self.increment_metric(METRIC_SET);
        Ok(())
    }

    pub async fn batch_set(&self, records: Vec<DbRecord>) -> Result<(), StorageError> {
        if records.is_empty() {
            return Ok(());
        }

        if self.is_transaction_active() {
            self.transaction.batch_set(&records);
            return Ok(());
        }

        if let Some(cache) = &self.cache {
            cache.batch_put(&records).await;
        }

        self.tic_toc(METRIC_WRITE_TIME, self.db.batch_set(records, DbSetState::General))
            .await?;
        self.increment_metric(METRIC_BATCH_SET);
        Ok(())
    }

    pub async fn get_direct<St: Storable>(
        &self,
        id: &St::StorageKey,
    ) -> Result<DbRecord, StorageError> {
        let record = self.tic_toc(METRIC_READ_TIME, self.db.get::<St>(id)).await?;
        self.increment_metric(METRIC_GET);
        Ok(record)
    }

    pub async fn get_from_cache_only<St: Storable>(&self, id: &St::StorageKey) -> Option<DbRecord> {
        if self.is_transaction_active() {
            if let Some(result) = self.transaction.get::<St>(id) {
                return Some(result);
            }
        }

        if let Some(cache) = &self.cache {
            if let Some(result) = cache.hit_test::<St>(id).await {
                return Some(result);
            }
        }

        None
    }

    pub async fn get<St: Storable>(&self, id: &St::StorageKey) -> Result<DbRecord, StorageError> {
        if let Some(result) = self.get_from_cache_only::<St>(id).await {
            return Ok(result);
        }

        self.increment_metric(METRIC_GET);

        let record = self.tic_toc(METRIC_READ_TIME, self.db.get::<St>(id)).await?;
        if let Some(cache) = &self.cache {
            cache.put(&record).await;
        }
        Ok(record)
    }

    pub async fn batch_get<St: Storable>(
        &self,
        ids: &[St::StorageKey],
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut records = Vec::new();

        if ids.is_empty() {
            return Ok(records);
        }

        let mut key_set: HashSet<St::StorageKey> = ids.iter().cloned().collect();

        let trans_active = self.is_transaction_active();

        for id in ids.iter() {
            if trans_active {
                if let Some(result) = self.transaction.get::<St>(id) {
                    records.push(result);
                    key_set.remove(id);
                    continue;
                }
            }

            if let Some(cache) = &self.cache {
                if let Some(result) = cache.hit_test::<St>(id).await {
                    records.push(result);
                    key_set.remove(id);
                    continue;
                }
            }
        }

        if !key_set.is_empty() {
            let keys = key_set.into_iter().collect::<Vec<_>>();
            let mut results =
                self.tic_toc(METRIC_READ_TIME, self.db.batch_get::<St>(&keys)).await?;

            if let Some(cache) = &self.cache {
                cache.batch_put(&results).await;
            }

            records.append(&mut results);
            self.increment_metric(METRIC_BATCH_GET);
        }
        Ok(records)
    }

    pub async fn flush_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.flush().await;
        }
    }

    pub async fn tombstone_value_states(
        &self,
        username: &AkdLabel,
        epoch: u64,
    ) -> Result<(), StorageError> {
        let key_data = self.get_user_data(username).await?;
        let mut new_data = vec![];
        for value_state in key_data.states.into_iter() {
            if value_state.epoch <= epoch && value_state.value.0 != crate::akd::TOMBSTONE {
                new_data.push(DbRecord::ValueState(ValueState {
                    epoch: value_state.epoch,
                    label: value_state.label,
                    value: crate::akd::AkdValue(crate::akd::TOMBSTONE.to_vec()),
                    username: value_state.username,
                    version: value_state.version,
                }));
            }
        }
        if !new_data.is_empty() {
            debug!("Tombstoning {} entries", new_data.len());
            self.batch_set(new_data).await?;
            self.increment_metric(METRIC_TOMBSTONE);
        }

        Ok(())
    }

    pub async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> Result<ValueState, StorageError> {
        let maybe_db_state =
            match self.tic_toc(METRIC_READ_TIME, self.db.get_user_state(username, flag)).await {
                Err(StorageError::NotFound(_)) => Ok(None),
                Ok(something) => Ok(Some(something)),
                Err(other) => Err(other),
            }?;
        self.increment_metric(METRIC_GET_USER_STATE);

        if self.is_transaction_active() {
            if let Some(transaction_value) = self.transaction.get_user_state(username, flag) {
                if let Some(db_value) = &maybe_db_state {
                    if let Some(record) = Self::compare_db_and_transaction_records(
                        db_value.epoch,
                        transaction_value,
                        flag,
                    ) {
                        return Ok(record);
                    }
                } else {
                    return Ok(transaction_value);
                }
            }
        }

        if let Some(state) = maybe_db_state {
            if let Some(cache) = &self.cache {
                cache.put(&DbRecord::ValueState(state.clone())).await;
            }

            Ok(state)
        } else {
            Err(StorageError::NotFound(format!("ValueState {username:?}")))
        }
    }

    pub async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError> {
        let maybe_db_data =
            match self.tic_toc(METRIC_READ_TIME, self.db.get_user_data(username)).await {
                Err(StorageError::NotFound(_)) => Ok(None),
                Ok(something) => Ok(Some(something)),
                Err(other) => Err(other),
            }?;
        self.increment_metric(METRIC_GET_USER_DATA);

        if self.is_transaction_active() {
            let mut map = maybe_db_data
                .map(|data| {
                    data.states
                        .into_iter()
                        .map(|state| (state.epoch, state))
                        .collect::<HashMap<u64, _>>()
                })
                .unwrap_or_else(HashMap::new);

            let transaction_records = self
                .transaction
                .get_users_data(&[username.clone()])
                .remove(username)
                .unwrap_or_default();
            for transaction_record in transaction_records.into_iter() {
                map.insert(transaction_record.epoch, transaction_record);
            }

            return Ok(KeyData {
                states: map.into_values().collect::<Vec<_>>(),
            });
        }

        if let Some(data) = maybe_db_data {
            Ok(data)
        } else {
            Err(StorageError::NotFound(format!("ValueState records for {username:?}")))
        }
    }

    pub async fn get_user_state_versions(
        &self,
        usernames: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError> {
        let mut data = self
            .tic_toc(METRIC_READ_TIME, self.db.get_user_state_versions(usernames, flag))
            .await?;
        self.increment_metric(METRIC_GET_USER_STATE_VERSIONS);

        if self.is_transaction_active() {
            let transaction_records = self.transaction.get_users_states(usernames, flag);
            for (label, value_state) in transaction_records.into_iter() {
                if let Some((epoch, _)) = data.get(&label) {
                    if let Some(updated_record) =
                        Self::compare_db_and_transaction_records(*epoch, value_state, flag)
                    {
                        data.insert(label, (*epoch, updated_record.value));
                    }
                } else {
                    data.insert(label, (value_state.epoch, value_state.value));
                }
            }
        }

        Ok(data)
    }

    fn compare_db_and_transaction_records(
        state_epoch: u64,
        transaction_value: ValueState,
        flag: ValueStateRetrievalFlag,
    ) -> Option<ValueState> {
        match flag {
            ValueStateRetrievalFlag::SpecificVersion(_) => {
                return Some(transaction_value);
            },
            ValueStateRetrievalFlag::SpecificEpoch(_) => {
                return Some(transaction_value);
            },
            ValueStateRetrievalFlag::LeqEpoch(_) => {
                if transaction_value.epoch >= state_epoch {
                    return Some(transaction_value);
                }
            },
            ValueStateRetrievalFlag::MaxEpoch => {
                if transaction_value.epoch >= state_epoch {
                    return Some(transaction_value);
                }
            },
            ValueStateRetrievalFlag::MinEpoch => {
                if transaction_value.epoch <= state_epoch {
                    return Some(transaction_value);
                }
            },
        }
        None
    }

    fn increment_metric(&self, _metric: Metric) {
        self.metrics[_metric].fetch_add(1, Ordering::Relaxed);
    }

    async fn tic_toc<T>(&self, _metric: Metric, f: impl std::future::Future<Output = T>) -> T {
        let tic = std::time::Instant::now();
        let out = f.await;
        let delta = std::time::Instant::now().duration_since(tic);

        self.metrics[_metric].fetch_add(delta.as_millis() as u64, Ordering::Relaxed);

        out
    }
}
