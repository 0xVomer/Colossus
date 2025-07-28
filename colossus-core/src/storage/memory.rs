use super::{
    traits::{Database, Storable, StorageUtil},
    types::{DbRecord, KeyData, StorageType, ValueState, ValueStateKey, ValueStateRetrievalFlag},
};
use crate::akd::{AkdLabel, AkdValue, errors::StorageError};
use async_trait::async_trait;
use dashmap::DashMap;
use std::{collections::HashMap, sync::Arc};

type Epoch = u64;
type UserValueMap = HashMap<Epoch, ValueState>;

#[derive(Default, Clone, Debug)]
pub struct AsyncInMemoryDatabase {
    db: Arc<DashMap<Vec<u8>, DbRecord>>,
    user_info: Arc<DashMap<Vec<u8>, UserValueMap>>,
}

unsafe impl Send for AsyncInMemoryDatabase {}
unsafe impl Sync for AsyncInMemoryDatabase {}

impl AsyncInMemoryDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub fn clear(&self) {
        self.db.clear();
        self.user_info.clear();
    }

    async fn get_internal<St: Storable>(
        &self,
        id: &St::StorageKey,
    ) -> Result<DbRecord, StorageError> {
        let bin_id = St::get_full_binary_key_id(id);

        if St::data_type() == StorageType::ValueState {
            if let Ok(ValueStateKey(username, epoch)) = ValueState::key_from_full_binary(&bin_id) {
                if let Some(state) = self.user_info.get(&username) {
                    if let Some(found) = state.get(&epoch) {
                        return Ok(DbRecord::ValueState(found.clone()));
                    }
                }
                return Err(StorageError::NotFound(format!("ValueState {id:?}")));
            }
        }

        if let Some(result) = self.db.get(&bin_id) {
            Ok(result.clone())
        } else {
            Err(StorageError::NotFound(format!("{:?} {:?}", St::data_type(), id)))
        }
    }
}

#[async_trait]
impl Database for AsyncInMemoryDatabase {
    async fn set(&self, record: DbRecord) -> Result<(), StorageError> {
        self.batch_set(vec![record], crate::storage::traits::DbSetState::General).await
    }

    async fn batch_set(
        &self,
        records: Vec<DbRecord>,
        _state: crate::storage::traits::DbSetState,
    ) -> Result<(), StorageError> {
        for record in records.into_iter() {
            if let DbRecord::ValueState(value_state) = record {
                let username = value_state.username.to_vec();
                match self.user_info.get_mut(&username) {
                    Some(mut states) => {
                        states.insert(value_state.epoch, value_state);
                    },
                    None => {
                        let mut new_map = HashMap::new();
                        new_map.insert(value_state.epoch, value_state);
                        self.user_info.insert(username, new_map);
                    },
                }
            } else {
                self.db.insert(record.get_full_binary_id(), record);
            }
        }
        Ok(())
    }

    async fn get<St: Storable>(&self, id: &St::StorageKey) -> Result<DbRecord, StorageError> {
        self.get_internal::<St>(id).await
    }

    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::StorageKey],
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut records = Vec::new();
        for key in ids.iter() {
            if let Ok(result) = self.get_internal::<St>(key).await {
                records.push(result);
            }
        }
        Ok(records)
    }

    async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError> {
        if let Some(result) = self.user_info.get(&username.0) {
            let mut results: Vec<ValueState> = result.values().cloned().collect::<Vec<_>>();

            results.sort_by(|a, b| a.epoch.cmp(&b.epoch));

            Ok(KeyData { states: results })
        } else {
            Err(StorageError::NotFound(format!("ValueState {username:?}")))
        }
    }

    async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> Result<ValueState, StorageError> {
        let intermediate = self.get_user_data(username).await?.states;
        match flag {
            ValueStateRetrievalFlag::MaxEpoch => {
                if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
                    return Ok(value.clone());
                }
            },
            ValueStateRetrievalFlag::MinEpoch => {
                if let Some(value) = intermediate.iter().min_by(|a, b| a.epoch.cmp(&b.epoch)) {
                    return Ok(value.clone());
                }
            },
            _ => {
                let mut tracked_epoch = 0u64;
                let mut tracker = None;
                for kvp in intermediate.iter() {
                    match flag {
                        ValueStateRetrievalFlag::SpecificVersion(version)
                            if version == kvp.version =>
                        {
                            return Ok(kvp.clone());
                        },
                        ValueStateRetrievalFlag::LeqEpoch(epoch) if epoch == kvp.epoch => {
                            return Ok(kvp.clone());
                        },
                        ValueStateRetrievalFlag::LeqEpoch(epoch) if kvp.epoch < epoch => {
                            match tracked_epoch {
                                0u64 => {
                                    tracked_epoch = kvp.epoch;
                                    tracker = Some(kvp.clone());
                                },
                                other_epoch => {
                                    if kvp.epoch > other_epoch {
                                        tracker = Some(kvp.clone());
                                        tracked_epoch = kvp.epoch;
                                    }
                                },
                            }
                        },
                        ValueStateRetrievalFlag::SpecificEpoch(epoch) if epoch == kvp.epoch => {
                            return Ok(kvp.clone());
                        },
                        _ => continue,
                    }
                }

                if let Some(r) = tracker {
                    return Ok(r);
                }
            },
        }
        Err(StorageError::NotFound(format!("ValueState {username:?}")))
    }

    async fn get_user_state_versions(
        &self,
        keys: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError> {
        let mut map = HashMap::new();
        for username in keys.iter() {
            if let Ok(result) = self.get_user_state(username, flag).await {
                map.insert(
                    AkdLabel(result.username.to_vec()),
                    (result.version, AkdValue(result.value.to_vec())),
                );
            }
        }
        Ok(map)
    }
}

#[async_trait]
impl StorageUtil for AsyncInMemoryDatabase {
    async fn batch_get_type_direct<St: Storable>(&self) -> Result<Vec<DbRecord>, StorageError> {
        let records = self
            .batch_get_all_direct()
            .await?
            .into_iter()
            .filter(|record| match record {
                DbRecord::Azks(_) => St::data_type() == StorageType::Azks,
                DbRecord::TreeNode(_) => St::data_type() == StorageType::TreeNode,
                DbRecord::ValueState(_) => St::data_type() == StorageType::ValueState,
            })
            .collect();

        Ok(records)
    }

    async fn batch_get_all_direct(&self) -> Result<Vec<DbRecord>, StorageError> {
        let u_records = self
            .user_info
            .iter()
            .flat_map(|r| r.value().clone().into_values())
            .map(DbRecord::ValueState);

        let records = self.db.iter().map(|r| r.value().clone()).chain(u_records).collect();

        Ok(records)
    }
}
