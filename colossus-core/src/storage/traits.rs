use super::types::{DbRecord, StorageType};
use crate::akd::{AkdLabel, AkdValue, errors::StorageError};
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::{Send, Sync};

pub enum DbSetState {
    TransactionCommit,

    General,
}

pub trait Storable: Clone + Serialize + DeserializeOwned + Sync + 'static {
    type StorageKey: Clone + Serialize + Eq + Hash + Send + Sync + std::fmt::Debug;

    fn data_type() -> StorageType;

    fn get_id(&self) -> Self::StorageKey;

    fn get_full_binary_id(&self) -> Vec<u8> {
        Self::get_full_binary_key_id(&self.get_id())
    }

    fn get_full_binary_key_id(key: &Self::StorageKey) -> Vec<u8>;

    fn key_from_full_binary(bin: &[u8]) -> Result<Self::StorageKey, String>;
}

#[async_trait]
pub trait Database: Send + Sync {
    async fn set(&self, record: DbRecord) -> Result<(), StorageError>;

    async fn batch_set(
        &self,
        records: Vec<DbRecord>,
        state: DbSetState,
    ) -> Result<(), StorageError>;

    async fn get<St: Storable>(&self, id: &St::StorageKey) -> Result<DbRecord, StorageError>;

    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::StorageKey],
    ) -> Result<Vec<DbRecord>, StorageError>;

    /* User data searching */

    async fn get_user_data(
        &self,
        username: &AkdLabel,
    ) -> Result<super::types::KeyData, StorageError>;

    async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: super::types::ValueStateRetrievalFlag,
    ) -> Result<super::types::ValueState, StorageError>;

    async fn get_user_state_versions(
        &self,
        usernames: &[AkdLabel],
        flag: super::types::ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError>;
}

#[async_trait]
pub trait StorageUtil: Database {
    async fn batch_get_type_direct<St: Storable>(&self) -> Result<Vec<DbRecord>, StorageError>;

    async fn batch_get_all_direct(&self) -> Result<Vec<DbRecord>, StorageError>;
}
