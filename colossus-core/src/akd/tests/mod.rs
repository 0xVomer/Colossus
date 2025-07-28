mod test_config_node_labels;
mod test_core_protocol;
mod test_errors;
mod test_preloads;

use crate::{
    akd::{AkdLabel, AkdValue, Azks, errors::StorageError, tree_node::TreeNodeWithPreviousValue},
    storage::{
        memory::AsyncInMemoryDatabase,
        traits::{Database, DbSetState, Storable},
        types::{DbRecord, KeyData, ValueState, ValueStateRetrievalFlag},
    },
};
use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Clone)]
pub struct LocalDatabase;

unsafe impl Send for LocalDatabase {}

unsafe impl Sync for LocalDatabase {}

mockall::mock! {
    pub LocalDatabase {

    }
    impl Clone for LocalDatabase {
        fn clone(&self) -> Self;
    }
    #[async_trait::async_trait]
    impl Database for LocalDatabase {
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
        async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError>;
        async fn get_user_state(
            &self,
            username: &AkdLabel,
            flag: ValueStateRetrievalFlag,
        ) -> Result<ValueState, StorageError>;
        async fn get_user_state_versions(
            &self,
            usernames: &[AkdLabel],
            flag: ValueStateRetrievalFlag,
        ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError>;
    }
}

fn setup_mocked_db(db: &mut MockLocalDatabase, test_db: &AsyncInMemoryDatabase) {
    let tmp_db = test_db.clone();
    db.expect_set()
        .returning(move |record| futures::executor::block_on(tmp_db.set(record)));

    let tmp_db = test_db.clone();
    db.expect_batch_set().returning(move |record, other| {
        futures::executor::block_on(tmp_db.batch_set(record, other))
    });

    let tmp_db = test_db.clone();
    db.expect_get::<Azks>()
        .returning(move |key| futures::executor::block_on(tmp_db.get::<Azks>(key)));

    let tmp_db = test_db.clone();
    db.expect_get::<TreeNodeWithPreviousValue>().returning(move |key| {
        futures::executor::block_on(tmp_db.get::<TreeNodeWithPreviousValue>(key))
    });

    let tmp_db = test_db.clone();
    db.expect_get::<Azks>()
        .returning(move |key| futures::executor::block_on(tmp_db.get::<Azks>(key)));

    let tmp_db = test_db.clone();
    db.expect_batch_get::<Azks>()
        .returning(move |key| futures::executor::block_on(tmp_db.batch_get::<Azks>(key)));

    let tmp_db = test_db.clone();
    db.expect_batch_get::<TreeNodeWithPreviousValue>().returning(move |key| {
        futures::executor::block_on(tmp_db.batch_get::<TreeNodeWithPreviousValue>(key))
    });

    let tmp_db = test_db.clone();
    db.expect_get_user_data()
        .returning(move |arg| futures::executor::block_on(tmp_db.get_user_data(arg)));

    let tmp_db = test_db.clone();
    db.expect_get_user_state()
        .returning(move |arg, flag| futures::executor::block_on(tmp_db.get_user_state(arg, flag)));

    let tmp_db = test_db.clone();
    db.expect_get_user_state_versions().returning(move |arg, flag| {
        futures::executor::block_on(tmp_db.get_user_state_versions(arg, flag))
    });
}
