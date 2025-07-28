use super::traits::Storable;
use super::types::{DbRecord, ValueState, ValueStateRetrievalFlag};
use crate::akd::errors::StorageError;
use crate::log::info;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct Transaction {
    mods: Arc<DashMap<Vec<u8>, DbRecord>>,
    active: Arc<AtomicBool>,

    num_writes: Arc<AtomicU64>,
    num_reads: Arc<AtomicU64>,
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a lone transaction")
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            mods: Arc::new(DashMap::new()),
            active: Arc::new(AtomicBool::new(false)),
            num_reads: Arc::new(AtomicU64::new(0)),
            num_writes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn count(&self) -> usize {
        self.mods.len()
    }

    pub fn log_metrics(&self) {
        let r = self.num_reads.swap(0, Ordering::Relaxed);
        let w = self.num_writes.swap(0, Ordering::Relaxed);

        let msg = format!("Transaction writes: {w}, Transaction reads: {r}");
        info!("{msg}");
    }

    pub fn begin_transaction(&self) -> bool {
        !self.active.swap(true, Ordering::Relaxed)
    }

    pub fn commit_transaction(&self) -> Result<Vec<DbRecord>, StorageError> {
        if !self.active.load(Ordering::Relaxed) {
            return Err(StorageError::Transaction("Transaction not currently active".to_string()));
        }

        let mut records = self.mods.iter().map(|p| p.value().clone()).collect::<Vec<_>>();

        records.sort_by_key(|r| r.transaction_priority());

        self.mods.clear();

        self.active.store(false, Ordering::Relaxed);
        Ok(records)
    }

    pub fn rollback_transaction(&self) -> Result<(), StorageError> {
        if !self.active.load(Ordering::Relaxed) {
            return Err(StorageError::Transaction("Transaction not currently active".to_string()));
        }

        self.mods.clear();

        self.active.store(false, Ordering::Relaxed);
        Ok(())
    }

    pub fn is_transaction_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn get<St: Storable>(&self, key: &St::StorageKey) -> Option<DbRecord> {
        let bin_id = St::get_full_binary_key_id(key);

        let out = self.mods.get(&bin_id).map(|p| p.value().clone());
        if out.is_some() {
            self.num_reads.fetch_add(1, Ordering::Relaxed);
        }
        out
    }

    pub fn batch_set(&self, records: &[DbRecord]) {
        for record in records {
            self.mods.insert(record.get_full_binary_id(), record.clone());
        }

        self.num_writes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set(&self, record: &DbRecord) {
        let bin_id = record.get_full_binary_id();

        self.mods.insert(bin_id, record.clone());

        self.num_writes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_users_data(
        &self,
        usernames: &[crate::akd::AkdLabel],
    ) -> HashMap<crate::akd::AkdLabel, Vec<ValueState>> {
        let mut results: HashMap<crate::akd::AkdLabel, Vec<ValueState>> = HashMap::new();

        let mut set = std::collections::HashSet::with_capacity(usernames.len());
        for username in usernames.iter() {
            if !set.contains(username) {
                set.insert(username.clone());
            }
        }

        for pair in self.mods.iter() {
            if let DbRecord::ValueState(value_state) = pair.value() {
                if set.contains(&value_state.username) {
                    if results.contains_key(&value_state.username) {
                        if let Some(item) = results.get_mut(&value_state.username) {
                            item.push(value_state.clone())
                        }
                    } else {
                        results.insert(value_state.username.clone(), vec![value_state.clone()]);
                    }
                }
            }
        }

        for (_k, v) in results.iter_mut() {
            v.sort_unstable_by(|a, b| a.epoch.cmp(&b.epoch));
        }

        results
    }

    #[allow(clippy::let_and_return)]
    pub fn get_user_state(
        &self,
        username: &crate::akd::AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> Option<ValueState> {
        let intermediate =
            self.get_users_data(&[username.clone()]).remove(username).unwrap_or_default();
        let out = Self::find_appropriate_item(intermediate, flag);
        if out.is_some() {
            self.num_reads.fetch_add(1, Ordering::Relaxed);
        }
        out
    }

    pub fn get_users_states(
        &self,
        usernames: &[crate::akd::AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> HashMap<crate::akd::AkdLabel, ValueState> {
        let mut result_map = HashMap::new();
        let intermediate = self.get_users_data(usernames);

        for (key, value_list) in intermediate.into_iter() {
            if let Some(found) = Self::find_appropriate_item(value_list, flag) {
                result_map.insert(key, found);
            }
        }
        self.num_reads.fetch_add(1, Ordering::Relaxed);

        result_map
    }

    fn find_appropriate_item(
        intermediate: Vec<ValueState>,
        flag: ValueStateRetrievalFlag,
    ) -> Option<ValueState> {
        match flag {
            ValueStateRetrievalFlag::SpecificVersion(version) => {
                intermediate.into_iter().find(|item| item.version == version)
            },
            ValueStateRetrievalFlag::SpecificEpoch(epoch) => {
                intermediate.into_iter().find(|item| item.epoch == epoch)
            },
            ValueStateRetrievalFlag::LeqEpoch(epoch) => {
                intermediate.into_iter().rev().find(|item| item.epoch <= epoch)
            },
            ValueStateRetrievalFlag::MaxEpoch => intermediate.into_iter().next_back(),
            ValueStateRetrievalFlag::MinEpoch => intermediate.into_iter().next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::akd::{
        AkdLabel, AkdValue, Azks, AzksValue, EMPTY_DIGEST, NodeLabel, tree_node::*,
        utils::byte_arr_from_u64,
    };
    use crate::storage::types::*;
    use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};

    #[test]
    fn test_commit_order() -> Result<(), StorageError> {
        let azks = DbRecord::Azks(Azks { num_nodes: 0, latest_epoch: 0 });
        let node1 = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
            label: NodeLabel::new(byte_arr_from_u64(0), 0),
            last_epoch: 1,
            min_descendant_epoch: 1,
            parent: NodeLabel::new(byte_arr_from_u64(0), 0),
            node_type: TreeNodeType::Root,
            left_child: None,
            right_child: None,
            hash: AzksValue(EMPTY_DIGEST),
        }));
        let node2 = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            last_epoch: 1,
            min_descendant_epoch: 1,
            parent: NodeLabel::new(byte_arr_from_u64(0), 0),
            node_type: TreeNodeType::Leaf,
            left_child: None,
            right_child: None,
            hash: AzksValue(EMPTY_DIGEST),
        }));
        let value1 = DbRecord::ValueState(ValueState {
            username: AkdLabel::from("test"),
            epoch: 1,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            version: 1,
            value: AkdValue::from("abc123"),
        });
        let value2 = DbRecord::ValueState(ValueState {
            username: AkdLabel::from("test"),
            epoch: 2,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            version: 2,
            value: AkdValue::from("abc1234"),
        });

        let records = vec![azks, node1, node2, value1, value2];
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 1..10 {
            let txn = Transaction::new();
            txn.begin_transaction();

            let mut shuffled = records.clone();
            shuffled.shuffle(&mut rng);
            for record in shuffled {
                txn.set(&record);
            }

            let mut running_priority = 0;
            for record in txn.commit_transaction()? {
                let priority = record.transaction_priority();
                #[allow(clippy::comparison_chain)]
                if priority > running_priority {
                    running_priority = priority;
                } else if priority < running_priority {
                    panic!("Transaction did not obey record priority when committing");
                }
            }
        }

        Ok(())
    }
}
