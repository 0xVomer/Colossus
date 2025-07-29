use super::{CachedItem, DEFAULT_CACHE_CLEAN_FREQUENCY_MS, DEFAULT_ITEM_LIFETIME_MS};
use crate::{
    akd::SizeOf,
    log::{debug, info},
    storage::{traits::Storable, types::DbRecord},
};

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct TimedCache {
    azks: Arc<RwLock<Option<DbRecord>>>,
    map: Arc<DashMap<Vec<u8>, CachedItem>>,
    last_clean: Arc<RwLock<Instant>>,
    can_clean: Arc<AtomicBool>,
    item_lifetime: Duration,
    memory_limit_bytes: Option<usize>,
    clean_frequency: Duration,

    hit_count: Arc<AtomicU64>,
}

impl TimedCache {
    pub fn log_metrics(&self) {
        let hit_count = self.hit_count.swap(0, Ordering::Relaxed);
        let cache_size = self.map.len();

        let msg = format!("Cache hit since last: {hit_count}, cached size: {cache_size} items");
        info!("{msg}");
    }
}

impl TimedCache {
    async fn clean(&self) {
        if !self.can_clean.load(Ordering::Relaxed) {
            return;
        }

        let do_clean = { *(self.last_clean.read().await) + self.clean_frequency < Instant::now() };
        if do_clean {
            let mut last_clean_write = self.last_clean.write().await;

            let now = Instant::now();
            if let Some(memory_limit_bytes) = self.memory_limit_bytes {
                let mut retained_size = 0;
                let mut num_retained = 0u32;
                let mut num_removed = 0u32;
                self.map.retain(|k, v| {
                    if v.expiration >= now {
                        retained_size += k.len() + v.size_of();
                        num_retained += 1;
                        true
                    } else {
                        num_removed += 1;
                        false
                    }
                });

                info!("Removed {} expired elements from the cache", num_removed);
                debug!("Retained cache size is {} bytes", retained_size);

                if retained_size > memory_limit_bytes {
                    info!(
                        "Retained cache size has exceeded the predefined limit, cleaning old entries"
                    );

                    let percent_clean =
                        0.05 + 1.0 - (memory_limit_bytes as f64) / (retained_size as f64);

                    let num_clean = ((num_retained as f64) * percent_clean).ceil() as usize;

                    let mut keys_and_expiration = self
                        .map
                        .iter()
                        .map(|kv| (kv.key().clone(), kv.value().expiration))
                        .collect::<Vec<_>>();
                    keys_and_expiration.sort_by(|(_, a), (_, b)| a.cmp(b));

                    for key in keys_and_expiration.into_iter().take(num_clean).map(|(k, _)| k) {
                        self.map.remove(&key);
                    }

                    debug!("END cache memory pressure clean")
                }
            } else {
                self.map.retain(|_, v| v.expiration >= now);
            }

            *last_clean_write = Instant::now();
        }
    }

    pub fn new(
        o_lifetime: Option<Duration>,
        o_memory_limit_bytes: Option<usize>,
        o_clean_frequency: Option<Duration>,
    ) -> Self {
        let lifetime = match o_lifetime {
            Some(life) if life > Duration::from_millis(1) => life,
            _ => Duration::from_millis(DEFAULT_ITEM_LIFETIME_MS),
        };
        let clean_frequency = match o_clean_frequency {
            Some(frequency) if frequency > Duration::from_millis(1) => frequency,
            _ => Duration::from_millis(DEFAULT_CACHE_CLEAN_FREQUENCY_MS),
        };
        Self {
            azks: Arc::new(RwLock::new(None)),
            map: Arc::new(DashMap::new()),
            last_clean: Arc::new(RwLock::new(Instant::now())),
            can_clean: Arc::new(AtomicBool::new(true)),
            item_lifetime: lifetime,
            memory_limit_bytes: o_memory_limit_bytes,
            clean_frequency,

            hit_count: Arc::new(AtomicU64::new(0u64)),
        }
    }

    pub async fn hit_test<St: Storable>(&self, key: &St::StorageKey) -> Option<DbRecord> {
        self.clean().await;

        let full_key = St::get_full_binary_key_id(key);

        if full_key == crate::akd::Azks::get_full_binary_key_id(&crate::akd::DEFAULT_AZKS_KEY) {
            let record = self.azks.read().await.clone();

            self.hit_count.fetch_add(1, Ordering::Relaxed);

            return record;
        }

        if let Some(result) = self.map.get(&full_key) {
            self.hit_count.fetch_add(1, Ordering::Relaxed);

            let ignore_clean = !self.can_clean.load(Ordering::Relaxed);

            if ignore_clean || result.expiration > Instant::now() {
                return Some(result.data.clone());
            }
        }

        None
    }

    pub async fn put(&self, record: &DbRecord) {
        self.clean().await;

        let key = record.get_full_binary_id();

        if let DbRecord::Azks(azks_ref) = &record {
            let mut guard = self.azks.write().await;
            *guard = Some(DbRecord::Azks(azks_ref.clone()));
        } else {
            let item = CachedItem {
                expiration: Instant::now() + self.item_lifetime,
                data: record.clone(),
            };
            self.map.insert(key, item);
        }
    }

    pub async fn batch_put(&self, records: &[DbRecord]) {
        self.clean().await;

        for record in records.iter() {
            if let DbRecord::Azks(azks_ref) = &record {
                let mut azks_guard = self.azks.write().await;
                *azks_guard = Some(DbRecord::Azks(azks_ref.clone()));
            } else {
                let key = record.get_full_binary_id();
                let item = CachedItem {
                    expiration: Instant::now() + self.item_lifetime,
                    data: record.clone(),
                };
                self.map.insert(key, item);
            }
        }
    }

    pub async fn flush(&self) {
        self.map.clear();
        *(self.azks.write().await) = None;
    }

    pub async fn get_all(&self) -> Vec<DbRecord> {
        self.clean().await;

        let mut items = vec![];
        if let Some(record) = self.azks.read().await.clone() {
            items.push(record);
        }
        for kv in self.map.iter() {
            items.push(kv.value().data.clone());
        }

        items
    }

    pub fn disable_clean(&self) {
        debug!("Disabling cache cleaning");
        self.can_clean.store(false, Ordering::Relaxed);
    }

    pub fn enable_clean(&self) {
        debug!("Enabling cache cleaning");
        self.can_clean.store(true, Ordering::Relaxed);
    }
}
