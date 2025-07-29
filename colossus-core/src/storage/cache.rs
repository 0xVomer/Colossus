use super::types::DbRecord;
use std::time::Instant;

#[cfg(test)]
mod tests;

pub(crate) const DEFAULT_ITEM_LIFETIME_MS: u64 = 30000;

pub(crate) const DEFAULT_CACHE_CLEAN_FREQUENCY_MS: u64 = 15000;

pub(crate) struct CachedItem {
    pub(crate) expiration: Instant,
    pub(crate) data: DbRecord,
}

impl crate::akd::SizeOf for CachedItem {
    fn size_of(&self) -> usize {
        16 + self.data.size_of()
    }
}

pub mod high_parallelism;

pub use high_parallelism::TimedCache;
