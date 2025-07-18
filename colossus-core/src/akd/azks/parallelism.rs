use crate::log::info;

/// Parallelism configuration for [Azks]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct AzksParallelismConfig {
    /// Parallelization for node insertion.
    pub insertion: AzksParallelismOption,
    /// Parallelization for node preloading, during insertion and auditing.
    pub preload: AzksParallelismOption,
}

impl AzksParallelismConfig {
    /// The default fallback parallelism for parallel azks operations, used when
    /// available parallelism cannot be determined automatically at runtime. Should be > 1
    const DEFAULT_FALLBACK_PARALLELISM: u32 = 32;

    /// Instantiate a parallelism config with no parallelism set for all fields.
    pub fn disabled() -> Self {
        Self {
            insertion: AzksParallelismOption::Disabled,
            preload: AzksParallelismOption::Disabled,
        }
    }
}

impl Default for AzksParallelismConfig {
    fn default() -> Self {
        Self {
            insertion: AzksParallelismOption::AvailableOr(Self::DEFAULT_FALLBACK_PARALLELISM),
            preload: AzksParallelismOption::AvailableOr(Self::DEFAULT_FALLBACK_PARALLELISM),
        }
    }
}

/// Parallelism setting for a given field in [AzksParallelismConfig].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum AzksParallelismOption {
    /// No parallelism.
    Disabled,
    /// Set parallelism to a static value.
    Static(u32),
    /// Dynamically derive parallelism from the number of available cores,
    /// falling back to the passed value if available cores cannot be retrieved.
    AvailableOr(u32),
}

impl AzksParallelismOption {
    pub(super) fn get_parallel_levels(&self) -> Option<u8> {
        let parallelism = match *self {
            AzksParallelismOption::Disabled => return None,
            AzksParallelismOption::Static(parallelism) => parallelism,
            AzksParallelismOption::AvailableOr(fallback_parallelism) => {
                std::thread::available_parallelism()
                    .map_or(fallback_parallelism, |v| v.get() as u32)
            },
        };

        // We calculate the number of levels that should be executed in parallel
        // to give the number of tasks closest to the available parallelism.
        // The number of tasks spawned at a level is the number of leaves at
        // the level. As we are using a binary tree, the number of leaves at a
        // level is 2^level. Therefore, the number of levels that should be
        // executed in parallel is the log2 of the number of available threads.
        let parallel_levels = (parallelism as f32).log2().ceil() as u8;

        info!(
            "Parallel levels requested (parallelism: {}, parallel levels: {})",
            parallelism, parallel_levels
        );
        Some(parallel_levels)
    }
}
