use crate::log::info;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct AzksParallelismConfig {
    pub insertion: AzksParallelismOption,

    pub preload: AzksParallelismOption,
}

impl AzksParallelismConfig {
    const DEFAULT_FALLBACK_PARALLELISM: u32 = 32;

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

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum AzksParallelismOption {
    Disabled,

    Static(u32),

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

        let parallel_levels = (parallelism as f32).log2().ceil() as u8;

        info!(
            "Parallel levels requested (parallelism: {}, parallel levels: {})",
            parallelism, parallel_levels
        );
        Some(parallel_levels)
    }
}
