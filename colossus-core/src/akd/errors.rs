mod auditor;
mod azks;
mod directory;
mod parallelism;
mod storage;
mod tree_node;
mod verification;
mod vrf;

pub use auditor::AuditorError;
pub use azks::AzksError;
pub use directory::DirectoryError;
pub use parallelism::ParallelismError;
pub use storage::StorageError;
pub use tree_node::TreeNodeError;
pub use verification::VerificationError;
pub use vrf::VrfError;

use super::{Direction, node_label::NodeLabel};

#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum AkdError {
    TreeNode(TreeNodeError),

    Directory(DirectoryError),

    AzksErr(AzksError),

    Vrf(VrfError),

    Storage(StorageError),

    AuditErr(AuditorError),

    Parallelism(ParallelismError),

    TestErr(String),
}

impl std::error::Error for AkdError {}

impl From<TreeNodeError> for AkdError {
    fn from(error: TreeNodeError) -> Self {
        Self::TreeNode(error)
    }
}

impl From<StorageError> for AkdError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<DirectoryError> for AkdError {
    fn from(error: DirectoryError) -> Self {
        Self::Directory(error)
    }
}

impl From<AzksError> for AkdError {
    fn from(error: AzksError) -> Self {
        Self::AzksErr(error)
    }
}

impl From<AuditorError> for AkdError {
    fn from(error: AuditorError) -> Self {
        Self::AuditErr(error)
    }
}

impl From<ParallelismError> for AkdError {
    fn from(error: ParallelismError) -> Self {
        Self::Parallelism(error)
    }
}

impl From<VerificationError> for AkdError {
    fn from(err: VerificationError) -> Self {
        Self::Directory(err.into())
    }
}

impl From<VrfError> for AkdError {
    fn from(error: VrfError) -> Self {
        Self::Vrf(error)
    }
}

impl std::fmt::Display for AkdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            AkdError::TreeNode(err) => {
                writeln!(f, "AKD Tree Node Error: {err}")
            },
            AkdError::Directory(err) => {
                writeln!(f, "AKD Directory Error: {err}")
            },
            AkdError::AzksErr(err) => {
                writeln!(f, "AKD AZKS Error: {err}")
            },
            AkdError::Vrf(err) => {
                writeln!(f, "AKD VRF Error: {err}")
            },
            AkdError::Storage(err) => {
                writeln!(f, "AKD Storage Error: {err}")
            },
            AkdError::AuditErr(err) => {
                writeln!(f, "AKD Auditor Error {err}")
            },
            AkdError::Parallelism(err) => {
                writeln!(f, "AKD Parallelism Error: {err}")
            },
            AkdError::TestErr(err) => {
                writeln!(f, "{err}")
            },
        }
    }
}
