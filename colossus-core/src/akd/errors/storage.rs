/// Represents a storage-layer error
#[derive(Debug, PartialEq, Eq)]
pub enum StorageError {
    /// Data wasn't found in the storage layer
    NotFound(String),
    /// A transaction error
    Transaction(String),
    /// Some kind of storage connection error occurred
    Connection(String),
    /// Some other storage-layer error occurred
    Other(String),
}

impl std::error::Error for StorageError {}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Connection(inner) => {
                write!(f, "Storage connection: {inner}")
            },
            StorageError::Transaction(inner) => {
                write!(f, "Transaction: {inner}")
            },
            StorageError::NotFound(inner) => {
                write!(f, "Data not found: {inner}")
            },
            StorageError::Other(inner) => {
                write!(f, "Other storage error: {inner}")
            },
        }
    }
}
