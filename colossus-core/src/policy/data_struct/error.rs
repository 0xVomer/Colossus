use std::fmt::Debug;
use thiserror::Error;

type Key = String;

/// Errors that can occur in data structure operations.
#[derive(Error, Debug)]
pub enum Error {
    /// The entry with the given key was not found
    #[error("entry not found with key: {0}")]
    EntryNotFound(Key),

    /// An entry with the given key already exists
    #[error("entry already exists with key: {0}")]
    ExistingEntry(Key),

    /// The entry already has a child node
    #[error("entry with key '{0}' already has a child")]
    AlreadyHasChild(Key),
}

impl Error {
    /// Create an EntryNotFound error from any Debug type
    pub fn missing_entry<T>(key: &T) -> Self
    where
        T: Debug,
    {
        Self::EntryNotFound(format!("{key:?}"))
    }

    /// Create an ExistingEntry error from any Debug type
    pub fn existing_entry<T>(key: &T) -> Self
    where
        T: Debug,
    {
        Self::ExistingEntry(format!("{key:?}"))
    }

    /// Create an AlreadyHasChild error from any Debug type
    pub fn already_has_child<T>(key: &T) -> Self
    where
        T: Debug,
    {
        Self::AlreadyHasChild(format!("{key:?}"))
    }
}
