pub mod cache;
pub mod ecvrf;
pub mod manager;
pub mod memory;
pub mod tests;
pub mod traits;
pub mod transaction;
pub mod types;
pub use manager::StorageManager;

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

#[async_trait::async_trait]
impl ecvrf::VRFKeyStorage for crate::akd::ecvrf::HardCodedAkdVRF {
    async fn retrieve(&self) -> Result<Vec<u8>, crate::akd::errors::VrfError> {
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .map_err(|hex_err| crate::akd::errors::VrfError::PublicKey(hex_err.to_string()))
    }
}
