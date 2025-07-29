mod ecvrf_impl;

use super::errors::VrfError;
pub use ecvrf_impl::{Output, Proof, VRFExpandedPrivateKey, VRFPrivateKey, VRFPublicKey};

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct HardCodedAkdVRF;

unsafe impl Sync for HardCodedAkdVRF {}
unsafe impl Send for HardCodedAkdVRF {}
