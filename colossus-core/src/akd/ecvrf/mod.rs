//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
//! This module contains implementations of a
//! [verifiable random function](https://en.wikipedia.org/wiki/Verifiable_random_function)
//! (currently only ECVRF). VRFs are used, in the case of this crate, to anonymize the
//! user id <-> node label mapping into a 1-way hash, which is verifyable without being
//! regeneratable without the secret key.
//!
//! VRFs allow us to have the server generate a constant mapping from a user id to a node label
//! but the client cannot themselves generate the mapping, only verify it. They can confirm
//! a user id matches the label, but don't have the ability to determine the labels of other
//! users in the directory.
//!
//! This module implements an instantiation of a verifiable random function known as
//! [ECVRF-EDWARDS25519-SHA512-TAI from RFC9381](https://www.ietf.org/rfc/rfc9381.html).
//!
//!
//! Adapted from Diem's NextGen Crypto module available [here](https://github.com/diem/diem/blob/502936fbd59e35276e2cf455532b143796d68a16/crypto/nextgen_crypto/src/vrf/ecvrf.rs)

mod ecvrf_impl;
// export the functionality we want visible
use super::errors::VrfError;
pub use ecvrf_impl::{Output, Proof, VRFExpandedPrivateKey, VRFPrivateKey, VRFPublicKey};

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct HardCodedAkdVRF;

unsafe impl Sync for HardCodedAkdVRF {}
unsafe impl Send for HardCodedAkdVRF {}
