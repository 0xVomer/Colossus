mod access_control;
mod fixtures;

use crate::{
    access_control::{AccessClaim, AccessControl, EncryptedHeader},
    dac::{
        entry::{Entry, MaxEntries},
        keypair::{Alias, Issuer},
        zkp::Nonce,
    },
    policy::{AccessPolicy, AccessStructure, QualifiedAttribute},
};
use anyhow::Result;
use bls12_381_plus::Scalar;
use fixtures::{Age, Device, Location, Sex};
use lazy_static::lazy_static;

lazy_static! {
    static ref NONCE: Nonce = Nonce(Scalar::from(42u64));
}
