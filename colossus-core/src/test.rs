mod access_control;
mod fixtures;
mod secure_data_transfer;

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
use fixtures::{Age, Challenge, Device, GroupID, Location, Permission, Sex, UserID};
use lazy_static::lazy_static;
use std::collections::HashSet;

lazy_static! {
    static ref NONCE: Nonce = Nonce(Scalar::from(42u64));
}
