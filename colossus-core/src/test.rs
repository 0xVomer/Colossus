mod access_control;
mod attestation;
mod blinded_attributes;
mod secure_data_transfer;

use crate::dac::zkp::Nonce;
use bls12_381_plus::Scalar;
use lazy_static::lazy_static;

lazy_static! {
    static ref NONCE: Nonce = Nonce(Scalar::from(42u64));
}
