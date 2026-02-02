// Error type used by kdf module functions
#![allow(dead_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid G1 point")]
    InvalidG1Point,

    #[error("Invalid G2 point")]
    InvalidG2Point,

    #[error("{0}")]
    CustomMsg(String),
}
