#![allow(non_snake_case)]

use curv::BigInt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod party_one;
pub mod party_two;
pub mod utilities;

pub const SECURITY_BITS: usize = 256;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid signature")]
    InvalidSig,

    #[error("invalid key")]
    InvalidKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedSignature {
    pub sd_prime: BigInt,
}
