//! One private conditional ML DSA87 reconstructed row.
//! Signature sources, owner binding and final challenge equality remain separate.
#![forbid(unsafe_code)]
mod air;
mod arithmetic;
mod build;
mod control;
mod hash;
mod ntt;
mod program;
mod proof;
mod row_hash;
#[cfg(test)]
mod tests;

use super::key_source::keccak;
use thorum_arithmetic_proof_lab::{hints, mul, packing};

pub const MODULUS: u32 = 8_380_417;
#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Forward,
    Inverse,
}
pub struct Statement {
    row: u8,
    context: [u8; 64],
}
impl Statement {
    fn validate(&self) -> Result<(), Error> {
        if self.row >= 8 {
            Err(Error::InvalidStatement)
        } else {
            Ok(())
        }
    }
    pub fn new(row: u8, context: [u8; 64]) -> Result<Self, Error> {
        if row >= 8 {
            return Err(Error::InvalidStatement);
        }
        Ok(Self { row, context })
    }
}
pub struct Witness {
    rho: [u8; 32],
    zhat: [[u32; 256]; 7],
    t1: [u16; 256],
    chat: [u32; 256],
    hints: [u8; 256],
}
impl Witness {
    pub fn from_inputs(
        rho: [u8; 32],
        zhat: [[u32; 256]; 7],
        t1: [u16; 256],
        chat: [u32; 256],
        hints: [u8; 256],
    ) -> Self {
        Self {
            rho,
            zhat,
            t1,
            chat,
            hints,
        }
    }
}
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    InvalidStatement,
    InvalidWitness,
    UnsupportedCapacity,
    EntropyUnavailable,
    ProvingFailed,
    InvalidEncoding,
    LimitExceeded,
    InvalidProof,
}

use build::trace;

pub use proof::{MAX_PROOF_BYTES, PROFILE, prove_reconstructed_row, verify_reconstructed_row};
