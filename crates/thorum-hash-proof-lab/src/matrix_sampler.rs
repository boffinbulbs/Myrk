//! Bounded matrix sampling with connected SHAKE128 state and exact rejection.
//! This diagnostic profile is not a ledger authorization route.

#![forbid(unsafe_code)]

mod air;
mod hash;
mod proof;
pub use proof::{MAX_PROOF_BYTES, PROFILE, prove_matrix_sampler, verify_matrix_sampler};
#[cfg(test)]
mod tests;

pub const MODULUS: u32 = 8_380_417;
pub const CAPACITY: usize = 1008;

#[derive(Clone, Copy)]
pub struct Statement {
    row: u8,
    column: u8,
    coefficients: [u32; 256],
    context: [u8; 64],
}
impl Statement {
    pub fn new(
        row: u8,
        column: u8,
        coefficients: [u32; 256],
        context: [u8; 64],
    ) -> Result<Self, Error> {
        let value = Self {
            row,
            column,
            coefficients,
            context,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.row >= 8 || self.column >= 7 || self.coefficients.iter().any(|v| *v >= MODULUS) {
            return Err(Error::InvalidStatement);
        }
        Ok(())
    }
}

pub struct Witness {
    rho: [u8; 32],
}
impl Witness {
    pub fn from_rho(rho: [u8; 32]) -> Self {
        Self { rho }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    InvalidStatement,
    UnsupportedCapacity,
    EntropyUnavailable,
    InvalidWitness,
    ProvingFailed,
    InvalidEncoding,
    LimitExceeded,
    InvalidProof,
}
