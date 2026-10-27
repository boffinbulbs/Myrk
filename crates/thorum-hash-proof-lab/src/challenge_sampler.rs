//! Bounded sparse challenge sampling with connected SHAKE256 state.
//! No complete signature or owner permission is supplied by this component.

#![forbid(unsafe_code)]

mod air;
mod hash;
mod proof;
pub mod signature;
pub use proof::{MAX_PROOF_BYTES, PROFILE, prove_challenge_sampler, verify_challenge_sampler};
#[cfg(test)]
mod tests;
pub const CAPACITY: usize = 272;
pub const MODULUS: u32 = 8_380_417;

#[derive(Clone, Copy)]
pub struct Statement {
    coefficients: [u32; 256],
    context: [u8; 64],
}
impl Statement {
    pub fn new(coefficients: [u32; 256], context: [u8; 64]) -> Result<Self, Error> {
        let value = Self {
            coefficients,
            context,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), Error> {
        if self
            .coefficients
            .iter()
            .any(|v| ![0, 1, MODULUS - 1].contains(v))
            || self.coefficients.iter().filter(|v| **v != 0).count() != 60
        {
            return Err(Error::InvalidStatement);
        }
        Ok(())
    }
}
pub struct Witness {
    seed: [u8; 64],
}
impl Witness {
    pub fn from_challenge_seed(seed: [u8; 64]) -> Self {
        Self { seed }
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
