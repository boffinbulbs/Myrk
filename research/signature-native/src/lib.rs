//! Same witness sources and sixteen private forward transforms.
//! Reconstructed rows, inverse transforms and final verification are unfinished.
//! The native constructor has no prover, proof verifier or payment API.
#![forbid(unsafe_code)]

mod air;
pub mod authorization;
mod build;
mod decoding;
mod keccak;
pub mod layout;
mod mul;
pub mod ntt;
mod packing;
pub mod program;
mod sampler;
mod sources;

pub use air::PrivateForwardNttAir;
pub use build::{build_private_forward_ntts, BuildError};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use thorum_relation_lab::{PaymentStatement, RelationError};

pub const MODULUS: u32 = 8_380_417;

/// Only raw source inputs. No free decoded or transformed witness operands.
pub struct Witness {
    key: [u8; 2592],
    signature: [u8; 4627],
    note: [u8; 418],
}

#[cfg(test)]
mod tests;
impl Witness {
    pub fn from_sources(key: [u8; 2592], signature: [u8; 4627], note: [u8; 418]) -> Self {
        Self {
            key,
            signature,
            note,
        }
    }
}

pub struct Statement {
    authorization_input: [u8; 196],
}
impl Statement {
    pub fn from_transaction(transaction: &PaymentStatement) -> Result<Self, RelationError> {
        let mapped = authorization::ExpectedAuthorization::from_transaction(transaction)?;
        Ok(Self {
            authorization_input: *mapped.authorization_input(),
        })
    }
    pub fn public_values(&self) -> Vec<BabyBear> {
        self.authorization_input
            .iter()
            .copied()
            .map(BabyBear::from_u8)
            .collect()
    }
}
