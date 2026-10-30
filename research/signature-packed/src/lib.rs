//! Complete packed source candidate for the private signature relation.
//! Native laboratory without a proof backend or payment acceptance API.
#![forbid(unsafe_code)]

#[path = "../../signature-storage/src/activity.rs"]
mod activity;
mod air;
#[path = "../../signature-complete-native/src/authorization.rs"]
pub mod authorization;
mod build;
#[path = "../../signature-storage/src/clock.rs"]
pub mod clock;
mod decoding;
mod full_program;
#[path = "../../signature-complete-native/src/hint_rows.rs"]
mod hint_rows;
#[path = "../../signature-complete-native/src/hints.rs"]
mod hints;
#[path = "../../signature-complete-native/src/keccak.rs"]
mod keccak;
pub mod layout;
#[path = "../../signature-storage/src/matrix.rs"]
mod matrix;
#[path = "../../signature-complete-native/src/mul.rs"]
mod mul;
#[path = "../../signature-storage/src/ntt.rs"]
pub mod ntt;
pub mod packed;
#[path = "../../signature-complete-native/src/packing.rs"]
mod packing;
#[path = "../../signature-storage/src/program.rs"]
pub mod program;
#[path = "../../signature-storage/src/sampler.rs"]
mod sampler;
mod sources;
mod sponge;

pub use air::PackedSignatureOwnerAir;
pub use build::{build_full_private_signature_owner_sources, BuildError};
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
