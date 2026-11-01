//! Complete packed source candidate for the private signature relation.
//! Native laboratory without a proof backend or payment acceptance API.
#![forbid(unsafe_code)]

#[path = "../../signature-storage/src/activity.rs"]
mod activity;
#[path = "../../signature-overlay/src/air.rs"]
mod air;
#[path = "../../signature-overlay/src/arithmetic_modes.rs"]
mod arithmetic_modes;
#[path = "../../signature-complete-native/src/authorization.rs"]
pub mod authorization;
mod build;
#[path = "../../signature-storage/src/clock.rs"]
pub mod clock;
#[path = "../../signature-packed/src/decoding.rs"]
mod decoding;
#[path = "../../signature-overlay/src/full_program.rs"]
mod full_program;
#[path = "../../signature-overlay/src/hint_rows.rs"]
mod hint_rows;
#[path = "../../signature-complete-native/src/hints.rs"]
mod hints;
#[path = "../../signature-complete-native/src/keccak.rs"]
mod keccak;
#[path = "../../signature-overlay/src/layout.rs"]
pub mod layout;
#[path = "../../signature-storage/src/matrix.rs"]
mod matrix;
#[path = "../../signature-complete-native/src/mul.rs"]
mod mul;
#[path = "../../signature-overlay/src/ntt.rs"]
pub mod ntt;
#[path = "../../signature-packed/src/packed.rs"]
pub mod packed;
#[path = "../../signature-complete-native/src/packing.rs"]
mod packing;
#[path = "../../signature-storage/src/program.rs"]
pub mod program;
#[path = "../../signature-storage/src/sampler.rs"]
mod sampler;
#[path = "../../signature-packed/src/sources.rs"]
mod sources;
#[path = "../../signature-packed/src/sponge.rs"]
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

/// One owned raw witness and its immutable canonical public transaction.
/// Array sizes and public encoding are checked separately from private validity.
pub struct BoundInputs {
    _witness: Witness,
    _transaction: PaymentStatement,
    statement: Statement,
}

impl BoundInputs {
    /// Deterministic public preprocessing. No signature, note or ledger claim
    /// is established by accepting these correctly sized private arrays.
    pub fn bind(witness: Witness, transaction: PaymentStatement) -> Result<Self, RelationError> {
        let statement = Statement::from_transaction(&transaction)?;
        Ok(Self {
            _witness: witness,
            _transaction: transaction,
            statement,
        })
    }

    /// Values derive only from the retained canonical transaction mapper.
    pub fn public_values(&self) -> Vec<BabyBear> {
        self.statement.public_values()
    }
}

#[cfg(feature = "diagnostics")]
pub mod stream_controls;
