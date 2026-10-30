//! Cohesive source ownership and private forward transform construction for the packed relation.
//! Full streamed construction and private payment proving remain unfinished.
#![forbid(unsafe_code)]

#[path = "../../signature-storage/src/activity.rs"]
mod activity;
#[path = "../../signature-packed/src/air.rs"]
mod air;
#[path = "../../signature-complete-native/src/authorization.rs"]
pub mod authorization;
mod build;
#[path = "../../signature-storage/src/clock.rs"]
pub mod clock;
#[path = "../../signature-packed/src/decoding.rs"]
mod decoding;
#[path = "../../signature-packed/src/full_program.rs"]
mod full_program;
#[path = "../../signature-complete-native/src/hint_rows.rs"]
mod hint_rows;
#[path = "../../signature-complete-native/src/hints.rs"]
mod hints;
#[path = "../../signature-complete-native/src/keccak.rs"]
mod keccak;
#[path = "../../signature-packed/src/layout.rs"]
pub mod layout;
#[path = "../../signature-storage/src/matrix.rs"]
mod matrix;
#[path = "../../signature-complete-native/src/mul.rs"]
mod mul;
#[path = "../../signature-storage/src/ntt.rs"]
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

use core::convert::Infallible;
use kova_proof_preflight::{
    preflight::{Refusal, Request},
    storage::MatrixStore,
    HidingFriPcs,
};
use layout::HEIGHT;
use p3_air::BaseAir;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{extension::BinomialExtensionField, BasedVectorSpace};
use p3_uni_stark::{num_batched_openings, OpeningShape};
use rand::CryptoRng;

#[cfg(feature = "forward-controls")]
pub mod forward_controls;

type RetainedChallenge = BinomialExtensionField<BabyBear, 4>;

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

/// Resource denial and unsupported integration are distinct from proof failure.
#[derive(Debug, PartialEq, Eq)]
pub enum AssessmentFailure {
    Resource(Refusal),
    UnsupportedIntegration,
}

fn retained_request(air: &PackedSignatureOwnerAir) -> Request {
    Request {
        version: 1,
        height: HEIGHT,
        extension: <RetainedChallenge as BasedVectorSpace<BabyBear>>::DIMENSION,
        main_opening_points: 2,
        quotient_chunks: 8,
        batched_functions: num_batched_openings(
            BaseAir::<BabyBear>::width(air),
            true,
            0,
            false,
            8,
            <RetainedChallenge as BasedVectorSpace<BabyBear>>::DIMENSION,
            OpeningShape::hiding(4),
        ),
        domain_shift: 1,
    }
}

/// Assess the actual fixed AIR against the actual borrowed retained PCS.
/// Current RawWidth refusal precedes later parameter, symbolic and storage
/// checks. It does not validate those later checks or authorize construction.
pub fn assess_retained_class<D, I, F, R, S>(
    pcs: &HidingFriPcs<BabyBear, D, I, F, R, S>,
) -> Result<Infallible, AssessmentFailure>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear>,
    F: Mmcs<RetainedChallenge>,
    R: CryptoRng + Send + Sync,
    S: MatrixStore<BabyBear>,
{
    let air = PackedSignatureOwnerAir;
    match pcs.resource_plan::<RetainedChallenge, _>(&air, retained_request(&air)) {
        Err(reason) => Err(AssessmentFailure::Resource(reason)),
        // A changed planner cannot silently turn this boundary into a prover.
        Ok(_) => Err(AssessmentFailure::UnsupportedIntegration),
    }
}
