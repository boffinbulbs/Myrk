//! Owned input binding and resource assessment for the fixed packed relation.
//! This boundary constructs neither a trace nor a private payment proof.
#![forbid(unsafe_code)]

use core::convert::Infallible;
use kova_proof_preflight::{
    HidingFriPcs,
    preflight::{Refusal, Request},
    storage::MatrixStore,
};
use kova_signature_packed::{PackedSignatureOwnerAir, Statement, Witness, layout::HEIGHT};
use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{BasedVectorSpace, extension::BinomialExtensionField};
use p3_uni_stark::{OpeningShape, num_batched_openings};
use rand::CryptoRng;
use thorum_relation_lab::{PaymentStatement, RelationError};

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
