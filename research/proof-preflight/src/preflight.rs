//! Resource accounting only. Proof validity and security are separate.
#![forbid(unsafe_code)]
use crate::{HidingFriPcs, HidingFriProverError};
use p3_air::{
    Air,
    symbolic::{AirLayout, SymbolicAirBuilder},
};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, PrimeField64, TwoAdicField, coset::TwoAdicMultiplicativeCoset};
use p3_uni_stark::{OpeningShape, get_log_num_quotient_chunks_for_domain, num_batched_openings};
use rand::CryptoRng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub version: u32,
    pub height: usize,
    pub extension: usize,
    pub main_opening_points: usize,
    pub quotient_chunks: usize,
    pub batched_functions: usize,
    pub domain_shift: u64,
}

impl Request {
    pub const QUARTIC_V1: Self = Self {
        version: 1,
        height: 256,
        extension: 4,
        main_opening_points: 2,
        quotient_chunks: 8,
        batched_functions: 84,
        domain_shift: 1,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskBudget {
    pub extension: usize,
    pub random_columns: usize,
    pub queries: usize,
    pub points: usize,
    pub minimum_height: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub random_columns: usize,
    pub queries: usize,
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub grinding: [usize; 3],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Version,
    Extension,
    OpeningLifetime,
    Height,
    RawWidth,
    RandomColumns,
    Domain,
    Parameters,
    StoredShape,
    AirShape,
    Arithmetic,
    Quotient,
    BatchedFunctions,
    FileCount,
    FieldBytes,
    Mask(HidingFriProverError),
}

/// This record is neither a proof nor permission to admit a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourcePlan {
    pub version: u32,
    pub relation_type: &'static str,
    pub height: usize,
    pub width: usize,
    pub public_values: usize,
    pub prepared: [usize; 2],
    pub main_lde: [usize; 2],
    pub auxiliary_lde: [usize; 2],
    pub quotient_chunks: usize,
    pub batched_functions: usize,
    pub field_files: usize,
    pub field_bytes: usize,
    pub main_query_field_bytes: usize,
    pub declared_serialized_proof_cap: usize,
    pub mask_budgets: [MaskBudget; 3],
    pub parameters: Parameters,
    pub remaining_obligations: [&'static str; 7],
}

const OBLIGATIONS: [&str; 7] = [
    "hash and hiding MMCS policy",
    "actual transcript profile binding",
    "complete transport and parser bound",
    "hiding and classical theorem applicability",
    "quantum and knowledge composition",
    "same witness private ledger joins",
    "prover and storage entry integration",
];

pub(crate) fn resource_plan<Val, Dft, InputMmcs, FriMmcs, R, Store, Challenge, A>(
    pcs: &HidingFriPcs<Val, Dft, InputMmcs, FriMmcs, R, Store>,
    air: &A,
    request: Request,
) -> Result<ResourcePlan, Refusal>
where
    Val: TwoAdicField + PrimeField64,
    Dft: TwoAdicSubgroupDft<Val>,
    InputMmcs: Mmcs<Val>,
    FriMmcs: Mmcs<Challenge>,
    R: CryptoRng + Send + Sync,
    Store: crate::storage::MatrixStore<Val>,
    Challenge: TwoAdicField + ExtensionField<Val>,
    A: Air<SymbolicAirBuilder<Val>>,
{
    // Reject the complete shape before a symbolic helper can allocate its DAG.
    if request.version != 1 {
        return Err(Refusal::Version);
    }
    if request.extension != Challenge::DIMENSION || ![4, 8].contains(&Challenge::DIMENSION) {
        return Err(Refusal::Extension);
    }
    if request.main_opening_points != 2 {
        return Err(Refusal::OpeningLifetime);
    }
    if request.quotient_chunks != 8 {
        return Err(Refusal::Quotient);
    }
    if !request.height.is_power_of_two() {
        return Err(Refusal::Height);
    }
    let width = air.width();
    if width == 0 || width > 8 {
        return Err(Refusal::RawWidth);
    }
    let params = pcs.resource_parameters();
    let random = params.random_columns;
    if random > 4 {
        return Err(Refusal::RandomColumns);
    }
    let prepared_height = request.height.checked_mul(2).ok_or(Refusal::Arithmetic)?;
    if Val::ORDER_U64 != 2013265921 || request.domain_shift != 1 {
        return Err(Refusal::Domain);
    }
    if params.queries != 64
        || params.log_blowup != 3
        || params.log_final_poly_len != 0
        || params.max_log_arity != 1
        || params.grinding != [0; 3]
    {
        return Err(Refusal::Parameters);
    }
    let lde_height = prepared_height.checked_mul(8).ok_or(Refusal::Arithmetic)?;
    if lde_height.ilog2() as usize > Val::TWO_ADICITY {
        return Err(Refusal::Domain);
    }
    let main_width = width.checked_add(random).ok_or(Refusal::Arithmetic)?;
    let auxiliary_width = Challenge::DIMENSION
        .checked_add(random)
        .ok_or(Refusal::Arithmetic)?;
    if prepared_height > 4096 || lde_height > 4096 || main_width > 12 || auxiliary_width > 12 {
        return Err(Refusal::StoredShape);
    }
    if air.preprocessed_width() != 0
        || air.num_periodic_columns() != 0
        || air.num_public_values() > 8
        || !air.public_boundary_io().is_empty()
    {
        return Err(Refusal::AirShape);
    }
    let main = pcs
        .masking_preflight::<Challenge>(request.height, 2)
        .map_err(Refusal::Mask)?;
    let auxiliary = pcs
        .masking_preflight::<Challenge>(request.height, 1)
        .map_err(Refusal::Mask)?;
    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, request.height.ilog2() as usize)
        .ok_or(Refusal::Domain)?;
    let log_chunks = get_log_num_quotient_chunks_for_domain::<Val, A>(
        air,
        AirLayout::from_air::<Val>(air),
        domain,
        1,
    );
    let quotient_chunks = 1usize
        .checked_shl(
            u32::try_from(log_chunks.checked_add(1).ok_or(Refusal::Arithmetic)?)
                .map_err(|_| Refusal::Arithmetic)?,
        )
        .ok_or(Refusal::Arithmetic)?;
    if quotient_chunks != request.quotient_chunks {
        return Err(Refusal::Quotient);
    }
    let field_files = quotient_chunks.checked_add(3).ok_or(Refusal::Arithmetic)?;
    if field_files > 16 {
        return Err(Refusal::FileCount);
    }
    let batched = num_batched_openings(
        width,
        true,
        0,
        false,
        quotient_chunks,
        Challenge::DIMENSION,
        OpeningShape::hiding(random),
    );
    if batched != request.batched_functions {
        return Err(Refusal::BatchedFunctions);
    }
    let prepared_bytes = prepared_height
        .checked_mul(main_width)
        .and_then(|x| x.checked_mul(4))
        .ok_or(Refusal::Arithmetic)?;
    let auxiliary_sum = quotient_chunks
        .checked_add(1)
        .and_then(|x| x.checked_mul(auxiliary_width))
        .ok_or(Refusal::Arithmetic)?;
    let commitment_bytes = main_width
        .checked_add(auxiliary_sum)
        .and_then(|x| x.checked_mul(lde_height))
        .and_then(|x| x.checked_mul(4))
        .ok_or(Refusal::Arithmetic)?;
    let field_bytes = prepared_bytes
        .checked_add(commitment_bytes)
        .ok_or(Refusal::Arithmetic)?;
    if field_bytes > 2097152 {
        return Err(Refusal::FieldBytes);
    }
    let query_bytes = params
        .queries
        .checked_mul(main_width)
        .and_then(|x| x.checked_mul(4))
        .ok_or(Refusal::Arithmetic)?;
    Ok(ResourcePlan {
        version: 1,
        relation_type: core::any::type_name::<A>(),
        height: request.height,
        width,
        public_values: air.num_public_values(),
        prepared: [prepared_height, main_width],
        main_lde: [lde_height, main_width],
        auxiliary_lde: [lde_height, auxiliary_width],
        quotient_chunks,
        batched_functions: batched,
        field_files,
        field_bytes,
        main_query_field_bytes: query_bytes,
        declared_serialized_proof_cap: 2097152,
        mask_budgets: [main, auxiliary, auxiliary],
        parameters: params,
        remaining_obligations: OBLIGATIONS,
    })
}
