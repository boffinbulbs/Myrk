use kova_proof_preflight::{
    FriParameters, HidingFriPcs, HidingFriProverError,
    preflight::{Refusal, Request},
    storage::MatrixStore,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{ExtensionField, extension::BinomialExtensionField};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::CompressionFunctionFromHasher;
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[path = "../../storage-pcs/tests/common/hash.rs"]
pub mod hash;
// Only the AIR is used. Its retained trace constructor is never selected.
#[path = "../../storage-pcs/tests/common/air.rs"]
pub mod reference_air;

type E4 = BinomialExtensionField<BabyBear, 4>;
type E8 = BinomialExtensionField<BabyBear, 8>;
#[derive(Default, Debug)]
struct Audit {
    rng: AtomicUsize,
    storage: AtomicUsize,
    symbolic: AtomicUsize,
}
struct ObservedRng {
    inner: StdRng,
    audit: Arc<Audit>,
}
impl SeedableRng for ObservedRng {
    type Seed = [u8; 32];
    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            inner: StdRng::from_seed(seed),
            audit: Arc::new(Audit::default()),
        }
    }
}
impl TryRng for ObservedRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.audit.rng.fetch_add(1, Ordering::SeqCst);
        Ok(self.inner.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.audit.rng.fetch_add(1, Ordering::SeqCst);
        Ok(self.inner.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.audit.rng.fetch_add(1, Ordering::SeqCst);
        self.inner.fill_bytes(dst);
        Ok(())
    }
}
impl TryCryptoRng for ObservedRng {}
#[derive(Clone)]
struct TripwireStore(Arc<Audit>);
impl MatrixStore<BabyBear> for TripwireStore {
    type Stored = RowMajorMatrix<BabyBear>;
    fn store(&self, _: RowMajorMatrix<BabyBear>) -> Self::Stored {
        self.0.storage.fetch_add(1, Ordering::SeqCst);
        panic!("resource preflight must not construct field storage")
    }
}
type InputMmcs = MerkleTreeHidingMmcs<
    BabyBear,
    u64,
    hash::LeafHash,
    CompressionFunctionFromHasher<hash::NodeHash, 2, 8>,
    ObservedRng,
    2,
    8,
    16,
>;
type Pcs<E> = HidingFriPcs<
    BabyBear,
    Radix2DitParallel<BabyBear>,
    InputMmcs,
    ExtensionMmcs<BabyBear, E, InputMmcs>,
    ObservedRng,
    TripwireStore,
>;

fn config<E: ExtensionField<BabyBear>>(random: usize, queries: usize) -> (Pcs<E>, Arc<Audit>) {
    let audit = Arc::new(Audit::default());
    let rng = |seed| ObservedRng {
        inner: StdRng::from_seed([seed; 32]),
        audit: audit.clone(),
    };
    let input = InputMmcs::new(
        hash::LeafHash,
        CompressionFunctionFromHasher::new(hash::NodeHash),
        0,
        rng(19),
    );
    let ext_input = InputMmcs::new(
        hash::LeafHash,
        CompressionFunctionFromHasher::new(hash::NodeHash),
        0,
        rng(20),
    );
    let ext = ExtensionMmcs::new(ext_input);
    let params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: queries,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ext,
    };
    let pcs = HidingFriPcs::new(Radix2DitParallel::default(), input, params, random, rng(7))
        .with_storage(TripwireStore(audit.clone()));
    // Construction uses fixed public test seeds. Only subsequent preflight
    // activity is measured. This is not a production seeding test.
    (pcs, audit)
}

fn no_effects(audit: &Audit) {
    assert_eq!(audit.rng.load(Ordering::SeqCst), 0);
    assert_eq!(audit.storage.load(Ordering::SeqCst), 0);
}

#[test]
fn actual_masking_helper_boundaries() {
    let (pcs, audit) = config::<E4>(4, 64);
    assert_eq!(
        pcs.masking_preflight::<E4>(144, 2).unwrap().minimum_height,
        144
    );
    assert!(matches!(
        pcs.masking_preflight::<E4>(143, 2),
        Err(HidingFriProverError::HidingBudgetExceeded { .. })
    ));
    assert_eq!(pcs.masking_preflight::<E4>(136, 0).unwrap().points, 1);
    assert_eq!(
        pcs.masking_preflight::<E4>(136, 0).unwrap().minimum_height,
        136
    );
    assert_eq!(
        pcs.masking_preflight::<E4>(usize::MAX, usize::MAX),
        Err(HidingFriProverError::BudgetOverflow)
    );
    no_effects(&audit);
    let (pcs8, audit8) = config::<E8>(8, 64);
    assert_eq!(
        pcs8.masking_preflight::<E8>(160, 2).unwrap().minimum_height,
        160
    );
    no_effects(&audit8);
    let (short, short_audit) = config::<E8>(4, 64);
    assert_eq!(
        short.masking_preflight::<E8>(256, 2),
        Err(HidingFriProverError::InsufficientRandomCodewords {
            required: 8,
            got: 4
        })
    );
    no_effects(&short_audit);
}

#[test]
fn resource_plan_uses_retained_air_and_helpers() {
    let (pcs, audit) = config::<E4>(4, 64);
    let result = pcs
        .resource_plan::<E4, _>(&reference_air::QuarticAir, Request::QUARTIC_V1)
        .unwrap();
    assert_eq!(
        (
            result.width,
            result.public_values,
            result.quotient_chunks,
            result.batched_functions
        ),
        (2, 2, 8, 84)
    );
    assert_eq!(result.prepared, [512, 6]);
    assert_eq!(result.main_lde, [4096, 6]);
    assert_eq!(result.auxiliary_lde, [4096, 8]);
    assert_eq!(
        (
            result.field_files,
            result.field_bytes,
            result.main_query_field_bytes
        ),
        (11, 1290240, 1536)
    );
    assert_eq!(
        result.mask_budgets.map(|x| x.minimum_height),
        [144, 136, 136]
    );
    assert_eq!(result.remaining_obligations.len(), 7);
    let recorded: serde_json::Value =
        serde_json::from_str(include_str!("../../storage-pcs/validation.json")).unwrap();
    assert_eq!(
        result.field_files as u64,
        recorded["total_field_files"].as_u64().unwrap()
    );
    assert_eq!(
        result.field_bytes as u64,
        recorded["total_field_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        result.prepared.to_vec(),
        recorded["prepared_source_shape"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as usize)
            .collect::<Vec<_>>()
    );
    no_effects(&audit);
}

struct RefusedAir {
    audit: Arc<Audit>,
    width: usize,
}
impl<F> BaseAir<F> for RefusedAir {
    fn width(&self) -> usize {
        self.width
    }
}
impl<AB: AirBuilder> Air<AB> for RefusedAir {
    fn eval(&self, _: &mut AB) {
        self.audit.symbolic.fetch_add(1, Ordering::SeqCst);
        panic!("cheap refusal must precede symbolic evaluation")
    }
}

#[test]
fn complete_shapes_refuse_before_symbolic_or_entropy() {
    let (pcs, audit) = config::<E4>(4, 64);
    let request = Request {
        height: 8192,
        ..Request::QUARTIC_V1
    };
    assert_eq!(
        pcs.resource_plan::<E4, _>(&kova_signature_storage::FactorSignatureOwnerAir, request),
        Err(Refusal::RawWidth)
    );
    let air = RefusedAir {
        audit: audit.clone(),
        width: 2,
    };
    assert_eq!(
        pcs.resource_plan::<E4, _>(&air, request),
        Err(Refusal::StoredShape)
    );
    assert_eq!(
        pcs.resource_plan::<E4, _>(
            &air,
            Request {
                height: 1usize << (usize::BITS - 1),
                ..request
            }
        ),
        Err(Refusal::Arithmetic)
    );
    assert_eq!(
        pcs.resource_plan::<E4, _>(
            &air,
            Request {
                height: 256,
                quotient_chunks: usize::MAX,
                ..request
            }
        ),
        Err(Refusal::Quotient)
    );
    assert_eq!(audit.symbolic.load(Ordering::SeqCst), 0);
    no_effects(&audit);
    let (pcs8, audit8) = config::<E8>(8, 128);
    let request8 = Request {
        extension: 8,
        ..request
    };
    assert_eq!(
        pcs8.resource_plan::<E8, _>(&kova_signature_storage::FactorSignatureOwnerAir, request8),
        Err(Refusal::RawWidth)
    );
    assert_eq!(
        pcs8.resource_plan::<E8, _>(
            &air,
            Request {
                height: 256,
                ..request8
            }
        ),
        Err(Refusal::RandomColumns)
    );
    no_effects(&audit8);
}

#[test]
fn malformed_descriptors_and_shape_claims_refuse() {
    let (pcs, audit) = config::<E4>(4, 64);
    let air = reference_air::QuarticAir;
    let base = Request::QUARTIC_V1;
    for (request, expected) in [
        (Request { version: 2, ..base }, Refusal::Version),
        (
            Request {
                extension: 8,
                ..base
            },
            Refusal::Extension,
        ),
        (
            Request {
                main_opening_points: 0,
                ..base
            },
            Refusal::OpeningLifetime,
        ),
        (Request { height: 0, ..base }, Refusal::Height),
        (
            Request {
                height: 255,
                ..base
            },
            Refusal::Height,
        ),
        (
            Request {
                domain_shift: 2,
                ..base
            },
            Refusal::Domain,
        ),
        (
            Request {
                quotient_chunks: 4,
                ..base
            },
            Refusal::Quotient,
        ),
        (
            Request {
                batched_functions: 85,
                ..base
            },
            Refusal::BatchedFunctions,
        ),
    ] {
        assert_eq!(pcs.resource_plan::<E4, _>(&air, request), Err(expected));
    }
    let (short, other) = config::<E4>(3, 64);
    assert!(matches!(
        short.resource_plan::<E4, _>(&air, base),
        Err(Refusal::Mask(
            HidingFriProverError::InsufficientRandomCodewords { .. }
        ))
    ));
    no_effects(&other);
    let (changed, other) = config::<E4>(4, 128);
    assert_eq!(
        changed.resource_plan::<E4, _>(&air, base),
        Err(Refusal::Parameters)
    );
    no_effects(&other);
    no_effects(&audit);
}
