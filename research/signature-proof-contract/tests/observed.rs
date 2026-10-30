// Actual retained PCS fixture adapted from proof-preflight/tests/preflight.rs.
use kova_proof_preflight::{
    FriParameters, HidingFriPcs,
    storage::{MatrixStore, RowSource},
};
use p3_baby_bear::BabyBear;
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::CompressionFunctionFromHasher;
use rand::{
    Rng, SeedableRng, TryCryptoRng, TryRng,
    distr::{Distribution, StandardUniform},
    rngs::StdRng,
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[path = "../../storage-pcs/tests/common/hash.rs"]
pub mod hash;

#[derive(Default)]
pub struct Audit {
    rng: AtomicUsize,
    storage: AtomicUsize,
    store_clones: AtomicUsize,
}
impl Audit {
    pub fn snapshot(&self) -> [usize; 3] {
        [
            self.rng.load(Ordering::SeqCst),
            self.storage.load(Ordering::SeqCst),
            self.store_clones.load(Ordering::SeqCst),
        ]
    }
    fn forbidden_storage(&self) -> ! {
        self.storage.fetch_add(1, Ordering::SeqCst);
        panic!("packed resource denial must precede every storage hook")
    }
}

pub struct ObservedRng {
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
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Infallible> {
        self.audit.rng.fetch_add(1, Ordering::SeqCst);
        self.inner.fill_bytes(bytes);
        Ok(())
    }
}
impl TryCryptoRng for ObservedRng {}

pub struct TripwireStore(Arc<Audit>);
impl Clone for TripwireStore {
    fn clone(&self) -> Self {
        self.0.store_clones.fetch_add(1, Ordering::SeqCst);
        Self(self.0.clone())
    }
}
impl MatrixStore<BabyBear> for TripwireStore {
    type Stored = RowMajorMatrix<BabyBear>;
    fn store(&self, _: RowMajorMatrix<BabyBear>) -> Self::Stored {
        self.0.forbidden_storage()
    }
    fn randomize<R>(&self, _: RowMajorMatrix<BabyBear>, _: usize, _: &mut R) -> Self::Stored
    where
        R: Rng + Send + Sync,
        StandardUniform: Distribution<BabyBear>,
    {
        self.0.forbidden_storage()
    }
    fn extend_prepared<D, M>(&self, _: &D, _: M, _: usize, _: BabyBear) -> Self::Stored
    where
        D: TwoAdicSubgroupDft<BabyBear>,
        M: RowSource<BabyBear>,
    {
        self.0.forbidden_storage()
    }
    fn extend<D>(&self, _: &D, _: RowMajorMatrix<BabyBear>, _: usize, _: BabyBear) -> Self::Stored
    where
        D: TwoAdicSubgroupDft<BabyBear>,
    {
        self.0.forbidden_storage()
    }
    fn extend_quotient<D>(
        &self,
        _: &D,
        _: RowMajorMatrix<BabyBear>,
        _: &[BabyBear],
        _: usize,
        _: BabyBear,
    ) -> Self::Stored
    where
        D: TwoAdicSubgroupDft<BabyBear>,
    {
        self.0.forbidden_storage()
    }
}

type E4 = BinomialExtensionField<BabyBear, 4>;
type Input = MerkleTreeHidingMmcs<
    BabyBear,
    u64,
    hash::LeafHash,
    CompressionFunctionFromHasher<hash::NodeHash, 2, 8>,
    ObservedRng,
    2,
    8,
    16,
>;
pub type Pcs = HidingFriPcs<
    BabyBear,
    Radix2DitParallel<BabyBear>,
    Input,
    ExtensionMmcs<BabyBear, E4, Input>,
    ObservedRng,
    TripwireStore,
>;

pub fn config(queries: usize) -> (Pcs, Arc<Audit>) {
    let audit = Arc::new(Audit::default());
    // Public deterministic fixture seeds, outside the observation interval.
    let rng = |seed| ObservedRng {
        inner: StdRng::from_seed([seed; 32]),
        audit: audit.clone(),
    };
    let input = Input::new(
        hash::LeafHash,
        CompressionFunctionFromHasher::new(hash::NodeHash),
        0,
        rng(19),
    );
    let ext_input = Input::new(
        hash::LeafHash,
        CompressionFunctionFromHasher::new(hash::NodeHash),
        0,
        rng(20),
    );
    let params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: queries,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ExtensionMmcs::new(ext_input),
    };
    let pcs = HidingFriPcs::new(Radix2DitParallel::default(), input, params, 4, rng(7))
        .with_storage(TripwireStore(audit.clone()));
    (pcs, audit)
}
