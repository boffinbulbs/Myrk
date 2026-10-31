//! Full small proof observer using retained hash, DFT and MMCS operations.
//! Counter and RNG framing derive from mask-normalization diagnostics_setup.
//! MMCS phase/shape observations derive from source-stark/tests/common.rs.
//! No leaf preimages, expected roots or acceptance callbacks are supplied.
use crate::{Context, FriParameters, HidingFriPcs};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{BatchOpening, BatchOpeningRef, ExtensionMmcs, Mmcs};
use p3_dft::{Layout, Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{
    Dimensions, Matrix,
    bitrev::BitReversedMatrixView,
    dense::{RowMajorMatrix, RowMajorMatrixView, RowMajorMatrixViewMut},
};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::CompressionFunctionFromHasher;
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
use sha3::{Digest, Sha3_256};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

// The actual retained SHA3-512 leaf/node/transcript framing is reused unchanged.
// hash.rs SHA256 e669f5b7b4c3675e4747eff41933a9ff8327951bb32c32aff22aa97d5431704a.
#[path = "../../storage-pcs/tests/common/hash.rs"]
mod hash;

type Challenge = crate::composite::Challenge;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct RngCounts {
    pub bytes: usize,
    pub next_u32: usize,
    pub next_u64: usize,
    pub fill_bytes: usize,
}
#[derive(Default)]
struct Journal {
    bytes: AtomicUsize,
    next_u32: AtomicUsize,
    next_u64: AtomicUsize,
    fill_bytes: AtomicUsize,
    digest: std::sync::Mutex<Sha3_256>,
}
impl Journal {
    fn observe(&self, bytes: &[u8]) {
        self.digest.lock().unwrap().update(bytes);
    }
    fn fingerprint(&self) -> [u8; 32] {
        self.digest.lock().unwrap().clone().finalize().into()
    }
    fn counts(&self) -> RngCounts {
        RngCounts {
            bytes: self.bytes.load(Ordering::SeqCst),
            next_u32: self.next_u32.load(Ordering::SeqCst),
            next_u64: self.next_u64.load(Ordering::SeqCst),
            fill_bytes: self.fill_bytes.load(Ordering::SeqCst),
        }
    }
}

/// Counts bytes delivered by the original seeded source, not stored entropy.
/// SeedableRng forks construct their own journal, exactly as the old observer
/// did. Source-stream advancement therefore observes a clone's seed draw, not
/// every later draw made by an otherwise unobserved fork. Extension use is
/// counted separately, and MMCS clone entries retain their original fork.
pub(super) struct Observed {
    inner: StdRng,
    journal: Arc<Journal>,
}
impl Observed {
    fn new(seed: u8, journal: Arc<Journal>) -> Self {
        Self {
            inner: StdRng::from_seed([seed; 32]),
            journal,
        }
    }
}
impl SeedableRng for Observed {
    type Seed = [u8; 32];
    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            inner: StdRng::from_seed(seed),
            journal: Arc::new(Journal::default()),
        }
    }
}
impl TryRng for Observed {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let value = self.inner.next_u32();
        self.journal.observe(&value.to_le_bytes());
        self.journal.next_u32.fetch_add(1, Ordering::SeqCst);
        self.journal.bytes.fetch_add(4, Ordering::SeqCst);
        Ok(value)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let value = self.inner.next_u64();
        self.journal.observe(&value.to_le_bytes());
        self.journal.next_u64.fetch_add(1, Ordering::SeqCst);
        self.journal.bytes.fetch_add(8, Ordering::SeqCst);
        Ok(value)
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Infallible> {
        self.inner.fill_bytes(destination);
        self.journal.observe(destination);
        self.journal.fill_bytes.fetch_add(1, Ordering::SeqCst);
        self.journal
            .bytes
            .fetch_add(destination.len(), Ordering::SeqCst);
        Ok(())
    }
}
impl TryCryptoRng for Observed {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct DftCounts {
    pub dft_batch: usize,
    pub coset_dft_batch: usize,
    pub idft_batch: usize,
    pub coset_idft_batch: usize,
    pub lde_batch: usize,
    pub coset_lde_batch: usize,
    pub coset_lde_batch_with_transform: usize,
    pub coset_lde_batch_with_blocks: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct Counts {
    pub input_commits: usize,
    pub extension_commits: usize,
    pub scalar_opens: usize,
    pub input_openings: usize,
    pub extension_openings: usize,
    pub input_multi_opens: usize,
    pub extension_multi_opens: usize,
    pub verify_calls: usize,
    pub get_matrices: usize,
    pub mmcs_clones: usize,
    pub dft: DftCounts,
    pub mask: RngCounts,
    pub salt: RngCounts,
    pub initial_salt_bytes: usize,
}
#[derive(Default)]
pub(super) struct Audit {
    input_commits: AtomicUsize,
    extension_commits: AtomicUsize,
    scalar_opens: AtomicUsize,
    input_openings: AtomicUsize,
    extension_openings: AtomicUsize,
    input_multi_opens: AtomicUsize,
    extension_multi_opens: AtomicUsize,
    verify_calls: AtomicUsize,
    get_matrices: AtomicUsize,
    mmcs_clones: AtomicUsize,
    dft: [AtomicUsize; 8],
    mask: Arc<Journal>,
    salt: Arc<Journal>,
    initial_salt_bytes: AtomicUsize,
    owner: std::sync::Mutex<Option<std::sync::Weak<OwnedContext>>>,
    roots: std::sync::Mutex<Vec<serde_json::Value>>,
}
impl Audit {
    pub(super) fn bind_owner(&self, owner: &Arc<OwnedContext>) {
        *self.owner.lock().unwrap() = Some(Arc::downgrade(owner));
    }
    pub(super) fn roots(&self) -> Vec<serde_json::Value> {
        self.roots.lock().unwrap().clone()
    }
    fn phase(&self, expected: crate::Phase) {
        if let Some(owner) = self
            .owner
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            let state = owner.snapshot().unwrap();
            assert_eq!(state.phase, expected);
            assert_eq!(
                (state.reserved_files, state.reserved_bytes),
                (13, 1_325_056)
            );
            assert!(state.failure.is_none());
        }
    }
    pub(super) fn delivered_fingerprints(&self) -> [[u8; 32]; 2] {
        [self.mask.fingerprint(), self.salt.fingerprint()]
    }
    /// Call only at the fixed serial diagnostic boundaries, after operations
    /// have returned. Separate atomic loads are not a concurrent snapshot.
    pub(super) fn detailed_counts(&self) -> Counts {
        let d = self.dft.each_ref().map(|n| n.load(Ordering::SeqCst));
        Counts {
            input_commits: self.input_commits.load(Ordering::SeqCst),
            extension_commits: self.extension_commits.load(Ordering::SeqCst),
            scalar_opens: self.scalar_opens.load(Ordering::SeqCst),
            input_openings: self.input_openings.load(Ordering::SeqCst),
            extension_openings: self.extension_openings.load(Ordering::SeqCst),
            input_multi_opens: self.input_multi_opens.load(Ordering::SeqCst),
            extension_multi_opens: self.extension_multi_opens.load(Ordering::SeqCst),
            verify_calls: self.verify_calls.load(Ordering::SeqCst),
            get_matrices: self.get_matrices.load(Ordering::SeqCst),
            mmcs_clones: self.mmcs_clones.load(Ordering::SeqCst),
            dft: DftCounts {
                dft_batch: d[0],
                coset_dft_batch: d[1],
                idft_batch: d[2],
                coset_idft_batch: d[3],
                lde_batch: d[4],
                coset_lde_batch: d[5],
                coset_lde_batch_with_transform: d[6],
                coset_lde_batch_with_blocks: d[7],
            },
            mask: self.mask.counts(),
            salt: self.salt.counts(),
            initial_salt_bytes: self.initial_salt_bytes.load(Ordering::SeqCst),
        }
    }
}

/// Retained optimized methods are delegated, not replaced by trait defaults.
/// These are *wrapper entry* counts: inner coset_lde_batch performs its own
/// inverse/forward operations which do not reenter this wrapper. The scalar
/// and algebra defaults remain the retained trait defaults and reach a batch
/// entry here. Counts do not measure internal FFT butterflies or all arithmetic.
#[derive(Clone, Default)]
pub(super) struct CountingDft {
    inner: Radix2DitParallel<BabyBear>,
    audit: Arc<Audit>,
}
impl TwoAdicSubgroupDft<BabyBear> for CountingDft {
    type Evaluations = <Radix2DitParallel<BabyBear> as TwoAdicSubgroupDft<BabyBear>>::Evaluations;
    fn dft_batch(&self, matrix: RowMajorMatrix<BabyBear>) -> Self::Evaluations {
        self.audit.dft[0].fetch_add(1, Ordering::SeqCst);
        self.inner.dft_batch(matrix)
    }
    fn coset_dft_batch(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        shift: BabyBear,
    ) -> Self::Evaluations {
        self.audit.dft[1].fetch_add(1, Ordering::SeqCst);
        self.inner.coset_dft_batch(matrix, shift)
    }
    fn idft_batch(&self, matrix: RowMajorMatrix<BabyBear>) -> RowMajorMatrix<BabyBear> {
        self.audit.dft[2].fetch_add(1, Ordering::SeqCst);
        self.inner.idft_batch(matrix)
    }
    fn coset_idft_batch(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        shift: BabyBear,
    ) -> RowMajorMatrix<BabyBear> {
        self.audit.dft[3].fetch_add(1, Ordering::SeqCst);
        self.inner.coset_idft_batch(matrix, shift)
    }
    fn lde_batch(&self, matrix: RowMajorMatrix<BabyBear>, added_bits: usize) -> Self::Evaluations {
        self.audit.dft[4].fetch_add(1, Ordering::SeqCst);
        self.inner.lde_batch(matrix, added_bits)
    }
    fn coset_lde_batch(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        added_bits: usize,
        shift: BabyBear,
    ) -> Self::Evaluations {
        self.audit.dft[5].fetch_add(1, Ordering::SeqCst);
        self.inner.coset_lde_batch(matrix, added_bits, shift)
    }
    fn coset_lde_batch_with_transform<T>(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        added_bits: usize,
        shift: BabyBear,
        transform: T,
    ) -> Self::Evaluations
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, BabyBear>, Layout),
    {
        self.audit.dft[6].fetch_add(1, Ordering::SeqCst);
        self.inner
            .coset_lde_batch_with_transform(matrix, added_bits, shift, transform)
    }
    fn coset_lde_batch_with_blocks<T, K, C>(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        added_bits: usize,
        shift: BabyBear,
        transform: T,
        make_consumer: K,
    ) -> BitReversedMatrixView<RowMajorMatrix<BabyBear>>
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, BabyBear>, Layout),
        K: FnOnce(usize) -> C,
        C: Fn(usize, RowMajorMatrixView<'_, BabyBear>) + Sync,
    {
        self.audit.dft[7].fetch_add(1, Ordering::SeqCst);
        self.inner
            .coset_lde_batch_with_blocks(matrix, added_bits, shift, transform, make_consumer)
    }
}

type Inner = MerkleTreeHidingMmcs<
    BabyBear,
    u64,
    hash::LeafHash,
    CompressionFunctionFromHasher<hash::NodeHash, 2, 8>,
    Observed,
    2,
    8,
    16,
>;
pub(super) struct InputSpy {
    inner: Inner,
    audit: Arc<Audit>,
    extension: bool,
}
impl Clone for InputSpy {
    fn clone(&self) -> Self {
        self.audit.mmcs_clones.fetch_add(1, Ordering::SeqCst);
        Self {
            inner: self.inner.clone(),
            audit: self.audit.clone(),
            extension: self.extension,
        }
    }
}
impl Mmcs<BabyBear> for InputSpy {
    type ProverData<M> = <Inner as Mmcs<BabyBear>>::ProverData<M>;
    type Commitment = <Inner as Mmcs<BabyBear>>::Commitment;
    type Proof = <Inner as Mmcs<BabyBear>>::Proof;
    type MultiProof = <Inner as Mmcs<BabyBear>>::MultiProof;
    type Error = <Inner as Mmcs<BabyBear>>::Error;

    fn commit<M: Matrix<BabyBear>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        let (shape, phase) = if self.extension {
            let round = self.audit.extension_commits.fetch_add(1, Ordering::SeqCst);
            assert!(round < 9, "finite FRI commitment count");
            ([1, 2048 >> round, 8], crate::Phase::Opening)
        } else {
            let round = self.audit.input_commits.fetch_add(1, Ordering::SeqCst);
            assert!(round < 3, "finite input commitment count");
            (
                [[1, 4096, 6], [8, 4096, 8], [1, 4096, 8]][round],
                [
                    crate::Phase::MainCommitting,
                    crate::Phase::QuotientCommitting,
                    crate::Phase::AuxiliaryCommitting,
                ][round],
            )
        };
        self.audit.phase(phase);
        assert_eq!(inputs.len(), shape[0]);
        assert!(
            inputs
                .iter()
                .all(|m| [m.height(), m.width()] == [shape[1], shape[2]])
        );
        let result = self.inner.commit(inputs);
        self.audit
            .roots
            .lock()
            .unwrap()
            .push(serde_json::to_value(&result.0).unwrap());
        result
    }

    fn get_matrices<'a, M: Matrix<BabyBear>>(&self, data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        self.audit.get_matrices.fetch_add(1, Ordering::SeqCst);
        self.inner.get_matrices(data)
    }

    fn open_batch<M: Matrix<BabyBear>>(
        &self,
        _: usize,
        _: &Self::ProverData<M>,
    ) -> BatchOpening<BabyBear, Self> {
        self.audit.scalar_opens.fetch_add(1, Ordering::SeqCst);
        panic!("the fixed complete proof uses only batched openings")
    }

    fn open_multi_batch<M: Matrix<BabyBear>>(
        &self,
        indices: &[usize],
        data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<BabyBear>>>, Self::MultiProof) {
        assert_eq!(indices.len(), 64);
        let shape = if self.extension {
            self.audit.extension_openings.fetch_add(1, Ordering::SeqCst);
            let round = self
                .audit
                .extension_multi_opens
                .fetch_add(1, Ordering::SeqCst);
            assert!(round < 9, "finite FRI opening count");
            [1, 2048 >> round, 8]
        } else {
            self.audit.input_openings.fetch_add(1, Ordering::SeqCst);
            let round = self.audit.input_multi_opens.fetch_add(1, Ordering::SeqCst);
            assert!(round < 3, "finite input opening count");
            [[1, 4096, 8], [1, 4096, 6], [8, 4096, 8]][round]
        };
        self.audit.phase(crate::Phase::Opening);
        let matrices = self.inner.get_matrices(data);
        assert_eq!(matrices.len(), shape[0]);
        assert!(
            matrices
                .iter()
                .all(|m| [m.height(), m.width()] == [shape[1], shape[2]])
        );
        assert!(indices.iter().all(|&index| index < shape[1]));
        self.inner.open_multi_batch(indices, data)
    }

    fn verify_batch(
        &self,
        _: &Self::Commitment,
        _: &[Dimensions],
        _: usize,
        _: BatchOpeningRef<'_, BabyBear, Self>,
    ) -> Result<(), Self::Error> {
        self.audit.verify_calls.fetch_add(1, Ordering::SeqCst);
        panic!("the retained verifier uses only batched verification")
    }

    fn verify_multi_batch<T: AsRef<[BabyBear]> + PartialEq>(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        values: &[Vec<T>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.audit.verify_calls.fetch_add(1, Ordering::SeqCst);
        assert!(dimensions.len() <= 8);
        assert_eq!(indices.len(), 64);
        self.inner
            .verify_multi_batch(commitment, dimensions, indices, values, proof)
    }
}

type Ext = ExtensionMmcs<BabyBear, Challenge, InputSpy>;
pub(super) type Base = HidingFriPcs<BabyBear, CountingDft, InputSpy, Ext, Observed>;
pub(super) type Anchor =
    kova_proof_preflight::HidingFriPcs<BabyBear, CountingDft, InputSpy, Ext, Observed>;
pub(super) type OwnedContext = Context<CountingDft, InputSpy, Ext, Observed, Challenger>;
pub(super) type Challenger =
    SerializingChallenger32<BabyBear, HashChallenger<u8, hash::TranscriptHash, 64>>;

fn parts() -> (CountingDft, InputSpy, Ext, Observed, Arc<Audit>) {
    let audit = Arc::new(Audit::default());
    let input = InputSpy {
        inner: Inner::new(
            hash::LeafHash,
            CompressionFunctionFromHasher::new(hash::NodeHash),
            0,
            Observed::new(19, audit.salt.clone()),
        ),
        audit: audit.clone(),
        extension: false,
    };
    // This is the retained construction-time salt fork, not an operation to
    // reset away. Its source-byte baseline is captured after the actual clone.
    let mut child = input.clone();
    child.extension = true;
    audit
        .initial_salt_bytes
        .store(audit.salt.counts().bytes, Ordering::SeqCst);
    (
        CountingDft {
            inner: Radix2DitParallel::default(),
            audit: audit.clone(),
        },
        input,
        Ext::new(child),
        Observed::new(7, audit.mask.clone()),
        audit,
    )
}
pub(super) fn base() -> (Base, Arc<Audit>) {
    let (dft, input, mmcs, rng, audit) = parts();
    (
        Base::new(
            dft,
            input,
            FriParameters {
                log_blowup: 3,
                log_final_poly_len: 0,
                max_log_arity: 1,
                num_queries: 64,
                batch_proof_of_work_bits: 0,
                commit_proof_of_work_bits: 0,
                query_proof_of_work_bits: 0,
                mmcs,
            },
            4,
            rng,
        ),
        audit,
    )
}
pub(super) fn anchor() -> (Anchor, Arc<Audit>) {
    let (dft, input, mmcs, rng, audit) = parts();
    (
        Anchor::new(
            dft,
            input,
            kova_proof_preflight::FriParameters {
                log_blowup: 3,
                log_final_poly_len: 0,
                max_log_arity: 1,
                num_queries: 64,
                batch_proof_of_work_bits: 0,
                commit_proof_of_work_bits: 0,
                query_proof_of_work_bits: 0,
                mmcs,
            },
            4,
            rng,
        ),
        audit,
    )
}
pub(super) fn challenger() -> Challenger {
    Challenger::new(HashChallenger::new(
        b"kova.storage-pcs.quartic.v1".to_vec(),
        hash::TranscriptHash,
    ))
}

pub(super) fn different_challenger() -> Challenger {
    Challenger::new(HashChallenger::new(
        b"kova.storage-pcs.quartic.altered-context".to_vec(),
        hash::TranscriptHash,
    ))
}

/// Parse the frozen synthetic literal; do not invoke air::trace or evaluate
/// any polynomial here. The actual bound applies before JSON allocation.
/// trace.json SHA256 240051c8b99b3626dd6bebe8a27fef0512a4e928425b27e69db2f1ce6b950c52.
pub(super) fn rawliteral() -> Vec<BabyBear> {
    const RAW: &[u8] = include_bytes!("../../storage-pcs/fixtures/trace.json");
    const { assert!(RAW.len() <= 65_536) };
    let rows: Vec<[u32; 2]> = serde_json::from_slice(RAW).expect("frozen trace JSON");
    assert_eq!(rows.len(), 256);
    rows.into_iter()
        .flatten()
        .map(|value| {
            assert!(value < BabyBear::ORDER_U32, "canonical literal field");
            BabyBear::from_u32(value)
        })
        .collect()
}
