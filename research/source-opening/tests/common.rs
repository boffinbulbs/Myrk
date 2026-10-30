use kova_source_commitment::{
    FriParameters, HidingFriPcs,
    source::{Challenge, Phase, SourceStore},
};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{BatchOpening, BatchOpeningRef, ExtensionMmcs, Mmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, PrimeField32, coset::TwoAdicMultiplicativeCoset};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
use std::{
    convert::Infallible,
    fs::{self, OpenOptions},
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[path = "../../storage-pcs/tests/common/air.rs"]
pub mod air;
#[path = "../../storage-pcs/tests/common/hash.rs"]
pub mod hash;

#[derive(Default)]
struct Journal(Mutex<Vec<u8>>);
impl Journal {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}
struct Observed {
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
        let v = self.inner.next_u32();
        let mut j = self.journal.0.lock().unwrap();
        j.push(4);
        j.extend(v.to_le_bytes());
        Ok(v)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let v = self.inner.next_u64();
        let mut j = self.journal.0.lock().unwrap();
        j.push(8);
        j.extend(v.to_le_bytes());
        Ok(v)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.inner.fill_bytes(dst);
        let mut j = self.journal.0.lock().unwrap();
        j.push(0);
        j.extend((dst.len() as u64).to_le_bytes());
        j.extend_from_slice(dst);
        Ok(())
    }
}
impl TryCryptoRng for Observed {}
#[derive(Default)]
struct Audit {
    input_commits: AtomicUsize,
    extension_commits: AtomicUsize,
    input_opens: AtomicUsize,
    extension_opens: AtomicUsize,
    scalar_opens: AtomicUsize,
    capturing: AtomicBool,
    leaf_width: AtomicUsize,
    leaves: Mutex<Vec<u8>>,
    shapes: Mutex<Vec<[usize; 2]>>,
    owner: Mutex<Option<SourceStore>>,
}
#[derive(Clone)]
struct Leaf(Arc<Audit>);
impl CryptographicHasher<BabyBear, [u64; 8]> for Leaf {
    fn hash_iter<I: IntoIterator<Item = BabyBear>>(&self, input: I) -> [u64; 8] {
        let values: Vec<_> = input.into_iter().collect();
        if self.0.capturing.load(Ordering::SeqCst) {
            assert_eq!(values.len(), self.0.leaf_width.load(Ordering::SeqCst));
            let mut captured = self.0.leaves.lock().unwrap();
            for value in &values {
                captured.extend(value.as_canonical_u32().to_le_bytes());
            }
            assert!(captured.len() <= 752896);
        }
        hash::LeafHash.hash_iter(values)
    }
}
type Inner = MerkleTreeHidingMmcs<
    BabyBear,
    u64,
    Leaf,
    CompressionFunctionFromHasher<hash::NodeHash, 2, 8>,
    Observed,
    2,
    8,
    16,
>;
#[derive(Clone)]
struct Spy {
    inner: Inner,
    audit: Arc<Audit>,
    extension: bool,
}
impl Mmcs<BabyBear> for Spy {
    type ProverData<M> = <Inner as Mmcs<BabyBear>>::ProverData<M>;
    type Commitment = <Inner as Mmcs<BabyBear>>::Commitment;
    type Proof = <Inner as Mmcs<BabyBear>>::Proof;
    type MultiProof = <Inner as Mmcs<BabyBear>>::MultiProof;
    type Error = <Inner as Mmcs<BabyBear>>::Error;
    fn commit<M: Matrix<BabyBear>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        let expected = if self.extension {
            let round = self.audit.extension_commits.fetch_add(1, Ordering::SeqCst);
            assert!(round < 9);
            [2048 >> round, 8]
        } else {
            assert_eq!(self.audit.input_commits.fetch_add(1, Ordering::SeqCst), 0);
            [4096, 6]
        };
        if let Some(owner) = &*self.audit.owner.lock().unwrap() {
            let s = owner.snapshot().unwrap();
            assert_eq!(
                s.phase,
                if self.extension {
                    Phase::Committed
                } else {
                    Phase::Committing
                }
            );
            assert_eq!(s.construction.phase, kova_source_extension::Phase::LdeReady);
        }
        assert_eq!(inputs.len(), 1);
        assert_eq!([inputs[0].height(), inputs[0].width()], expected);
        self.audit.shapes.lock().unwrap().push(expected);
        self.audit
            .leaf_width
            .store(expected[1] + 16, Ordering::SeqCst);
        assert!(!self.audit.capturing.swap(true, Ordering::SeqCst));
        let result = self.inner.commit(inputs);
        self.audit.capturing.store(false, Ordering::SeqCst);
        result
    }
    fn open_batch<M: Matrix<BabyBear>>(
        &self,
        index: usize,
        data: &Self::ProverData<M>,
    ) -> BatchOpening<BabyBear, Self> {
        self.audit.scalar_opens.fetch_add(1, Ordering::SeqCst);
        let (v, p) = self.inner.open_batch(index, data).unpack();
        BatchOpening::new(v, p)
    }
    fn get_matrices<'a, M: Matrix<BabyBear>>(&self, data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        self.inner.get_matrices(data)
    }
    fn verify_batch(
        &self,
        c: &Self::Commitment,
        d: &[Dimensions],
        i: usize,
        b: BatchOpeningRef<'_, BabyBear, Self>,
    ) -> Result<(), Self::Error> {
        let (v, p) = b.unpack();
        self.inner.verify_batch(c, d, i, BatchOpeningRef::new(v, p))
    }
    fn open_multi_batch<M: Matrix<BabyBear>>(
        &self,
        indices: &[usize],
        data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<BabyBear>>>, Self::MultiProof) {
        assert_eq!(indices.len(), 64);
        let expected = if self.extension {
            let round = self.audit.extension_opens.fetch_add(1, Ordering::SeqCst);
            assert!(round < 9);
            [2048 >> round, 8]
        } else {
            assert_eq!(self.audit.input_opens.fetch_add(1, Ordering::SeqCst), 0);
            [4096, 6]
        };
        let matrices = self.inner.get_matrices(data);
        assert_eq!(matrices.len(), 1);
        assert_eq!([matrices[0].height(), matrices[0].width()], expected);
        assert!(indices.iter().all(|&i| i < expected[0]));
        if let Some(owner) = &*self.audit.owner.lock().unwrap() {
            assert_eq!(owner.snapshot().unwrap().phase, Phase::Committed);
        }
        self.inner.open_multi_batch(indices, data)
    }
    fn verify_multi_batch<T: AsRef<[BabyBear]> + PartialEq>(
        &self,
        c: &Self::Commitment,
        d: &[Dimensions],
        i: &[usize],
        v: &[Vec<T>],
        p: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.inner.verify_multi_batch(c, d, i, v, p)
    }
}
type Ext = ExtensionMmcs<BabyBear, Challenge, Spy>;
type Base = HidingFriPcs<BabyBear, Radix2DitParallel<BabyBear>, Spy, Ext, Observed>;
type Owned = HidingFriPcs<BabyBear, Radix2DitParallel<BabyBear>, Spy, Ext, Observed, SourceStore>;
type Anchor =
    kova_proof_preflight::HidingFriPcs<BabyBear, Radix2DitParallel<BabyBear>, Spy, Ext, Observed>;
type Dense = p3_fri::HidingFriPcs<BabyBear, Radix2DitParallel<BabyBear>, Spy, Ext, Observed>;
type Challenger = SerializingChallenger32<BabyBear, HashChallenger<u8, hash::TranscriptHash, 64>>;
struct Observation {
    mask: Arc<Journal>,
    salt: Arc<Journal>,
    audit: Arc<Audit>,
    initial_salt: Vec<u8>,
}
fn parts() -> (Spy, Ext, Observed, Observation) {
    let audit = Arc::new(Audit::default());
    let mask = Arc::new(Journal::default());
    let salt = Arc::new(Journal::default());
    let input = Spy {
        inner: Inner::new(
            Leaf(audit.clone()),
            CompressionFunctionFromHasher::new(hash::NodeHash),
            0,
            Observed::new(19, salt.clone()),
        ),
        audit: audit.clone(),
        extension: false,
    };
    let mut child = input.clone();
    child.extension = true;
    let initial_salt = salt.bytes();
    (
        input,
        Ext::new(child),
        Observed::new(7, mask.clone()),
        Observation {
            mask,
            salt,
            audit,
            initial_salt,
        },
    )
}
fn base(queries: usize) -> (Base, Observation) {
    let (input, mmcs, rng, o) = parts();
    (
        Base::new(
            Radix2DitParallel::default(),
            input,
            FriParameters {
                log_blowup: 3,
                log_final_poly_len: 0,
                max_log_arity: 1,
                num_queries: queries,
                batch_proof_of_work_bits: 0,
                commit_proof_of_work_bits: 0,
                query_proof_of_work_bits: 0,
                mmcs,
            },
            4,
            rng,
        ),
        o,
    )
}
fn anchor() -> (Anchor, Observation) {
    let (input, mmcs, rng, o) = parts();
    (
        Anchor::new(
            Radix2DitParallel::default(),
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
        o,
    )
}
fn dense() -> (Dense, Observation) {
    let (input, mmcs, rng, o) = parts();
    (
        Dense::new(
            Radix2DitParallel::default(),
            input,
            p3_fri::FriParameters {
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
        o,
    )
}
fn owned(anchor: &Anchor, queries: usize) -> (Owned, SourceStore, Observation) {
    let store = SourceStore::new(anchor).unwrap();
    let (pcs, o) = base(queries);
    *o.audit.owner.lock().unwrap() = Some(store.clone());
    (pcs.with_storage(store.clone()), store, o)
}
fn values() -> impl Iterator<Item = BabyBear> {
    (5..261).flat_map(|n| {
        let a = BabyBear::from_u32(n);
        [a, a.exp_u64(4)]
    })
}
fn domain() -> TwoAdicMultiplicativeCoset<BabyBear> {
    TwoAdicMultiplicativeCoset::new(BabyBear::ONE, 9).unwrap()
}
