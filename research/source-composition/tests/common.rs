use kova_source_composition::{
    FriParameters, HidingFriPcs,
    composite::{
        Challenge, CompositeStore, Error, FileState, Phase, RESERVED_BYTES, RESERVED_FILES,
    },
    storage::MatrixStore,
};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{BatchOpening, BatchOpeningRef, ExtensionMmcs, Mmcs, Pcs, UnivariateStarkPcs};
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32, coset::TwoAdicMultiplicativeCoset};
use p3_matrix::{Dimensions, Matrix, dense::RowMajorMatrix};
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
    unwind: AtomicBool,
    fields: Mutex<Vec<Vec<Vec<u32>>>>,
    opens: AtomicUsize,
    owner: Mutex<Option<CompositeStore>>,
}
#[derive(Clone)]
struct Leaf;
impl CryptographicHasher<BabyBear, [u64; 8]> for Leaf {
    fn hash_iter<I: IntoIterator<Item = BabyBear>>(&self, input: I) -> [u64; 8] {
        let values: Vec<_> = input.into_iter().collect();
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
        if self.extension {
            self.audit.extension_commits.fetch_add(1, Ordering::SeqCst);
        } else {
            self.audit.input_commits.fetch_add(1, Ordering::SeqCst);
        }
        assert!(
            !self.extension,
            "construction admission has no FRI commitment"
        );
        let round = self.audit.input_commits.load(Ordering::SeqCst);
        assert!((1..=3).contains(&round));
        if let Some(owner) = &*self.audit.owner.lock().unwrap() {
            let s = owner.snapshot().unwrap();
            assert_eq!(
                s.phase,
                [
                    Phase::MainCommitting,
                    Phase::QuotientCommitting,
                    Phase::AuxiliaryCommitting
                ][round - 1]
            );
            assert_eq!(s.reserved_files, RESERVED_FILES);
            assert_eq!(s.reserved_bytes, RESERVED_BYTES);
            assert_eq!(
                s.entries
                    .iter()
                    .filter(|e| e.state == FileState::Complete)
                    .count(),
                [3, 11, 12][round - 1]
            );
        }
        assert_eq!(inputs.len(), [1, 8, 1][round - 1]);
        let fields = inputs
            .iter()
            .map(|m| {
                assert_eq!(m.height(), 4096);
                assert_eq!(m.width(), if round == 1 { 6 } else { 8 });
                (0..m.height())
                    .flat_map(|row| {
                        m.row(row)
                            .unwrap()
                            .into_iter()
                            .map(|v| v.as_canonical_u32())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        self.audit.fields.lock().unwrap().push(fields);
        let result = self.inner.commit(inputs);
        assert!(
            !self.audit.unwind.load(Ordering::SeqCst),
            "injected unwind after actual hiding MMCS commitment"
        );
        result
    }
    fn open_batch<M: Matrix<BabyBear>>(
        &self,
        index: usize,
        data: &Self::ProverData<M>,
    ) -> BatchOpening<BabyBear, Self> {
        self.audit.opens.fetch_add(1, Ordering::SeqCst);
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
        self.audit.opens.fetch_add(1, Ordering::SeqCst);
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
type Owned =
    HidingFriPcs<BabyBear, Radix2DitParallel<BabyBear>, Spy, Ext, Observed, CompositeStore>;
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
            Leaf,
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
