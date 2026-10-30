use kova_source_commitment::{
    FriParameters, HidingFriPcs,
    source::{Challenge, Error, Phase, SourceStore},
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
    fields: Mutex<Vec<u32>>,
    leaves: Mutex<Vec<Vec<u32>>>,
    owner: Mutex<Option<SourceStore>>,
}
#[derive(Clone)]
struct Leaf(Arc<Audit>);
impl CryptographicHasher<BabyBear, [u64; 8]> for Leaf {
    fn hash_iter<I: IntoIterator<Item = BabyBear>>(&self, input: I) -> [u64; 8] {
        let values: Vec<_> = input.into_iter().collect();
        self.0
            .leaves
            .lock()
            .unwrap()
            .push(values.iter().map(|v| v.as_canonical_u32()).collect());
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
        if let Some(owner) = &*self.audit.owner.lock().unwrap() {
            let s = owner.snapshot().unwrap();
            assert_eq!(s.phase, Phase::Committing);
            assert_eq!(s.construction.phase, kova_source_extension::Phase::LdeReady);
        }
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].height(), 4096);
        assert_eq!(inputs[0].width(), 6);
        let fields = (0..4096)
            .flat_map(|r| {
                inputs[0]
                    .row(r)
                    .unwrap()
                    .into_iter()
                    .map(|v| v.as_canonical_u32())
            })
            .collect();
        *self.audit.fields.lock().unwrap() = fields;
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
fn no_calls(o: &Observation) {
    assert_eq!(o.audit.input_commits.load(Ordering::SeqCst), 0);
    assert_eq!(o.audit.extension_commits.load(Ordering::SeqCst), 0);
    assert!(o.mask.bytes().is_empty());
    assert_eq!(o.salt.bytes(), o.initial_salt);
}

#[test]
fn roots_fields_and_continuing_entropy_match_retained_ordinary_dispatch() {
    let (anchor, anchor_o) = anchor();
    let anchor_mask = anchor_o.mask.bytes();
    let anchor_salt = anchor_o.salt.bytes();
    let (first, first_store, a) = owned(&anchor, 64);
    let (second, second_store, b) = owned(&anchor, 64);
    let (reference, c) = dense();
    let raw = first_store.write_raw(values()).unwrap();
    let duplicate = raw.clone();
    let (root, data) = first.commit_owned_source(domain(), raw).unwrap();
    let (other, other_data) = second.commit_dense_source(domain(), air::trace()).unwrap();
    let (expected, reference_data) =
        <_ as Pcs<Challenge, Challenger>>::commit(&reference, [(domain(), air::trace())]).unwrap();
    assert_eq!(root, other);
    assert_eq!(root, expected);
    assert_eq!(
        *a.audit.fields.lock().unwrap(),
        *b.audit.fields.lock().unwrap()
    );
    assert_eq!(
        *a.audit.fields.lock().unwrap(),
        *c.audit.fields.lock().unwrap()
    );
    assert_eq!(a.mask.bytes(), b.mask.bytes());
    assert_eq!(a.mask.bytes(), c.mask.bytes());
    assert_eq!(a.salt.bytes(), b.salt.bytes());
    assert_eq!(a.salt.bytes(), c.salt.bytes());
    assert_eq!(first_store.snapshot().unwrap().phase, Phase::Committed);
    assert_eq!(second_store.snapshot().unwrap().phase, Phase::Committed);
    assert_eq!(
        first_store.snapshot().unwrap().construction.reserved_bytes,
        112640
    );
    assert_eq!(
        second_store.snapshot().unwrap().construction.reserved_bytes,
        110592
    );
    let before = a.mask.bytes();
    assert_eq!(
        first.commit_owned_source(domain(), duplicate).err(),
        Some(Error::Complete)
    );
    assert_eq!(a.mask.bytes(), before);
    // These real clone operations observe the continuing fork bytes. They do
    // not construct more commitments or clone private prover data.
    drop(first.clone());
    drop(second.clone());
    drop(reference.clone());
    assert_eq!(a.mask.bytes(), b.mask.bytes());
    assert_eq!(a.mask.bytes(), c.mask.bytes());
    assert_eq!(a.salt.bytes(), b.salt.bytes());
    assert_eq!(a.salt.bytes(), c.salt.bytes());
    assert_eq!(anchor_o.mask.bytes(), anchor_mask);
    assert_eq!(anchor_o.salt.bytes(), anchor_salt);
    no_calls(&anchor_o);
    for o in [&a, &b, &c] {
        assert_eq!(o.audit.input_commits.load(Ordering::SeqCst), 1);
        assert_eq!(o.audit.extension_commits.load(Ordering::SeqCst), 0);
    }
    let leaves = a.audit.leaves.lock().unwrap();
    assert_eq!(leaves.len(), 4096);
    assert!(leaves.iter().all(|r| r.len() == 22));
    assert_eq!(*leaves, *b.audit.leaves.lock().unwrap());
    assert_eq!(*leaves, *c.audit.leaves.lock().unwrap());
    let results = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    fs::create_dir_all(&results).unwrap();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(results.join("salted-leaves.bin"))
        .unwrap();
    for row in leaves.iter() {
        for v in row {
            output.write_all(&v.to_le_bytes()).unwrap();
        }
    }
    let record = serde_json::json!({"root":root.roots(),"leaf_rows":4096,"leaf_fields":22,"data_fields":6,"salt_fields":16,"input_commit_calls":3,"opening_calls":0,"backend_proofs":0});
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(results.join("root.json"))
        .unwrap();
    serde_json::to_writer_pretty(output, &record).unwrap();
    let view =
        <Owned as UnivariateStarkPcs<Challenge, Challenger>>::get_evaluations_on_domain_no_random(
            &first,
            &data,
            0,
            TwoAdicMultiplicativeCoset::new(BabyBear::GENERATOR, 12).unwrap(),
        );
    *a.audit.owner.lock().unwrap() = None;
    drop(first_store);
    drop(first);
    assert_eq!(view.height(), 4096);
    assert_eq!(view.width(), 6);
    for row in [0usize, 1, 31, 4095] {
        let physical = row.reverse_bits() >> (usize::BITS - 12);
        let fields = a.audit.fields.lock().unwrap();
        assert_eq!(
            view.row(row)
                .unwrap()
                .into_iter()
                .map(|v| v.as_canonical_u32())
                .collect::<Vec<_>>(),
            fields[physical * 6..physical * 6 + 6]
        );
    }
    drop(view);
    drop(data);
    drop(other_data);
    drop(reference_data);
}

#[test]
fn metadata_refusals_consume_no_masks_or_mmcs_calls() {
    let (anchor, _) = anchor();
    let (pcs, store, o) = owned(&anchor, 64);
    let raw = store.write_raw(values()).unwrap();
    for d in [
        TwoAdicMultiplicativeCoset::new(BabyBear::ONE, 8).unwrap(),
        TwoAdicMultiplicativeCoset::new(BabyBear::from_u32(2), 9).unwrap(),
    ] {
        assert_eq!(
            pcs.commit_owned_source(d, raw.clone()).err(),
            Some(Error::Domain)
        );
    }
    assert_eq!(
        pcs.commit_dense_source(domain(), RowMajorMatrix::new(vec![BabyBear::ONE; 513], 2))
            .err(),
        Some(Error::Shape)
    );
    let (foreign, foreign_store, foreign_o) = owned(&anchor, 64);
    assert_eq!(
        foreign.commit_owned_source(domain(), raw.clone()).err(),
        Some(Error::Owner)
    );
    assert_eq!(
        foreign_store
            .snapshot()
            .unwrap()
            .construction
            .reserved_bytes,
        0
    );
    drop(foreign);
    drop(foreign_store);
    drop(foreign_o);
    let (bad, bad_store, bad_o) = owned(&anchor, 63);
    assert_eq!(
        bad.commit_owned_source(domain(), raw).err(),
        Some(Error::Profile)
    );
    assert_eq!(store.snapshot().unwrap().construction.reserved_bytes, 2048);
    assert_eq!(store.snapshot().unwrap().phase, Phase::Ready);
    assert_eq!(bad_store.snapshot().unwrap().phase, Phase::Ready);
    no_calls(&o);
    no_calls(&bad_o);
}

#[test]
fn unsupported_matrix_hooks_refuse_before_entropy_or_dense_fallback() {
    let (anchor, _) = anchor();
    let (_pcs, store, o) = owned(&anchor, 64);
    let mut rng = Observed::new(42, Arc::new(Journal::default()));
    let dft = Radix2DitParallel::default();
    fn refuses(f: impl FnOnce()) {
        let p = catch_unwind(AssertUnwindSafe(f)).err().unwrap();
        assert_eq!(p.downcast_ref::<Error>(), Some(&Error::Unsupported));
    }
    refuses(|| {
        let _ = MatrixStore::store(&store, air::trace());
    });
    refuses(|| {
        let _ = MatrixStore::randomize(&store, air::trace(), 4, &mut rng);
    });
    refuses(|| {
        let _ = MatrixStore::extend(&store, &dft, air::trace(), 3, BabyBear::ONE);
    });
    refuses(|| {
        let _ = MatrixStore::extend_prepared(&store, &dft, air::trace(), 3, BabyBear::ONE);
    });
    refuses(|| {
        let _ = MatrixStore::extend_quotient(&store, &dft, air::trace(), &[], 3, BabyBear::ONE);
    });
    assert!(rng.journal.bytes().is_empty());
    assert_eq!(store.snapshot().unwrap().construction.reserved_bytes, 0);
    no_calls(&o);
}

#[test]
fn actual_mmcs_unwind_fails_outer_clones_and_keeps_inner_lde() {
    let (anchor, _) = anchor();
    let (pcs, store, o) = owned(&anchor, 64);
    o.audit.unwind.store(true, Ordering::SeqCst);
    let raw = store.write_raw(values()).unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| pcs.commit_owned_source(domain(), raw))).is_err());
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.phase, Phase::Failed);
    assert_eq!(snap.failure, Some(Error::Unwind));
    assert_eq!(
        snap.construction.phase,
        kova_source_extension::Phase::LdeReady
    );
    assert_eq!(snap.construction.reserved_bytes, 112640);
    assert_eq!(o.audit.input_commits.load(Ordering::SeqCst), 1);
    assert_eq!(o.audit.extension_commits.load(Ordering::SeqCst), 0);
    assert!(!o.salt.bytes().is_empty());
    let mask = o.mask.bytes();
    let salt = o.salt.bytes();
    let clone = store.clone();
    assert_eq!(clone.write_raw(values()).err(), Some(Error::Failed));
    assert_eq!(
        pcs.commit_dense_source(domain(), air::trace()).err(),
        Some(Error::Failed)
    );
    assert_eq!(o.mask.bytes(), mask);
    assert_eq!(o.salt.bytes(), salt);
}
