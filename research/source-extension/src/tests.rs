use super::*;
use kova_proof_preflight::{FriParameters, storage::DenseStore};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::CompressionFunctionFromHasher;
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
use std::{
    convert::Infallible,
    panic::{AssertUnwindSafe, catch_unwind},
};

#[path = "../../storage-pcs/tests/common/hash.rs"]
#[allow(
    dead_code,
    reason = "The retained helper also defines an unused transcript hash"
)]
pub mod hash;
type Input = MerkleTreeHidingMmcs<
    BabyBear,
    u64,
    hash::LeafHash,
    CompressionFunctionFromHasher<hash::NodeHash, 2, 8>,
    StdRng,
    2,
    8,
    16,
>;
type Pcs = HidingFriPcs<
    BabyBear,
    Radix2DitParallel<BabyBear>,
    Input,
    ExtensionMmcs<BabyBear, E4, Input>,
    StdRng,
>;
fn pcs(queries: usize) -> Pcs {
    let input = Input::new(
        hash::LeafHash,
        CompressionFunctionFromHasher::new(hash::NodeHash),
        0,
        StdRng::from_seed([19; 32]),
    );
    let ext = ExtensionMmcs::new(input.clone());
    Pcs::new(
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
            mmcs: ext,
        },
        4,
        StdRng::from_seed([7; 32]),
    )
}
fn store() -> CommitmentStore {
    CommitmentStore::new(&pcs(64)).unwrap()
}
fn fault_store(faults: Faults) -> CommitmentStore {
    let plan = pcs(64)
        .resource_plan::<E4, _>(&reference_air::QuarticAir, Request::QUARTIC_V1)
        .unwrap();
    CommitmentStore::from_plan(plan, faults).unwrap()
}
struct Observed {
    inner: StdRng,
    calls: usize,
    observe: Option<CommitmentStore>,
    saw_preparing: bool,
}
impl Observed {
    fn new() -> Self {
        Self {
            inner: StdRng::from_seed([41; 32]),
            calls: 0,
            observe: None,
            saw_preparing: false,
        }
    }
    fn observe(&mut self) {
        if !self.saw_preparing
            && let Some(store) = &self.observe
        {
            let s = store.snapshot().unwrap();
            assert_eq!(s.phase, Phase::Preparing);
            assert_eq!(s.reserved_bytes, 112640);
            assert_eq!(s.reserved_files, 3);
            assert_eq!(s.pending_preparation_bytes, 0);
            assert_eq!(s.preparation_files.len(), 2);
            self.saw_preparing = true;
        }
    }
}
impl TryRng for Observed {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.observe();
        self.calls += 1;
        Ok(self.inner.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.observe();
        self.calls += 1;
        Ok(self.inner.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.observe();
        self.calls += 1;
        self.inner.fill_bytes(dst);
        Ok(())
    }
}
impl TryCryptoRng for Observed {}
fn fields() -> impl Iterator<Item = BabyBear> {
    (0..256).flat_map(|i| {
        let a = BabyBear::from_usize(i + 5);
        [a, a.exp_u64(4)]
    })
}
fn dense() -> RowMajorMatrix<BabyBear> {
    RowMajorMatrix::new(fields().collect(), 2)
}
fn prepared(s: &CommitmentStore, rng: &mut Observed) -> Stored {
    let raw = s.write_raw(fields()).unwrap();
    s.prepare_owned(raw, Header::QUARTIC, rng).unwrap()
}
fn count(s: &CommitmentStore) -> usize {
    fs::read_dir(&s.0.path).unwrap().count()
        + fs::read_dir(s.0.preparation.directory()).unwrap().count()
}

#[test]
fn owned_and_dense_streams_match_retained_fields_and_rng() {
    let owned = store();
    let dense_store = store();
    let mut rng = Observed::new();
    let mut dense_rng = Observed::new();
    let mut reference_rng = Observed::new();
    rng.observe = Some(owned.clone());
    let p = prepared(&owned, &mut rng);
    assert!(rng.saw_preparing);
    rng.observe = None;
    let dp = dense_store
        .prepare_dense(dense(), Header::QUARTIC, &mut dense_rng)
        .unwrap();
    let expected = DenseStore.randomize(dense(), 4, &mut reference_rng);
    assert_eq!(owned.snapshot().unwrap().reserved_bytes, 112640);
    assert_eq!(owned.snapshot().unwrap().pending_preparation_bytes, 0);
    assert_eq!(owned.snapshot().unwrap().reserved_files, 3);
    assert_eq!(count(&owned), 2);
    let columns: Vec<Vec<u32>> = [0, 5]
        .into_iter()
        .map(|c| {
            (0..512)
                .map(|r| p.try_window(r, c, c + 1).unwrap()[0].as_canonical_u32())
                .collect()
        })
        .collect();
    let dft = Radix2DitParallel::default();
    let reference = dft
        .coset_lde_batch(expected, 3, BabyBear::GENERATOR)
        .bit_reverse_rows();
    let lde = owned.extend_owned(p, &dft).unwrap();
    let dense_lde = dense_store.extend_owned(dp, &dft).unwrap();
    for row in 0..4096 {
        let expected = reference.row(row).unwrap().into_iter().collect::<Vec<_>>();
        assert_eq!(lde.try_window(row, 0, 6).unwrap(), expected);
        assert_eq!(dense_lde.try_window(row, 0, 6).unwrap(), expected);
    }
    assert_eq!(rng.calls, reference_rng.calls);
    assert_eq!(dense_rng.calls, reference_rng.calls);
    for _ in 0..16 {
        let next = reference_rng.next_u64();
        assert_eq!(rng.next_u64(), next);
        assert_eq!(dense_rng.next_u64(), next);
    }
    let snapshot = owned.snapshot().unwrap();
    assert_eq!(snapshot.phase, Phase::LdeReady);
    assert_eq!(snapshot.reserved_bytes, 112640);
    assert_eq!(count(&owned), 3);
    assert_eq!(count(&dense_store), 2);
    assert_eq!(dense_store.snapshot().unwrap().reserved_bytes, 110592);
    assert_eq!(
        snapshot
            .preparation_files
            .iter()
            .map(|f| f.role)
            .collect::<Vec<_>>(),
        [prep::Role::RawInput, prep::Role::PreparedInput]
    );
    let event = snapshot.stream.unwrap();
    assert_eq!(event.batches, 2);
    assert_eq!(event.source_windows, 1024);
    assert_eq!(event.source_fields, 3072);
    assert_eq!(event.largest_input_tile_fields, 2048);
    assert_eq!(event.largest_output_tile_fields, 16384);
    assert_eq!(event.written_fields, 24576);
    assert_eq!(event.write_calls, 8192);
    let rows = [0, 1, 2, 7, 31, 255, 511, 4095];
    let cells:Vec<_>=rows.into_iter().flat_map(|r|[0,5].map(|c|serde_json::json!({"row":r,"column":c,"value":lde.try_window(r,c,c+1).unwrap()[0].as_canonical_u32()}))).collect();
    let capture = serde_json::json!({"modulus":2013265921u64,"generator":31,"input_height":512,"output_height":4096,"columns":[0,5],"prepared_columns":columns,"cells":cells,"backend_proofs":0,"commitment_calls":0});
    let results = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    fs::create_dir_all(&results).unwrap();
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(results.join("interpolation-observed.json"))
        .unwrap();
    serde_json::to_writer_pretty(output, &capture).unwrap();
    let path = owned.0.path.clone();
    let prep_path = owned.0.preparation.directory().to_path_buf();
    drop(owned);
    assert!(path.exists());
    assert!(prep_path.exists());
    assert_eq!(
        lde.try_window(0, 0, 1).unwrap(),
        reference
            .row(0)
            .unwrap()
            .into_iter()
            .take(1)
            .collect::<Vec<_>>()
    );
    drop(lde);
    assert!(!path.exists());
    assert!(!prep_path.exists());
}

#[test]
fn early_profile_header_shape_and_owner_refusals_have_no_draws() {
    assert!(matches!(
        CommitmentStore::new(&pcs(0)),
        Err(Error::Profile(Refusal::Parameters))
    ));
    let s = store();
    let mut rng = Observed::new();
    let raw = s.write_raw(fields()).unwrap();
    for h in [
        Header {
            pcs_height: 256,
            ..Header::QUARTIC
        },
        Header {
            shift: 2,
            ..Header::QUARTIC
        },
        Header {
            log_blowup: 4,
            ..Header::QUARTIC
        },
        Header {
            opening_points: 1,
            ..Header::QUARTIC
        },
    ] {
        assert_eq!(
            s.prepare_owned(raw.clone(), h, &mut rng).err(),
            Some(Error::Header)
        );
        assert_eq!(rng.calls, 0);
        assert_eq!(count(&s), 1);
        assert!(s.snapshot().unwrap().lde.is_none());
    }
    let other = store();
    assert_eq!(
        other.prepare_owned(raw, Header::QUARTIC, &mut rng).err(),
        Some(Error::Owner)
    );
    for matrix in [
        RowMajorMatrix::new(vec![], 0),
        RowMajorMatrix::new(vec![BabyBear::ONE; 513], 2),
        RowMajorMatrix::new(vec![BabyBear::ONE; 512], 4),
    ] {
        assert_eq!(
            other.prepare_dense(matrix, Header::QUARTIC, &mut rng).err(),
            Some(Error::Shape)
        );
    }
    assert_eq!(rng.calls, 0);
    assert_eq!(count(&other), 0);
    s.reserve(Header::QUARTIC, false).unwrap();
    let planned = s.snapshot().unwrap();
    assert_eq!(planned.pending_preparation_bytes, 12288);
    assert_eq!(planned.reserved_files, 3);
    assert_eq!(planned.reserved_bytes, 112640);
    assert_eq!(count(&s), 1);
    other.reserve(Header::QUARTIC, true).unwrap();
    let planned_dense = other.snapshot().unwrap();
    assert_eq!(planned_dense.pending_preparation_bytes, 12288);
    assert_eq!(planned_dense.reserved_files, 2);
    assert_eq!(planned_dense.reserved_bytes, 110592);
    assert_eq!(count(&other), 0);
    assert_eq!(rng.calls, 0);
}

#[test]
fn actual_noncanonical_and_truncated_prepared_files_fail() {
    for truncate in [false, true] {
        let s = store();
        let mut rng = Observed::new();
        let p = prepared(&s, &mut rng);
        let clone = p.clone();
        let path = s.0.preparation.directory().join("1.bin");
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        if truncate {
            file.set_len(4).unwrap();
        } else {
            file.write_all(&2013265921u32.to_le_bytes()).unwrap();
        }
        drop(file);
        let calls = rng.calls;
        assert!(matches!(
            s.extend_owned(p, &Radix2DitParallel::default()),
            Err(Error::Preparation(prep::Error::Access(_)))
        ));
        assert_eq!(rng.calls, calls);
        assert_eq!(s.snapshot().unwrap().phase, Phase::Failed);
        assert_eq!(s.snapshot().unwrap().lde.unwrap().state, FileState::Removed);
        assert_eq!(count(&s), 2);
        assert_eq!(clone.try_window(0, 0, 1).err(), Some(Error::Failed));
    }
}

#[test]
fn partial_write_orphan_cleanup_and_replacement_preserve_reservations() {
    let s = fault_store(Faults {
        write_after: Some(3),
        cleanup: AtomicUsize::new(1),
        ..Default::default()
    });
    let mut rng = Observed::new();
    let p = prepared(&s, &mut rng);
    let clone = p.clone();
    let calls = rng.calls;
    assert_eq!(
        s.extend_owned(p, &Radix2DitParallel::default()).err(),
        Some(Error::Io(std::io::ErrorKind::WriteZero))
    );
    let snap = s.snapshot().unwrap();
    assert_eq!(snap.phase, Phase::Failed);
    assert_eq!(snap.reserved_bytes, 112640);
    assert_eq!(snap.lde.unwrap().state, FileState::Orphan);
    assert_eq!(
        snap.cleanup_failures,
        [std::io::ErrorKind::PermissionDenied]
    );
    assert_eq!(count(&s), 3);
    assert_eq!(rng.calls, calls);
    assert_eq!(
        s.extend_owned(clone, &Radix2DitParallel::default()).err(),
        Some(Error::Failed)
    );
    assert!(s.cleanup_failed().unwrap().is_empty());
    assert_eq!(count(&s), 2);
    assert_eq!(s.snapshot().unwrap().reserved_bytes, 112640);
    let path = s.0.path.join("0.bin");
    fs::write(&path, b"replacement after cleanup").unwrap();
    drop(s);
    assert_eq!(fs::read(&path).unwrap(), b"replacement after cleanup");
    fs::remove_file(&path).unwrap();
    fs::remove_dir(path.parent().unwrap()).unwrap();
}

#[test]
fn writer_unwind_closes_all_clones_and_preserves_preparation() {
    let s = fault_store(Faults {
        panic_after: Some(4),
        ..Default::default()
    });
    let mut rng = Observed::new();
    let p = prepared(&s, &mut rng);
    let cloned = s.clone();
    let calls = rng.calls;
    assert!(
        catch_unwind(AssertUnwindSafe(
            || s.extend_owned(p, &Radix2DitParallel::default())
        ))
        .is_err()
    );
    assert_eq!(s.snapshot().unwrap().failure, Some(Error::Unwind));
    assert_eq!(count(&s), 2);
    assert_eq!(cloned.write_raw(fields()).err(), Some(Error::Failed));
    assert_eq!(rng.calls, calls);
}

#[test]
fn actual_outer_mutex_poison_never_becomes_empty_budget() {
    let s = store();
    let mut rng = Observed::new();
    let p = prepared(&s, &mut rng);
    let clone = s.clone();
    let worker = std::thread::spawn(move || {
        let _held = clone.0.state.lock().unwrap();
        panic!("intentional outer state poison");
    });
    assert!(worker.join().is_err());
    assert_eq!(s.snapshot().err(), Some(Error::Poisoned));
    assert_eq!(
        s.extend_owned(p, &Radix2DitParallel::default()).err(),
        Some(Error::Poisoned)
    );
    assert!(s.cleanup_failed().unwrap().is_empty());
    assert_eq!(count(&s), 2);
    assert_eq!(s.snapshot().err(), Some(Error::Poisoned));
}

#[test]
fn injected_missing_short_and_poisoned_windows_fail() {
    for (read, error) in [
        (ReadFault::Missing, Error::Incomplete),
        (ReadFault::Short, Error::Incomplete),
        (ReadFault::Poison, Error::Poisoned),
    ] {
        let s = fault_store(Faults {
            read: Some(read),
            ..Default::default()
        });
        let mut rng = Observed::new();
        let p = prepared(&s, &mut rng);
        let calls = rng.calls;
        assert_eq!(
            s.extend_owned(p, &Radix2DitParallel::default()).err(),
            Some(error)
        );
        assert_eq!(rng.calls, calls);
        assert_eq!(count(&s), 2);
        assert_eq!(s.snapshot().unwrap().phase, Phase::Failed);
    }
}

#[test]
fn unowned_target_and_whole_matrix_conversion_are_preserved_or_refused() {
    let s = store();
    let mut rng = Observed::new();
    let p = prepared(&s, &mut rng);
    let caught = catch_unwind(AssertUnwindSafe(|| p.clone().to_row_major_matrix()))
        .err()
        .unwrap();
    assert_eq!(caught.downcast_ref::<Error>(), Some(&Error::Unsupported));
    let path = s.0.path.join("0.bin");
    fs::write(&path, b"caller owned target").unwrap();
    assert_eq!(
        s.extend_owned(p, &Radix2DitParallel::default()).err(),
        Some(Error::Io(std::io::ErrorKind::AlreadyExists))
    );
    assert_eq!(
        s.snapshot().unwrap().lde.unwrap().state,
        FileState::Uncreated
    );
    drop(s);
    assert_eq!(fs::read(&path).unwrap(), b"caller owned target");
    fs::remove_file(&path).unwrap();
    fs::remove_dir(path.parent().unwrap()).unwrap();
}
