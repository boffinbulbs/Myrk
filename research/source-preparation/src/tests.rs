use super::*;
use kova_proof_preflight::storage::DenseStore;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use rand::{SeedableRng, TryRng, rngs::StdRng};
use std::{
    convert::Infallible,
    io::{Seek, SeekFrom},
    panic::{AssertUnwindSafe, catch_unwind},
};

struct Observed {
    inner: StdRng,
    calls: usize,
}
impl Observed {
    fn new() -> Self {
        Self {
            inner: StdRng::from_seed([7; 32]),
            calls: 0,
        }
    }
}
impl TryRng for Observed {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.calls += 1;
        Ok(self.inner.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.calls += 1;
        Ok(self.inner.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.calls += 1;
        self.inner.fill_bytes(dst);
        Ok(())
    }
}
fn fields(height: usize, width: usize) -> impl Iterator<Item = BabyBear> {
    (0..height).flat_map(move |row| {
        (0..width).map(move |column| {
            let a = BabyBear::from_usize(5 + row);
            if column == 0 {
                a
            } else if column == 1 {
                a.square().square()
            } else {
                a.exp_u64((column + 1) as u64)
            }
        })
    })
}
fn dense(height: usize, width: usize) -> RowMajorMatrix<BabyBear> {
    RowMajorMatrix::new(fields(height, width).collect(), width)
}
fn malformed(width: usize, values: Vec<BabyBear>) -> RowMajorMatrix<BabyBear> {
    let mut matrix = RowMajorMatrix::new(vec![], 1);
    matrix.width = width;
    matrix.values = values;
    matrix
}
fn raw(store: &PreparationStore) -> OwnedMatrix {
    store.write_raw(256, 2, fields(256, 2)).unwrap()
}
fn flatten(matrix: &OwnedMatrix) -> Vec<BabyBear> {
    (0..matrix.height())
        .flat_map(|row| matrix.try_window(row, 0, matrix.width()).unwrap())
        .collect()
}
fn count(store: &PreparationStore) -> usize {
    fs::read_dir(store.directory()).unwrap().count()
}
fn faulted(write: Option<usize>, cleanup: usize) -> PreparationStore {
    PreparationStore::new_inner(Faults {
        write_after: write,
        cleanup_remaining: AtomicUsize::new(cleanup),
    })
    .unwrap()
}

#[test]
fn dense_and_owned_share_retained_field_layout_and_rng() {
    for (height, width) in [(256, 2), (16, 5)] {
        let stored = PreparationStore::new().unwrap();
        let input = stored
            .write_raw(height, width, fields(height, width))
            .unwrap();
        let mut owned_rng = Observed::new();
        let prepared = stored
            .prepare_owned(input, 4, Domain::natural(height), &mut owned_rng)
            .unwrap();
        let dense_store = PreparationStore::new().unwrap();
        let mut dense_rng = Observed::new();
        let prepared_dense =
            MatrixStore::randomize(&dense_store, dense(height, width), 4, &mut dense_rng);
        let mut reference_rng = Observed::new();
        let expected = DenseStore.randomize(dense(height, width), 4, &mut reference_rng);
        assert_eq!(flatten(&prepared), expected.values);
        assert_eq!(flatten(&prepared_dense), expected.values);
        assert_eq!(
            [prepared.height(), prepared.width()],
            [height * 2, width + 4]
        );
        assert_eq!(owned_rng.calls, reference_rng.calls);
        assert_eq!(dense_rng.calls, reference_rng.calls);
        for _ in 0..16 {
            let next = reference_rng.next_u64();
            assert_eq!(owned_rng.next_u64(), next);
            assert_eq!(dense_rng.next_u64(), next);
        }
        let snapshot = stored.snapshot().unwrap();
        assert_eq!(snapshot.phase, Phase::Complete);
        assert_eq!(
            snapshot.files.iter().map(|x| x.role).collect::<Vec<_>>(),
            vec![Role::RawInput, Role::PreparedInput]
        );
        assert_eq!(
            snapshot.reserved_bytes,
            4 * (height * width + 2 * height * (width + 4))
        );
        if height == 256 {
            assert_eq!(snapshot.reserved_bytes, 14336);
        }
        // A view retains its owned directory and descriptor after the public
        // policy handle drops. It never needs a full raw dense conversion.
        drop(stored);
        assert_eq!(
            prepared.try_window(0, 0, width).unwrap(),
            fields(1, width).collect::<Vec<_>>()
        );
    }
}

#[test]
fn early_shape_domain_and_owner_refusals_have_no_draws() {
    for (random, domain, expected) in [
        (0, Domain::natural(256), Error::Shape),
        (5, Domain::natural(256), Error::Shape),
        (4, Domain::natural(128), Error::Domain),
        (
            4,
            Domain {
                height: 256,
                shift: 2,
            },
            Error::Domain,
        ),
    ] {
        let store = PreparationStore::new().unwrap();
        let input = raw(&store);
        let mut rng = Observed::new();
        assert_eq!(
            store.prepare_owned(input, random, domain, &mut rng).err(),
            Some(expected)
        );
        assert_eq!(rng.calls, 0);
        assert_eq!(count(&store), 1);
        assert_eq!(store.snapshot().unwrap().phase, Phase::Ready);
    }
    let store = PreparationStore::new().unwrap();
    let mut rng = Observed::new();
    assert_eq!(
        store
            .prepare_dense(dense(2, 9), 4, Domain::natural(2), &mut rng)
            .err(),
        Some(Error::Shape)
    );
    assert_eq!(store.write_raw(0, 2, []).err(), Some(Error::Shape));
    for matrix in [malformed(0, vec![]), malformed(2, vec![BabyBear::ONE; 3])] {
        assert_eq!(
            store
                .prepare_dense(matrix, 4, Domain::natural(1), &mut rng)
                .err(),
            Some(Error::Shape)
        );
    }
    let malformed = malformed(2, vec![BabyBear::ONE; 3]);
    let error = catch_unwind(AssertUnwindSafe(|| {
        let _ = MatrixStore::randomize(&store, malformed, 4, &mut rng);
    }))
    .err()
    .unwrap();
    assert_eq!(error.downcast_ref::<Error>(), Some(&Error::Shape));
    assert_eq!(count(&store), 0);
    let foreign = PreparationStore::new().unwrap();
    let input = raw(&foreign);
    assert_eq!(
        store
            .prepare_owned(input, 4, Domain::natural(256), &mut rng)
            .err(),
        Some(Error::Owner)
    );
    assert_eq!(rng.calls, 0);
    assert_eq!(count(&store), 0);
}

#[test]
fn actual_noncanonical_and_truncated_sources_fail() {
    for truncate in [false, true] {
        let store = PreparationStore::new().unwrap();
        let input = raw(&store);
        let mut writer = OpenOptions::new()
            .write(true)
            .open(store.directory().join("0.bin"))
            .unwrap();
        if truncate {
            writer.set_len(4).unwrap();
        } else {
            writer.seek(SeekFrom::Start(0)).unwrap();
            writer
                .write_all(&BabyBear::ORDER_U32.to_le_bytes())
                .unwrap();
        }
        drop(writer);
        let mut rng = Observed::new();
        let error = store
            .prepare_owned(input, 4, Domain::natural(256), &mut rng)
            .err()
            .unwrap();
        assert_eq!(
            error,
            Error::Access(if truncate {
                StorageError::Length
            } else {
                StorageError::NonCanonicalField
            })
        );
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.phase, Phase::Failed);
        assert_eq!(snapshot.files[1].state, FileState::Removed);
        assert_eq!(count(&store), 1);
        assert_eq!(rng.calls, 0);
    }
}

struct FaultInput {
    source: OwnedMatrix,
    kind: usize,
}
impl Input for FaultInput {
    fn shape(&self) -> [usize; 2] {
        self.source.shape()
    }
    fn window(&self, row: usize, start: usize, end: usize) -> Result<Vec<BabyBear>, Error> {
        match self.kind {
            0 => Err(Error::Incomplete),
            1 => {
                let mut actual = self.source.try_window(row, start, end)?;
                actual.pop();
                Ok(actual)
            }
            _ => Err(Error::Access(StorageError::LockPoisoned)),
        }
    }
}
#[test]
fn injected_missing_short_and_reader_poison_are_typed() {
    for kind in 0..3 {
        let store = PreparationStore::new().unwrap();
        let input = FaultInput {
            source: raw(&store),
            kind,
        };
        let mut rng = Observed::new();
        let result = store.prepare(input, 4, Domain::natural(256), &mut rng);
        assert_eq!(
            result.err(),
            Some(if kind == 2 {
                Error::Access(StorageError::LockPoisoned)
            } else {
                Error::Incomplete
            })
        );
        assert_eq!(rng.calls, 0);
        assert_eq!(store.snapshot().unwrap().phase, Phase::Failed);
        assert_eq!(count(&store), 1);
    }
}

#[test]
fn partial_write_keeps_rng_progress_and_fails_all_clones() {
    let store = faulted(Some(3), 0);
    let clone = store.clone();
    let input = raw(&store);
    let mut rng = Observed::new();
    assert_eq!(
        store
            .prepare_owned(input, 4, Domain::natural(256), &mut rng)
            .err(),
        Some(Error::Io(std::io::ErrorKind::WriteZero))
    );
    let draws = rng.calls;
    assert!(draws > 0);
    let mut expected = Observed::new();
    for _ in 0..2 {
        let _: BabyBear = expected.random();
    }
    assert_eq!(draws, expected.calls);
    assert_eq!(rng.next_u64(), expected.next_u64());
    let before = rng.calls;
    assert_eq!(
        clone
            .prepare_dense(dense(256, 2), 4, Domain::natural(256), &mut rng)
            .err(),
        Some(Error::Failed)
    );
    assert_eq!(rng.calls, before);
    assert_eq!(count(&store), 1);
    assert_eq!(store.snapshot().unwrap().files[1].state, FileState::Removed);
}

#[test]
fn cleanup_refusal_retains_reservations_and_preserves_unowned_files() {
    let store = faulted(Some(3), 1);
    let input = raw(&store);
    let mut rng = Observed::new();
    assert!(
        store
            .prepare_owned(input, 4, Domain::natural(256), &mut rng)
            .is_err()
    );
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.phase, Phase::Failed);
    assert_eq!(snapshot.reserved_bytes, 14336);
    assert_eq!(snapshot.files[1].state, FileState::Orphan);
    assert_eq!(
        snapshot.cleanup_failures,
        vec![std::io::ErrorKind::PermissionDenied]
    );
    assert_eq!(count(&store), 2);
    assert!(store.cleanup_failed().unwrap().is_empty());
    assert_eq!(count(&store), 0);
    assert_eq!(store.snapshot().unwrap().reserved_bytes, 14336);
    assert_eq!(
        store
            .prepare_dense(dense(256, 2), 4, Domain::natural(256), &mut rng)
            .err(),
        Some(Error::Failed)
    );
    let directory = store.directory().to_path_buf();
    let replacement = directory.join("1.bin");
    fs::write(&replacement, b"replacement after completed cleanup").unwrap();
    drop(store);
    assert_eq!(
        fs::read(&replacement).unwrap(),
        b"replacement after completed cleanup"
    );
    fs::remove_file(&replacement).unwrap();
    fs::remove_dir(&directory).unwrap();
    let other = PreparationStore::new().unwrap();
    let path = other.directory().join("0.bin");
    fs::write(&path, b"caller owned fixture").unwrap();
    assert_eq!(
        other.write_raw(2, 2, fields(2, 2)).err(),
        Some(Error::Io(std::io::ErrorKind::AlreadyExists))
    );
    assert_eq!(fs::read(&path).unwrap(), b"caller owned fixture");
    assert!(!other.snapshot().unwrap().files[0].owned);
    drop(other);
    assert!(path.exists());
    fs::remove_file(&path).unwrap();
    fs::remove_dir(path.parent().unwrap()).unwrap();
}

#[test]
fn actual_owner_state_poison_refuses_reuse() {
    let unwound = PreparationStore::new().unwrap();
    let clone = unwound.clone();
    let values = (0..4).map(|index| {
        if index == 1 {
            panic!("intentional raw writer unwind");
        }
        BabyBear::ONE
    });
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = unwound.write_raw(2, 2, values);
        }))
        .is_err()
    );
    let snapshot = unwound.snapshot().unwrap();
    assert_eq!(snapshot.phase, Phase::Failed);
    assert_eq!(snapshot.failure, Some(Error::Unwind));
    assert_eq!(snapshot.files[0].state, FileState::Removed);
    assert_eq!(count(&unwound), 0);
    assert_eq!(
        clone.write_raw(2, 2, fields(2, 2)).err(),
        Some(Error::Failed)
    );
    let store = PreparationStore::new().unwrap();
    let input = raw(&store);
    let clone = store.clone();
    let worker = std::thread::spawn(move || {
        let _guard = clone.0.state.lock().unwrap();
        panic!("intentional owner state poison")
    });
    assert!(worker.join().is_err());
    let mut rng = Observed::new();
    assert_eq!(
        store
            .prepare_owned(input, 4, Domain::natural(256), &mut rng)
            .err(),
        Some(Error::Poisoned)
    );
    assert_eq!(rng.calls, 0);
    assert_eq!(count(&store), 1);
    assert_eq!(store.snapshot().err(), Some(Error::Poisoned));
    assert!(store.cleanup_failed().unwrap().is_empty());
    assert_eq!(count(&store), 0);
}

fn unsupported(f: impl FnOnce()) {
    let result = catch_unwind(AssertUnwindSafe(f)).err().unwrap();
    assert_eq!(result.downcast_ref::<Error>(), Some(&Error::Unsupported));
}
#[test]
fn unimplemented_hooks_and_whole_matrix_conversion_refuse() {
    let store = PreparationStore::new().unwrap();
    let input = raw(&store);
    unsupported(|| {
        let _ = input.clone().to_row_major_matrix();
    });
    let dft = Radix2DitParallel::default();
    unsupported(|| {
        let _ = MatrixStore::store(&store, dense(2, 2));
    });
    unsupported(|| {
        let _ = MatrixStore::extend(&store, &dft, dense(2, 2), 3, BabyBear::ONE);
    });
    unsupported(|| {
        let _ = MatrixStore::extend_prepared(&store, &dft, input.clone(), 3, BabyBear::ONE);
    });
    unsupported(|| {
        let _ = MatrixStore::extend_quotient(
            &store,
            &dft,
            dense(2, 2),
            &[BabyBear::ZERO; 4],
            3,
            BabyBear::ONE,
        );
    });
    let mut rng = Observed::new();
    let prepared = store
        .prepare_owned(input, 4, Domain::natural(256), &mut rng)
        .unwrap();
    assert_eq!(
        prepared.try_window(0, 0, 2).unwrap(),
        fields(1, 2).collect::<Vec<_>>()
    );
    assert_eq!(count(&store), 2);
}
