#![deny(unsafe_code)]

use kova_fallible_input::{Error, FileState, OwnedMatrix, Phase, PreparationStore};
use kova_storage_matrix::{CheckedFileMatrix, StorageError};
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

// Saved canonical literals from storage-matrix/src/tests.rs, not candidate output.
const WORDS: [u32; 12] = [0, 1, 2_013_265_920, 17, 42, 9, 5, 7, 11, 31, 127, 65_535];
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn bytes() -> Vec<u8> {
    WORDS.into_iter().flat_map(u32::to_le_bytes).collect()
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!(
            "kova_fallible_input_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let path = path.canonicalize().unwrap();
        assert_eq!(path.parent(), Some(root.as_path()));
        let fixture = Self(path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(fixture.path())
            .unwrap();
        file.write_all(&bytes()).unwrap();
        file.sync_all().unwrap();
        fixture
    }
    fn path(&self) -> PathBuf {
        let path = self.0.join("source.bin");
        assert_eq!(path.parent(), Some(self.0.as_path()));
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // This exclusive fixture has one known flat leaf. Never traverse a directory.
        fs::remove_file(self.path()).unwrap();
        fs::remove_dir(&self.0).unwrap();
    }
}

#[derive(Default)]
struct Counters {
    initialized: AtomicUsize,
    pulls: AtomicUsize,
}
impl Counters {
    fn read(&self) -> [usize; 2] {
        [
            self.initialized.load(Ordering::SeqCst),
            self.pulls.load(Ordering::SeqCst),
        ]
    }
}
#[derive(Clone, Copy)]
enum Fault {
    None,
    Truncate,
    NonCanonical,
    EndBounds,
}
struct Input {
    // Close the checked descriptor before the last fixture owner removes the file.
    reader: CheckedFileMatrix,
    owner: Arc<Fixture>,
    counters: Arc<Counters>,
    fault: Fault,
}
impl Input {
    fn new(fault: Fault) -> (Self, Arc<Counters>) {
        let owner = Arc::new(Fixture::new());
        let reader = CheckedFileMatrix::open(&owner.path(), 4, 3).unwrap();
        let counters = Arc::new(Counters::default());
        (
            Self {
                reader,
                owner,
                counters: counters.clone(),
                fault,
            },
            counters,
        )
    }
}
struct Cursor {
    input: Input,
    index: usize,
    stopped: bool,
}
impl IntoIterator for Input {
    type Item = Result<BabyBear, Error>;
    type IntoIter = Cursor;
    fn into_iter(self) -> Cursor {
        self.counters.initialized.fetch_add(1, Ordering::SeqCst);
        Cursor {
            input: self,
            index: 0,
            stopped: false,
        }
    }
}
impl Iterator for Cursor {
    type Item = Result<BabyBear, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.input.counters.pulls.fetch_add(1, Ordering::SeqCst);
        if self.stopped {
            return None;
        }
        if self.index == WORDS.len() && !matches!(self.input.fault, Fault::EndBounds) {
            return None;
        }
        // Mutate the same opened source. The checked reader produces the error.
        if self.index == 6 && matches!(self.input.fault, Fault::Truncate) {
            OpenOptions::new()
                .write(true)
                .open(self.input.owner.path())
                .unwrap()
                .set_len(4)
                .unwrap();
        }
        if self.index == 5 && matches!(self.input.fault, Fault::NonCanonical) {
            let mut file = OpenOptions::new()
                .write(true)
                .open(self.input.owner.path())
                .unwrap();
            file.seek(SeekFrom::Start(20)).unwrap();
            file.write_all(&2_013_265_921u32.to_le_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let result = self
            .input
            .reader
            .try_window(self.index / 3, self.index % 3, self.index % 3 + 1)
            .map(|values| values[0])
            .map_err(Error::Access);
        self.index += 1;
        self.stopped = result.is_err();
        Some(result)
    }
}
struct Legacy(Input);
impl IntoIterator for Legacy {
    type Item = BabyBear;
    type IntoIter = std::iter::Map<Cursor, fn(Result<BabyBear, Error>) -> BabyBear>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter().map(Result::unwrap)
    }
}
fn write(
    store: &PreparationStore,
    legacy: bool,
    shape: [usize; 2],
    input: Input,
) -> Result<OwnedMatrix, Error> {
    if legacy {
        store.write_raw(shape[0], shape[1], Legacy(input))
    } else {
        store.try_write_raw(shape[0], shape[1], input)
    }
}
fn failed(store: &PreparationStore, cause: Error, state: FileState) {
    let before = store.snapshot().unwrap();
    assert_eq!(before.phase, Phase::Failed);
    assert_eq!(before.failure, Some(cause));
    assert_eq!(before.reserved_bytes, 48);
    assert_eq!(before.files.len(), 1);
    assert_eq!(before.files[0].state, state);
    assert!(before.cleanup_failures.is_empty());
    assert!(store.cleanup_failed().unwrap().is_empty());
    assert_eq!(store.snapshot().unwrap(), before);
}
fn reentry(store: &PreparationStore, legacy: bool) {
    let before = store.snapshot().unwrap();
    let (input, counters) = Input::new(Fault::None);
    assert!(matches!(
        write(store, legacy, [4, 3], input),
        Err(Error::Failed)
    ));
    assert_eq!(counters.read(), [0, 0]);
    assert_eq!(store.snapshot().unwrap(), before);
}

#[test]
#[ignore = "One separately bounded raw input ownership diagnostic"]
fn deferred_input_retains_actual_source_failures() {
    assert_eq!(
        std::env::var("KOVA_FALLIBLE_INPUT_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let mut cases: Vec<Value> = vec![];
    for legacy in [false, true] {
        let store = PreparationStore::new().unwrap();
        let directory = store.directory().to_owned();
        let (input, counters) = Input::new(Fault::None);
        let lease = write(&store, legacy, [4, 3], input).unwrap();
        assert_eq!(counters.read(), [1, 13]);
        assert_eq!(fs::read(directory.join("0.bin")).unwrap(), bytes());
        for row in 0..4 {
            let actual: Vec<_> = lease
                .try_window(row, 0, 3)
                .unwrap()
                .iter()
                .map(PrimeField32::as_canonical_u32)
                .collect();
            assert_eq!(actual, WORDS[row * 3..row * 3 + 3]);
        }
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.phase, Phase::Ready);
        assert_eq!(snapshot.reserved_bytes, 48);
        assert_eq!(snapshot.files[0].state, FileState::Complete);
        drop(store);
        assert!(directory.exists());
        drop(lease);
        assert!(!directory.exists());
        cases.push(
            json!({"kind":"success", "legacy":legacy, "counters":[1,13], "bytes":48, "fields":12}),
        );
    }
    for (fault, cause, pulls) in [
        (Fault::Truncate, StorageError::Length, 7),
        (Fault::NonCanonical, StorageError::NonCanonicalField, 6),
        (Fault::EndBounds, StorageError::Bounds, 13),
    ] {
        let store = PreparationStore::new().unwrap();
        let alias = store.clone();
        let directory = store.directory().to_owned();
        let (input, counters) = Input::new(fault);
        let result = store.try_write_raw(4, 3, input);
        assert!(matches!(result, Err(Error::Access(actual)) if actual == cause));
        assert_eq!(counters.read(), [1, pulls]);
        assert!(!directory.join("0.bin").exists());
        failed(&alias, Error::Access(cause), FileState::Removed);
        reentry(&alias, false);
        drop(store);
        assert!(directory.exists());
        drop(alias);
        assert!(!directory.exists());
        cases.push(json!({"kind":"source_error", "error":format!("{cause:?}"), "counters":[1,pulls], "reentry":[0,0]}));
    }
    for legacy in [false, true] {
        for shape in [[0, 3], [3, 3], [8192, 3], [8192, 42178]] {
            let store = PreparationStore::new().unwrap();
            let before = store.snapshot().unwrap();
            let (input, counters) = Input::new(Fault::None);
            assert!(matches!(
                write(&store, legacy, shape, input),
                Err(Error::Shape)
            ));
            assert_eq!(counters.read(), [0, 0]);
            assert_eq!(store.snapshot().unwrap(), before);
            assert_eq!(fs::read_dir(store.directory()).unwrap().count(), 0);
            cases.push(json!({"kind":"metadata_refusal", "legacy":legacy, "shape":shape, "counters":[0,0]}));
        }
        let store = PreparationStore::new().unwrap();
        let directory = store.directory().to_owned();
        let sentinel = directory.join("0.bin");
        assert_eq!(sentinel.parent(), Some(store.directory()));
        const SENTINEL: &[u8] = b"unowned collision sentinel";
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sentinel)
            .unwrap();
        file.write_all(SENTINEL).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let (input, counters) = Input::new(Fault::None);
        assert!(matches!(
            write(&store, legacy, [4, 3], input),
            Err(Error::Io(std::io::ErrorKind::AlreadyExists))
        ));
        assert_eq!(counters.read(), [0, 0]);
        failed(
            &store,
            Error::Io(std::io::ErrorKind::AlreadyExists),
            FileState::Uncreated,
        );
        reentry(&store, legacy);
        assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
        drop(store);
        // The owner preserved the unowned file and could not remove its directory.
        assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
        assert_eq!(sentinel.parent(), Some(directory.as_path()));
        fs::remove_file(&sentinel).unwrap();
        fs::remove_dir(&directory).unwrap();
        cases.push(
            json!({"kind":"output_collision", "legacy":legacy, "counters":[0,0], "reentry":[0,0]}),
        );
    }
    assert_eq!(cases.len(), 15);
    let report = json!({
        "format":"kova.fallible-input.native.v1", "cases":cases,
        "primary_cases":15, "failed_owner_reentries":5,
        "source_shape":[4,3], "source_bytes":48,
        "reference_field_comparisons":24, "reference_byte_comparisons":96,
        "maximum_store_reservation":48, "maximum_store_files":1,
        "complete_proofs":0, "full_signature_calls":0
    });
    let encoded = serde_json::to_vec_pretty(&report).unwrap();
    assert!(encoded.len() < 16 * 1024);
    let path = PathBuf::from(std::env::var_os("KOVA_FALLIBLE_INPUT_RECORD").unwrap());
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&encoded).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}
