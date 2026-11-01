//! Actual raw source failures through the retained owned proving context.
#![forbid(unsafe_code)]
use crate::{
    Context, OwnedError, Phase, StorageError, composite::FileState, diagnostics_setup as setup,
    extension, source,
};
use kova_fallible_input as prep;
use kova_storage_matrix::{CheckedFileMatrix, StorageError as AccessError};
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!(
            "kova_fallible_source_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let path = path.canonicalize().unwrap();
        assert_eq!(path.parent(), Some(root.as_path()));
        let fixture = Self(path);
        let values = setup::rawliteral();
        assert_eq!(values.len(), 512);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(fixture.path())
            .unwrap();
        for value in values {
            file.write_all(&value.as_canonical_u32().to_le_bytes())
                .unwrap();
        }
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
    Truncate,
    NonCanonical,
    EndBounds,
}
struct Input {
    // Close the actual source descriptor before the final fixture owner.
    reader: CheckedFileMatrix,
    owner: Arc<Fixture>,
    counters: Arc<Counters>,
    fault: Fault,
}
impl Input {
    fn new(fault: Fault) -> (Self, Arc<Counters>) {
        let owner = Arc::new(Fixture::new());
        let reader = CheckedFileMatrix::open(&owner.path(), 256, 2).unwrap();
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
    type Item = Result<BabyBear, prep::Error>;
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
    type Item = Result<BabyBear, prep::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.input.counters.pulls.fetch_add(1, Ordering::SeqCst);
        if self.stopped {
            return None;
        }
        if self.index == 0 && matches!(self.input.fault, Fault::Truncate) {
            OpenOptions::new()
                .write(true)
                .open(self.input.owner.path())
                .unwrap()
                .set_len(4)
                .unwrap();
        }
        if self.index == 255 && matches!(self.input.fault, Fault::NonCanonical) {
            let mut file = OpenOptions::new()
                .write(true)
                .open(self.input.owner.path())
                .unwrap();
            file.seek(SeekFrom::Start(255 * 4)).unwrap();
            file.write_all(&2_013_265_921u32.to_le_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        // In EndBounds the real checked reader rejects row256 on the extra probe.
        let result = self
            .input
            .reader
            .try_window(self.index / 2, self.index % 2, self.index % 2 + 1)
            .map(|values| values[0])
            .map_err(prep::Error::Access);
        self.index += 1;
        self.stopped = result.is_err();
        Some(result)
    }
}
fn nested(cause: AccessError) -> StorageError {
    StorageError::Main(source::Error::Storage(extension::Error::Preparation(
        prep::Error::Access(cause),
    )))
}
fn baseline(counts: setup::Counts) {
    assert_eq!(
        (
            counts.input_commits,
            counts.extension_commits,
            counts.scalar_opens
        ),
        (0, 0, 0)
    );
    assert_eq!(
        (
            counts.input_openings,
            counts.extension_openings,
            counts.input_multi_opens,
            counts.extension_multi_opens
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        (counts.verify_calls, counts.get_matrices, counts.mmcs_clones),
        (0, 0, 1)
    );
    assert_eq!(
        (
            counts.mask.bytes,
            counts.salt.bytes,
            counts.initial_salt_bytes
        ),
        (0, 32, 32)
    );
    assert!(
        serde_json::to_value(counts.dft)
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .all(|v| v.as_u64() == Some(0))
    );
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > 16384)
        {
            return Err(std::io::Error::other(
                "fixed raw source report cap exceeded",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn fixed_raw_source_failures() {
    const {
        assert!(!cfg!(debug_assertions));
        assert!(cfg!(panic = "unwind"));
    }
    assert_eq!(
        std::env::var("KOVA_FALLIBLE_SOURCE_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let mut cases = vec![];
    for (fault, cause, pulls) in [
        (Fault::Truncate, AccessError::Length, 1),
        (Fault::NonCanonical, AccessError::NonCanonicalField, 256),
        (Fault::EndBounds, AccessError::Bounds, 513),
    ] {
        let (pcs, audit) = setup::base();
        let (anchor, anchor_audit) = setup::anchor();
        let context = Arc::new(Context::new(pcs, setup::challenger(), &anchor).unwrap());
        audit.bind_owner(&context);
        let before = audit.detailed_counts();
        let anchor_before = anchor_audit.detailed_counts();
        baseline(before);
        baseline(anchor_before);
        let fingerprints = audit.delivered_fingerprints();
        let anchor_fingerprints = anchor_audit.delivered_fingerprints();
        let alias = context.clone();
        let (input, counters) = Input::new(fault);
        let result = context.try_prove(input);
        assert!(
            matches!(result, Err(OwnedError::Storage { phase: "owned lifecycle", source }) if source == nested(cause))
        );
        assert_eq!(counters.read(), [1, pulls]);
        let snapshot = alias.snapshot().unwrap();
        assert_eq!(snapshot.phase, Phase::Failed);
        assert_eq!(snapshot.failure, Some(nested(cause)));
        assert_eq!(
            (snapshot.reserved_files, snapshot.reserved_bytes),
            (13, 1_325_056)
        );
        assert_eq!(snapshot.entries.len(), 13);
        assert_eq!(snapshot.entries[0].state, FileState::Removed);
        assert!(
            snapshot.entries[1..]
                .iter()
                .all(|e| e.state == FileState::Planned)
        );
        assert!(snapshot.cleanup_failures.is_empty());
        let construction = alias.construction_snapshot().unwrap();
        assert_eq!(construction.phase, source::Phase::Failed);
        assert_eq!(
            construction.failure,
            Some(source::Error::Storage(extension::Error::Preparation(
                prep::Error::Access(cause)
            )))
        );
        assert_eq!(construction.construction.phase, extension::Phase::Failed);
        assert_eq!(
            construction.construction.failure,
            Some(extension::Error::Preparation(prep::Error::Access(cause)))
        );
        assert_eq!(construction.construction.reserved_bytes, 2048);
        assert_eq!(construction.construction.reserved_files, 1);
        assert!(
            construction.construction.lde.is_none() && construction.construction.stream.is_none()
        );
        let (again, reentry) = Input::new(Fault::EndBounds);
        assert!(matches!(
            alias.try_prove(again),
            Err(OwnedError::Storage {
                source: StorageError::Failed,
                ..
            })
        ));
        assert_eq!(reentry.read(), [0, 0]);
        assert_eq!(alias.snapshot().unwrap(), snapshot);
        assert_eq!(alias.construction_snapshot().unwrap(), construction);
        assert_eq!(audit.detailed_counts(), before);
        assert_eq!(anchor_audit.detailed_counts(), anchor_before);
        assert_eq!(audit.delivered_fingerprints(), fingerprints);
        assert_eq!(anchor_audit.delivered_fingerprints(), anchor_fingerprints);
        assert!(audit.roots().is_empty() && anchor_audit.roots().is_empty());
        cases.push(json!({"error":format!("{cause:?}"), "counters":[1,pulls], "reentry":[0,0],
            "outer_phase":"Failed", "source_phase":"Failed", "extension_phase":"Failed",
            "raw_entry":"Removed", "planned_entries":12, "reserved_files":13, "reserved_bytes":1325056,
            "before":before, "after":audit.detailed_counts(), "anchor_unchanged":true, "fingerprints_unchanged":true}));
    }
    let report: Value = json!({"format":"kova.fallible-source.native.v1", "cases":cases,
        "source_shape":[256,2], "source_bytes":2048, "source_cases":3, "failed_owner_reentries":3,
        "complete_proofs":0, "full_signature_calls":0, "old_proof_replays":0});
    let mut encoded = Bounded(vec![]);
    serde_json::to_writer_pretty(&mut encoded, &report).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(PathBuf::from(
            std::env::var_os("KOVA_FALLIBLE_SOURCE_RECORD").unwrap(),
        ))
        .unwrap();
    file.write_all(&encoded.0).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}
