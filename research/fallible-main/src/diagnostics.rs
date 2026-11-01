//! Successful owned source consumption and terminal main observation.
#![forbid(unsafe_code)]
use crate::{
    Context, OwnedError, Phase, StorageError, composite::FileState, diagnostics_setup as setup,
    extension, source,
};
use kova_fallible_input as prep;
use kova_storage_matrix::CheckedFileMatrix;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const SAVED_LEAVES: &[u8] = include_bytes!("../../source-commitment/fixtures/salted-leaves.bin");
const SAVED_ROOT: &[u8] = include_bytes!("../../source-commitment/fixtures/root.json");
const SAVED_PREFIX: &[u8] = include_bytes!("../../source-consumption/results/measurement.json");
const _: () = {
    assert!(SAVED_LEAVES.len() == 360448);
    assert!(SAVED_ROOT.len() < 4096);
    assert!(SAVED_PREFIX.len() < 16384);
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!(
            "kova_fallible_main_{}_{}",
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
struct Input {
    // The checked descriptor closes before the final fixture owner removes its file.
    reader: CheckedFileMatrix,
    _owner: Arc<Fixture>,
    counters: Arc<Counters>,
}
impl Input {
    fn new() -> (Self, Arc<Counters>) {
        let owner = Arc::new(Fixture::new());
        let reader = CheckedFileMatrix::open(&owner.path(), 256, 2).unwrap();
        let counters = Arc::new(Counters::default());
        (
            Self {
                reader,
                _owner: owner,
                counters: counters.clone(),
            },
            counters,
        )
    }
}
struct Cursor {
    input: Input,
    index: usize,
}
impl IntoIterator for Input {
    type Item = Result<BabyBear, prep::Error>;
    type IntoIter = Cursor;
    fn into_iter(self) -> Cursor {
        self.counters.initialized.fetch_add(1, Ordering::SeqCst);
        Cursor {
            input: self,
            index: 0,
        }
    }
}
impl Iterator for Cursor {
    type Item = Result<BabyBear, prep::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.input.counters.pulls.fetch_add(1, Ordering::SeqCst);
        if self.index == 512 {
            return None;
        }
        let result = self
            .input
            .reader
            .try_window(self.index / 2, self.index % 2, self.index % 2 + 1)
            .map(|values| values[0])
            .map_err(prep::Error::Access);
        self.index += 1;
        Some(result)
    }
}
fn effects(counts: setup::Counts) {
    assert_eq!(
        (
            counts.input_commits,
            counts.extension_commits,
            counts.get_matrices
        ),
        (1, 0, 1)
    );
    assert_eq!(
        (
            counts.scalar_opens,
            counts.input_openings,
            counts.extension_openings,
            counts.input_multi_opens,
            counts.extension_multi_opens,
            counts.verify_calls
        ),
        (0, 0, 0, 0, 0, 0)
    );
    assert_eq!((counts.mmcs_clones, counts.initial_salt_bytes), (1, 32));
    assert_eq!((counts.mask.bytes, counts.salt.bytes), (10948, 279800));
    assert_eq!(counts.dft.coset_lde_batch, 2);
    for (name, value) in serde_json::to_value(counts.dft)
        .unwrap()
        .as_object()
        .unwrap()
    {
        if name != "coset_lde_batch" {
            assert_eq!(value.as_u64(), Some(0));
        }
    }
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
            return Err(std::io::Error::other("main observation record bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub fn fixed_main_commitment_observation() {
    const {
        assert!(!cfg!(debug_assertions));
        assert!(cfg!(panic = "unwind"));
    }
    assert_eq!(
        std::env::var("KOVA_FALLIBLE_MAIN_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let (pcs, audit) = setup::base();
    let (anchor, anchor_audit) = setup::anchor();
    let context = Arc::new(Context::new(pcs, setup::challenger(), &anchor).unwrap());
    audit.bind_owner(&context);
    let anchor_before = anchor_audit.detailed_counts();
    let anchor_fingerprint = anchor_audit.delivered_fingerprints();
    let (input, counters) = Input::new();
    let control = context.main_control(input).unwrap();
    assert_eq!(counters.read(), [1, 513]);
    assert_eq!(control.unused, [true, true]);
    assert_eq!(control.before.phase, Phase::MainCommitted);
    assert!(control.before.failure.is_none());
    assert_eq!(
        (control.before.reserved_files, control.before.reserved_bytes),
        (13, 1325056)
    );
    assert_eq!(control.before.entries.len(), 13);
    assert!(
        control.before.entries[..3]
            .iter()
            .all(|e| e.state == FileState::Complete)
    );
    assert!(
        control.before.entries[3..]
            .iter()
            .all(|e| e.state == FileState::Planned)
    );
    assert_eq!(control.construction.phase, source::Phase::Committed);
    assert_eq!(
        control.construction.construction.phase,
        extension::Phase::LdeReady
    );
    assert_eq!(control.construction.construction.reserved_bytes, 112640);
    assert_eq!(control.construction.construction.reserved_files, 3);
    let captured = audit.take_main_leaves();
    assert_eq!(captured.len(), SAVED_LEAVES.len());
    let first_difference = captured.iter().zip(SAVED_LEAVES).position(|(a, b)| a != b);
    assert_eq!(
        first_difference, None,
        "actual leaf preimages differ from saved capture"
    );
    assert_eq!(control.fields.len(), 4096 * 6);
    for (index, actual) in control.fields.iter().enumerate() {
        let offset = ((index / 6) * 22 + index % 6) * 4;
        let expected = u32::from_le_bytes(SAVED_LEAVES[offset..offset + 4].try_into().unwrap());
        assert_eq!(
            actual.as_canonical_u32(),
            expected,
            "returned main field {index}"
        );
    }
    let root = serde_json::to_value(&control.root).unwrap();
    let saved_root: Value = serde_json::from_slice(SAVED_ROOT).unwrap();
    assert_eq!(root["cap"], saved_root["root"]);
    assert_eq!(audit.roots(), vec![root.clone()]);
    let saved_prefix: Value = serde_json::from_slice(SAVED_PREFIX).unwrap();
    assert_eq!(
        serde_json::to_value(audit.delivered_fingerprints()).unwrap(),
        saved_prefix["cases"][0]["delivered_rng_fingerprints"]
    );
    let counts = audit.detailed_counts();
    effects(counts);
    assert_eq!(anchor_audit.detailed_counts(), anchor_before);
    assert_eq!(anchor_audit.delivered_fingerprints(), anchor_fingerprint);
    assert!(anchor_audit.roots().is_empty());
    let closed = context.snapshot().unwrap();
    assert_eq!(closed.phase, Phase::Failed);
    assert_eq!(closed.failure, Some(StorageError::Unwind));
    assert_eq!(closed.entries, control.before.entries);
    let lease_alias = control.lease.clone();
    for lease in [&control.lease, &lease_alias] {
        assert!(matches!(
            lease.try_window(0, 0, 1),
            Err(StorageError::Failed)
        ));
    }
    let (again, reentry) = Input::new();
    assert!(matches!(
        context.try_prove(again),
        Err(OwnedError::Storage {
            source: StorageError::Failed,
            ..
        })
    ));
    assert_eq!(reentry.read(), [0, 0]);
    assert_eq!(context.snapshot().unwrap(), closed);
    assert_eq!(audit.detailed_counts(), counts);
    drop(context);
    for lease in [&control.lease, &lease_alias] {
        assert!(matches!(
            lease.try_window(0, 0, 1),
            Err(StorageError::Failed)
        ));
    }
    let record = json!({"format":"kova.fallible-main.native.v1", "main_commits":counts.input_commits,
        "source_shape":[256,2], "source_bytes":2048, "source_counters":counters.read(),
        "leaf_rows":4096, "leaf_width":22, "captured_leaf_bytes":captured.len(),
        "returned_main_fields":control.fields.len(), "committed_salt_preimage_fields":65536,
        "actual_root":root, "delivered_rng_fingerprints":audit.delivered_fingerprints(), "counts":counts,
        "main_phase_before":"MainCommitted", "phase_after":"Failed", "closure_cause":"Unwind",
        "unused_private_opening_before_after":control.unused, "reserved_files":13, "reserved_bytes":1325056,
        "retained_main_field_bytes":112640, "cheap_lease_refusals":4, "reentry_counters":reentry.read(),
        "anchor_unchanged":true, "complete_proofs":0, "old_proof_replays":0, "full_signature_calls":0});
    let mut encoded = Bounded(vec![]);
    serde_json::to_writer_pretty(&mut encoded, &record).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(PathBuf::from(
            std::env::var_os("KOVA_FALLIBLE_MAIN_RECORD").unwrap(),
        ))
        .unwrap();
    file.write_all(&encoded.0).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}
