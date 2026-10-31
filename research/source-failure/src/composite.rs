//! One private matrix family and one reserved lifetime across all input roles.
//! Source derivative of research/source-stark/src/composite.rs (MIT).
//! Adds an owned unmasked quotient source; it does not establish proof validity.
#![deny(unsafe_code)]

use crate::{
    source,
    storage::{DenseStore, MatrixStore, RowSource},
};
use kova_proof_preflight::preflight::{Refusal, Request};
use kova_source_extension as ext;
use kova_source_preparation as prep;
use kova_storage_matrix::{CheckedFileMatrix, StorageError};
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeField32};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{CryptoRng, Rng};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

pub type Challenge = source::Challenge;
pub const RESERVED_FILES: usize = 13;
pub const RESERVED_BYTES: usize = 1_325_056;
const QUOTIENT_SOURCE_INDEX: usize = 12;
const QUOTIENT_SOURCE_HEIGHT: usize = 2048;
const QUOTIENT_SOURCE_WIDTH: usize = 4;
const QUOTIENT_SOURCE_BYTES: usize = 32_768;
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Profile(Refusal),
    Main(source::Error),
    Access(StorageError),
    Mask(crate::HidingFriProverError),
    Shape,
    Domain,
    Owner,
    Phase,
    Busy,
    Limit,
    Failed,
    Poisoned,
    Unsupported,
    Unwind,
    Incomplete,
    Closed,
    Io(std::io::ErrorKind),
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl From<source::Error> for Error {
    fn from(e: source::Error) -> Self {
        Self::Main(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Ready,
    WritingRaw,
    RawReady,
    MainReady,
    MainPreparing,
    MainCommitting,
    MainCommitted,
    QuotientEvaluating,
    QuotientReady,
    QuotientBuilding,
    QuotientCommitting,
    QuotientCommitted,
    AuxiliaryBuilding,
    AuxiliaryCommitting,
    AuxiliaryCommitted,
    Opening,
    ProofProduced,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Raw,
    Prepared,
    Main,
    Quotient(usize),
    Auxiliary,
    QuotientEvaluations,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    Planned,
    Pending,
    Complete,
    Removed,
    Uncreated,
    Orphan,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub role: Role,
    pub shape: [usize; 2],
    pub bytes: usize,
    pub state: FileState,
    owned: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub failure: Option<Error>,
    pub entries: Vec<Entry>,
    pub reserved_files: usize,
    pub reserved_bytes: usize,
    pub cleanup_failures: Vec<std::io::ErrorKind>,
}
struct State {
    phase: Phase,
    failure: Option<Error>,
    entries: Vec<Entry>,
    cleanup_failures: Vec<std::io::ErrorKind>,
    quotient_shifts: Option<[BabyBear; 8]>,
    writing: bool,
    cleaning: bool,
}
struct Owner {
    main: source::SourceStore,
    path: PathBuf,
    state: Mutex<State>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
        for (index, entry) in state.entries.iter().enumerate().skip(3) {
            if entry.owned && !matches!(entry.state, FileState::Removed | FileState::Uncreated) {
                let _ = fs::remove_file(self.path.join(format!("{index}.bin")));
            }
        }
        let _ = fs::remove_dir(&self.path);
    }
}
struct NewDirectory(Option<PathBuf>);
impl Drop for NewDirectory {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir(path);
        }
    }
}
#[derive(Clone)]
pub struct CompositeStore(Arc<Owner>);

impl CompositeStore {
    /// The actual retained planner runs before raw files or protocol entropy.
    pub fn new<D, I, F, R, S>(
        anchor: &kova_proof_preflight::HidingFriPcs<BabyBear, D, I, F, R, S>,
    ) -> Result<Self, Error>
    where
        D: TwoAdicSubgroupDft<BabyBear>,
        I: Mmcs<BabyBear>,
        F: Mmcs<Challenge>,
        R: CryptoRng + Send + Sync,
        S: kova_proof_preflight::storage::MatrixStore<BabyBear>,
    {
        let plan = anchor
            .resource_plan::<Challenge, _>(&ext::reference_air::QuarticAir, Request::QUARTIC_V1)
            .map_err(Error::Profile)?;
        if plan.height != 256
            || plan.width != 2
            || plan.prepared != [512, 6]
            || plan.main_lde != [4096, 6]
            || plan.auxiliary_lde != [4096, 8]
            || plan.quotient_chunks != 8
            || plan.parameters.random_columns != 4
            || plan.field_files.checked_add(2) != Some(RESERVED_FILES)
            || plan
                .field_bytes
                .checked_add(2048)
                .and_then(|bytes| bytes.checked_add(QUOTIENT_SOURCE_BYTES))
                != Some(RESERVED_BYTES)
            || RESERVED_FILES > 16
            || RESERVED_BYTES > 2 * 1024 * 1024
        {
            return Err(Error::Shape);
        }
        let mut entries = vec![];
        for (role, shape) in [
            (Role::Raw, [256usize, 2usize]),
            (Role::Prepared, [512, 6]),
            (Role::Main, [4096, 6]),
        ]
        .into_iter()
        .chain((0..8).map(|i| (Role::Quotient(i), [4096, 8])))
        .chain([(Role::Auxiliary, [4096, 8])])
        .chain([(
            Role::QuotientEvaluations,
            [QUOTIENT_SOURCE_HEIGHT, QUOTIENT_SOURCE_WIDTH],
        )]) {
            let bytes = shape[0]
                .checked_mul(shape[1])
                .and_then(|n| n.checked_mul(4))
                .ok_or(Error::Limit)?;
            entries.push(Entry {
                role,
                shape,
                bytes,
                state: FileState::Planned,
                owned: false,
            });
        }
        if entries.len() != RESERVED_FILES
            || entries.iter().map(|e| e.bytes).sum::<usize>() != RESERVED_BYTES
        {
            return Err(Error::Limit);
        }
        let main = source::SourceStore::new(anchor)?;
        let root = std::env::temp_dir().canonicalize()?;
        let path = root.join(format!(
            "kova_quotient_composite_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        let mut pending = NewDirectory(Some(path.clone()));
        let path = path.canonicalize()?;
        if path.parent() != Some(root.as_path()) {
            return Err(Error::Owner);
        }
        let result = Self(Arc::new(Owner {
            main,
            path,
            state: Mutex::new(State {
                phase: Phase::Ready,
                failure: None,
                entries,
                cleanup_failures: vec![],
                quotient_shifts: None,
                writing: false,
                cleaning: false,
            }),
        }));
        pending.0 = None;
        Ok(result)
    }
    fn fail(&self, error: Error) {
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        state.phase = Phase::Failed;
        if state.failure.is_none() {
            state.failure = Some(error);
        }
    }
    // Recovery is only for recording shared closure, never for resuming work.
    fn checked_state(&self) -> Result<std::sync::MutexGuard<'_, State>, Error> {
        match self.0.state.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                drop(poisoned.into_inner());
                self.fail(Error::Poisoned);
                Err(Error::Poisoned)
            }
        }
    }
    pub(crate) fn check_phase(&self, expected: Phase) -> Result<(), Error> {
        let state = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.phase != expected {
            return Err(Error::Phase);
        }
        Ok(())
    }
    pub(crate) fn transition(&self, from: Phase, to: Phase) -> Result<(), Error> {
        let mut state = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.phase != from {
            return Err(Error::Phase);
        }
        state.phase = to;
        Ok(())
    }
    fn readable(&self) -> Result<(), Error> {
        let state = self.checked_state()?;
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.phase == Phase::ProofProduced {
            return Err(Error::Closed);
        }
        Ok(())
    }
    /// Reservations are never released by partial cleanup or failure.
    /// Component metadata replaces a planned entry and never adds another one.
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let (phase, failure, mut entries, cleanup_failures) = {
            let s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            (
                s.phase,
                s.failure.clone(),
                s.entries.clone(),
                s.cleanup_failures.clone(),
            )
        };
        let main = match self.0.main.snapshot() {
            Ok(s) => {
                if s.phase == source::Phase::Failed || s.construction.phase == ext::Phase::Failed {
                    self.fail(Error::Main(s.failure.unwrap_or(source::Error::Failed)));
                }
                s.construction
            }
            Err(e) => {
                let e = Error::from(e);
                self.fail(e.clone());
                return Err(e);
            }
        };
        if main.reserved_files > 3 || main.reserved_bytes > 112_640 {
            self.fail(Error::Limit);
            return Err(Error::Limit);
        }
        for item in main.preparation_files {
            let index = match item.role {
                prep::Role::RawInput => 0,
                prep::Role::PreparedInput => 1,
                _ => {
                    self.fail(Error::Owner);
                    return Err(Error::Owner);
                }
            };
            if entries[index].state != FileState::Planned
                || entries[index].shape != item.shape
                || entries[index].bytes != item.bytes
            {
                self.fail(Error::Owner);
                return Err(Error::Owner);
            }
            entries[index].state = match item.state {
                prep::FileState::Pending => FileState::Pending,
                prep::FileState::Complete => FileState::Complete,
                prep::FileState::Removed => FileState::Removed,
                prep::FileState::Uncreated => FileState::Uncreated,
                prep::FileState::Orphan => FileState::Orphan,
            };
        }
        if let Some(item) = main.lde {
            if entries[2].shape != item.shape || entries[2].bytes != item.bytes {
                self.fail(Error::Owner);
                return Err(Error::Owner);
            }
            entries[2].state = match item.state {
                ext::FileState::Reserved => FileState::Pending,
                ext::FileState::Complete => FileState::Complete,
                ext::FileState::Removed => FileState::Removed,
                ext::FileState::Uncreated => FileState::Uncreated,
                ext::FileState::Orphan => FileState::Orphan,
            };
        }
        // Refresh the outer phase after inspecting a failed component.
        let (phase, failure) = if phase != Phase::Failed {
            let s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            (s.phase, s.failure.clone())
        } else {
            (phase, failure)
        };
        Ok(Snapshot {
            phase,
            failure,
            entries,
            reserved_files: RESERVED_FILES,
            reserved_bytes: RESERVED_BYTES,
            cleanup_failures,
        })
    }
    pub fn write_raw(&self, values: impl IntoIterator<Item = BabyBear>) -> Result<RawInput, Error> {
        self.transition(Phase::Ready, Phase::WritingRaw)?;
        let mut step = Step::new(self);
        let inner = self.0.main.write_raw(values).map_err(|e| {
            let e = Error::from(e);
            step.fail(e.clone());
            e
        })?;
        self.transition(Phase::WritingRaw, Phase::RawReady)?;
        step.done = true;
        Ok(RawInput {
            inner,
            owner: self.clone(),
        })
    }
    /// Dropping this guard closes every composite read across all clones.
    /// Proof construction success remains separate from AIR verification.
    pub(crate) fn begin_attempt(&self, raw: &RawInput) -> Result<ProvingAttempt, Error> {
        self.check_raw(raw)?;
        self.transition(Phase::RawReady, Phase::MainReady)?;
        Ok(ProvingAttempt {
            store: self.clone(),
            done: false,
        })
    }
    pub(crate) fn check_raw(&self, raw: &RawInput) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.0, &raw.owner.0) {
            return Err(Error::Owner);
        }
        self.0.main.check_raw(&raw.inner)?;
        Ok(())
    }
    pub(crate) fn main(&self) -> &source::SourceStore {
        &self.0.main
    }
    pub(crate) fn wrap_main(&self, inner: source::Stored) -> Stored {
        Stored {
            data: Data::Main(inner),
            owner: self.clone(),
        }
    }
    /// Constructor check only: the hiding adapter must obtain this matrix
    /// from its actual MMCS prover data, not a caller supplied descriptor.
    pub(crate) fn check_committed_main(&self, matrix: &Stored) -> Result<(), Error> {
        self.readable()?;
        if !Arc::ptr_eq(&self.0, &matrix.owner.0) || !matches!(&matrix.data, Data::Main(_)) {
            return Err(Error::Owner);
        }
        if matrix.height() != 4096 || matrix.width() != 6 {
            return Err(Error::Shape);
        }
        let state = self.checked_state()?;
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.phase != Phase::MainCommitted {
            return Err(Error::Phase);
        }
        Ok(())
    }
    /// Claim the one fixed sink before any file I/O. No protocol entropy is
    /// sampled here, and an unsuccessful second claimant changes no state.
    pub(crate) fn begin_quotient_evaluations(&self) -> Result<QuotientWriter, Error> {
        self.readable()?;
        {
            let mut state = self.checked_state()?;
            if state.phase == Phase::Failed {
                return Err(Error::Failed);
            }
            if state.writing || state.cleaning {
                return Err(Error::Busy);
            }
            if state.phase != Phase::MainCommitted
                || state.entries[QUOTIENT_SOURCE_INDEX].role != Role::QuotientEvaluations
                || state.entries[QUOTIENT_SOURCE_INDEX].state != FileState::Planned
            {
                return Err(Error::Phase);
            }
            state.phase = Phase::QuotientEvaluating;
            state.writing = true;
            state.entries[QUOTIENT_SOURCE_INDEX].state = FileState::Pending;
        }
        let mut writer = QuotientWriter {
            file: None,
            owner: self.clone(),
            next_row: 0,
            created: false,
            done: false,
        };
        if let Err(error) = writer.create_file() {
            writer.abort(error.clone());
            return Err(error);
        }
        Ok(writer)
    }
    fn check_quotient_writer(&self) -> Result<(), Error> {
        self.readable()?;
        let state = self.checked_state()?;
        let entry = &state.entries[QUOTIENT_SOURCE_INDEX];
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.phase != Phase::QuotientEvaluating
            || !state.writing
            || entry.role != Role::QuotientEvaluations
            || entry.state != FileState::Pending
            || entry.shape != [QUOTIENT_SOURCE_HEIGHT, QUOTIENT_SOURCE_WIDTH]
            || entry.bytes != QUOTIENT_SOURCE_BYTES
        {
            return Err(Error::Phase);
        }
        Ok(())
    }
    pub(crate) fn check_quotient_input(&self, input: &QuotientInput) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.0, &input.owner.0) {
            return Err(Error::Owner);
        }
        input.check_readable()
    }
    fn reserve_other(&self, auxiliary: bool, shift: BabyBear) -> Result<usize, Error> {
        let mut state = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        let expected = if auxiliary {
            Phase::AuxiliaryBuilding
        } else {
            Phase::QuotientBuilding
        };
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.phase != expected {
            return Err(Error::Phase);
        }
        if state.writing {
            return Err(Error::Busy);
        }
        let index = if auxiliary {
            11
        } else {
            (3..11)
                .find(|i| state.entries[*i].state == FileState::Planned)
                .ok_or(Error::Limit)?
        };
        if state.entries[index].state != FileState::Planned {
            return Err(Error::Phase);
        }
        if !auxiliary && state.quotient_shifts.ok_or(Error::Incomplete)?[index - 3] != shift {
            return Err(Error::Domain);
        }
        state.entries[index].state = FileState::Pending;
        state.writing = true;
        Ok(index)
    }
    fn write_other(&self, index: usize, matrix: RowMajorMatrix<BabyBear>) -> Result<Stored, Error> {
        if matrix.height() != 4096 || matrix.width() != 8 || matrix.values.len() != 32768 {
            return Err(Error::Shape);
        }
        let mut pending = Pending {
            store: self,
            index,
            file: None,
            created: false,
            done: false,
        };
        let result = (|| {
            pending.file = Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.path(index))?,
            );
            pending.created = true;
            self.0.state.lock().map_err(|_| Error::Poisoned)?.entries[index].owned = true;
            let file = pending.file.as_mut().ok_or(Error::Incomplete)?;
            for row in matrix.values.chunks_exact(8) {
                let mut bytes = [0u8; 32];
                for (field, out) in row.iter().zip(bytes.chunks_exact_mut(4)) {
                    out.copy_from_slice(&field.as_canonical_u32().to_le_bytes());
                }
                file.write_all(&bytes)?;
            }
            file.sync_all()?;
            drop(pending.file.take());
            let matrix =
                CheckedFileMatrix::open(&self.path(index), 4096, 8).map_err(Error::Access)?;
            let mut state = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            let expected = if index == 11 {
                Phase::AuxiliaryBuilding
            } else {
                Phase::QuotientBuilding
            };
            if state.phase == Phase::Failed {
                return Err(Error::Failed);
            }
            if state.phase != expected
                || !state.writing
                || state.entries[index].state != FileState::Pending
            {
                return Err(Error::Phase);
            }
            state.entries[index].state = FileState::Complete;
            state.writing = false;
            if index == 10 {
                state.phase = Phase::QuotientCommitting;
            }
            if index == 11 {
                state.phase = Phase::AuxiliaryCommitting;
            }
            Ok(Stored {
                data: Data::Other(matrix),
                owner: self.clone(),
            })
        })();
        match result {
            Ok(stored) => {
                pending.done = true;
                Ok(stored)
            }
            Err(e) => {
                pending.abort(e.clone());
                Err(e)
            }
        }
    }
    fn path(&self, index: usize) -> PathBuf {
        self.0.path.join(format!("{index}.bin"))
    }
    /// Only orphaned partial files are retried. Complete leased data is retained.
    pub fn cleanup_orphans(&self) -> Result<Vec<std::io::ErrorKind>, Error> {
        let indices = {
            let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            if s.phase != Phase::Failed {
                return Err(Error::Phase);
            }
            if s.cleaning {
                return Err(Error::Busy);
            }
            s.cleaning = true;
            s.entries
                .iter()
                .enumerate()
                .skip(3)
                .filter(|(_, e)| e.owned && e.state == FileState::Orphan)
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        };
        let _claim = CleanupClaim(self);
        let mut failures = vec![];
        for index in indices {
            match fs::remove_file(self.path(index)) {
                Ok(()) => {
                    self.0.state.lock().map_err(|_| Error::Poisoned)?.entries[index].state =
                        FileState::Removed
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.0.state.lock().map_err(|_| Error::Poisoned)?.entries[index].state =
                        FileState::Removed
                }
                Err(e) => failures.push(e.kind()),
            }
        }
        let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        for e in &failures {
            if s.cleanup_failures.len() < 16 {
                s.cleanup_failures.push(*e);
            }
        }
        Ok(failures)
    }
}

struct CleanupClaim<'a>(&'a CompositeStore);
impl Drop for CleanupClaim<'_> {
    fn drop(&mut self) {
        self.0
            .0
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cleaning = false;
    }
}

pub(crate) struct ProvingAttempt {
    store: CompositeStore,
    done: bool,
}
impl Drop for ProvingAttempt {
    fn drop(&mut self) {
        if !self.done {
            self.store.fail(Error::Unwind);
        }
    }
}
pub(crate) struct Step<'a> {
    store: &'a CompositeStore,
    pub(crate) done: bool,
}
impl<'a> Step<'a> {
    pub(crate) fn new(store: &'a CompositeStore) -> Self {
        Self { store, done: false }
    }
    pub(crate) fn fail(&mut self, error: Error) {
        self.store.fail(error);
        self.done = true;
    }
}
impl Drop for Step<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.store.fail(Error::Unwind);
        }
    }
}
struct Pending<'a> {
    store: &'a CompositeStore,
    index: usize,
    file: Option<File>,
    created: bool,
    done: bool,
}
impl Pending<'_> {
    fn abort(&mut self, error: Error) {
        drop(self.file.take());
        self.store.fail(error);
        let result = if self.created {
            fs::remove_file(self.store.path(self.index))
        } else {
            Ok(())
        };
        let mut state = self.store.0.state.lock().unwrap_or_else(|p| p.into_inner());
        // The failed owner's writer has closed its descriptor. Releasing this
        // claim does not reopen the failed owner or restore unlink authority.
        state.writing = false;
        let entry = &mut state.entries[self.index];
        entry.owned |= self.created;
        entry.state = if !self.created {
            FileState::Uncreated
        } else {
            match result {
                Ok(()) => FileState::Removed,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileState::Removed,
                Err(e) => {
                    if state.cleanup_failures.len() < 16 {
                        state.cleanup_failures.push(e.kind());
                    }
                    state.entries[self.index].state = FileState::Orphan;
                    self.done = true;
                    return;
                }
            }
        };
        self.done = true;
    }
}
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.abort(Error::Unwind);
        }
    }
}

/// One exclusive, fixed-shape quotient evaluation sink. Neither this writer nor
/// its completed input is Clone; their descriptors precede the owner lease.
pub(crate) struct QuotientWriter {
    file: Option<File>,
    owner: CompositeStore,
    next_row: usize,
    created: bool,
    done: bool,
}
impl QuotientWriter {
    fn check_active(&self) -> Result<(), Error> {
        if self.done {
            return Err(Error::Closed);
        }
        self.owner.check_quotient_writer()
    }
    fn create_file(&mut self) -> Result<(), Error> {
        self.check_active()?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.owner.path(QUOTIENT_SOURCE_INDEX))?;
        // This flag does not depend on successfully locking the ledger later.
        self.created = true;
        self.file = Some(file);
        let mut state = self.owner.checked_state()?;
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.phase != Phase::QuotientEvaluating
            || !state.writing
            || state.entries[QUOTIENT_SOURCE_INDEX].state != FileState::Pending
        {
            return Err(Error::Phase);
        }
        state.entries[QUOTIENT_SOURCE_INDEX].owned = true;
        Ok(())
    }
    /// Fail the shared owner before the writer is dropped. The construction
    /// driver must call this on kernel errors that did not originate here, so
    /// the first cause is not replaced by the subsequent unwind/drop marker.
    pub(crate) fn abort(&mut self, error: Error) {
        if self.done {
            return;
        }
        drop(self.file.take());
        self.owner.fail(error);
        // Only a successful create_new grants this attempt unlink authority.
        let removal = if self.created {
            fs::remove_file(self.owner.path(QUOTIENT_SOURCE_INDEX))
        } else {
            Ok(())
        };
        let mut state = self.owner.0.state.lock().unwrap_or_else(|p| p.into_inner());
        state.entries[QUOTIENT_SOURCE_INDEX].owned |= self.created;
        let (file_state, cleanup_failure) = if !self.created {
            (FileState::Uncreated, None)
        } else {
            match removal {
                Ok(()) => (FileState::Removed, None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    (FileState::Removed, None)
                }
                Err(error) => (FileState::Orphan, Some(error.kind())),
            }
        };
        state.entries[QUOTIENT_SOURCE_INDEX].state = file_state;
        state.writing = false;
        if let Some(error) = cleanup_failure
            && state.cleanup_failures.len() < 16
        {
            state.cleanup_failures.push(error);
        }
        self.done = true;
    }
    pub(crate) fn write_row(&mut self, row: usize, coefficients: &[BabyBear]) -> Result<(), Error> {
        let result = (|| {
            self.check_active()?;
            if row != self.next_row
                || row >= QUOTIENT_SOURCE_HEIGHT
                || coefficients.len() != QUOTIENT_SOURCE_WIDTH
            {
                return Err(Error::Shape);
            }
            let mut bytes = [0u8; QUOTIENT_SOURCE_WIDTH * 4];
            for (field, output) in coefficients.iter().zip(bytes.chunks_exact_mut(4)) {
                output.copy_from_slice(&field.as_canonical_u32().to_le_bytes());
            }
            self.file
                .as_mut()
                .ok_or(Error::Incomplete)?
                .write_all(&bytes)?;
            // A concurrent failure cannot let this write report new progress.
            self.check_active()?;
            self.next_row += 1;
            Ok(())
        })();
        if let Err(error) = &result {
            self.abort(error.clone());
        }
        result
    }
    /// Data completion only. No constraint verdict or proof phase is inferred.
    /// The completed descriptor is reopened before the ledger is sealed.
    pub(crate) fn finish(mut self) -> Result<QuotientInput, Error> {
        let result = (|| {
            self.check_active()?;
            if self.next_row != QUOTIENT_SOURCE_HEIGHT {
                return Err(Error::Incomplete);
            }
            self.file.as_ref().ok_or(Error::Incomplete)?.sync_all()?;
            drop(self.file.take());
            let matrix = CheckedFileMatrix::open(
                &self.owner.path(QUOTIENT_SOURCE_INDEX),
                QUOTIENT_SOURCE_HEIGHT,
                QUOTIENT_SOURCE_WIDTH,
            )
            .map_err(Error::Access)?;
            {
                let mut state = self.owner.checked_state()?;
                let entry = &state.entries[QUOTIENT_SOURCE_INDEX];
                if state.phase == Phase::Failed {
                    return Err(Error::Failed);
                }
                if state.phase != Phase::QuotientEvaluating
                    || !state.writing
                    || entry.role != Role::QuotientEvaluations
                    || entry.state != FileState::Pending
                    || !entry.owned
                    || entry.shape != [QUOTIENT_SOURCE_HEIGHT, QUOTIENT_SOURCE_WIDTH]
                    || entry.bytes != QUOTIENT_SOURCE_BYTES
                {
                    return Err(Error::Phase);
                }
                state.entries[QUOTIENT_SOURCE_INDEX].state = FileState::Complete;
                state.writing = false;
                state.phase = Phase::QuotientReady;
            }
            Ok(QuotientInput {
                matrix,
                owner: self.owner.clone(),
            })
        })();
        match result {
            Ok(input) => {
                self.done = true;
                Ok(input)
            }
            Err(error) => {
                self.abort(error.clone());
                Err(error)
            }
        }
    }
}
impl Drop for QuotientWriter {
    fn drop(&mut self) {
        if !self.done {
            self.abort(Error::Unwind);
        }
    }
}
impl crate::quotient_kernel::QuotientWrite for QuotientWriter {
    type Error = Error;
    fn dimensions(&self) -> Result<[usize; 2], Error> {
        if let Err(error) = self.check_active() {
            // &self cannot close the descriptor; the live writer's Drop does.
            self.owner.fail(error.clone());
            return Err(error);
        }
        Ok([QUOTIENT_SOURCE_HEIGHT, QUOTIENT_SOURCE_WIDTH])
    }
    fn write_row(&mut self, row: usize, coefficients: &[BabyBear]) -> Result<(), Error> {
        QuotientWriter::write_row(self, row, coefficients)
    }
}

/// Sealed completed data, retained in this owner until its lifecycle closes.
/// Deliberately no Matrix implementation, descriptor/path getter or Clone.
pub(crate) struct QuotientInput {
    matrix: CheckedFileMatrix,
    owner: CompositeStore,
}
impl QuotientInput {
    pub(crate) fn check_readable(&self) -> Result<(), Error> {
        self.owner.readable()?;
        let state = self.owner.checked_state()?;
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.phase == Phase::ProofProduced {
            return Err(Error::Closed);
        }
        let entry = &state.entries[QUOTIENT_SOURCE_INDEX];
        let complete = entry.role == Role::QuotientEvaluations
            && entry.state == FileState::Complete
            && entry.owned
            && entry.shape == [QUOTIENT_SOURCE_HEIGHT, QUOTIENT_SOURCE_WIDTH]
            && entry.bytes == QUOTIENT_SOURCE_BYTES;
        let allowed = matches!(
            state.phase,
            Phase::QuotientReady
                | Phase::QuotientBuilding
                | Phase::QuotientCommitting
                | Phase::QuotientCommitted
                | Phase::AuxiliaryBuilding
                | Phase::AuxiliaryCommitting
                | Phase::AuxiliaryCommitted
                | Phase::Opening
        );
        if !complete || !allowed {
            drop(state);
            self.owner.fail(Error::Phase);
            return Err(Error::Phase);
        }
        Ok(())
    }
    pub(crate) fn dimensions(&self) -> Result<[usize; 2], Error> {
        self.check_readable()?;
        Ok([QUOTIENT_SOURCE_HEIGHT, QUOTIENT_SOURCE_WIDTH])
    }
    pub(crate) fn try_window(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> Result<Vec<BabyBear>, Error> {
        self.check_readable()?;
        if row >= QUOTIENT_SOURCE_HEIGHT || start > end || end > QUOTIENT_SOURCE_WIDTH {
            return Err(Error::Access(StorageError::Bounds));
        }
        let values = self.matrix.try_window(row, start, end).map_err(|error| {
            let error = Error::Access(error);
            self.owner.fail(error.clone());
            error
        })?;
        self.check_readable()?;
        Ok(values)
    }
}

#[derive(Clone)]
pub struct RawInput {
    pub(crate) inner: source::RawInput,
    owner: CompositeStore,
}
#[derive(Clone)]
enum Data {
    Main(source::Stored),
    Other(CheckedFileMatrix),
}
/// The data descriptor precedes the directory owner in destruction order.
#[derive(Clone)]
pub struct Stored {
    data: Data,
    owner: CompositeStore,
}
impl Stored {
    /// The hiding view may validate shared closure without performing I/O.
    pub(crate) fn check_readable(&self) -> Result<(), Error> {
        self.owner.readable()
    }
    pub fn try_window(&self, row: usize, start: usize, end: usize) -> Result<Vec<BabyBear>, Error> {
        self.check_readable()?;
        if row >= self.height() || start > end || end > self.width() {
            return Err(Error::Access(StorageError::Bounds));
        }
        let result = match &self.data {
            Data::Main(m) => m.try_window(row, start, end).map_err(Error::Main),
            Data::Other(m) => m.try_window(row, start, end).map_err(Error::Access),
        };
        let values = result.inspect_err(|error| {
            self.owner.fail(error.clone());
        })?;
        self.check_readable()?;
        Ok(values)
    }
}
#[allow(unsafe_code)]
mod matrix {
    use super::*;
    impl Matrix<BabyBear> for Stored {
        fn height(&self) -> usize {
            match &self.data {
                Data::Main(m) => m.height(),
                Data::Other(m) => m.height(),
            }
        }
        fn width(&self) -> usize {
            match &self.data {
                Data::Main(m) => m.width(),
                Data::Other(m) => m.width(),
            }
        }
        unsafe fn row_unchecked(
            &self,
            row: usize,
        ) -> impl IntoIterator<Item = BabyBear, IntoIter = impl Iterator<Item = BabyBear> + Send + Sync>
        {
            self.try_window(row, 0, self.width())
                .unwrap_or_else(|e| std::panic::panic_any(e))
        }
        fn to_row_major_matrix(self) -> RowMajorMatrix<BabyBear> {
            std::panic::panic_any(Error::Unsupported)
        }
    }
}
impl RowSource<BabyBear> for Stored {
    fn read_window(&self, row: usize, start: usize, end: usize) -> Option<Vec<BabyBear>> {
        if row >= self.height() || start > end || end > self.width() {
            return None;
        }
        Some(
            self.try_window(row, start, end)
                .unwrap_or_else(|e| std::panic::panic_any(e)),
        )
    }
}
impl MatrixStore<BabyBear> for CompositeStore {
    type Stored = Stored;
    fn store(&self, _: RowMajorMatrix<BabyBear>) -> Stored {
        std::panic::panic_any(Error::Unsupported)
    }
    fn randomize<R: Rng + Send + Sync>(
        &self,
        _: RowMajorMatrix<BabyBear>,
        _: usize,
        _: &mut R,
    ) -> Stored {
        std::panic::panic_any(Error::Unsupported)
    }
    fn extend_prepared<D: TwoAdicSubgroupDft<BabyBear>, M: RowSource<BabyBear>>(
        &self,
        _: &D,
        _: M,
        _: usize,
        _: BabyBear,
    ) -> Stored {
        std::panic::panic_any(Error::Unsupported)
    }
    fn extend<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &D,
        evaluations: RowMajorMatrix<BabyBear>,
        log_blowup: usize,
        shift: BabyBear,
    ) -> Stored {
        let mut step = Step::new(self);
        let run = || -> Result<Stored, Error> {
            self.check_phase(Phase::AuxiliaryBuilding)?;
            if evaluations.height() != 512
                || evaluations.width() != 8
                || evaluations.values.len() != 4096
                || log_blowup != 3
                || shift != BabyBear::GENERATOR
            {
                return Err(Error::Shape);
            }
            let index = self.reserve_other(true, shift)?;
            let output = DenseStore.extend(dft, evaluations, log_blowup, shift);
            self.write_other(index, output)
        };
        match run() {
            Ok(stored) => {
                step.done = true;
                stored
            }
            Err(e) => {
                step.fail(e.clone());
                std::panic::panic_any(e)
            }
        }
    }
    fn extend_quotient<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &D,
        evaluations: RowMajorMatrix<BabyBear>,
        masks: &[BabyBear],
        log_blowup: usize,
        shift: BabyBear,
    ) -> Stored {
        self.extend_quotient_owned(dft, evaluations, masks, log_blowup, shift)
            .unwrap_or_else(|error| std::panic::panic_any(error))
    }
}

// Place in the fresh composite module with the existing private owner types.
impl CompositeStore {
    pub(crate) fn begin_quotient_source(
        &self,
        input: &QuotientInput,
        shifts: [BabyBear; 8],
    ) -> Result<(), Error> {
        self.check_quotient_input(input)?;
        let mut state = self.checked_state()?;
        if state.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        if state.writing || state.cleaning {
            return Err(Error::Busy);
        }
        if state.phase != Phase::QuotientReady || state.quotient_shifts.is_some() {
            return Err(Error::Phase);
        }
        // The fixed hiding adapter derived these shifts from its checked domain.
        // No caller-controlled filename, role or field-file reservation is added.
        for i in 0..8 {
            let entry = &state.entries[3 + i];
            if entry.role != Role::Quotient(i)
                || entry.state != FileState::Planned
                || entry.owned
                || entry.shape != [4096, 8]
                || entry.bytes != 131_072
            {
                return Err(Error::Phase);
            }
        }
        state.quotient_shifts = Some(shifts);
        state.phase = Phase::QuotientBuilding;
        Ok(())
    }

    /// Fallible owner bridge to the actual retained masked LDE kernel.
    /// Infallible MatrixStore callers may separately convert this error to panic.
    pub(crate) fn extend_quotient_owned<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &D,
        evaluations: RowMajorMatrix<BabyBear>,
        masks: &[BabyBear],
        log_blowup: usize,
        shift: BabyBear,
    ) -> Result<Stored, Error> {
        let mut step = Step::new(self);
        let result = (|| {
            self.check_phase(Phase::QuotientBuilding)?;
            if evaluations.height() != 256
                || evaluations.width() != 8
                || evaluations.values.len() != 2048
                || masks.len() != 2048
                || log_blowup != 3
            {
                return Err(Error::Shape);
            }
            let index = self.reserve_other(false, shift)?;
            let output = DenseStore.extend_quotient(dft, evaluations, masks, log_blowup, shift);
            self.write_other(index, output)
        })();
        match &result {
            Ok(_) => step.done = true,
            Err(error) => step.fail(error.clone()),
        }
        result
    }
}

// Original source-stark attempt transitions for the future fresh owner module.
// These are absent from the published commitment-only nominal owner.
impl ProvingAttempt {
    pub(crate) fn begin_opening(&self) -> Result<(), Error> {
        self.store
            .transition(Phase::AuxiliaryCommitted, Phase::Opening)
    }

    pub(crate) fn finish_produced(&mut self) -> Result<(), Error> {
        self.store
            .transition(Phase::Opening, Phase::ProofProduced)?;
        self.done = true;
        Ok(())
    }
}

#[path = "faults.rs"]
pub(crate) mod faults;
