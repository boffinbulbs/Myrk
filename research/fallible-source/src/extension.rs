//! Bounded owned preparation and streamed main LDE. No PCS entry or proof.
#![deny(unsafe_code)]

use kova_fallible_input as prep;
use kova_proof_preflight::{
    HidingFriPcs,
    preflight::{Refusal, Request, ResourcePlan},
    storage::MatrixStore,
};
use kova_storage_matrix::{CheckedFileMatrix, StorageError};
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeField32, extension::BinomialExtensionField};
use p3_matrix::{Matrix, bitrev::BitReversibleMatrix, dense::RowMajorMatrix};
use rand::CryptoRng;
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

#[path = "../../storage-pcs/tests/common/air.rs"]
#[allow(
    dead_code,
    reason = "Retained trace generators are outside raw input failure controls"
)]
pub mod reference_air;

type E4 = BinomialExtensionField<BabyBear, 4>;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const TILE: usize = 4;
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct NewDirectory(Option<PathBuf>);
impl Drop for NewDirectory {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir(path);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Profile(Refusal),
    Preparation(prep::Error),
    Access(StorageError),
    Shape,
    Header,
    Owner,
    Limit,
    Busy,
    Complete,
    Failed,
    Poisoned,
    Incomplete,
    Unsupported,
    Unwind,
    Io(std::io::ErrorKind),
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl From<prep::Error> for Error {
    fn from(e: prep::Error) -> Self {
        Self::Preparation(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Ready,
    WritingRaw,
    Preparing,
    Prepared,
    Extending,
    LdeReady,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    Reserved,
    Complete,
    Removed,
    Uncreated,
    Orphan,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub pcs_height: usize,
    pub shift: u64,
    pub log_blowup: usize,
    pub opening_points: usize,
}
impl Header {
    pub const QUARTIC: Self = Self {
        pcs_height: 512,
        shift: 1,
        log_blowup: 3,
        opening_points: 2,
    };
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdeReservation {
    pub shape: [usize; 2],
    pub bytes: usize,
    pub state: FileState,
    owned: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamEvent {
    pub input: [usize; 2],
    pub output: [usize; 2],
    pub source_windows: usize,
    pub source_fields: usize,
    pub batches: usize,
    pub largest_input_tile_fields: usize,
    pub largest_output_tile_fields: usize,
    pub written_fields: usize,
    pub write_calls: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub preparation_files: Vec<prep::Entry>,
    pub lde: Option<LdeReservation>,
    pub reserved_files: usize,
    pub reserved_bytes: usize,
    pub pending_preparation_bytes: usize,
    pub failure: Option<Error>,
    pub cleanup_failures: Vec<std::io::ErrorKind>,
    pub stream: Option<StreamEvent>,
}
struct State {
    phase: Phase,
    lde: Option<LdeReservation>,
    planning_preparation: bool,
    failure: Option<Error>,
    cleanup_failures: Vec<std::io::ErrorKind>,
    stream: Option<StreamEvent>,
}
#[derive(Default)]
struct Faults {
    write_after: Option<usize>,
    panic_after: Option<usize>,
    read: Option<ReadFault>,
    cleanup: AtomicUsize,
}
#[derive(Clone, Copy)]
#[allow(
    dead_code,
    reason = "Variants are constructed only by explicit fault controls"
)]
enum ReadFault {
    Missing,
    Short,
    Poison,
}
struct Owner {
    preparation: prep::PreparationStore,
    path: PathBuf,
    plan: ResourcePlan,
    state: Mutex<State>,
    faults: Faults,
}
impl Drop for Owner {
    fn drop(&mut self) {
        let s = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = &s.lde
            && e.owned
            && !matches!(e.state, FileState::Removed | FileState::Uncreated)
        {
            let _ = fs::remove_file(self.path.join("0.bin"));
        }
        let _ = fs::remove_dir(&self.path);
    }
}
#[derive(Clone)]
pub struct CommitmentStore(Arc<Owner>);
impl CommitmentStore {
    /// The actual retained small resource planner runs before owner construction.
    pub fn new<D, I, F, R, S>(pcs: &HidingFriPcs<BabyBear, D, I, F, R, S>) -> Result<Self, Error>
    where
        D: TwoAdicSubgroupDft<BabyBear>,
        I: Mmcs<BabyBear>,
        F: Mmcs<E4>,
        R: CryptoRng + Send + Sync,
        S: MatrixStore<BabyBear>,
    {
        let plan = pcs
            .resource_plan::<E4, _>(&reference_air::QuarticAir, Request::QUARTIC_V1)
            .map_err(Error::Profile)?;
        Self::from_plan(plan, Faults::default())
    }
    fn from_plan(plan: ResourcePlan, faults: Faults) -> Result<Self, Error> {
        if plan.height != 256
            || plan.width != 2
            || plan.prepared != [512, 6]
            || plan.main_lde != [4096, 6]
        {
            return Err(Error::Shape);
        }
        let preparation = prep::PreparationStore::new()?;
        let root = std::env::temp_dir().canonicalize()?;
        let path = root.join(format!(
            "kova_source_lde_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        let mut pending_directory = NewDirectory(Some(path.clone()));
        let path = path.canonicalize()?;
        if path.parent() != Some(root.as_path()) {
            return Err(Error::Owner);
        }
        let store = Self(Arc::new(Owner {
            preparation,
            path,
            plan,
            faults,
            state: Mutex::new(State {
                phase: Phase::Ready,
                lde: None,
                planning_preparation: false,
                failure: None,
                cleanup_failures: vec![],
                stream: None,
            }),
        }));
        pending_directory.0 = None;
        Ok(store)
    }
    fn check_header(&self, h: Header) -> Result<(), Error> {
        if h != Header::QUARTIC {
            return Err(Error::Header);
        }
        Ok(())
    }
    fn state_error(phase: Phase) -> Error {
        match phase {
            Phase::Failed => Error::Failed,
            Phase::LdeReady => Error::Complete,
            _ => Error::Busy,
        }
    }
    fn snapshot_locked(&self, s: &State) -> Result<Snapshot, Error> {
        let p = self.0.preparation.snapshot()?;
        let expected = bytes(self.0.plan.prepared)?;
        let observed = p
            .files
            .iter()
            .filter(|f| f.role == prep::Role::PreparedInput)
            .try_fold(0usize, |n, f| n.checked_add(f.bytes).ok_or(Error::Limit))?;
        if observed > expected {
            return Err(Error::Limit);
        }
        let pending = if s.planning_preparation {
            expected - observed
        } else {
            0
        };
        let reserved_files = p
            .files
            .len()
            .checked_add(usize::from(pending > 0))
            .and_then(|n| n.checked_add(usize::from(s.lde.is_some())))
            .ok_or(Error::Limit)?;
        let reserved_bytes = p
            .reserved_bytes
            .checked_add(pending)
            .and_then(|n| n.checked_add(s.lde.as_ref().map_or(0, |f| f.bytes)))
            .ok_or(Error::Limit)?;
        if reserved_files > 16 || reserved_bytes > MAX_BYTES {
            return Err(Error::Limit);
        }
        Ok(Snapshot {
            phase: s.phase,
            preparation_files: p.files,
            lde: s.lde.clone(),
            reserved_files,
            reserved_bytes,
            pending_preparation_bytes: pending,
            failure: s.failure.clone(),
            cleanup_failures: s.cleanup_failures.clone(),
            stream: s.stream.clone(),
        })
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        self.snapshot_locked(&s)
    }
    fn readable(&self) -> Result<(), Error> {
        let s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if s.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        Ok(())
    }
    fn fail(&self, error: Error) {
        let mut s = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        s.phase = Phase::Failed;
        if s.failure.is_none() {
            s.failure = Some(error);
        }
    }
    pub fn write_raw(&self, values: impl IntoIterator<Item = BabyBear>) -> Result<RawInput, Error> {
        self.write_raw_with(|| self.0.preparation.write_raw(256, 2, values))
    }
    pub fn try_write_raw(
        &self,
        values: impl IntoIterator<Item = Result<BabyBear, prep::Error>>,
    ) -> Result<RawInput, Error> {
        self.write_raw_with(|| self.0.preparation.try_write_raw(256, 2, values))
    }
    fn write_raw_with(
        &self,
        write: impl FnOnce() -> Result<prep::OwnedMatrix, prep::Error>,
    ) -> Result<RawInput, Error> {
        {
            let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            if s.phase != Phase::Ready {
                return Err(Self::state_error(s.phase));
            }
            if !self.0.preparation.snapshot()?.files.is_empty() {
                return Err(Error::Owner);
            }
            s.phase = Phase::WritingRaw;
        }
        let mut attempt = Attempt {
            store: self,
            done: false,
        };
        let result = write().map_err(Error::from);
        match result {
            Ok(matrix) => {
                self.0.state.lock().map_err(|_| Error::Poisoned)?.phase = Phase::Ready;
                attempt.done = true;
                Ok(RawInput {
                    matrix,
                    owner: self.clone(),
                })
            }
            Err(e) => {
                self.fail(e.clone());
                attempt.done = true;
                Err(e)
            }
        }
    }
    fn reserve(&self, header: Header, dense: bool) -> Result<(), Error> {
        self.check_header(header)?;
        let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if s.phase != Phase::Ready {
            return Err(Self::state_error(s.phase));
        }
        let p = self.0.preparation.snapshot()?;
        if (dense && !p.files.is_empty())
            || (!dense
                && (p.files.len() != 1
                    || p.files[0].role != prep::Role::RawInput
                    || p.files[0].state != prep::FileState::Complete))
        {
            return Err(Error::Owner);
        }
        let lde = LdeReservation {
            shape: self.0.plan.main_lde,
            bytes: bytes(self.0.plan.main_lde)?,
            state: FileState::Reserved,
            owned: false,
        };
        let total = p
            .reserved_bytes
            .checked_add(bytes(self.0.plan.prepared)?)
            .and_then(|n| n.checked_add(lde.bytes))
            .ok_or(Error::Limit)?;
        if total > MAX_BYTES || p.files.len() + 2 > 16 {
            return Err(Error::Limit);
        }
        s.planning_preparation = true;
        s.lde = Some(lde);
        s.phase = Phase::Preparing;
        Ok(())
    }
    pub fn prepare_owned<R: CryptoRng + Send + Sync>(
        &self,
        raw: RawInput,
        header: Header,
        rng: &mut R,
    ) -> Result<Stored, Error> {
        if !Arc::ptr_eq(&self.0, &raw.owner.0) {
            return Err(Error::Owner);
        }
        self.reserve(header, false)?;
        let attempt = Attempt {
            store: self,
            done: false,
        };
        let result =
            self.0
                .preparation
                .prepare_owned(raw.matrix, 4, prep::Domain::natural(256), rng);
        self.finish_preparation(result, attempt)
    }
    pub fn prepare_dense<R: CryptoRng + Send + Sync>(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        header: Header,
        rng: &mut R,
    ) -> Result<Stored, Error> {
        if matrix.width != 2 || matrix.values.len() != 512 {
            return Err(Error::Shape);
        }
        self.reserve(header, true)?;
        let attempt = Attempt {
            store: self,
            done: false,
        };
        let result = self
            .0
            .preparation
            .prepare_dense(matrix, 4, prep::Domain::natural(256), rng);
        self.finish_preparation(result, attempt)
    }
    fn finish_preparation(
        &self,
        result: Result<prep::OwnedMatrix, prep::Error>,
        mut attempt: Attempt<'_>,
    ) -> Result<Stored, Error> {
        match result {
            Ok(matrix) => {
                let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
                self.snapshot_locked(&s)?;
                s.planning_preparation = false;
                s.phase = Phase::Prepared;
                attempt.done = true;
                Ok(Stored {
                    matrix: Data::Prepared(matrix),
                    owner: self.clone(),
                })
            }
            Err(e) => {
                let e = Error::from(e);
                self.fail(e.clone());
                attempt.done = true;
                Err(e)
            }
        }
    }
    /// Only an owned prepared handle from this attempt may enter the streaming kernel.
    pub fn extend_owned<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        source: Stored,
        dft: &D,
    ) -> Result<Stored, Error> {
        if !Arc::ptr_eq(&self.0, &source.owner.0) || !matches!(&source.matrix, Data::Prepared(_)) {
            return Err(Error::Owner);
        }
        {
            let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            if s.phase != Phase::Prepared {
                return Err(Self::state_error(s.phase));
            }
            if [source.height(), source.width()] != self.0.plan.prepared {
                return Err(Error::Shape);
            }
            self.snapshot_locked(&s)?;
            s.phase = Phase::Extending;
        }
        let mut attempt = Attempt {
            store: self,
            done: false,
        };
        let mut pending = Pending {
            store: self,
            file: None,
            created: false,
            done: false,
        };
        let result: Result<Stored, Error> = (|| {
            pending.file = Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.0.path.join("0.bin"))?,
            );
            pending.created = true;
            self.0
                .state
                .lock()
                .map_err(|_| Error::Poisoned)?
                .lde
                .as_mut()
                .ok_or(Error::Incomplete)?
                .owned = true;
            let mut event = StreamEvent {
                input: self.0.plan.prepared,
                output: self.0.plan.main_lde,
                ..Default::default()
            };
            let file = pending.file.as_mut().ok_or(Error::Incomplete)?;
            stream(&source, dft, file, &self.0.faults, &mut event)?;
            file.sync_all()?;
            drop(pending.file.take());
            let matrix = CheckedFileMatrix::open(&self.0.path.join("0.bin"), 4096, 6)
                .map_err(Error::Access)?;
            let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            s.lde.as_mut().ok_or(Error::Incomplete)?.state = FileState::Complete;
            s.stream = Some(event);
            s.phase = Phase::LdeReady;
            Ok(Stored {
                matrix: Data::Lde(matrix),
                owner: self.clone(),
            })
        })();
        match result {
            Ok(matrix) => {
                pending.done = true;
                attempt.done = true;
                Ok(matrix)
            }
            Err(e) => {
                pending.abort(e.clone());
                attempt.done = true;
                Err(e)
            }
        }
    }
    /// Only new LDE paths are removed. Frozen successful preparation leases remain intact.
    #[allow(
        dead_code,
        reason = "Retained LDE cleanup is outside raw input failure controls"
    )]
    pub fn cleanup_failed(&self) -> Result<Vec<std::io::ErrorKind>, Error> {
        let mut s = match self.0.state.lock() {
            Ok(s) => s,
            Err(p) => {
                let mut s = p.into_inner();
                s.phase = Phase::Failed;
                s.failure = Some(Error::Poisoned);
                s
            }
        };
        if s.phase != Phase::Failed {
            return Err(Error::Failed);
        }
        let mut failures = vec![];
        if let Some(e) = s.lde.as_mut()
            && e.owned
            && !matches!(e.state, FileState::Removed | FileState::Uncreated)
        {
            match fs::remove_file(self.0.path.join("0.bin")) {
                Ok(()) => e.state = FileState::Removed,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    e.state = FileState::Removed
                }
                Err(err) => {
                    e.state = FileState::Orphan;
                    failures.push(err.kind());
                }
            }
        }
        for error in &failures {
            if s.cleanup_failures.len() < 16 {
                s.cleanup_failures.push(*error);
            }
        }
        Ok(failures)
    }
}

struct Attempt<'a> {
    store: &'a CommitmentStore,
    done: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.store.fail(Error::Unwind);
        }
    }
}
struct Pending<'a> {
    store: &'a CommitmentStore,
    file: Option<File>,
    created: bool,
    done: bool,
}
impl Pending<'_> {
    fn abort(&mut self, error: Error) {
        drop(self.file.take());
        self.store.fail(error);
        let mut s = self.store.0.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = s.lde.as_mut() {
            e.owned |= self.created;
            if !self.created {
                e.state = FileState::Uncreated;
            } else {
                let result = if self
                    .store
                    .0
                    .faults
                    .cleanup
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
                {
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                } else {
                    fs::remove_file(self.store.0.path.join("0.bin"))
                };
                match result {
                    Ok(()) => e.state = FileState::Removed,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        e.state = FileState::Removed
                    }
                    Err(err) => {
                        e.state = FileState::Orphan;
                        if s.cleanup_failures.len() < 16 {
                            s.cleanup_failures.push(err.kind());
                        }
                    }
                }
            }
        }
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

#[derive(Clone)]
pub struct RawInput {
    matrix: prep::OwnedMatrix,
    owner: CommitmentStore,
}
#[derive(Clone)]
enum Data {
    Prepared(prep::OwnedMatrix),
    Lde(CheckedFileMatrix),
}
/// Matrix descriptor first, owner second, preserving both directory leases.
#[derive(Clone)]
pub struct Stored {
    matrix: Data,
    owner: CommitmentStore,
}
impl Stored {
    pub fn try_window(&self, row: usize, start: usize, end: usize) -> Result<Vec<BabyBear>, Error> {
        self.owner.readable()?;
        match &self.matrix {
            Data::Prepared(m) => m.try_window(row, start, end).map_err(Error::from),
            Data::Lde(m) => m.try_window(row, start, end).map_err(Error::Access),
        }
    }
}
impl Matrix<BabyBear> for Stored {
    fn height(&self) -> usize {
        match &self.matrix {
            Data::Prepared(m) => m.height(),
            Data::Lde(m) => m.height(),
        }
    }
    fn width(&self) -> usize {
        match &self.matrix {
            Data::Prepared(m) => m.width(),
            Data::Lde(m) => m.width(),
        }
    }
    #[allow(unsafe_code)]
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
fn bytes(shape: [usize; 2]) -> Result<usize, Error> {
    let [h, w] = shape;
    if h == 0 || h > 4096 || !h.is_power_of_two() || w == 0 || w > 12 {
        return Err(Error::Shape);
    }
    h.checked_mul(w)
        .and_then(|n| n.checked_mul(4))
        .ok_or(Error::Limit)
}

// Tiled construction follows storage-pcs/tests/common/store.rs, with genuine
// fallible owned windows, checked offsets and the new attempt failure owner.
fn stream<D: TwoAdicSubgroupDft<BabyBear>>(
    source: &Stored,
    dft: &D,
    file: &mut File,
    faults: &Faults,
    event: &mut StreamEvent,
) -> Result<(), Error> {
    for start in (0..6).step_by(TILE) {
        let end = (start + TILE).min(6);
        let width = end - start;
        let mut values = Vec::with_capacity(512 * width);
        for row in 0..512 {
            let mut window = source.try_window(row, start, end)?;
            match faults.read {
                Some(ReadFault::Missing) => return Err(Error::Incomplete),
                Some(ReadFault::Poison) => return Err(Error::Poisoned),
                Some(ReadFault::Short) => {
                    window.pop();
                }
                None => {}
            }
            if window.len() != width {
                return Err(Error::Incomplete);
            }
            event.source_windows += 1;
            event.source_fields += window.len();
            values.extend(window);
        }
        event.largest_input_tile_fields = event.largest_input_tile_fields.max(values.len());
        let output = dft
            .coset_lde_batch(RowMajorMatrix::new(values, width), 3, BabyBear::GENERATOR)
            .bit_reverse_rows();
        if output.height() != 4096 || output.width() != width {
            return Err(Error::Shape);
        }
        event.batches += 1;
        event.largest_output_tile_fields = event.largest_output_tile_fields.max(4096 * width);
        let mut buffer = [0u8; TILE * 4];
        for row in 0..4096 {
            let mut count = 0;
            for value in output.row(row).ok_or(Error::Incomplete)? {
                if count >= width {
                    return Err(Error::Incomplete);
                }
                buffer[4 * count..4 * (count + 1)]
                    .copy_from_slice(&value.as_canonical_u32().to_le_bytes());
                count += 1;
            }
            if count != width {
                return Err(Error::Incomplete);
            }
            if faults
                .panic_after
                .is_some_and(|n| event.written_fields >= n)
            {
                panic!("injected LDE writer unwind");
            }
            let allowed = faults
                .write_after
                .map_or(width, |n| n.saturating_sub(event.written_fields).min(width));
            if allowed > 0 {
                let offset = row
                    .checked_mul(6usize)
                    .and_then(|n| n.checked_add(start))
                    .and_then(|n| n.checked_mul(4))
                    .and_then(|n| u64::try_from(n).ok())
                    .ok_or(Error::Limit)?;
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(&buffer[..4 * allowed])?;
                event.written_fields += allowed;
                event.write_calls += 1;
            }
            if allowed != width {
                return Err(Error::Io(std::io::ErrorKind::WriteZero));
            }
        }
    }
    if event.written_fields != 4096 * 6 {
        return Err(Error::Incomplete);
    }
    Ok(())
}
