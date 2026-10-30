//! Owned synthetic input preparation. No commitment or proof entry.
#![deny(unsafe_code)]

use kova_proof_preflight::storage::{MatrixStore, RowSource};
use kova_storage_matrix::{CheckedFileMatrix, StorageError};
use p3_baby_bear::BabyBear;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::PrimeField32;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{Rng, RngExt};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const MAX_BYTES: usize = 2 * 1024 * 1024;
const WINDOW: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Domain,
    Limit,
    Busy,
    Complete,
    Failed,
    Poisoned,
    Owner,
    Incomplete,
    Unsupported,
    Unwind,
    Io(std::io::ErrorKind),
    Access(StorageError),
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    RawInput,
    PreparedInput,
    Commitment,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Ready,
    Preparing,
    Complete,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    Pending,
    Complete,
    Removed,
    Orphan,
    Uncreated,
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
    pub files: Vec<Entry>,
    pub reserved_bytes: usize,
    pub cleanup_failures: Vec<std::io::ErrorKind>,
    pub failure: Option<Error>,
}
struct State {
    phase: Phase,
    files: Vec<Entry>,
    cleanup_failures: Vec<std::io::ErrorKind>,
    failure: Option<Error>,
}
#[derive(Default)]
struct Faults {
    write_after: Option<usize>,
    cleanup_remaining: AtomicUsize,
}
struct Directory {
    path: PathBuf,
    state: Mutex<State>,
    faults: Faults,
}

// Only paths successfully created by this owner may be removed. This is flat
// artifact cleanup, never recursive directory traversal.
impl Drop for Directory {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
        for (index, entry) in state.files.iter().enumerate() {
            if entry.owned && !matches!(entry.state, FileState::Removed | FileState::Uncreated) {
                let _ = fs::remove_file(self.path.join(format!("{index}.bin")));
            }
        }
        let _ = fs::remove_dir(&self.path);
    }
}

#[derive(Clone)]
pub struct PreparationStore(Arc<Directory>);
impl PreparationStore {
    pub fn new() -> Result<Self, Error> {
        Self::new_inner(Faults::default())
    }
    fn new_inner(faults: Faults) -> Result<Self, Error> {
        let root = std::env::temp_dir().canonicalize()?;
        let path = root.join(format!(
            "kova_source_prep_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        let path = path.canonicalize()?;
        if path.parent() != Some(root.as_path()) {
            return Err(Error::Owner);
        }
        Ok(Self(Arc::new(Directory {
            path,
            state: Mutex::new(State {
                phase: Phase::Ready,
                files: vec![],
                cleanup_failures: vec![],
                failure: None,
            }),
            faults,
        })))
    }
    pub fn directory(&self) -> &Path {
        &self.0.path
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(Snapshot {
            phase: s.phase,
            files: s.files.clone(),
            reserved_bytes: s.files.iter().map(|x| x.bytes).sum(),
            cleanup_failures: s.cleanup_failures.clone(),
            failure: s.failure.clone(),
        })
    }
    fn ready(&self) -> Result<(), Error> {
        match self.0.state.lock().map_err(|_| Error::Poisoned)?.phase {
            Phase::Ready => Ok(()),
            Phase::Preparing => Err(Error::Busy),
            Phase::Complete => Err(Error::Complete),
            Phase::Failed => Err(Error::Failed),
        }
    }
    pub fn write_raw(
        &self,
        height: usize,
        width: usize,
        values: impl IntoIterator<Item = BabyBear>,
    ) -> Result<OwnedMatrix, Error> {
        if !(1..=8).contains(&width) {
            return Err(Error::Shape);
        }
        let count = height.checked_mul(width).ok_or(Error::Limit)?;
        let mut values = values.into_iter();
        self.create(height, width, Role::RawInput, |file| {
            for _ in 0..count {
                let value = values.next().ok_or(Error::Incomplete)?;
                file.write_all(&value.as_canonical_u32().to_le_bytes())?;
            }
            if values.next().is_some() {
                return Err(Error::Incomplete);
            }
            Ok(())
        })
    }
    pub fn prepare_owned<R: Rng + Send + Sync>(
        &self,
        source: OwnedMatrix,
        random: usize,
        domain: Domain,
        rng: &mut R,
    ) -> Result<OwnedMatrix, Error> {
        if !Arc::ptr_eq(&self.0, &source.owner) || source.role != Role::RawInput {
            return Err(Error::Owner);
        }
        self.prepare(source, random, domain, rng)
    }
    pub fn prepare_dense<R: Rng + Send + Sync>(
        &self,
        source: RowMajorMatrix<BabyBear>,
        random: usize,
        domain: Domain,
        rng: &mut R,
    ) -> Result<OwnedMatrix, Error> {
        dense_height(&source)?;
        self.prepare(source, random, domain, rng)
    }
    fn prepare<S: Input, R: Rng + Send + Sync>(
        &self,
        source: S,
        random: usize,
        domain: Domain,
        rng: &mut R,
    ) -> Result<OwnedMatrix, Error> {
        self.ready()?;
        let [height, width] = source.shape();
        if !(1..=8).contains(&width) || !(1..=4).contains(&random) || !height.is_power_of_two() {
            return Err(Error::Shape);
        }
        if domain.height != height || domain.shift != 1 {
            return Err(Error::Domain);
        }
        let prepared_height = height.checked_mul(2).ok_or(Error::Limit)?;
        let prepared_width = width.checked_add(random).ok_or(Error::Limit)?;
        self.create(
            prepared_height,
            prepared_width,
            Role::PreparedInput,
            |file| {
                let mut written = 0;
                let mut write = |value: BabyBear| -> Result<(), Error> {
                    if self.0.faults.write_after == Some(written) {
                        return Err(Error::Io(std::io::ErrorKind::WriteZero));
                    }
                    file.write_all(&value.as_canonical_u32().to_le_bytes())?;
                    written += 1;
                    Ok(())
                };
                for row in 0..height {
                    for start in (0..width).step_by(WINDOW) {
                        let end = (start + WINDOW).min(width);
                        let window = source.window(row, start, end)?;
                        if window.len() != end - start {
                            return Err(Error::Incomplete);
                        }
                        for value in window {
                            write(value)?;
                        }
                    }
                    // This is the retained flat layout before width reinterpretation.
                    // Field sampling occurs before a potentially failing write.
                    for _ in 0..width + 2 * random {
                        write(rng.random())?;
                    }
                }
                if written != prepared_height * prepared_width {
                    return Err(Error::Incomplete);
                }
                Ok(())
            },
        )
    }
    fn create(
        &self,
        height: usize,
        width: usize,
        role: Role,
        write: impl FnOnce(&mut File) -> Result<(), Error>,
    ) -> Result<OwnedMatrix, Error> {
        if height == 0 || height > 4096 || !height.is_power_of_two() || width == 0 || width > 12 {
            return Err(Error::Shape);
        }
        let bytes = height
            .checked_mul(width)
            .and_then(|x| x.checked_mul(4))
            .ok_or(Error::Limit)?;
        let index = {
            let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            match s.phase {
                Phase::Ready => {}
                Phase::Preparing => return Err(Error::Busy),
                Phase::Complete => return Err(Error::Complete),
                Phase::Failed => return Err(Error::Failed),
            }
            let total = s
                .files
                .iter()
                .try_fold(0usize, |n, x| n.checked_add(x.bytes))
                .ok_or(Error::Limit)?;
            if s.files.len() >= 16 || total.checked_add(bytes).ok_or(Error::Limit)? > MAX_BYTES {
                return Err(Error::Limit);
            }
            let index = s.files.len();
            s.files.push(Entry {
                role,
                shape: [height, width],
                bytes,
                state: FileState::Pending,
                owned: false,
            });
            s.phase = Phase::Preparing;
            index
        };
        let path = self.0.path.join(format!("{index}.bin"));
        let mut pending = Pending {
            store: self,
            index,
            path,
            file: None,
            created: false,
            done: false,
        };
        let result: Result<OwnedMatrix, Error> = (|| {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pending.path)?;
            pending.file = Some(file);
            pending.created = true;
            self.0.state.lock().map_err(|_| Error::Poisoned)?.files[index].owned = true;
            write(pending.file.as_mut().ok_or(Error::Incomplete)?)?;
            pending.file.as_mut().ok_or(Error::Incomplete)?.sync_all()?;
            drop(pending.file.take());
            let matrix =
                CheckedFileMatrix::open(&pending.path, height, width).map_err(Error::Access)?;
            let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            s.files[index].state = FileState::Complete;
            s.phase = if role == Role::PreparedInput {
                Phase::Complete
            } else {
                Phase::Ready
            };
            Ok(OwnedMatrix {
                matrix,
                owner: self.0.clone(),
                index,
                height,
                width,
                role,
            })
        })();
        match result {
            Ok(matrix) => {
                pending.done = true;
                Ok(matrix)
            }
            Err(error) => {
                pending.abort(error.clone());
                Err(error)
            }
        }
    }
    /// Cleanup never reopens a failed owner or releases its reservations.
    /// Drop is best effort. Durable crash recovery is outside this laboratory.
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
        for (index, entry) in s.files.iter_mut().enumerate() {
            if entry.owned && entry.state != FileState::Removed {
                match fs::remove_file(self.0.path.join(format!("{index}.bin"))) {
                    Ok(()) => entry.state = FileState::Removed,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        entry.state = FileState::Removed
                    }
                    Err(e) => {
                        entry.state = FileState::Orphan;
                        failures.push(e.kind());
                    }
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

struct Pending<'a> {
    store: &'a PreparationStore,
    index: usize,
    path: PathBuf,
    file: Option<File>,
    created: bool,
    done: bool,
}
impl Pending<'_> {
    fn abort(&mut self, error: Error) {
        drop(self.file.take());
        let mut s = self.store.0.state.lock().unwrap_or_else(|p| p.into_inner());
        s.phase = Phase::Failed;
        s.failure = Some(error);
        let owned = self.created;
        s.files[self.index].owned |= owned;
        let result = if !owned {
            Ok(())
        } else if self
            .store
            .0
            .faults
            .cleanup_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| x.checked_sub(1))
            .is_ok()
        {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        } else {
            fs::remove_file(&self.path)
        };
        match result {
            Ok(()) => {
                s.files[self.index].state = if owned {
                    FileState::Removed
                } else {
                    FileState::Uncreated
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                s.files[self.index].state = FileState::Removed
            }
            Err(e) => {
                s.files[self.index].state = FileState::Orphan;
                if s.cleanup_failures.len() < 16 {
                    s.cleanup_failures.push(e.kind());
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain {
    pub height: usize,
    pub shift: u64,
}
impl Domain {
    pub const fn natural(height: usize) -> Self {
        Self { height, shift: 1 }
    }
}

// Descriptor first, owner second: the final file lease closes before directory cleanup.
#[derive(Clone)]
pub struct OwnedMatrix {
    matrix: CheckedFileMatrix,
    owner: Arc<Directory>,
    index: usize,
    height: usize,
    width: usize,
    role: Role,
}
impl OwnedMatrix {
    pub fn try_window(&self, row: usize, start: usize, end: usize) -> Result<Vec<BabyBear>, Error> {
        {
            let s = self.owner.state.lock().map_err(|_| Error::Poisoned)?;
            if s.phase == Phase::Failed {
                return Err(Error::Failed);
            }
            if s.files[self.index].state != FileState::Complete {
                return Err(Error::Incomplete);
            }
        }
        self.matrix
            .try_window(row, start, end)
            .map_err(Error::Access)
    }
}
impl Matrix<BabyBear> for OwnedMatrix {
    fn height(&self) -> usize {
        self.height
    }
    fn width(&self) -> usize {
        self.width
    }
    #[allow(unsafe_code)]
    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = BabyBear, IntoIter = impl Iterator<Item = BabyBear> + Send + Sync>
    {
        self.try_window(row, 0, self.width)
            .unwrap_or_else(|e| std::panic::panic_any(e))
    }
    fn to_row_major_matrix(self) -> RowMajorMatrix<BabyBear> {
        std::panic::panic_any(Error::Unsupported)
    }
}
impl RowSource<BabyBear> for OwnedMatrix {
    fn read_window(&self, row: usize, start: usize, end: usize) -> Option<Vec<BabyBear>> {
        if row >= self.height || start > end || end > self.width {
            return None;
        }
        Some(
            self.try_window(row, start, end)
                .unwrap_or_else(|e| std::panic::panic_any(e)),
        )
    }
}

trait Input {
    fn shape(&self) -> [usize; 2];
    fn window(&self, row: usize, start: usize, end: usize) -> Result<Vec<BabyBear>, Error>;
}
fn dense_height(matrix: &RowMajorMatrix<BabyBear>) -> Result<usize, Error> {
    if !(1..=8).contains(&matrix.width) || !matrix.values.len().is_multiple_of(matrix.width) {
        return Err(Error::Shape);
    }
    Ok(matrix.values.len() / matrix.width)
}
impl Input for OwnedMatrix {
    fn shape(&self) -> [usize; 2] {
        [self.height, self.width]
    }
    fn window(&self, row: usize, start: usize, end: usize) -> Result<Vec<BabyBear>, Error> {
        self.try_window(row, start, end)
    }
}
impl Input for RowMajorMatrix<BabyBear> {
    fn shape(&self) -> [usize; 2] {
        [self.height(), self.width()]
    }
    fn window(&self, row: usize, start: usize, end: usize) -> Result<Vec<BabyBear>, Error> {
        if row >= self.height() || start > end || end > self.width() {
            return Err(Error::Incomplete);
        }
        Ok(self.values[row * self.width() + start..row * self.width() + end].to_vec())
    }
}

/// Only raw input preparation is implemented. Every extension hook refuses
/// before a DFT or a dense fallback can run.
impl MatrixStore<BabyBear> for PreparationStore {
    type Stored = OwnedMatrix;
    fn store(&self, _: RowMajorMatrix<BabyBear>) -> OwnedMatrix {
        std::panic::panic_any(Error::Unsupported)
    }
    fn randomize<R: Rng + Send + Sync>(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        random: usize,
        rng: &mut R,
    ) -> OwnedMatrix {
        let domain =
            Domain::natural(dense_height(&matrix).unwrap_or_else(|e| std::panic::panic_any(e)));
        self.prepare_dense(matrix, random, domain, rng)
            .unwrap_or_else(|e| std::panic::panic_any(e))
    }
    fn extend<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        _: &D,
        _: RowMajorMatrix<BabyBear>,
        _: usize,
        _: BabyBear,
    ) -> OwnedMatrix {
        std::panic::panic_any(Error::Unsupported)
    }
    fn extend_prepared<D: TwoAdicSubgroupDft<BabyBear>, M: RowSource<BabyBear>>(
        &self,
        _: &D,
        _: M,
        _: usize,
        _: BabyBear,
    ) -> OwnedMatrix {
        std::panic::panic_any(Error::Unsupported)
    }
    fn extend_quotient<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        _: &D,
        _: RowMajorMatrix<BabyBear>,
        _: &[BabyBear],
        _: usize,
        _: BabyBear,
    ) -> OwnedMatrix {
        std::panic::panic_any(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests;
