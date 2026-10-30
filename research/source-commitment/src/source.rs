//! Owned entry lifetime and nominal storage bridge. No validity callback.
#![deny(unsafe_code)]

use crate::storage::{MatrixStore, RowSource};
use kova_source_extension as ext;
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::extension::BinomialExtensionField;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{CryptoRng, Rng};
use std::sync::{Arc, Mutex};

pub type Challenge = BinomialExtensionField<BabyBear, 4>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Profile,
    Domain,
    Shape,
    Owner,
    Busy,
    Complete,
    Failed,
    Poisoned,
    Unsupported,
    Unwind,
    Storage(ext::Error),
    Mask(crate::HidingFriProverError),
}
impl From<ext::Error> for Error {
    fn from(e: ext::Error) -> Self {
        Self::Storage(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Ready,
    WritingRaw,
    Preparing,
    LdeReady,
    Committing,
    Committed,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub failure: Option<Error>,
    pub construction: ext::Snapshot,
}
struct State {
    phase: Phase,
    failure: Option<Error>,
}
struct Owner {
    inner: ext::CommitmentStore,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct SourceStore(Arc<Owner>);
impl SourceStore {
    /// The borrowed anchor is only an input to the frozen resource constructor.
    /// It is not cloned and supplies no masks or commitment salts.
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
        let inner = ext::CommitmentStore::new(anchor)?;
        Ok(Self(Arc::new(Owner {
            inner,
            state: Mutex::new(State {
                phase: Phase::Ready,
                failure: None,
            }),
        })))
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let (phase, failure) = {
            let s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            (s.phase, s.failure.clone())
        };
        Ok(Snapshot {
            phase,
            failure,
            construction: self.0.inner.snapshot()?,
        })
    }
    fn refuse(phase: Phase) -> Error {
        match phase {
            Phase::Failed => Error::Failed,
            Phase::Committed => Error::Complete,
            _ => Error::Busy,
        }
    }
    fn fail(&self, error: Error) {
        let mut s = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        s.phase = Phase::Failed;
        if s.failure.is_none() {
            s.failure = Some(error);
        }
    }
    fn readable(&self) -> Result<(), Error> {
        let s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if s.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        Ok(())
    }
    pub fn write_raw(&self, values: impl IntoIterator<Item = BabyBear>) -> Result<RawInput, Error> {
        {
            let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
            if s.phase != Phase::Ready {
                return Err(Self::refuse(s.phase));
            }
            if !self.0.inner.snapshot()?.preparation_files.is_empty() {
                return Err(Error::Owner);
            }
            s.phase = Phase::WritingRaw;
        }
        let mut guard = Attempt {
            store: self,
            done: false,
        };
        match self.0.inner.write_raw(values) {
            Ok(inner) => {
                self.0.state.lock().map_err(|_| Error::Poisoned)?.phase = Phase::Ready;
                guard.done = true;
                Ok(RawInput {
                    inner,
                    owner: self.clone(),
                })
            }
            Err(e) => {
                let e = Error::from(e);
                guard.fail(e.clone());
                Err(e)
            }
        }
    }
    pub(crate) fn check_raw(&self, raw: &RawInput) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.0, &raw.owner.0) {
            return Err(Error::Owner);
        }
        Ok(())
    }
    pub(crate) fn begin(&self, dense: bool) -> Result<Attempt<'_>, Error> {
        let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if s.phase != Phase::Ready {
            return Err(Self::refuse(s.phase));
        }
        // Metadata snapshots acquire no I/O or RNG callback. The state lock is
        // released before actual preparation, DFT or MMCS operations.
        let inner = self.0.inner.snapshot()?;
        if inner.phase != ext::Phase::Ready
            || (dense && !inner.preparation_files.is_empty())
            || (!dense && inner.preparation_files.len() != 1)
        {
            return Err(Error::Owner);
        }
        s.phase = Phase::Preparing;
        Ok(Attempt {
            store: self,
            done: false,
        })
    }
    pub(crate) fn prepare_owned<R: CryptoRng + Send + Sync>(
        &self,
        raw: RawInput,
        rng: &mut R,
    ) -> Result<ext::Stored, Error> {
        Ok(self
            .0
            .inner
            .prepare_owned(raw.inner, ext::Header::QUARTIC, rng)?)
    }
    pub(crate) fn prepare_dense<R: CryptoRng + Send + Sync>(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        rng: &mut R,
    ) -> Result<ext::Stored, Error> {
        Ok(self
            .0
            .inner
            .prepare_dense(matrix, ext::Header::QUARTIC, rng)?)
    }
    pub(crate) fn extend<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        input: ext::Stored,
        dft: &D,
    ) -> Result<Stored, Error> {
        let inner = self.0.inner.extend_owned(input, dft)?;
        self.0.state.lock().map_err(|_| Error::Poisoned)?.phase = Phase::LdeReady;
        Ok(Stored {
            inner,
            owner: self.clone(),
        })
    }
    pub(crate) fn committing(&self) -> Result<(), Error> {
        let mut s = self.0.state.lock().map_err(|_| Error::Poisoned)?;
        if s.phase != Phase::LdeReady {
            return Err(Self::refuse(s.phase));
        }
        s.phase = Phase::Committing;
        Ok(())
    }
}

pub(crate) struct Attempt<'a> {
    store: &'a SourceStore,
    done: bool,
}
impl Attempt<'_> {
    pub(crate) fn finish(&mut self) -> Result<(), Error> {
        let mut s = self.store.0.state.lock().map_err(|_| Error::Poisoned)?;
        if s.phase != Phase::Committing {
            return Err(SourceStore::refuse(s.phase));
        }
        s.phase = Phase::Committed;
        self.done = true;
        Ok(())
    }
    pub(crate) fn fail(&mut self, error: Error) {
        self.store.fail(error);
        self.done = true;
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.store.fail(Error::Unwind);
        }
    }
}

#[derive(Clone)]
pub struct RawInput {
    inner: ext::RawInput,
    owner: SourceStore,
}
pub(crate) enum Input {
    Owned(RawInput),
    Dense(RowMajorMatrix<BabyBear>),
}
/// The descriptor is released before the outer owner and its directory leases.
#[derive(Clone)]
pub struct Stored {
    inner: ext::Stored,
    owner: SourceStore,
}
impl Stored {
    pub fn try_window(&self, row: usize, start: usize, end: usize) -> Result<Vec<BabyBear>, Error> {
        self.owner.readable()?;
        Ok(self.inner.try_window(row, start, end)?)
    }
}
// Only the required unsafe trait signatures are allowed. Bodies use checked
// windows and no unsafe operations.
#[allow(unsafe_code)]
mod matrix {
    use super::*;
    impl Matrix<BabyBear> for Stored {
        fn height(&self) -> usize {
            self.inner.height()
        }
        fn width(&self) -> usize {
            self.inner.width()
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
impl MatrixStore<BabyBear> for SourceStore {
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
    fn extend<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        _: &D,
        _: RowMajorMatrix<BabyBear>,
        _: usize,
        _: BabyBear,
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
    fn extend_quotient<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        _: &D,
        _: RowMajorMatrix<BabyBear>,
        _: &[BabyBear],
        _: usize,
        _: BabyBear,
    ) -> Stored {
        std::panic::panic_any(Error::Unsupported)
    }
}
