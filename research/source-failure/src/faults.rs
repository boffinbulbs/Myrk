//! Fixed file faults inside the nominal owner. No caller path or verdict.
#![forbid(unsafe_code)]
use super::*;
use std::io::Read;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    TruncatedQuotient,
    AuxiliaryCollision,
}

pub(crate) struct Run {
    kind: Kind,
    main: Mutex<Option<Stored>>,
    sentinel: Mutex<Option<Sentinel>>,
}
impl Run {
    pub(crate) fn new(kind: Kind) -> Self {
        Self {
            kind,
            main: Mutex::new(None),
            sentinel: Mutex::new(None),
        }
    }
    pub(crate) fn retain_main(&self, lease: Stored) {
        let mut slot = self.main.lock().unwrap();
        assert!(slot.is_none());
        *slot = Some(lease);
    }
    pub(crate) fn after_source(
        &self,
        owner: &CompositeStore,
        input: &QuotientInput,
    ) -> Result<(), Error> {
        if self.kind == Kind::TruncatedQuotient {
            truncate_owned_quotient(owner, input)?;
        }
        Ok(())
    }
    pub(crate) fn after_quotient(&self, owner: &CompositeStore) -> Result<(), Error> {
        if self.kind == Kind::AuxiliaryCollision {
            assert!(self.sentinel.lock().unwrap().is_none());
            // The test retains this guard across the actual proving unwind.
            // There is no owner state lock or diagnostic mutex during I/O.
            let sentinel = Sentinel::create(owner)?;
            *self.sentinel.lock().unwrap() = Some(sentinel);
        }
        Ok(())
    }
    pub(crate) fn assert_closed_leases(&self, cause: Error) -> usize {
        let lease = self.main.lock().unwrap().as_ref().unwrap().clone();
        let owner = lease.owner.clone();
        let before = owner.snapshot().unwrap();
        assert_eq!(before.phase, Phase::Failed);
        assert_eq!(before.failure, Some(cause.clone()));
        assert_eq!(
            (before.reserved_files, before.reserved_bytes),
            (13, 1_325_056)
        );
        assert!(before.cleanup_failures.is_empty());
        for alias in [lease.clone(), lease] {
            assert_eq!(alias.try_window(0, 0, 2), Err(Error::Failed));
        }
        assert_eq!(owner.snapshot().unwrap().failure, Some(cause));
        2
    }
    pub(crate) fn remove_preserved_sentinel(&self) -> Result<bool, Error> {
        let sentinel = self.sentinel.lock().unwrap().take();
        match sentinel {
            Some(sentinel) => {
                sentinel.remove()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
    pub(crate) fn assert_source_metadata(&self, truncated: bool) {
        let lease = self.main.lock().unwrap().as_ref().unwrap().clone();
        let owner = &lease.owner;
        let state = owner.checked_state().unwrap();
        assert!(!state.writing && !state.cleaning);
        let source = &state.entries[QUOTIENT_SOURCE_INDEX];
        assert_eq!(source.state, FileState::Complete);
        assert!(source.owned);
        assert_eq!(source.shape, [2048, 4]);
        assert_eq!(source.bytes, 32_768);
        let auxiliary = &state.entries[11];
        if truncated {
            assert_eq!(auxiliary.state, FileState::Planned);
        } else {
            assert_eq!(auxiliary.state, FileState::Uncreated);
        }
        assert!(!auxiliary.owned);
        drop(state);
        let physical = fs::metadata(owner.path(QUOTIENT_SOURCE_INDEX))
            .unwrap()
            .len();
        assert_eq!(physical, if truncated { 4 } else { 32_768 });
    }
}

/// The same owner and completed source must precede the actual truncation.
fn truncate_owned_quotient(owner: &CompositeStore, input: &QuotientInput) -> Result<(), Error> {
    owner.check_quotient_input(input)?;
    owner.check_phase(Phase::QuotientReady)?;
    {
        let state = owner.checked_state()?;
        let entry = &state.entries[QUOTIENT_SOURCE_INDEX];
        if state.writing
            || state.cleaning
            || entry.role != Role::QuotientEvaluations
            || entry.state != FileState::Complete
            || !entry.owned
            || entry.shape != [QUOTIENT_SOURCE_HEIGHT, QUOTIENT_SOURCE_WIDTH]
            || entry.bytes != QUOTIENT_SOURCE_BYTES
        {
            return Err(Error::Phase);
        }
    }
    let file = OpenOptions::new()
        .write(true)
        .open(owner.path(QUOTIENT_SOURCE_INDEX))?;
    file.set_len(4)?;
    file.sync_all()?;
    Ok(())
}

const SENTINEL: &[u8] = b"kova auxiliary collision";
struct Sentinel {
    owner: CompositeStore,
}
impl Sentinel {
    fn create(owner: &CompositeStore) -> Result<Self, Error> {
        owner.check_phase(Phase::QuotientCommitted)?;
        {
            let state = owner.checked_state()?;
            let entry = &state.entries[11];
            if state.writing
                || state.cleaning
                || entry.role != Role::Auxiliary
                || entry.state != FileState::Planned
                || entry.owned
                || entry.shape != [4096, 8]
                || entry.bytes != 131_072
            {
                return Err(Error::Phase);
            }
        }
        let path = owner.path(11);
        assert_eq!(path.parent(), Some(owner.0.path.as_path()));
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(SENTINEL)?;
        file.sync_all()?;
        Ok(Self {
            owner: owner.clone(),
        })
    }
    fn remove(self) -> Result<(), Error> {
        let path = self.owner.path(11);
        assert_eq!(path.parent(), Some(self.owner.0.path.as_path()));
        let metadata = fs::symlink_metadata(&path)?;
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.len(), SENTINEL.len() as u64);
        let mut body = Vec::with_capacity(SENTINEL.len() + 1);
        File::open(&path)?
            .take((SENTINEL.len() + 1) as u64)
            .read_to_end(&mut body)?;
        assert_eq!(body, SENTINEL);
        // Only the diagnostic created this file. The storage owner never
        // acquired unlink authority when its create_new returned AlreadyExists.
        fs::remove_file(path)?;
        Ok(())
    }
}
