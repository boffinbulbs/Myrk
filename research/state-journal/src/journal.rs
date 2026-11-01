//! Cooperative writer storage in a trusted directory. No power failure claim.
use std::{
    error, fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

pub const MAX_PAYLOAD: usize = 64;
pub const MAX_GENERATION: u64 = 3;
pub const MAX_FRAME: usize = 92;
pub const PENDING_SLOTS: usize = 4;

#[derive(Clone, Debug)]
pub enum Error {
    Io {
        stage: &'static str,
        source: Arc<io::Error>,
    },
    Busy,
    Metadata,
    Length,
    Format,
    Checksum,
    Gap,
    Limit,
    NoFreeSlot,
    DestinationExists,
    Stale,
    Failed,
    Phase,
    Aborted,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
fn io_error(stage: &'static str, source: io::Error) -> Error {
    Error::Io {
        stage,
        source: Arc::new(source),
    }
}
fn checked(path: &Path, directory: bool) -> Result<fs::Metadata, Error> {
    let m = fs::symlink_metadata(path).map_err(|e| io_error("metadata", e))?;
    if m.file_type().is_symlink() || m.is_dir() != directory || (!directory && !m.is_file()) {
        return Err(Error::Metadata);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(Error::Metadata);
        }
    }
    Ok(m)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub generation: u64,
    pub payload: Vec<u8>,
}
fn sum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |n, b| n.wrapping_add(u32::from(*b)))
}
fn encode(generation: u64, payload: &[u8]) -> ([u8; MAX_FRAME], usize) {
    let mut out = [0u8; MAX_FRAME];
    out[..4].copy_from_slice(b"KJS1");
    out[4..12].copy_from_slice(&generation.to_be_bytes());
    out[12..20].copy_from_slice(&generation.wrapping_sub(1).to_be_bytes());
    out[20..24].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[24..24 + payload.len()].copy_from_slice(payload);
    let end = 24 + payload.len();
    let checksum = sum(&out[..end]);
    out[end..end + 4].copy_from_slice(&checksum.to_be_bytes());
    (out, end + 4)
}
fn read_frame(path: &Path, generation: u64) -> Result<Frame, Error> {
    let m = checked(path, false)?;
    if !(28..=MAX_FRAME as u64).contains(&m.len()) {
        return Err(Error::Length);
    }
    let mut file = File::open(path).map_err(|e| io_error("read open", e))?;
    if !file
        .metadata()
        .map_err(|e| io_error("read metadata", e))?
        .is_file()
    {
        return Err(Error::Metadata);
    }
    let mut bytes = [0u8; MAX_FRAME];
    let n = m.len() as usize;
    file.read_exact(&mut bytes[..n])
        .map_err(|e| io_error("read exact", e))?;
    let mut tail = [0];
    if file.read(&mut tail).map_err(|e| io_error("read eof", e))? != 0 {
        return Err(Error::Length);
    }
    let number = u64::from_be_bytes(bytes[4..12].try_into().map_err(|_| Error::Format)?);
    let parent = u64::from_be_bytes(bytes[12..20].try_into().map_err(|_| Error::Format)?);
    let length = u32::from_be_bytes(bytes[20..24].try_into().map_err(|_| Error::Format)?) as usize;
    if &bytes[..4] != b"KJS1" || number != generation || parent != generation.wrapping_sub(1) {
        return Err(Error::Format);
    }
    if length > MAX_PAYLOAD || n != length + 28 {
        return Err(Error::Length);
    }
    let end = 24 + length;
    if sum(&bytes[..end])
        != u32::from_be_bytes(bytes[end..end + 4].try_into().map_err(|_| Error::Format)?)
    {
        return Err(Error::Checksum);
    }
    Ok(Frame {
        generation,
        payload: bytes[24..end].to_vec(),
    })
}
fn scan(path: &Path) -> Result<Frame, Error> {
    let mut present = [false; 4];
    for (count, entry) in fs::read_dir(path)
        .map_err(|e| io_error("scan", e))?
        .enumerate()
    {
        if count >= 9 {
            return Err(Error::Limit);
        }
        let entry = entry.map_err(|e| io_error("scan entry", e))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::Format)?;
        if name == "LOCK" {
            continue;
        }
        let mut known = false;
        for generation in 0..=MAX_GENERATION {
            if name == format!("frame-{generation}") {
                present[generation as usize] = true;
                known = true;
            }
        }
        for slot in 0..PENDING_SLOTS {
            if name == format!("pending-{slot}") {
                known = true;
            }
        }
        if !known {
            return Err(Error::Format);
        }
        if checked(&entry.path(), false)?.len() > MAX_FRAME as u64 {
            return Err(Error::Limit);
        }
    }
    if !present[0] {
        return Err(Error::Gap);
    }
    let mut head = None;
    let mut gap = false;
    for (generation, exists) in present.into_iter().enumerate() {
        if !exists {
            gap = true;
            continue;
        }
        if gap {
            return Err(Error::Gap);
        }
        head = Some(read_frame(
            &path.join(format!("frame-{generation}")),
            generation as u64,
        )?);
    }
    head.ok_or(Error::Gap)
}

/// A locked storage owner. Drop closes its lease and preserves committed files.
pub struct Journal {
    _lease: File,
    path: PathBuf,
    head: Frame,
    failure: Option<Error>,
    cleanup_failure: Option<Error>,
}
impl Journal {
    pub fn initialize(path: &Path, payload: &[u8]) -> Result<Self, Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::Limit);
        }
        fs::create_dir(path).map_err(|e| io_error("create directory", e))?;
        checked(path, true)?;
        let path = path
            .canonicalize()
            .map_err(|e| io_error("canonical directory", e))?;
        let mut lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path.join("LOCK"))
            .map_err(|e| io_error("create lease", e))?;
        lock(&lease)?;
        lease
            .write_all(b"KJL1")
            .map_err(|e| io_error("write lease", e))?;
        lease.sync_all().map_err(|e| io_error("sync lease", e))?;
        let mut journal = Self {
            _lease: lease,
            path,
            head: Frame {
                generation: u64::MAX,
                payload: vec![],
            },
            failure: None,
            cleanup_failure: None,
        };
        let mut attempt = journal.begin_inner(0, payload)?;
        attempt.write()?;
        attempt.sync()?;
        attempt.publish()?;
        attempt.finish()?;
        Ok(journal)
    }
    pub fn open(path: &Path) -> Result<Self, Error> {
        checked(path, true)?;
        let path = path
            .canonicalize()
            .map_err(|e| io_error("canonical directory", e))?;
        if checked(&path.join("LOCK"), false)?.len() != 4 {
            return Err(Error::Length);
        }
        let mut lease = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.join("LOCK"))
            .map_err(|e| io_error("open lease", e))?;
        lock(&lease)?;
        let mut magic = [0; 4];
        lease
            .read_exact(&mut magic)
            .map_err(|e| io_error("read lease", e))?;
        if &magic != b"KJL1" {
            return Err(Error::Format);
        }
        let head = scan(&path)?;
        Ok(Self {
            _lease: lease,
            path,
            head,
            failure: None,
            cleanup_failure: None,
        })
    }
    pub fn head(&self) -> &Frame {
        &self.head
    }
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }
    pub fn cleanup_failure(&self) -> Option<&Error> {
        self.cleanup_failure.as_ref()
    }
    fn fail(&mut self, error: Error) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
    }
    pub fn begin(&mut self, expected: u64, payload: &[u8]) -> Result<Attempt<'_>, Error> {
        if self.failure.is_some() {
            return Err(Error::Failed);
        }
        if expected != self.head.generation {
            self.fail(Error::Stale);
            return Err(Error::Stale);
        }
        if self.head.generation >= MAX_GENERATION || payload.len() > MAX_PAYLOAD {
            self.fail(Error::Limit);
            return Err(Error::Limit);
        }
        self.begin_inner(self.head.generation + 1, payload)
    }
    fn begin_inner(&mut self, generation: u64, payload: &[u8]) -> Result<Attempt<'_>, Error> {
        let mut reserved = None;
        for slot in 0..PENDING_SLOTS {
            let path = self.path.join(format!("pending-{slot}"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    reserved = Some((path, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    let error = io_error("create pending", source);
                    self.fail(error.clone());
                    return Err(error);
                }
            }
        }
        let Some((path, file)) = reserved else {
            self.fail(Error::NoFreeSlot);
            return Err(Error::NoFreeSlot);
        };
        let (bytes, length) = encode(generation, payload);
        Ok(Attempt {
            owner: self,
            path,
            file: Some(file),
            bytes,
            length,
            generation,
            phase: 0,
            published: false,
            done: false,
        })
    }
}
fn lock(file: &File) -> Result<(), Error> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(Error::Busy),
        Err(TryLockError::Error(e)) => Err(io_error("lock", e)),
    }
}

/// Move-only writer. Stages expose actual I/O boundaries for process controls.
pub struct Attempt<'a> {
    owner: &'a mut Journal,
    path: PathBuf,
    file: Option<File>,
    bytes: [u8; MAX_FRAME],
    length: usize,
    generation: u64,
    phase: u8,
    published: bool,
    done: bool,
}
impl Attempt<'_> {
    fn check(&self, phase: u8) -> Result<(), Error> {
        if self.done || self.owner.failure.is_some() {
            Err(Error::Failed)
        } else if self.phase != phase {
            Err(Error::Phase)
        } else {
            Ok(())
        }
    }
    fn outcome(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        if let Err(error) = &result {
            self.abort(error.clone());
        }
        result
    }
    pub fn write(&mut self) -> Result<(), Error> {
        let result = (|| {
            self.check(0)?;
            self.file
                .as_mut()
                .ok_or(Error::Phase)?
                .write_all(&self.bytes[..self.length])
                .map_err(|e| io_error("write pending", e))?;
            self.phase = 1;
            Ok(())
        })();
        self.outcome(result)
    }
    pub fn sync(&mut self) -> Result<(), Error> {
        let result = (|| {
            self.check(1)?;
            self.file
                .as_ref()
                .ok_or(Error::Phase)?
                .sync_all()
                .map_err(|e| io_error("sync pending", e))?;
            drop(self.file.take());
            self.phase = 2;
            Ok(())
        })();
        self.outcome(result)
    }
    pub fn publish(&mut self) -> Result<(), Error> {
        let result = (|| {
            self.check(2)?;
            let destination = self.owner.path.join(format!("frame-{}", self.generation));
            // The lease excludes cooperative writers. Rename can replace a
            // racing entry, so noncooperating namespace changes are out of scope.
            match fs::symlink_metadata(&destination) {
                Ok(_) => return Err(Error::DestinationExists),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error("publish metadata", error)),
            }
            fs::rename(&self.path, &destination).map_err(|e| io_error("publish rename", e))?;
            self.published = true;
            self.owner.head = Frame {
                generation: self.generation,
                payload: self.bytes[24..self.length - 4].to_vec(),
            };
            self.phase = 3;
            Ok(())
        })();
        self.outcome(result)
    }
    pub fn finish(mut self) -> Result<(), Error> {
        let result = (|| {
            self.check(3)?;
            let actual = read_frame(
                &self.owner.path.join(format!("frame-{}", self.generation)),
                self.generation,
            )?;
            if actual != self.owner.head {
                return Err(Error::Format);
            }
            self.done = true;
            Ok(())
        })();
        self.outcome(result)
    }
    pub fn published(&self) -> bool {
        self.published
    }
    fn abort(&mut self, error: Error) {
        if self.done {
            return;
        }
        self.owner.fail(error);
        drop(self.file.take());
        if !self.published
            && let Err(e) = fs::remove_file(&self.path)
        {
            self.owner.cleanup_failure = Some(io_error("cleanup pending", e));
        }
        self.done = true;
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.abort(Error::Aborted);
        }
    }
}
