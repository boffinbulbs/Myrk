#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
//! Checked synthetic field storage with owned rows for the retained matrix trait.
//!
//! Storage failure aborts matrix evaluation through a typed panic. It is never
//! interpreted as proof rejection or replaced with fabricated field values.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;

pub const MAX_HEIGHT: usize = 4096;
pub const MAX_WIDTH: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    Shape,
    Bounds,
    FileKind,
    Length,
    NonCanonicalField,
    LockPoisoned,
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for StorageError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

/// A trait access failed before a field value could be supplied.
#[derive(Debug)]
pub struct StorageAccessFailure(pub StorageError);

struct Lease {
    file: Mutex<File>,
    bytes: u64,
}

/// A bounded view over an already open, read only synthetic field file.
///
/// Clones share the same descriptor and lock. Path replacement cannot redirect
/// subsequent reads. External modification of the opened file remains a threat
/// for a later commitment and immutable storage design to address.
#[derive(Clone)]
pub struct CheckedFileMatrix {
    lease: Arc<Lease>,
    height: usize,
    width: usize,
}

impl CheckedFileMatrix {
    pub fn open(path: &Path, height: usize, width: usize) -> Result<Self, StorageError> {
        if !(1..=MAX_HEIGHT).contains(&height) || !(1..=MAX_WIDTH).contains(&width) {
            return Err(StorageError::Shape);
        }
        let bytes = height
            .checked_mul(width)
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(StorageError::Shape)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(StorageError::FileKind);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(StorageError::FileKind);
            }
        }
        let file = OpenOptions::new().read(true).open(path)?;
        if !file.metadata()?.is_file() {
            return Err(StorageError::FileKind);
        }
        if metadata.len() != bytes || file.metadata()?.len() != bytes {
            return Err(StorageError::Length);
        }
        Ok(Self {
            lease: Arc::new(Lease {
                file: Mutex::new(file),
                bytes,
            }),
            height,
            width,
        })
    }

    pub fn try_row(&self, row: usize) -> Result<Vec<BabyBear>, StorageError> {
        self.try_window(row, 0, self.width)
    }

    pub fn try_window(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> Result<Vec<BabyBear>, StorageError> {
        if row >= self.height || start > end || end > self.width {
            return Err(StorageError::Bounds);
        }
        let offset = row
            .checked_mul(self.width)
            .and_then(|n| n.checked_add(start))
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(StorageError::Bounds)?;
        let count = end - start;
        let mut bytes = vec![0u8; count * 4];
        let mut file = self
            .lease
            .file
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        if file.metadata()?.len() != self.lease.bytes {
            return Err(StorageError::Length);
        }
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut bytes)?;
        drop(file);
        bytes
            .chunks_exact(4)
            .map(|chunk| {
                let value = u32::from_le_bytes(chunk.try_into().expect("four byte chunk"));
                if value >= BabyBear::ORDER_U32 {
                    return Err(StorageError::NonCanonicalField);
                }
                Ok(BabyBear::from_u32(value))
            })
            .collect()
    }
}

impl Matrix<BabyBear> for CheckedFileMatrix {
    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.height
    }

    // The retained trait requires an unsafe method declaration. The entire body
    // uses checked safe operations, including bounds checks for every caller.
    #[allow(unsafe_code)]
    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = BabyBear, IntoIter = impl Iterator<Item = BabyBear> + Send + Sync>
    {
        self.try_row(row)
            .unwrap_or_else(|error| std::panic::panic_any(StorageAccessFailure(error)))
    }
}

#[cfg(test)]
mod tests;
