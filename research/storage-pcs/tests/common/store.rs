use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kova_storage_fri::storage::MatrixStore;
use kova_storage_matrix::{CheckedFileMatrix, StorageError};
use p3_baby_bear::BabyBear;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{Rng, RngExt};

static NEXT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstructionError {
    Shape,
    Limit,
    Poisoned,
    Io(std::io::ErrorKind),
    Access(StorageError),
    Incomplete,
}

impl From<std::io::Error> for ConstructionError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamEvent {
    pub quotient: bool,
    pub input: [usize; 2],
    pub output: [usize; 2],
    pub column_dft_calls: usize,
    pub inverse_column_dft_calls: usize,
    pub largest_output_column_fields: usize,
    pub written_fields: usize,
}

#[derive(Default)]
struct State {
    shapes: Vec<[usize; 2]>,
    streamed: Vec<StreamEvent>,
    files: Vec<([usize; 2], bool)>,
    preparations: Vec<PreparationEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparationEvent {
    pub raw: [usize; 2],
    pub prepared: [usize; 2],
    pub random_field_draws: usize,
}
struct Directory {
    path: PathBuf,
    state: Mutex<State>,
}

impl Drop for Directory {
    fn drop(&mut self) {
        for entry in fs::read_dir(&self.path).expect("synthetic directory") {
            fs::remove_file(entry.expect("synthetic file").path()).expect("remove synthetic file");
        }
        fs::remove_dir(&self.path).expect("remove synthetic directory");
    }
}

struct PendingFile {
    file: Option<File>,
    path: PathBuf,
    finished: bool,
}
impl Drop for PendingFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.finished {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Clone)]
pub struct FileStore(Arc<Directory>);

impl FileStore {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "kova_pcs_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("new synthetic directory");
        Self(Arc::new(Directory {
            path,
            state: Mutex::new(State::default()),
        }))
    }

    pub fn shapes(&self) -> Vec<[usize; 2]> {
        self.0.state.lock().unwrap().shapes.clone()
    }
    pub fn streamed(&self) -> Vec<StreamEvent> {
        self.0.state.lock().unwrap().streamed.clone()
    }
    pub fn file_count(&self) -> usize {
        fs::read_dir(&self.0.path).unwrap().count()
    }

    pub fn preparations(&self) -> Vec<PreparationEvent> {
        self.0.state.lock().unwrap().preparations.clone()
    }
    pub fn file_order(&self) -> Vec<([usize; 2], bool)> {
        self.0.state.lock().unwrap().files.clone()
    }
    pub fn field_bytes(&self) -> usize {
        self.0
            .state
            .lock()
            .unwrap()
            .files
            .iter()
            .map(|([h, w], _)| h * w * 4)
            .sum()
    }

    fn create(
        &self,
        height: usize,
        width: usize,
        write: impl FnOnce(&mut File) -> Result<Option<StreamEvent>, ConstructionError>,
    ) -> Result<StoredMatrix, ConstructionError> {
        self.create_as(height, width, false, write)
    }

    fn create_as(
        &self,
        height: usize,
        width: usize,
        prepared_input: bool,
        write: impl FnOnce(&mut File) -> Result<Option<StreamEvent>, ConstructionError>,
    ) -> Result<StoredMatrix, ConstructionError> {
        if !(1..=4096).contains(&height) || !height.is_power_of_two() || !(1..=12).contains(&width)
        {
            return Err(ConstructionError::Shape);
        }
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| ConstructionError::Poisoned)?;
        let total: usize = state.files.iter().map(|([h, w], _)| h * w * 4).sum();
        if state.files.len() >= 16 || total + height * width * 4 > 2 * 1024 * 1024 {
            return Err(ConstructionError::Limit);
        }
        let path = self.0.path.join(format!("{}.bin", state.files.len()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut pending = PendingFile {
            file: Some(file),
            path,
            finished: false,
        };
        let event = write(pending.file.as_mut().unwrap())?;
        pending.file.as_mut().unwrap().sync_all()?;
        drop(pending.file.take());
        let matrix = CheckedFileMatrix::open(&pending.path, height, width)
            .map_err(ConstructionError::Access)?;
        state.files.push(([height, width], prepared_input));
        if !prepared_input {
            state.shapes.push([height, width]);
        }
        if let Some(event) = event {
            state.streamed.push(event);
        }
        pending.finished = true;
        Ok(StoredMatrix {
            matrix,
            _directory: self.0.clone(),
        })
    }

    /// The optional field count injects an explicit write failure for testing.
    pub fn try_extend<Dft: TwoAdicSubgroupDft<BabyBear>, M: Matrix<BabyBear>>(
        &self,
        dft: &Dft,
        evaluations: M,
        log_blowup: usize,
        shift: BabyBear,
        fail_after_fields: Option<usize>,
    ) -> Result<StoredMatrix, ConstructionError> {
        let width = evaluations.width();
        if !(1..=12).contains(&width) {
            return Err(ConstructionError::Shape);
        }
        let input_height = evaluations.height();
        let height = u32::try_from(log_blowup)
            .ok()
            .and_then(|bits| input_height.checked_shl(bits))
            .ok_or(ConstructionError::Limit)?;
        if !input_height.is_power_of_two() || shift == BabyBear::ZERO {
            return Err(ConstructionError::Shape);
        }
        self.create(height, width, |file| {
            let mut written = 0;
            for column in 0..width {
                let values = (0..input_height)
                    .map(|r| {
                        evaluations
                            .get(r, column)
                            .ok_or(ConstructionError::Incomplete)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let output = dft
                    .coset_lde_batch(RowMajorMatrix::new(values, 1), log_blowup, shift)
                    .bit_reverse_rows();
                if output.height() != height || output.width() != 1 {
                    return Err(ConstructionError::Shape);
                }
                for row in 0..height {
                    if fail_after_fields == Some(written) {
                        return Err(ConstructionError::Io(std::io::ErrorKind::WriteZero));
                    }
                    let value = output
                        .row(row)
                        .ok_or(ConstructionError::Incomplete)?
                        .into_iter()
                        .next()
                        .ok_or(ConstructionError::Incomplete)?;
                    let offset = u64::try_from((row * width + column) * 4)
                        .map_err(|_| ConstructionError::Limit)?;
                    file.seek(SeekFrom::Start(offset))?;
                    file.write_all(&value.as_canonical_u32().to_le_bytes())?;
                    written += 1;
                }
            }
            if written != height * width {
                return Err(ConstructionError::Incomplete);
            }
            Ok(Some(StreamEvent {
                quotient: false,
                input: [input_height, width],
                output: [height, width],
                column_dft_calls: width,
                inverse_column_dft_calls: 0,
                largest_output_column_fields: height,
                written_fields: written,
            }))
        })
    }
}

// The descriptor is released before the last directory ownership is dropped.
#[derive(Clone)]
pub struct StoredMatrix {
    matrix: CheckedFileMatrix,
    _directory: Arc<Directory>,
}

impl MatrixStore<BabyBear> for FileStore {
    type Stored = StoredMatrix;

    fn store(&self, matrix: RowMajorMatrix<BabyBear>) -> StoredMatrix {
        self.create(matrix.height(), matrix.width(), |file| {
            for value in matrix.values {
                file.write_all(&value.as_canonical_u32().to_le_bytes())?;
            }
            Ok(None)
        })
        .unwrap_or_else(|error| std::panic::panic_any(error))
    }

    fn extend<Dft: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &Dft,
        evaluations: RowMajorMatrix<BabyBear>,
        log_blowup: usize,
        shift: BabyBear,
    ) -> Self::Stored {
        self.try_extend(dft, evaluations, log_blowup, shift, None)
            .unwrap_or_else(|error| std::panic::panic_any(error))
    }

    fn randomize<R: Rng + Send + Sync>(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        random_columns: usize,
        rng: &mut R,
    ) -> Self::Stored {
        self.try_randomize(matrix, random_columns, rng, None)
            .unwrap_or_else(|error| std::panic::panic_any(error))
    }

    fn extend_prepared<D: TwoAdicSubgroupDft<BabyBear>, M: Matrix<BabyBear>>(
        &self,
        dft: &D,
        evaluations: M,
        log_blowup: usize,
        shift: BabyBear,
    ) -> Self::Stored {
        self.try_extend(dft, evaluations, log_blowup, shift, None)
            .unwrap_or_else(|error| std::panic::panic_any(error))
    }

    fn extend_quotient<Dft: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &Dft,
        evaluations: RowMajorMatrix<BabyBear>,
        masks: &[BabyBear],
        log_blowup: usize,
        shift: BabyBear,
    ) -> Self::Stored {
        self.try_extend_quotient(dft, evaluations, masks, log_blowup, shift, None)
            .unwrap_or_else(|error| std::panic::panic_any(error))
    }
}

impl FileStore {
    pub fn try_randomize<R: Rng + Send + Sync>(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        random_columns: usize,
        rng: &mut R,
        fail_after_fields: Option<usize>,
    ) -> Result<StoredMatrix, ConstructionError> {
        let width = matrix.width();
        if !(1..=8).contains(&width) || !(1..=4).contains(&random_columns) {
            return Err(ConstructionError::Shape);
        }
        let height = matrix.height();
        if !height.is_power_of_two() {
            return Err(ConstructionError::Shape);
        }
        let prepared_height = height.checked_mul(2).ok_or(ConstructionError::Limit)?;
        let prepared_width = width + random_columns;
        let prepared = self.create_as(prepared_height, prepared_width, true, |file| {
            let mut written = 0;
            let mut write_field = |value: BabyBear| -> Result<(), ConstructionError> {
                if fail_after_fields == Some(written) {
                    return Err(ConstructionError::Io(std::io::ErrorKind::WriteZero));
                }
                file.write_all(&value.as_canonical_u32().to_le_bytes())?;
                written += 1;
                Ok(())
            };
            for row in 0..height {
                for column in 0..width {
                    write_field(matrix.values[row * width + column])?;
                }
                for _ in 0..width + 2 * random_columns {
                    write_field(rng.random())?;
                }
            }
            if written != prepared_height * prepared_width {
                return Err(ConstructionError::Incomplete);
            }
            Ok(None)
        })?;
        self.0
            .state
            .lock()
            .map_err(|_| ConstructionError::Poisoned)?
            .preparations
            .push(PreparationEvent {
                raw: [height, width],
                prepared: [prepared_height, prepared_width],
                random_field_draws: height * (width + 2 * random_columns),
            });
        Ok(prepared)
    }

    /// Masks are actual prepared coefficients. This method draws no randomness.
    pub fn try_extend_quotient<Dft: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &Dft,
        evaluations: RowMajorMatrix<BabyBear>,
        masks: &[BabyBear],
        log_blowup: usize,
        shift: BabyBear,
        fail_after_fields: Option<usize>,
    ) -> Result<StoredMatrix, ConstructionError> {
        let width = evaluations.width();
        if !(1..=12).contains(&width) {
            return Err(ConstructionError::Shape);
        }
        let h = evaluations.height();
        let bits = log_blowup
            .checked_add(1)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(ConstructionError::Limit)?;
        let factor = 1usize.checked_shl(bits).ok_or(ConstructionError::Limit)?;
        let height = h.checked_mul(factor).ok_or(ConstructionError::Limit)?;
        if !h.is_power_of_two() || masks.len() != h * width || shift == BabyBear::ZERO {
            return Err(ConstructionError::Shape);
        }
        self.create(height, width, |file| {
            let mut written = 0;
            for column in 0..width {
                let values = (0..h)
                    .map(|row| evaluations.values[row * width + column])
                    .collect();
                let coefficients =
                    dft.coset_idft_batch(RowMajorMatrix::new(values, 1), shift.inverse());
                if coefficients.height() != h || coefficients.width() != 1 {
                    return Err(ConstructionError::Shape);
                }
                let mut coefficients = coefficients.values;
                coefficients.resize(height, BabyBear::ZERO);
                let p = shift.exp_u64(h as u64);
                let mut power = BabyBear::ONE;
                for row in 0..h {
                    let value = power * masks[row * width + column];
                    coefficients[row] -= value;
                    coefficients[h + row] += p * value;
                    power *= BabyBear::GENERATOR;
                }
                let output = dft
                    .dft_batch(RowMajorMatrix::new(coefficients, 1))
                    .bit_reverse_rows();
                if output.height() != height || output.width() != 1 {
                    return Err(ConstructionError::Shape);
                }
                for row in 0..height {
                    if fail_after_fields == Some(written) {
                        return Err(ConstructionError::Io(std::io::ErrorKind::WriteZero));
                    }
                    let value = output
                        .row(row)
                        .ok_or(ConstructionError::Incomplete)?
                        .into_iter()
                        .next()
                        .ok_or(ConstructionError::Incomplete)?;
                    let offset = u64::try_from((row * width + column) * 4)
                        .map_err(|_| ConstructionError::Limit)?;
                    file.seek(SeekFrom::Start(offset))?;
                    file.write_all(&value.as_canonical_u32().to_le_bytes())?;
                    written += 1;
                }
            }
            if written != height * width {
                return Err(ConstructionError::Incomplete);
            }
            Ok(Some(StreamEvent {
                quotient: true,
                input: [h, width],
                output: [height, width],
                column_dft_calls: width,
                inverse_column_dft_calls: width,
                largest_output_column_fields: height,
                written_fields: written,
            }))
        })
    }
}

impl Matrix<BabyBear> for StoredMatrix {
    fn width(&self) -> usize {
        self.matrix.width()
    }
    fn height(&self) -> usize {
        self.matrix.height()
    }
    // A checked scalar window avoids reading a full stored row per column.
    unsafe fn get_unchecked(&self, row: usize, column: usize) -> BabyBear {
        let end = column.checked_add(1).unwrap_or_else(|| {
            std::panic::panic_any(kova_storage_matrix::StorageAccessFailure(
                StorageError::Bounds,
            ))
        });
        self.matrix
            .try_window(row, column, end)
            .unwrap_or_else(|error| {
                std::panic::panic_any(kova_storage_matrix::StorageAccessFailure(error))
            })[0]
    }
    // The declaration implements the retained trait. No unsafe operation occurs.
    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = BabyBear, IntoIter = impl Iterator<Item = BabyBear> + Send + Sync>
    {
        self.matrix.try_row(row).unwrap_or_else(|error| {
            std::panic::panic_any(kova_storage_matrix::StorageAccessFailure(error))
        })
    }
}
