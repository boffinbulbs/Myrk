use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kova_storage_fri::storage::MatrixStore;
use kova_storage_matrix::CheckedFileMatrix;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory {
    path: PathBuf,
    shapes: Mutex<Vec<[usize; 2]>>,
}

impl Drop for Directory {
    fn drop(&mut self) {
        for entry in fs::read_dir(&self.path).expect("synthetic directory") {
            fs::remove_file(entry.expect("synthetic file").path()).expect("remove synthetic file");
        }
        fs::remove_dir(&self.path).expect("remove synthetic directory");
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
            shapes: Mutex::new(Vec::new()),
        }))
    }

    pub fn shapes(&self) -> Vec<[usize; 2]> {
        self.0.shapes.lock().unwrap().clone()
    }
}

// Matrix drops its descriptor before the final directory ownership is released.
#[derive(Clone)]
pub struct StoredMatrix {
    matrix: CheckedFileMatrix,
    _directory: Arc<Directory>,
}

impl MatrixStore<BabyBear> for FileStore {
    type Stored = StoredMatrix;

    fn store(&self, matrix: RowMajorMatrix<BabyBear>) -> StoredMatrix {
        let height = matrix.height();
        let width = matrix.width();
        assert!((1..=4096).contains(&height) && height.is_power_of_two());
        assert!((1..=12).contains(&width));
        let mut shapes = self.0.shapes.lock().unwrap();
        assert!(shapes.len() < 16);
        let total: usize = shapes.iter().map(|[h, w]| h * w * 4).sum();
        assert!(total + height * width * 4 <= 2 * 1024 * 1024);
        let path = self.0.path.join(format!("{}.bin", shapes.len()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("new synthetic file");
        for value in matrix.values {
            file.write_all(&value.as_canonical_u32().to_le_bytes())
                .expect("synthetic write");
        }
        file.sync_all().expect("synthetic flush");
        drop(file);
        let matrix =
            CheckedFileMatrix::open(&path, height, width).expect("checked synthetic matrix");
        shapes.push([height, width]);
        StoredMatrix {
            matrix,
            _directory: self.0.clone(),
        }
    }
}

impl Matrix<BabyBear> for StoredMatrix {
    fn width(&self) -> usize {
        self.matrix.width()
    }
    fn height(&self) -> usize {
        self.matrix.height()
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
