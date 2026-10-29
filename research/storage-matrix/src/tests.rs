use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

static NEXT: AtomicUsize = AtomicUsize::new(0);
const WORDS: [u32; 12] = [0, 1, 2_013_265_920, 17, 42, 9, 5, 7, 11, 31, 127, 65_535];

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}

impl Fixture {
    fn new(words: &[u32]) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "kova_matrix_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("unique synthetic fixture directory");
        let path = directory.join("fields.bin");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        for word in words {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
        file.sync_all().unwrap();
        Self { directory, path }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_file(&self.path).unwrap();
        fs::remove_dir(&self.directory).unwrap();
    }
}

fn words(row: Vec<BabyBear>) -> Vec<u32> {
    row.into_iter().map(|x| x.as_canonical_u32()).collect()
}

#[test]
fn independent_words_and_owned_windows_match_retained_matrix_access() {
    let fixture = Fixture::new(&WORDS);
    let matrix = CheckedFileMatrix::open(&fixture.path, 4, 3).unwrap();
    for row in 0..4 {
        assert_eq!(
            words(matrix.try_row(row).unwrap()),
            WORDS[3 * row..3 * row + 3]
        );
        let through_trait = Matrix::row(&matrix, row)
            .unwrap()
            .into_iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<_>>();
        assert_eq!(through_trait, WORDS[3 * row..3 * row + 3]);
    }
    let owned = matrix.try_row(0).unwrap();
    assert_eq!(words(matrix.try_window(3, 1, 3).unwrap()), [127, 65_535]);
    assert_eq!(words(owned), WORDS[..3]);
    assert!(matrix.try_window(0, 3, 3).unwrap().is_empty());
    assert_eq!(Matrix::get(&matrix, 1, 2).unwrap().as_canonical_u32(), 9);
    assert!(Matrix::row(&matrix, 4).is_none());
    assert!(Matrix::get(&matrix, 0, 3).is_none());
}

#[test]
fn clones_serialize_file_cursor_access_and_return_independent_rows() {
    let fixture = Fixture::new(&WORDS);
    let matrix = CheckedFileMatrix::open(&fixture.path, 4, 3).unwrap();
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let cloned = matrix.clone();
            scope.spawn(move || {
                for step in 0..32 {
                    let row = (worker + step) % 4;
                    assert_eq!(
                        words(cloned.try_row(row).unwrap()),
                        WORDS[3 * row..3 * row + 3]
                    );
                }
            });
        }
    });
}

#[test]
fn malformed_shapes_bounds_and_file_lengths_fail_before_values() {
    let fixture = Fixture::new(&WORDS);
    for (height, width) in [(0, 3), (4, 0), (usize::MAX, 3), (4, usize::MAX)] {
        assert!(matches!(
            CheckedFileMatrix::open(&fixture.path, height, width),
            Err(StorageError::Shape)
        ));
    }
    assert!(matches!(
        CheckedFileMatrix::open(&fixture.path, 3, 3),
        Err(StorageError::Length)
    ));
    assert!(matches!(
        CheckedFileMatrix::open(&fixture.directory, 4, 3),
        Err(StorageError::FileKind)
    ));
    let matrix = CheckedFileMatrix::open(&fixture.path, 4, 3).unwrap();
    for (row, start, end) in [(4, 0, 1), (0, 2, 1), (0, 0, 4), (usize::MAX, 0, 0)] {
        assert_eq!(
            matrix.try_window(row, start, end),
            Err(StorageError::Bounds)
        );
    }
}

#[test]
fn noncanonical_words_are_not_reduced_into_valid_field_elements() {
    for invalid in [2_013_265_921, u32::MAX] {
        let fixture = Fixture::new(&[1, 2, invalid]);
        let matrix = CheckedFileMatrix::open(&fixture.path, 1, 3).unwrap();
        assert_eq!(matrix.try_row(0), Err(StorageError::NonCanonicalField));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Matrix::row(&matrix, 0);
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<StorageAccessFailure>().unwrap().0,
            StorageError::NonCanonicalField
        );
    }
}

#[test]
fn truncation_aborts_trait_evaluation_with_a_distinct_storage_failure() {
    let fixture = Fixture::new(&WORDS);
    let matrix = CheckedFileMatrix::open(&fixture.path, 4, 3).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&fixture.path)
        .unwrap()
        .set_len(4)
        .unwrap();
    assert_eq!(matrix.try_row(0), Err(StorageError::Length));
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = Matrix::row(&matrix, 0);
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<StorageAccessFailure>().unwrap().0,
        StorageError::Length
    );
}

#[test]
fn poisoned_cursor_lock_is_not_recovered_with_untrusted_state() {
    let fixture = Fixture::new(&WORDS);
    let matrix = CheckedFileMatrix::open(&fixture.path, 4, 3).unwrap();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = matrix.lease.file.lock().unwrap();
        panic!("synthetic cursor failure");
    }));
    assert_eq!(matrix.try_row(0), Err(StorageError::LockPoisoned));
}

#[test]
fn bounded_largest_file_and_canonical_mutation_have_explicit_scope() {
    let fixture = Fixture::new(&vec![1; MAX_HEIGHT * MAX_WIDTH]);
    let matrix = CheckedFileMatrix::open(&fixture.path, MAX_HEIGHT, MAX_WIDTH).unwrap();
    assert_eq!(
        words(matrix.try_row(MAX_HEIGHT - 1).unwrap()),
        vec![1; MAX_WIDTH]
    );
    let mut writer = OpenOptions::new().write(true).open(&fixture.path).unwrap();
    writer.seek(SeekFrom::Start(0)).unwrap();
    writer.write_all(&2u32.to_le_bytes()).unwrap();
    writer.sync_all().unwrap();
    assert_eq!(words(matrix.try_row(0).unwrap())[0], 2);
    // Canonical decoding is not authenticated storage. A later commitment must
    // detect this modification through its actual opening verification path.
}

#[cfg(unix)]
#[test]
fn symbolic_link_is_rejected_before_opening_the_field_file() {
    let fixture = Fixture::new(&WORDS);
    let link = fixture.directory.join("link.bin");
    std::os::unix::fs::symlink(&fixture.path, &link).unwrap();
    let result = CheckedFileMatrix::open(&link, 4, 3);
    fs::remove_file(link).unwrap();
    assert!(matches!(result, Err(StorageError::FileKind)));
}

#[cfg(unix)]
#[test]
fn replacing_the_path_does_not_redirect_the_open_descriptor() {
    let fixture = Fixture::new(&WORDS);
    let matrix = CheckedFileMatrix::open(&fixture.path, 4, 3).unwrap();
    let original = fixture.directory.join("original.bin");
    fs::rename(&fixture.path, &original).unwrap();
    fs::write(&fixture.path, [0u8; 48]).unwrap();
    assert_eq!(words(matrix.try_row(0).unwrap()), WORDS[..3]);
    fs::remove_file(original).unwrap();
}
