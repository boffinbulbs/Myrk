use super::*;
use kova_storage_fri::storage::DenseStore;
use p3_dft::Radix2DitParallel;

#[derive(Clone)]
struct ExactSource {
    values: RowMajorMatrix<BabyBear>,
    windows: Arc<Mutex<Vec<[usize; 3]>>>,
    wrong_length: bool,
}

impl Matrix<BabyBear> for ExactSource {
    fn width(&self) -> usize {
        self.values.width()
    }
    fn height(&self) -> usize {
        self.values.height()
    }
    unsafe fn row_unchecked(
        &self,
        _row: usize,
    ) -> impl IntoIterator<Item = BabyBear, IntoIter = impl Iterator<Item = BabyBear> + Send + Sync>
    {
        std::iter::once_with(|| -> BabyBear { panic!("whole source row read") })
    }
    fn to_row_major_matrix(self) -> RowMajorMatrix<BabyBear> {
        panic!("whole source materialization")
    }
}

impl RowSource<BabyBear> for ExactSource {
    fn read_window(&self, row: usize, start: usize, end: usize) -> Option<Vec<BabyBear>> {
        assert!(end - start <= TILE_COLUMNS);
        self.windows.lock().unwrap().push([row, start, end]);
        let mut values = self.values.read_window(row, start, end)?;
        if self.wrong_length {
            values.pop();
        }
        Some(values)
    }
}

fn input() -> RowMajorMatrix<BabyBear> {
    RowMajorMatrix::new(
        (0..80)
            .map(|value| BabyBear::from_u32(7 * value + 11))
            .collect(),
        5,
    )
}

#[test]
fn exact_partial_windows_and_bounded_tile_counters() {
    let windows = Arc::new(Mutex::new(Vec::new()));
    let source = ExactSource {
        values: input(),
        windows: windows.clone(),
        wrong_length: false,
    };
    let files = FileStore::new();
    let dft = Radix2DitParallel::default();
    let actual = files.extend_prepared(&dft, source, 2, BabyBear::GENERATOR);
    let expected = DenseStore.extend(&dft, input(), 2, BabyBear::GENERATOR);
    for row in 0..64 {
        assert_eq!(
            actual.read_window(row, 0, 5).unwrap(),
            expected.read_window(row, 0, 5).unwrap()
        );
    }
    let wanted: Vec<_> = [0, 4]
        .into_iter()
        .flat_map(|start| (0..16).map(move |row| [row, start, (start + TILE_COLUMNS).min(5)]))
        .collect();
    assert_eq!(*windows.lock().unwrap(), wanted);
    let event = files.streamed().remove(0);
    assert_eq!(event.source_windows, 32);
    assert_eq!(event.source_fields, 80);
    assert_eq!(event.output_write_calls, 128);
    assert_eq!(event.forward_dft_batches, 2);
    assert_eq!(event.inverse_dft_batches, 0);
    assert_eq!(event.largest_input_tile_fields, 64);
    assert_eq!(event.largest_output_tile_fields, 256);
    assert_eq!(event.written_fields, 320);
}

#[test]
fn short_window_refusal_cleans_output_and_allows_retry() {
    let files = FileStore::new();
    let source = ExactSource {
        values: input(),
        windows: Arc::default(),
        wrong_length: true,
    };
    let error = files
        .try_extend(
            &Radix2DitParallel::default(),
            source,
            2,
            BabyBear::ONE,
            None,
        )
        .err();
    assert_eq!(error, Some(ConstructionError::Incomplete));
    assert_eq!(files.file_count(), 0);
    assert!(files.streamed().is_empty());
    let actual = files.extend(&Radix2DitParallel::default(), input(), 2, BabyBear::ONE);
    assert_eq!(actual.width(), 5);
    assert_eq!(files.file_count(), 1);
}

#[test]
fn failures_before_and_inside_ordinary_and_quotient_tiles_cleanup() {
    let masks = vec![BabyBear::from_u32(7); 80];
    for quotient in [false, true] {
        for stop in [0, 1, 4, 5, 129, 257] {
            let files = FileStore::new();
            let dft = Radix2DitParallel::default();
            let result = if quotient {
                files.try_extend_quotient(&dft, input(), &masks, 1, BabyBear::GENERATOR, Some(stop))
            } else {
                files.try_extend(&dft, input(), 2, BabyBear::GENERATOR, Some(stop))
            };
            assert_eq!(
                result.err(),
                Some(ConstructionError::Io(std::io::ErrorKind::WriteZero))
            );
            assert_eq!(files.file_count(), 0);
            assert!(files.shapes().is_empty());
            assert!(files.streamed().is_empty());
        }
    }
}

#[test]
fn partial_quotient_tile_matches_dense_coefficient_kernel() {
    let files = FileStore::new();
    let dft = Radix2DitParallel::default();
    let masks: Vec<_> = (0..80).map(|index| BabyBear::from_u32(index + 3)).collect();
    let actual = files.extend_quotient(&dft, input(), &masks, 1, BabyBear::GENERATOR);
    let expected = DenseStore.extend_quotient(&dft, input(), &masks, 1, BabyBear::GENERATOR);
    for row in 0..64 {
        assert_eq!(
            actual.read_window(row, 0, 5),
            expected.read_window(row, 0, 5)
        );
    }
    let event = files.streamed().remove(0);
    assert_eq!(event.source_fields, 80);
    assert_eq!(event.source_windows, 32);
    assert_eq!(event.inverse_dft_batches, 2);
    assert_eq!(event.forward_dft_batches, 2);
    assert_eq!(event.output_write_calls, 128);
}

#[test]
fn checked_source_windows_preserve_typed_storage_abort() {
    for truncated in [false, true] {
        let files = FileStore::new();
        let source = files.store(input());
        let path = files.0.path.join("0.bin");
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        if truncated {
            writer.set_len(319).unwrap();
        } else {
            writer.seek(SeekFrom::Start(16)).unwrap();
            writer
                .write_all(&BabyBear::ORDER_U32.to_le_bytes())
                .unwrap();
        }
        drop(writer);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            files.extend_prepared(
                &Radix2DitParallel::default(),
                source.clone(),
                2,
                BabyBear::ONE,
            )
        }));
        let failure = result
            .err()
            .unwrap()
            .downcast::<kova_storage_matrix::StorageAccessFailure>()
            .unwrap();
        assert_eq!(
            failure.0,
            if truncated {
                StorageError::Length
            } else {
                StorageError::NonCanonicalField
            }
        );
        assert_eq!(files.file_count(), 1);
        // A panic while holding construction ownership makes later writes fail closed.
        let state = files.0.state.lock().unwrap_err().into_inner();
        assert_eq!(state.shapes, vec![[16, 5]]);
        assert!(state.streamed.is_empty());
        drop(state);
        assert_eq!(
            files
                .try_extend(
                    &Radix2DitParallel::default(),
                    input(),
                    2,
                    BabyBear::ONE,
                    None
                )
                .err(),
            Some(ConstructionError::Poisoned)
        );
    }
}

#[test]
fn dense_and_file_window_bounds_agree() {
    let files = FileStore::new();
    let dense = input();
    let stored = files.store(dense.clone());
    for (row, start, end) in [(0, 0, 0), (15, 4, 5), (16, 0, 1), (0, 4, 3), (0, 0, 6)] {
        assert_eq!(
            stored.read_window(row, start, end),
            dense.read_window(row, start, end)
        );
    }
}
