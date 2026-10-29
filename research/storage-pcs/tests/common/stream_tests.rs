use crate::common::store::{ConstructionError, FileStore};
use kova_storage_fri::storage::{DenseStore, MatrixStore};
use p3_baby_bear::BabyBear;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    height: usize,
    width: usize,
    log_blowup: usize,
    shift: u32,
    input: Vec<Vec<u32>>,
    output: Vec<Vec<u32>>,
}

fn cases() -> Vec<Case> {
    serde_json::from_str(include_str!("../../fixtures/stream.json")).unwrap()
}

fn matrix(case: &Case) -> RowMajorMatrix<BabyBear> {
    assert_eq!(case.input.len(), case.height);
    assert!(case.input.iter().all(|row| row.len() == case.width));
    RowMajorMatrix::new(
        case.input
            .iter()
            .flatten()
            .map(|&v| BabyBear::from_u32(v))
            .collect(),
        case.width,
    )
}

#[test]
fn streamed_and_default_construction_match_independent_polynomials() {
    let dft = Radix2DitParallel::default();
    for case in cases() {
        let files = FileStore::new();
        let shift = BabyBear::from_u32(case.shift);
        let actual = files.extend(&dft, matrix(&case), case.log_blowup, shift);
        let default = DenseStore.extend(&dft, matrix(&case), case.log_blowup, shift);
        assert_eq!(actual.height(), case.height << case.log_blowup);
        for (row, expected) in case.output.iter().enumerate() {
            let values = actual.row(row).unwrap().into_iter().collect::<Vec<_>>();
            assert_eq!(
                values,
                default.row(row).unwrap().into_iter().collect::<Vec<_>>()
            );
            assert_eq!(
                values
                    .into_iter()
                    .map(|v| v.as_canonical_u32())
                    .collect::<Vec<_>>(),
                *expected
            );
        }
        assert_eq!(case.output.len(), actual.height());
        assert_eq!(
            files.streamed()[0].largest_output_column_fields,
            actual.height()
        );
    }
}

#[test]
fn partial_write_failure_removes_unfinished_matrix() {
    let case = cases().remove(0);
    let files = FileStore::new();
    let error = files
        .try_extend(
            &Radix2DitParallel::default(),
            matrix(&case),
            case.log_blowup,
            BabyBear::from_u32(case.shift),
            Some((case.height << case.log_blowup) + 1),
        )
        .err()
        .unwrap();
    assert_eq!(error, ConstructionError::Io(std::io::ErrorKind::WriteZero));
    assert!(files.shapes().is_empty());
    assert!(files.streamed().is_empty());
    assert_eq!(files.file_count(), 0);
}

#[test]
fn construction_limits_and_retained_descriptor_lifetime() {
    let case = cases().remove(0);
    let dft = Radix2DitParallel::default();
    let files = FileStore::new();
    assert_eq!(
        files
            .try_extend(&dft, matrix(&case), usize::MAX, BabyBear::ONE, None)
            .err(),
        Some(ConstructionError::Limit)
    );
    assert_eq!(
        files
            .try_extend(&dft, matrix(&case), 12, BabyBear::ONE, None)
            .err(),
        Some(ConstructionError::Shape)
    );
    assert_eq!(
        files
            .try_extend(&dft, matrix(&case), 0, BabyBear::ZERO, None)
            .err(),
        Some(ConstructionError::Shape)
    );
    assert_eq!(files.file_count(), 0);
    let actual = files.extend(
        &dft,
        matrix(&case),
        case.log_blowup,
        BabyBear::from_u32(case.shift),
    );
    let clone = actual.clone();
    drop(files);
    drop(actual);
    assert_eq!(
        clone
            .row(0)
            .unwrap()
            .into_iter()
            .map(|v| v.as_canonical_u32())
            .collect::<Vec<_>>(),
        case.output[0]
    );
}
