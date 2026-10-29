use crate::common::{
    self,
    store::{ConstructionError, FileStore},
};
use kova_storage_fri::storage::{DenseStore, MatrixStore};
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_uni_stark::StarkGenericConfig;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use serde::Deserialize;

#[derive(Deserialize)]
struct Cell {
    random: bool,
    index: usize,
}
#[derive(Deserialize)]
struct Case {
    height: usize,
    width: usize,
    columns: usize,
    draws: usize,
    cells: Vec<Vec<Cell>>,
}
fn raw(height: usize, width: usize) -> RowMajorMatrix<BabyBear> {
    RowMajorMatrix::new(
        (0..height * width)
            .map(|i| BabyBear::from_usize(11 + 5 * i))
            .collect(),
        width,
    )
}

#[test]
fn prepared_rows_and_rng_continuation_match_independent_indices() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../../fixtures/preparation.json")).unwrap();
    for (index, case) in cases.into_iter().enumerate() {
        let files = FileStore::new();
        let seed = [41 + index as u8; 32];
        let mut expected_rng = StdRng::from_seed(seed);
        let draws: Vec<BabyBear> = (0..case.draws).map(|_| expected_rng.random()).collect();
        let mut actual_rng = StdRng::from_seed(seed);
        let mut dense_rng = StdRng::from_seed(seed);
        let actual = files.randomize(raw(case.height, case.width), case.columns, &mut actual_rng);
        let dense =
            DenseStore.randomize(raw(case.height, case.width), case.columns, &mut dense_rng);
        let raw = raw(case.height, case.width);
        assert_eq!(actual.height(), 2 * case.height);
        assert_eq!(case.cells.len(), actual.height());
        for (row, cells) in case.cells.iter().enumerate() {
            let expected: Vec<_> = cells
                .iter()
                .map(|c| {
                    if c.random {
                        draws[c.index]
                    } else {
                        raw.values[c.index]
                    }
                })
                .collect();
            assert_eq!(
                actual.row(row).unwrap().into_iter().collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                dense.row(row).unwrap().into_iter().collect::<Vec<_>>(),
                expected
            );
        }
        let next = expected_rng.next_u64();
        assert_eq!(actual_rng.next_u64(), next);
        assert_eq!(dense_rng.next_u64(), next);
        assert_eq!(files.preparations()[0].random_field_draws, case.draws);
        assert_eq!(
            files.file_order(),
            vec![([2 * case.height, case.width + case.columns], true)]
        );
        assert!(files.shapes().is_empty());
    }
}

#[test]
fn main_batch_preflight_order_and_continuing_commitments_match() {
    let files = FileStore::new();
    let candidate = common::adapted().with_storage(files.clone());
    let reference = common::dense();
    let domain = <_ as Pcs<common::Challenge, common::Challenger>>::natural_domain_for_degree(
        &candidate, 512,
    );
    let bad_domain = <_ as Pcs<common::Challenge, common::Challenger>>::natural_domain_for_degree(
        &candidate, 256,
    );
    let rejected = <_ as Pcs<common::Challenge, common::Challenger>>::commit(
        &candidate,
        [(domain, raw(256, 2)), (bad_domain, raw(128, 2))],
    );
    assert!(rejected.is_err());
    assert_eq!(files.file_count(), 0);
    assert!(files.preparations().is_empty());
    let batch = || vec![(domain, raw(256, 2)), (domain, raw(256, 3))];
    let (actual, _) =
        <_ as Pcs<common::Challenge, common::Challenger>>::commit(&candidate, batch()).unwrap();
    let (expected, _) =
        <_ as Pcs<common::Challenge, common::Challenger>>::commit(reference.pcs(), batch())
            .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        files.file_order(),
        vec![
            ([512, 6], true),
            ([512, 7], true),
            ([4096, 6], false),
            ([4096, 7], false)
        ]
    );
    let (next, _) = <_ as Pcs<common::Challenge, common::Challenger>>::commit(
        &candidate,
        [(domain, raw(256, 2))],
    )
    .unwrap();
    let (expected, _) = <_ as Pcs<common::Challenge, common::Challenger>>::commit(
        reference.pcs(),
        [(domain, raw(256, 2))],
    )
    .unwrap();
    assert_eq!(next, expected);
}

#[test]
fn input_write_failure_cleans_up_without_rewinding_entropy() {
    let files = FileStore::new();
    let mut rng = StdRng::from_seed([61; 32]);
    let mut expected = StdRng::from_seed([61; 32]);
    let error = files.try_randomize(raw(2, 2), 4, &mut rng, Some(4)).err();
    assert_eq!(
        error,
        Some(ConstructionError::Io(std::io::ErrorKind::WriteZero))
    );
    for _ in 0..3 {
        let _: BabyBear = expected.random();
    }
    assert_eq!(rng.next_u64(), expected.next_u64());
    assert_eq!(files.file_count(), 0);
    assert!(files.preparations().is_empty());
    assert!(files.shapes().is_empty());
}

struct ReadOnlySource(RowMajorMatrix<BabyBear>);
impl Matrix<BabyBear> for ReadOnlySource {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn height(&self) -> usize {
        self.0.height()
    }
    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = BabyBear, IntoIter = impl Iterator<Item = BabyBear> + Send + Sync>
    {
        self.0.row(row).unwrap().into_iter().collect::<Vec<_>>()
    }
    fn to_row_major_matrix(self) -> RowMajorMatrix<BabyBear> {
        panic!("prepared source must not materialize a dense bank")
    }
}

#[test]
fn prepared_source_extension_does_not_materialize_the_input() {
    let files = FileStore::new();
    let source = ReadOnlySource(raw(16, 2));
    let actual = files.extend_prepared(
        &Radix2DitParallel::default(),
        source,
        2,
        BabyBear::GENERATOR,
    );
    assert_eq!(actual.height(), 64);
    assert_eq!(actual.width(), 2);
}
