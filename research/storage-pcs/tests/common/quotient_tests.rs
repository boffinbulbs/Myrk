use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::common::{
    self, air,
    store::{ConstructionError, FileStore, StoredMatrix},
};
use kova_storage_fri::storage::{DenseStore, MatrixStore};
use p3_baby_bear::BabyBear;
use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_uni_stark::{Proof, StarkConfig, StarkGenericConfig};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    height: usize,
    width: usize,
    log_blowup: usize,
    shift: u32,
    input: Vec<Vec<u32>>,
    masks: Vec<Vec<u32>>,
    output: Vec<Vec<u32>>,
}
#[derive(Deserialize)]
struct Coupling {
    height: usize,
    chunks: usize,
    shift: u32,
    shifts: Vec<u32>,
    cis: Vec<u32>,
}
#[derive(Deserialize)]
struct Reference {
    cases: Vec<Case>,
    coupling: Coupling,
}
fn reference() -> Reference {
    serde_json::from_str(include_str!("../../fixtures/quotient.json")).unwrap()
}
fn matrix(case: &Case) -> RowMajorMatrix<BabyBear> {
    assert_eq!(case.input.len(), case.height);
    RowMajorMatrix::new(
        case.input
            .iter()
            .flatten()
            .map(|&v| BabyBear::from_u32(v))
            .collect(),
        case.width,
    )
}
fn masks(case: &Case) -> Vec<BabyBear> {
    case.masks
        .iter()
        .flatten()
        .map(|&v| BabyBear::from_u32(v))
        .collect()
}

#[test]
fn quotient_columns_match_independent_coefficient_reference() {
    let dft = Radix2DitParallel::default();
    for case in reference().cases {
        let files = FileStore::new();
        let masks = masks(&case);
        let shift = BabyBear::from_u32(case.shift);
        let actual = files.extend_quotient(&dft, matrix(&case), &masks, case.log_blowup, shift);
        let dense = DenseStore.extend_quotient(&dft, matrix(&case), &masks, case.log_blowup, shift);
        assert_eq!(actual.height(), case.output.len());
        for (row, expected) in case.output.iter().enumerate() {
            let values = actual.row(row).unwrap().into_iter().collect::<Vec<_>>();
            assert_eq!(
                values,
                dense.row(row).unwrap().into_iter().collect::<Vec<_>>()
            );
            assert_eq!(
                values
                    .into_iter()
                    .map(|v| v.as_canonical_u32())
                    .collect::<Vec<_>>(),
                *expected
            );
        }
        assert!(files.streamed()[0].quotient);
    }
}

#[derive(Clone, Default)]
struct CaptureStore(Arc<Mutex<Vec<Vec<BabyBear>>>>);
impl MatrixStore<BabyBear> for CaptureStore {
    type Stored = RowMajorMatrix<BabyBear>;
    fn store(&self, matrix: RowMajorMatrix<BabyBear>) -> Self::Stored {
        matrix
    }
    fn extend_quotient<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &D,
        evaluations: RowMajorMatrix<BabyBear>,
        masks: &[BabyBear],
        log_blowup: usize,
        shift: BabyBear,
    ) -> Self::Stored {
        self.0.lock().unwrap().push(masks.to_vec());
        DenseStore.extend_quotient(dft, evaluations, masks, log_blowup, shift)
    }
}

#[test]
fn actual_mask_coupling_and_dense_commitment_match() {
    let expected = reference().coupling;
    let size = expected.height * expected.chunks;
    let domain =
        TwoAdicMultiplicativeCoset::new(BabyBear::from_u32(expected.shift), size.ilog2() as usize)
            .unwrap();
    let domains = domain.split_domains(expected.chunks);
    assert_eq!(
        domains
            .iter()
            .map(|d| d.shift().as_canonical_u32())
            .collect::<Vec<_>>(),
        expected.shifts
    );
    let capture = CaptureStore::default();
    let pcs = common::adapted().with_storage(capture.clone());
    let values =
        || RowMajorMatrix::new_col((0..size).map(|r| BabyBear::from_usize(r + 3)).collect());
    let (actual, _) = <common::AdaptedPcs<CaptureStore> as UnivariateStarkPcs<
        common::Challenge,
        common::Challenger,
    >>::commit_quotient(&pcs, domain, values(), expected.chunks)
    .unwrap();
    let (dense, _) = <common::DensePcs as UnivariateStarkPcs<
        common::Challenge,
        common::Challenger,
    >>::commit_quotient(
        common::dense().pcs(), domain, values(), expected.chunks
    )
    .unwrap();
    assert_eq!(actual, dense);
    let masks = capture.0.lock().unwrap();
    assert_eq!(masks.len(), expected.chunks);
    assert!(masks[0].iter().any(|&v| v != BabyBear::ZERO));
    for coefficient in 0..masks[0].len() {
        let sum: BabyBear = masks
            .iter()
            .zip(&expected.cis)
            .map(|(m, &c)| m[coefficient] * BabyBear::from_u32(c))
            .sum();
        assert_eq!(sum, BabyBear::ZERO);
    }
    assert_ne!(
        BabyBear::from_u32(*expected.cis.last().unwrap()),
        BabyBear::ZERO
    );
}

#[test]
fn quotient_faults_do_not_publish_partial_matrices() {
    let case = reference().cases.remove(0);
    let files = FileStore::new();
    let dft = Radix2DitParallel::default();
    let masks = masks(&case);
    let shift = BabyBear::from_u32(case.shift);
    let error = files
        .try_extend_quotient(
            &dft,
            matrix(&case),
            &masks,
            case.log_blowup,
            shift,
            Some((case.height << (case.log_blowup + 1)) + 1),
        )
        .err();
    assert_eq!(
        error,
        Some(ConstructionError::Io(std::io::ErrorKind::WriteZero))
    );
    assert!(files.shapes().is_empty());
    assert_eq!(files.file_count(), 0);
    assert_eq!(
        files
            .try_extend_quotient(
                &dft,
                matrix(&case),
                &masks[1..],
                case.log_blowup,
                shift,
                None
            )
            .err(),
        Some(ConstructionError::Shape)
    );
    assert_eq!(
        files
            .try_extend_quotient(&dft, matrix(&case), &masks, usize::MAX, shift, None)
            .err(),
        Some(ConstructionError::Limit)
    );
    assert_eq!(files.file_count(), 0);
}

#[derive(Clone)]
struct BrokenLastMask {
    files: FileStore,
    calls: Arc<AtomicUsize>,
}
impl MatrixStore<BabyBear> for BrokenLastMask {
    type Stored = StoredMatrix;
    fn randomize<R: rand::Rng + Send + Sync>(
        &self,
        matrix: RowMajorMatrix<BabyBear>,
        random_columns: usize,
        rng: &mut R,
    ) -> Self::Stored {
        self.files.randomize(matrix, random_columns, rng)
    }
    fn extend_prepared<D: TwoAdicSubgroupDft<BabyBear>, M: Matrix<BabyBear>>(
        &self,
        dft: &D,
        evaluations: M,
        log_blowup: usize,
        shift: BabyBear,
    ) -> Self::Stored {
        self.files
            .extend_prepared(dft, evaluations, log_blowup, shift)
    }
    fn store(&self, matrix: RowMajorMatrix<BabyBear>) -> Self::Stored {
        self.files.store(matrix)
    }
    fn extend<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &D,
        evaluations: RowMajorMatrix<BabyBear>,
        log_blowup: usize,
        shift: BabyBear,
    ) -> Self::Stored {
        self.files.extend(dft, evaluations, log_blowup, shift)
    }
    fn extend_quotient<D: TwoAdicSubgroupDft<BabyBear>>(
        &self,
        dft: &D,
        evaluations: RowMajorMatrix<BabyBear>,
        masks: &[BabyBear],
        log_blowup: usize,
        shift: BabyBear,
    ) -> Self::Stored {
        let index = self.calls.fetch_add(1, Ordering::Relaxed);
        let mut altered = masks.to_vec();
        if index == 7 {
            altered[0] += BabyBear::ONE;
        }
        self.files
            .extend_quotient(dft, evaluations, &altered, log_blowup, shift)
    }
}

#[test]
#[ignore = "Explicit admitted incorrect coupling proof experiment"]
#[allow(
    clippy::assertions_on_constants,
    reason = "The negative construction must reach the release backend."
)]
fn incorrect_final_mask_rejected_by_retained_verifier() {
    assert!(!cfg!(debug_assertions));
    let calls = Arc::new(AtomicUsize::new(0));
    let files = FileStore::new();
    let policy = BrokenLastMask {
        files: files.clone(),
        calls: calls.clone(),
    };
    let config = StarkConfig::new(common::adapted().with_storage(policy), common::challenger());
    let proof =
        p3_uni_stark::prove(&config, &air::QuarticAir, air::trace(), &air::public()).unwrap();
    let encoded = serde_json::to_vec(&proof).unwrap();
    assert!(encoded.len() <= 2 * 1024 * 1024);
    let retained: Proof<common::DenseConfig> = serde_json::from_slice(&encoded).unwrap();
    assert!(
        p3_uni_stark::verify(
            &common::dense(),
            &air::QuarticAir,
            &retained,
            &air::public()
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 8);
    println!(
        "bad_mask_proof_bytes={} stored_shapes={:?}",
        encoded.len(),
        files.shapes()
    );
    assert_eq!(files.preparations()[0].random_field_draws, 2560);
    assert_eq!(files.field_bytes(), 1290240);
    println!(
        "prepared_source_bytes=12288 prepared_field_draws=2560 total_field_bytes={}",
        files.field_bytes()
    );
}
