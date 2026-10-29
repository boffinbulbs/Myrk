//! Input matrix representation without changes to proof or verifier fields.

use alloc::vec::Vec;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::TwoAdicField;
use p3_matrix::Matrix;
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};

/// A policy prepares inputs and retains exact physically ordered LDE values.
/// Main preparation consumes only the caller's continuing mask generator.
pub trait MatrixStore<F: Clone + Send + Sync>: Clone + Send + Sync {
    type Stored: Matrix<F> + 'static;
    fn store(&self, matrix: RowMajorMatrix<F>) -> Self::Stored;

    /// Prepare the exact retained main masking layout from the continuing RNG.
    fn randomize<R>(
        &self,
        matrix: RowMajorMatrix<F>,
        random_columns: usize,
        rng: &mut R,
    ) -> Self::Stored
    where
        F: p3_field::Field,
        R: Rng + Send + Sync,
        StandardUniform: Distribution<F>,
    {
        let width = matrix.width();
        let mut randomized = matrix.with_random_cols(width + 2 * random_columns, rng);
        randomized.width = width + random_columns;
        self.store(randomized)
    }

    /// Dense compatibility remains explicit for policies without a source view.
    fn extend_prepared<Dft, M>(
        &self,
        dft: &Dft,
        evaluations: M,
        log_blowup: usize,
        shift: F,
    ) -> Self::Stored
    where
        F: TwoAdicField,
        Dft: TwoAdicSubgroupDft<F>,
        M: Matrix<F>,
    {
        self.extend(dft, evaluations.to_row_major_matrix(), log_blowup, shift)
    }

    /// The default construction is the retained dense DFT and bit reversal.
    /// A storage policy may construct the same values without a full LDE buffer.
    fn extend<Dft>(
        &self,
        dft: &Dft,
        evaluations: RowMajorMatrix<F>,
        log_blowup: usize,
        shift: F,
    ) -> Self::Stored
    where
        F: TwoAdicField,
        Dft: TwoAdicSubgroupDft<F>,
    {
        self.store(
            dft.coset_lde_batch(evaluations, log_blowup, shift)
                .bit_reverse_rows()
                .to_row_major_matrix(),
        )
    }

    /// Construct the supplied coupled quotient mask without sampling entropy.
    fn extend_quotient<Dft>(
        &self,
        dft: &Dft,
        evaluations: RowMajorMatrix<F>,
        masks: &[F],
        log_blowup: usize,
        shift: F,
    ) -> Self::Stored
    where
        F: TwoAdicField,
        Dft: TwoAdicSubgroupDft<F>,
    {
        self.store(masked_quotient_lde(
            dft,
            evaluations,
            masks,
            log_blowup,
            shift,
        ))
    }
}

/// Retained dense coefficient calculation for an already coupled mask.
pub(crate) fn masked_quotient_lde<F: TwoAdicField, Dft: TwoAdicSubgroupDft<F>>(
    dft: &Dft,
    evaluations: RowMajorMatrix<F>,
    masks: &[F],
    log_blowup: usize,
    shift: F,
) -> RowMajorMatrix<F> {
    let h = evaluations.height();
    let w = evaluations.width();
    assert_eq!(masks.len(), h * w);
    let mut coefficients = dft.coset_idft_batch(evaluations, shift.inverse()).values;
    coefficients.resize((h * w) << (log_blowup + 1), F::ZERO);
    let p = shift.exp_u64(h as u64);
    F::GENERATOR
        .powers()
        .take(h)
        .enumerate()
        .for_each(|(i, power)| {
            for column in 0..w {
                let value = power * masks[i * w + column];
                coefficients[i * w + column] -= value;
                coefficients[(h + i) * w + column] += p * value;
            }
        });
    dft.dft_batch(RowMajorMatrix::new(coefficients, w))
        .bit_reverse_rows()
        .to_row_major_matrix()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DenseStore;

impl<F: Clone + Send + Sync + 'static> MatrixStore<F> for DenseStore {
    type Stored = RowMajorMatrix<F>;

    fn store(&self, matrix: RowMajorMatrix<F>) -> Self::Stored {
        matrix
    }
}

/// A physical row prefix. No bit reversal or column truncation occurs here.
pub struct RowPrefix<'a, M> {
    matrix: &'a M,
    height: usize,
}

impl<'a, M> RowPrefix<'a, M> {
    pub fn new<F: Clone + Send + Sync>(matrix: &'a M, height: usize) -> Self
    where
        M: Matrix<F>,
    {
        assert!(height > 0 && height <= matrix.height());
        Self { matrix, height }
    }
}

impl<F: Clone + Send + Sync, M: Matrix<F>> Matrix<F> for RowPrefix<'_, M> {
    fn width(&self) -> usize {
        self.matrix.width()
    }

    fn height(&self) -> usize {
        self.height
    }

    // The trait declaration is unsafe. The body checks its own row boundary
    // and delegates to the checked public row interface without unsafe calls.
    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = F, IntoIter = impl Iterator<Item = F> + Send + Sync> {
        assert!(row < self.height);
        self.matrix
            .row(row)
            .expect("checked prefix row")
            .into_iter()
            .collect::<Vec<_>>()
    }
}

/// A borrowed prefix or the retained owned alternate-domain calculation.
pub enum DomainMatrix<'a, F, M> {
    Prefix(RowPrefix<'a, M>),
    Owned(RowMajorMatrix<F>),
}

impl<F: Clone + Send + Sync, M: Matrix<F>> Matrix<F> for DomainMatrix<'_, F, M> {
    fn width(&self) -> usize {
        match self {
            Self::Prefix(m) => m.width(),
            Self::Owned(m) => m.width(),
        }
    }

    fn height(&self) -> usize {
        match self {
            Self::Prefix(m) => m.height(),
            Self::Owned(m) => m.height(),
        }
    }

    // Every returned row is owned. No row borrows a released storage guard.
    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = F, IntoIter = impl Iterator<Item = F> + Send + Sync> {
        assert!(row < self.height());
        match self {
            Self::Prefix(m) => m
                .row(row)
                .expect("checked domain row")
                .into_iter()
                .collect::<Vec<_>>(),
            Self::Owned(m) => m
                .row(row)
                .expect("checked domain row")
                .into_iter()
                .collect::<Vec<_>>(),
        }
    }
}
