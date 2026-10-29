//! Input matrix representation without changes to proof or verifier fields.

use alloc::vec::Vec;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::TwoAdicField;
use p3_matrix::Matrix;
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;

/// A policy constructs and retains exact physically ordered LDE values.
/// It does not sample masks or change the commitment protocol.
pub trait MatrixStore<F: Clone + Send + Sync>: Clone + Send + Sync {
    type Stored: Matrix<F> + 'static;
    fn store(&self, matrix: RowMajorMatrix<F>) -> Self::Stored;

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
