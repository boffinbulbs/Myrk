//! Actual matrix prefix followed by private accumulation with terminal failure.
use super::{
    accumulator_state::{MatrixAccumulatorError, MatrixAccumulatorState},
    decoder_state::DecodeError,
    hash_source::Generation,
    matrix_overlay::MatrixGeneration,
    matrix_source::MatrixSource,
};
use crate::{full_program as fp, layout::*, BoundInputs};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
pub(crate) fn owned(column: usize) -> bool {
    (MATRIX_COUNT..USE_HINT).contains(&column)
        || (ACTIVE_MATRIX..ACTIVE_MATRIX + 8).contains(&column)
}
#[derive(Debug)]
pub(crate) enum SourceError {
    RowShape,
    Exhausted,
    Incomplete,
    Failed,
    UnsupportedMatrixClass {
        row: usize,
        accepted: usize,
        cursor: u32,
    },
}
pub(crate) struct AccumulatorSource<'a> {
    prefix: MatrixSource<'a>,
    kernel: MatrixAccumulatorState,
    next_row: usize,
    upstream_rows: usize,
    failed: bool,
    baseline: Vec<BabyBear>,
    preserved: usize,
}
impl<'a> AccumulatorSource<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Result<Self, DecodeError> {
        let prefix = MatrixSource::new(inputs)?;
        Ok(Self {
            prefix,
            kernel: MatrixAccumulatorState::new(),
            next_row: 0,
            upstream_rows: 0,
            failed: false,
            baseline: vec![BabyBear::ZERO; WIDTH],
            preserved: 0,
        })
    }
    pub(crate) fn initial_generation(&self) -> Generation {
        self.prefix.initial_generation()
    }
    pub(crate) fn matrix_generation(&self) -> MatrixGeneration {
        self.prefix.matrix_generation()
    }
    pub(crate) fn preserved(&self) -> usize {
        self.preserved
    }
    pub(crate) fn prefix_preserved(&self) -> [usize; 3] {
        [
            self.prefix.preserved(),
            self.prefix.forward_preserved(),
            self.prefix.initial_preserved(),
        ]
    }
    pub(crate) fn position(&self) -> (usize, usize, bool) {
        (self.next_row, self.upstream_rows, self.failed)
    }
    pub(crate) fn probe_failed_kernel(
        &mut self,
        row: &mut [BabyBear],
    ) -> (
        Result<usize, MatrixAccumulatorError>,
        Result<(), MatrixAccumulatorError>,
    ) {
        (self.kernel.emit_next(row), self.kernel.finish())
    }
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, SourceError> {
        self.emit(row, false)
    }
    // Fixed private fault control. This is not a genuine hash-derived input.
    pub(crate) fn emit_shortage_source_row(
        &mut self,
        row: &mut [BabyBear],
    ) -> Result<usize, SourceError> {
        self.emit(row, true)
    }
    fn emit(&mut self, row: &mut [BabyBear], shortage: bool) -> Result<usize, SourceError> {
        if self.failed {
            return Err(SourceError::Failed);
        }
        if row.len() != WIDTH {
            return Err(SourceError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(SourceError::Exhausted);
        }
        let at = self.next_row;
        assert_eq!(self.prefix.emit_next(row).unwrap(), at);
        self.upstream_rows += 1;
        if shortage && fp::matrix(at).is_some_and(|(i, j, l)| i == 0 && j == 0 && l >= 6) {
            row[MATRIX_XOF..MATRIX_XOF + 1008].fill(BabyBear::from_u8(255));
        }
        self.baseline.copy_from_slice(row);
        match self.kernel.emit_next(row) {
            Ok(pc) => assert_eq!(pc, at),
            Err(MatrixAccumulatorError::UnsupportedMatrixClass {
                row,
                accepted,
                cursor,
            }) => {
                self.failed = true;
                return Err(SourceError::UnsupportedMatrixClass {
                    row,
                    accepted,
                    cursor,
                });
            }
            Err(e) => {
                self.failed = true;
                panic!("unexpected accumulator cursor error: {e:?}");
            }
        }
        for (column, (actual, before)) in row.iter().zip(&self.baseline).enumerate() {
            if !owned(column) {
                assert_eq!(
                    actual, before,
                    "accumulator changed source at row {at}, column {column}"
                );
                self.preserved += 1;
            }
        }
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), SourceError> {
        if self.failed {
            return Err(SourceError::Failed);
        }
        if self.next_row != HEIGHT {
            return Err(SourceError::Incomplete);
        }
        self.prefix
            .finish()
            .expect("synchronized prefix completion");
        self.kernel
            .finish()
            .expect("synchronized accumulator completion");
        Ok(())
    }
}
