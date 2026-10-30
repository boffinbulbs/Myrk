//! Actual accumulator prefix followed by one private inverse cursor.
use super::{
    accumulator_source::{AccumulatorSource, SourceError as PrefixError},
    decoder_state::DecodeError,
    hash_source::Generation,
    inverse_state::{InverseError, InverseState},
    matrix_overlay::MatrixGeneration,
};
use crate::{layout::*, BoundInputs};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

#[derive(Debug)]
pub(crate) enum SourceError {
    RowShape,
    Exhausted,
    Incomplete,
    Failed,
    Upstream(PrefixError),
    Kernel(InverseError),
}
impl core::fmt::Display for SourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Upstream(e) => write!(f, "upstream construction failure: {e:?}"),
            Self::Kernel(e) => write!(f, "inverse construction failure: {e:?}"),
            e => write!(f, "{e:?}"),
        }
    }
}
pub(crate) struct InverseSource<'a> {
    prefix: AccumulatorSource<'a>,
    kernel: InverseState,
    next_row: usize,
    upstream_rows: usize,
    failed: bool,
    baseline: Vec<BabyBear>,
    preserved: usize,
}
impl<'a> InverseSource<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Result<Self, DecodeError> {
        Ok(Self {
            prefix: AccumulatorSource::new(inputs)?,
            kernel: InverseState::new(),
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
    pub(crate) fn prefix_preserved(&self) -> [usize; 4] {
        let inherited = self.prefix.prefix_preserved();
        [
            self.prefix.preserved(),
            inherited[0],
            inherited[1],
            inherited[2],
        ]
    }
    pub(crate) fn position(&self) -> (usize, usize, bool) {
        (self.next_row, self.upstream_rows, self.failed)
    }
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, SourceError> {
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
        match self.prefix.emit_next(row) {
            Ok(pc) => {
                assert_eq!(pc, at);
                self.upstream_rows += 1;
            }
            Err(e) => {
                self.failed = true;
                return Err(SourceError::Upstream(e));
            }
        }
        self.baseline.copy_from_slice(row);
        match self.kernel.emit_next(row) {
            Ok(pc) => assert_eq!(pc, at),
            Err(e) => {
                self.failed = true;
                return Err(SourceError::Kernel(e));
            }
        }
        for (column, (actual, before)) in row.iter().zip(&self.baseline).enumerate() {
            if !InverseState::owns(at, column) {
                assert_eq!(
                    actual, before,
                    "inverse changed source at row {at}, column {column}"
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
        self.prefix.finish().map_err(SourceError::Upstream)?;
        self.kernel.finish().map_err(SourceError::Kernel)
    }
}
