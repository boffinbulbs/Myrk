//! Actual hint prefix followed by private final sponge construction.
use super::{
    decoder_state::DecodeError,
    final_state::{FinalError, FinalGeneration, FinalState},
    hash_source::Generation,
    hint_source::{HintSource, SourceError as PrefixError},
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
    Kernel(FinalError),
}
impl core::fmt::Display for SourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Upstream(e) => write!(f, "upstream construction failure: {e:?}"),
            Self::Kernel(e) => write!(f, "final sponge construction failure: {e:?}"),
            e => write!(f, "{e:?}"),
        }
    }
}
pub(crate) struct FinalSource<'a> {
    prefix: HintSource<'a>,
    kernel: FinalState,
    next_row: usize,
    upstream_rows: usize,
    failed: bool,
    baseline: Vec<BabyBear>,
    preserved: usize,
}
impl<'a> FinalSource<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Result<Self, DecodeError> {
        Ok(Self {
            prefix: HintSource::new(inputs)?,
            kernel: FinalState::new(),
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
    pub(crate) fn final_generation(&self) -> FinalGeneration {
        self.kernel.generation()
    }
    pub(crate) fn preserved(&self) -> usize {
        self.preserved
    }
    pub(crate) fn prefix_preserved(&self) -> [usize; 6] {
        let inherited = self.prefix.prefix_preserved();
        [
            self.prefix.preserved(),
            inherited[0],
            inherited[1],
            inherited[2],
            inherited[3],
            inherited[4],
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
                assert_eq!(self.prefix.position(), (at + 1, at + 1, false));
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
            if !FinalState::owns(at, column) {
                assert_eq!(
                    actual, before,
                    "final sponge changed source at row {at}, column {column}"
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
