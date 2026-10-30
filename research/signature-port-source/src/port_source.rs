//! Actual final prefix followed by clock and packed source words.
use super::{
    decoder_state::DecodeError,
    final_source::{FinalSource, SourceError as PrefixError},
    hash_source::Generation,
    matrix_overlay::MatrixGeneration,
    port_state::{PortError, PortState},
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
    Kernel(PortError),
}
impl core::fmt::Display for SourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Upstream(e) => write!(f, "upstream construction failure: {e:?}"),
            Self::Kernel(e) => write!(f, "packed source construction failure: {e:?}"),
            e => write!(f, "{e:?}"),
        }
    }
}
pub(crate) struct PortSource<'a> {
    prefix: FinalSource<'a>,
    kernel: PortState<'a>,
    next_row: usize,
    upstream_rows: usize,
    failed: bool,
    baseline: Vec<BabyBear>,
    preserved: usize,
}
impl<'a> PortSource<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Result<Self, DecodeError> {
        Ok(Self {
            prefix: FinalSource::new(inputs)?,
            kernel: PortState::new(inputs),
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
    pub(crate) fn final_generation(&self) -> super::final_state::FinalGeneration {
        self.prefix.final_generation()
    }
    pub(crate) fn preserved(&self) -> usize {
        self.preserved
    }
    pub(crate) fn prefix_preserved(&self) -> [usize; 7] {
        let inherited = self.prefix.prefix_preserved();
        [
            self.prefix.preserved(),
            inherited[0],
            inherited[1],
            inherited[2],
            inherited[3],
            inherited[4],
            inherited[5],
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
            if !PortState::owns(column) {
                assert_eq!(
                    actual, before,
                    "packed source changed prefix at row {at}, column {column}"
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
