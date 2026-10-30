//! Private clock stamping and unchanged bounded source word/port writer.
use crate::{layout::*, packed, BoundInputs, Witness};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

#[derive(Debug)]
pub(crate) enum PortError {
    RowShape,
    Exhausted,
    Incomplete,
}
pub(crate) struct PortState<'a> {
    witness: &'a Witness,
    next_row: usize,
}
impl<'a> PortState<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Self {
        Self {
            witness: &inputs._witness,
            next_row: 0,
        }
    }
    pub(crate) fn owns(column: usize) -> bool {
        (CLOCK..MESSAGE).contains(&column)
    }
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, PortError> {
        if row.len() != WIDTH {
            return Err(PortError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(PortError::Exhausted);
        }
        let at = self.next_row;
        row[CLOCK..KEY].fill(BabyBear::ZERO);
        row[CLOCK + at % CLOCK_LOW] = BabyBear::ONE;
        row[CLOCK + CLOCK_LOW + at / CLOCK_LOW] = BabyBear::ONE;
        // The original row helper rewrites every word and clears unused ports.
        packed::fill(row, at, self.witness);
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), PortError> {
        if self.next_row != HEIGHT {
            return Err(PortError::Incomplete);
        }
        Ok(())
    }
}
