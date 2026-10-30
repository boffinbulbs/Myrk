//! Private sampling state from the actual composed current row XOF.
use super::bits;
use crate::{layout::*, program, MODULUS};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

#[derive(Debug)]
pub(crate) enum SampleError {
    RowShape,
    Exhausted,
    Incomplete,
    UnsupportedChallengeClass,
}

pub(crate) struct SampleState {
    plus: [bool; 256],
    minus: [bool; 256],
    accepted: usize,
    cursor: u32,
    next_row: usize,
}
impl SampleState {
    pub(crate) fn new() -> Self {
        Self {
            plus: [false; 256],
            minus: [false; 256],
            accepted: 0,
            cursor: 8,
            next_row: 0,
        }
    }
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, SampleError> {
        if row.len() != WIDTH {
            return Err(SampleError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(SampleError::Exhausted);
        }
        let at = self.next_row;
        row[SIGN_BITS..INITIAL_WIDTH].fill(BabyBear::ZERO);
        for byte in 0..8 {
            let value = row[CHALLENGE_XOF + byte].as_canonical_u32();
            bits(row, SIGN_BITS + 8 * byte, value, 8);
        }
        row[COUNT + self.accepted] = BabyBear::ONE;
        bits(row, CURSOR, self.cursor, 9);
        for i in 0..256 {
            row[PLUS + i] = BabyBear::from_bool(self.plus[i]);
            row[MINUS + i] = BabyBear::from_bool(self.minus[i]);
            // This is 0,1,q-1 in BabyBear, never BabyBear's own -1.
            row[CHALLENGE + i] = BabyBear::from_u32(
                u32::from(self.plus[i]) + u32::from(self.minus[i]) * (MODULUS - 1),
            );
        }
        if (program::SAMPLE_START..program::SAMPLE_END).contains(&at) && self.accepted < 60 {
            let candidate = row[CHALLENGE_XOF + 8 + at - program::SAMPLE_START].as_canonical_u32();
            let destination = 196 + self.accepted;
            bits(row, CANDIDATE, candidate, 8);
            if (candidate as usize) <= destination {
                let index = candidate as usize;
                row[TAKE] = BabyBear::ONE;
                bits(row, LOWER, (destination - index) as u32, 8);
                row[INDEX + index] = BabyBear::ONE;
                row[OLD_PLUS] = BabyBear::from_bool(self.plus[index]);
                row[OLD_MINUS] = BabyBear::from_bool(self.minus[index]);
                let negative = (row[CHALLENGE_XOF + self.accepted / 8].as_canonical_u32()
                    >> (self.accepted % 8))
                    & 1
                    != 0;
                let old_plus = self.plus[index];
                let old_minus = self.minus[index];
                self.plus[destination] = old_plus;
                self.minus[destination] = old_minus;
                self.plus[index] = !negative;
                self.minus[index] = negative;
                self.accepted += 1;
            } else {
                bits(row, UPPER, candidate - destination as u32 - 1, 8);
            }
            self.cursor += 1;
        }

        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), SampleError> {
        if self.next_row != HEIGHT {
            return Err(SampleError::Incomplete);
        }
        if self.accepted != 60 {
            return Err(SampleError::UnsupportedChallengeClass);
        }
        Ok(())
    }
}
