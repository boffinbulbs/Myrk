//! Private matrix sampling and point accumulation from the actual row.
use crate::{build, full_program as fp, layout::*, mul, ntt};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
#[derive(Debug)]
pub(crate) enum MatrixAccumulatorError {
    RowShape,
    Exhausted,
    Incomplete,
    TerminalFailure,
    UnsupportedMatrixClass {
        row: usize,
        accepted: usize,
        cursor: u32,
    },
}
pub(crate) struct MatrixAccumulatorState {
    acc: [u32; 2048],
    count: usize,
    cursor: u32,
    next_row: usize,
    failed: bool,
}
impl MatrixAccumulatorState {
    pub(crate) fn new() -> Self {
        Self {
            acc: [0; 2048],
            count: 0,
            cursor: 0,
            next_row: 0,
            failed: false,
        }
    }
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn emit_next(
        &mut self,
        row: &mut [BabyBear],
    ) -> Result<usize, MatrixAccumulatorError> {
        if self.failed {
            return Err(MatrixAccumulatorError::TerminalFailure);
        }
        if row.len() != WIDTH {
            return Err(MatrixAccumulatorError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(MatrixAccumulatorError::Exhausted);
        }
        let at = self.next_row;
        row[MATRIX_COUNT..USE_HINT].fill(BabyBear::ZERO);
        row[ACTIVE_MATRIX..ACTIVE_MATRIX + 8].fill(BabyBear::ZERO);
        for (i, v) in self.acc.iter().enumerate() {
            row[ACCUMULATOR + i] = BabyBear::from_u32(*v);
        }
        let mut counts = [self.count; 9];
        let mut cursors = [self.cursor; 9];
        let mut candidates = [0u32; 8];
        let mut slacks = [0u32; 8];
        let mut takes = [false; 8];
        let mut products = [ntt::product(0, 0); 8];
        let mut writes = [0u32; 16];
        let mut flags = [false; 16];
        for s in 0..8 {
            counts[s + 1] = counts[s];
            cursors[s + 1] = cursors[s];
            if let Some((i, j, local)) = fp::matrix(at) {
                if local >= 6 {
                    let k = counts[s];
                    let mut y = 0;
                    if k < 256 {
                        let offset = 24 * (local - 6) + 3 * s;
                        let raw = core::array::from_fn::<u8, 3, _>(|n| {
                            row[MATRIX_XOF + offset + n].as_canonical_u32() as u8
                        });
                        let raw24 = u32::from(raw[0])
                            + (u32::from(raw[1]) << 8)
                            + (u32::from(raw[2]) << 16);
                        candidates[s] = raw24;
                        let a = raw24 & 0x7fffff;
                        let take = a < mul::MODULUS;
                        slacks[s] = if take {
                            mul::MODULUS - 1 - a
                        } else {
                            a - mul::MODULUS
                        };
                        takes[s] = take;
                        counts[s + 1] += usize::from(take);
                        cursors[s + 1] += 3;
                        y = row[output_column(j, k)].as_canonical_u32();
                        writes[2 * s] = self.acc[256 * i + k];
                        if take {
                            row[MATRIX_ENABLE + 8 * i + s] = BabyBear::ONE;
                        }
                    }
                    products[s] = ntt::product(
                        if takes[s] {
                            candidates[s] & 0x7fffff
                        } else {
                            0
                        },
                        y,
                    );
                    let sum = writes[2 * s] + products[s].values[3];
                    let carry = sum >= mul::MODULUS;
                    writes[2 * s + 1] = sum - if carry { mul::MODULUS } else { 0 };
                    flags[2 * s] = carry;
                    if takes[s] {
                        self.acc[256 * i + k] = writes[2 * s + 1];
                    }
                }
            } else if let Some((i, g)) = fp::point(at) {
                let k = 8 * g + s;
                products[s] = ntt::product(
                    row[output_column(7, k)].as_canonical_u32(),
                    row[output_column(8 + i, k)].as_canonical_u32(),
                );
                let old = self.acc[256 * i + k];
                let product = products[s].values[3];
                let borrow = old < product;
                writes[2 * s] = old;
                writes[2 * s + 1] = (u64::from(old)
                    + if borrow { u64::from(mul::MODULUS) } else { 0 }
                    - u64::from(product)) as u32;
                flags[2 * s] = borrow;
                self.acc[256 * i + k] = writes[2 * s + 1];
            }
        }
        for state in 0..9 {
            row[MATRIX_COUNT + state * 257 + counts[state]] = BabyBear::ONE;
            build::bits(row, MATRIX_CURSOR + state * 10, cursors[state], 10);
        }
        for s in 0..8 {
            build::bits(row, MATRIX_CANDIDATE + 24 * s, candidates[s], 24);
            build::bits(row, MATRIX_SLACK + 23 * s, slacks[s], 23);
            row[MATRIX_TAKE + s] = BabyBear::from_bool(takes[s]);
            ntt::encode_product(
                products[s],
                &mut row[EXTRA_PRODUCTS + s * mul::WIDTH..EXTRA_PRODUCTS + (s + 1) * mul::WIDTH],
            );
        }
        for s in 0..16 {
            ntt::encode_write(
                writes[s],
                &mut row[EXTRA_WRITES + 46 * s..EXTRA_WRITES + 46 * (s + 1)],
            );
            row[EXTRA_FLAGS + s] = BabyBear::from_bool(flags[s]);
        }
        self.count = counts[8];
        self.cursor = cursors[8];
        if let Some((_, _, local)) = fp::matrix(at) {
            if local == 47 {
                if self.count != 256 {
                    self.failed = true;
                    return Err(MatrixAccumulatorError::UnsupportedMatrixClass {
                        row: at,
                        accepted: self.count,
                        cursor: self.cursor,
                    });
                }
                if at + 1 < fp::MATRIX_END {
                    self.count = 0;
                    self.cursor = 0;
                }
            }
        }

        // Activity uses the emitted pre-decision count, never the final counter.
        let phase = fp::matrix(at).is_some_and(|(_, _, local)| local >= 6);
        for s in 0..8 {
            row[ACTIVE_MATRIX + s] =
                BabyBear::from_bool(phase) * (BabyBear::ONE - row[MATRIX_COUNT + 257 * s + 256]);
        }
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), MatrixAccumulatorError> {
        if self.failed {
            return Err(MatrixAccumulatorError::TerminalFailure);
        }
        if self.next_row != HEIGHT || self.count != 256 {
            return Err(MatrixAccumulatorError::Incomplete);
        }
        Ok(())
    }
}
