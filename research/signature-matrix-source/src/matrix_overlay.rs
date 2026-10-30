//! Private matrix hash and squeeze overlay over the same current source row.
use super::{absorb, bits, copy_rounds, permutation, state_after};
use crate::{
    full_program::{self as fp, Byte, Hash},
    layout::*,
};
use core::borrow::Borrow;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::KeccakCols;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MatrixGeneration {
    pub attempted: usize,
    pub completed: usize,
    pub maximum_live: usize,
}
#[derive(Debug)]
pub(crate) enum MatrixError {
    RowShape,
    Exhausted,
    Incomplete,
}
pub(crate) struct MatrixOverlay {
    next_row: usize,
    state: [u64; 25],
    input: [u8; 168],
    bank: [u8; 1008],
    logical: Option<RowMajorMatrix<BabyBear>>,
    generation: MatrixGeneration,
}
impl MatrixOverlay {
    pub(crate) fn new() -> Self {
        Self {
            next_row: 0,
            state: [0; 25],
            input: [0; 168],
            bank: [0; 1008],
            logical: None,
            generation: MatrixGeneration::default(),
        }
    }
    pub(crate) fn generation(&self) -> MatrixGeneration {
        self.generation
    }
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, MatrixError> {
        if row.len() != WIDTH {
            return Err(MatrixError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(MatrixError::Exhausted);
        }
        let at = self.next_row;
        // Current bank is visible before a terminal output is latched.
        for (i, &byte) in self.bank.iter().enumerate() {
            row[MATRIX_XOF + i] = BabyBear::from_u8(byte);
        }
        if let Some((i, j, local)) = fp::matrix(at) {
            if local < 36 {
                if local.is_multiple_of(6) {
                    assert!(self.logical.is_none());
                    let hash = Hash::Matrix {
                        row: i,
                        column: j,
                        block: local / 6,
                    };
                    if fp::fresh(hash) {
                        self.state = [0; 25];
                    }
                    self.input = core::array::from_fn(|byte| match fp::message(hash, byte) {
                        Byte::Fixed(v) => v,
                        Byte::Rho(k) => row[RHO + k]
                            .as_canonical_u32()
                            .try_into()
                            .expect("current RHO byte"),
                        _ => {
                            unreachable!("Matrix scope accepts fixed and current RHO sources only")
                        }
                    });
                    absorb(&mut self.state, &self.input, fp::rate(hash));
                    self.generation.attempted += 1;
                    self.logical = Some(permutation(self.state));
                    self.generation.completed += 1;
                    self.generation.maximum_live = 1;
                }
                let logical = self.logical.as_ref().unwrap();
                // Replace only matrix hash columns, preserving all source banks.
                row[..CLOCK].fill(BabyBear::ZERO);
                row[MESSAGE..RHO].fill(BabyBear::ZERO);
                copy_rounds(row, logical, 4 * (local % 6));
                for (byte, &value) in self.input.iter().enumerate() {
                    bits(row, MESSAGE + 8 * byte, u32::from(value), 8);
                }
                {
                    let round = logical.row_slice(4 * (local % 6) + 3).unwrap();
                    let k: &KeccakCols<BabyBear> = (*round).borrow();
                    for limb in 0..84 {
                        let word = k
                            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                            .as_canonical_u32();
                        bits(row, OUTPUT + 16 * limb, word, 16);
                    }
                }
                if local % 6 == 5 {
                    self.state = state_after(logical);
                    drop(self.logical.take());
                    for byte in 0..168 {
                        let value: u32 = (0..8)
                            .map(|b| row[OUTPUT + 8 * byte + b].as_canonical_u32() << b)
                            .sum();
                        self.bank[(local / 6) * 168 + byte] =
                            value.try_into().expect("current OUTPUT byte");
                    }
                }
            }
            if local == 47 {
                self.bank = [0; 1008];
            }
        }
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), MatrixError> {
        if self.next_row != HEIGHT || self.logical.is_some() || self.generation.completed != 336 {
            return Err(MatrixError::Incomplete);
        }
        Ok(())
    }
}
