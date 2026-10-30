//! Partial initial hash source constructor with one bounded logical cache.
use super::{absorb, bits, copy_rounds, message, permutation, state_after, HashBanks};
use crate::{layout::*, program, BoundInputs};
use core::borrow::Borrow;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::KeccakCols;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

#[derive(Debug)]
pub(crate) enum HashError {
    RowShape,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct Generation {
    pub attempted: usize,
    pub completed: usize,
    pub maximum_live: usize,
}

pub(crate) struct SourceHashState<'a> {
    inputs: &'a BoundInputs,
    next_row: usize,
    banks: HashBanks,
    state: [u64; 25],
    input: [u8; 168],
    logical: Option<RowMajorMatrix<BabyBear>>,
    generation: Generation,
}

impl<'a> SourceHashState<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Self {
        Self {
            inputs,
            next_row: 0,
            banks: HashBanks::new(),
            state: [0; 25],
            input: [0; 168],
            logical: None,
            generation: Generation::default(),
        }
    }
    pub(crate) fn generation(&self) -> Generation {
        self.generation
    }

    fn generate(&mut self, input: [u64; 25]) {
        // A previous block must be dropped before allocating its replacement.
        assert!(self.logical.is_none());
        self.generation.attempted += 1;
        let logical = permutation(input);
        self.generation.completed += 1;
        self.logical = Some(logical);
        self.generation.maximum_live = 1;
    }

    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, HashError> {
        if row.len() != WIDTH {
            return Err(HashError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(HashError::Exhausted);
        }
        let at = self.next_row;
        if at < program::SOURCE_END && at.is_multiple_of(6) {
            assert!(self.logical.is_none());
            let hash = program::hash(at / 6).unwrap();
            if hash.block == 0 {
                self.state = [0; 25];
            }
            self.input = message(
                &self.inputs._witness,
                &self.inputs.statement,
                &self.banks.tr,
                at / 6,
            );
            absorb(&mut self.state, &self.input, hash.rate);
            self.generate(self.state);
        } else if at == program::SOURCE_END {
            assert!(self.logical.is_none());
            self.generate([0; 25]);
        }
        row[..CLOCK].fill(BabyBear::ZERO);
        row[MESSAGE..T1].fill(BabyBear::ZERO);
        let logical = self.logical.as_ref().unwrap();
        copy_rounds(row, logical, (at % 6) * 4);
        if at < program::SOURCE_END {
            let hash = program::hash(at / 6).unwrap();
            for (i, byte) in self.input.iter().enumerate() {
                bits(row, MESSAGE + 8 * i, u32::from(*byte), 8);
            }
            let round = logical.row_slice(4 * (at % 6) + 3).unwrap();
            let k: &KeccakCols<BabyBear> = (*round).borrow();
            let mut output = [0u8; 168];
            for limb in 0..hash.rate / 2 {
                let word = k
                    .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                    .as_canonical_u32();
                bits(row, OUTPUT + 16 * limb, word, 16);
                output[2 * limb..2 * limb + 2].copy_from_slice(&(word as u16).to_le_bytes());
            }
            drop(round);
            self.banks.write(row);
            self.banks.advance(&self.inputs._witness, at, hash, &output);
            if at % 6 == 5 {
                self.state = state_after(logical);
                drop(self.logical.take());
            }
        } else {
            // This genuine dummy baseline is replaced by later hash phases.
            self.banks.write(row);
        }
        self.next_row += 1;
        Ok(at)
    }
}
