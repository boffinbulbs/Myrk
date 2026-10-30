//! Concrete block destination adaptation of the retained initial source pass.
//! This diagnostic oracle has independent banks and never accepts a witness.
use super::hash_source::Generation;
use super::{absorb, bits, copy_rounds, message, permutation, state_after, HashBanks};
use crate::{layout::*, program, BoundInputs};
use core::borrow::Borrow;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::KeccakCols;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

pub(crate) struct ReferenceBlock<'a> {
    inputs: &'a BoundInputs,
    banks: HashBanks,
    state: [u64; 25],
    values: Vec<BabyBear>,
    zero: Option<RowMajorMatrix<BabyBear>>,
    next_start: usize,
    current_start: usize,
    current_rows: usize,
    generation: Generation,
    prepared_rows: usize,
    prepared_blocks: usize,
}
impl<'a> ReferenceBlock<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Self {
        Self {
            inputs,
            banks: HashBanks::new(),
            state: [0; 25],
            values: vec![BabyBear::ZERO; 6 * WIDTH],
            zero: None,
            next_start: 0,
            current_start: 0,
            current_rows: 0,
            generation: Generation::default(),
            prepared_rows: 0,
            prepared_blocks: 0,
        }
    }
    pub(crate) fn generation(&self) -> Generation {
        self.generation
    }
    pub(crate) fn prepared(&self) -> [usize; 2] {
        [self.prepared_rows, self.prepared_blocks]
    }
    pub(crate) fn prepare(&mut self, start: usize) {
        assert_eq!(start, self.next_start);
        assert!(start < HEIGHT && start.is_multiple_of(6));
        self.values.fill(BabyBear::ZERO);
        self.current_start = start;
        self.current_rows = (HEIGHT - start).min(6);
        let w = &self.inputs._witness;
        let s = &self.inputs.statement;
        if start < program::SOURCE_END {
            let permutation_index = start / 6;
            let hash = program::hash(permutation_index).unwrap();
            if hash.block == 0 {
                self.state = [0; 25];
            }
            let input = message(w, s, &self.banks.tr, permutation_index);
            absorb(&mut self.state, &input, hash.rate);
            self.generation.attempted += 1;
            let logical = permutation(self.state);
            self.generation.completed += 1;
            self.generation.maximum_live = 1;
            for local_row in 0..6 {
                let global = 6 * permutation_index + local_row;
                // Only the physical destination changes from the old writer.
                let row = &mut self.values[local_row * WIDTH..(local_row + 1) * WIDTH];
                copy_rounds(row, &logical, 4 * local_row);
                for (i, byte) in input.iter().enumerate() {
                    bits(row, MESSAGE + 8 * i, u32::from(*byte), 8);
                }
                let round = logical.row_slice(4 * local_row + 3).unwrap();
                let k: &KeccakCols<BabyBear> = (*round).borrow();
                let mut output = [0u8; 168];
                for limb in 0..hash.rate / 2 {
                    let word = k
                        .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32();
                    bits(row, OUTPUT + 16 * limb, word, 16);
                    output[2 * limb..2 * limb + 2].copy_from_slice(&(word as u16).to_le_bytes());
                }
                self.banks.write(row);
                self.banks.advance(w, global, hash, &output);
                self.prepared_rows += 1;
            }
            self.state = state_after(&logical);
            drop(logical);
        } else {
            if self.zero.is_none() {
                self.generation.attempted += 1;
                let zero = permutation([0; 25]);
                self.generation.completed += 1;
                self.generation.maximum_live = 1;
                self.zero = Some(zero);
            }
            for local_row in 0..self.current_rows {
                let global = start + local_row;
                let row = &mut self.values[local_row * WIDTH..(local_row + 1) * WIDTH];
                copy_rounds(row, self.zero.as_ref().unwrap(), (global % 6) * 4);
                self.banks.write(row);
                self.prepared_rows += 1;
            }
        }
        self.next_start = start + self.current_rows;
        self.prepared_blocks += 1;
    }
    pub(crate) fn row(&self, global: usize) -> &[BabyBear] {
        assert!((self.current_start..self.current_start + self.current_rows).contains(&global));
        let local = global - self.current_start;
        &self.values[local * WIDTH..(local + 1) * WIDTH]
    }
}
