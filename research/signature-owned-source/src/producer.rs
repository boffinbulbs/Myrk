//! Current-row decoding state extracted from the retained constructor.
//! Only the decoding column interval is written. This is not a full row source.
use crate::build::{bits, BuildError};
use crate::{layout::*, packing, BoundInputs, Witness, MODULUS};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

use super::decode as reference;

#[derive(Debug)]
pub(crate) enum DecodeError {
    Encoding(BuildError),
    RowShape,
    Exhausted,
}

pub(crate) struct DecodeState<'a> {
    witness: &'a Witness,
    cuts: [usize; 8],
    t1: [u32; 2048],
    z: [u32; 1792],
    hints: [[bool; 256]; 8],
    last: [usize; 8],
    seen: [bool; 8],
    next_row: usize,
}

fn word5(bytes: &[u8]) -> u64 {
    let mut encoded = [0u8; 8];
    encoded[..5].copy_from_slice(bytes);
    u64::from_le_bytes(encoded)
}

impl<'a> DecodeState<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Result<Self, DecodeError> {
        let witness = &inputs._witness;
        reference::preflight(witness).map_err(DecodeError::Encoding)?;
        Ok(Self {
            witness,
            cuts: core::array::from_fn(|i| usize::from(witness.signature[4619 + i])),
            t1: [0; 2048],
            z: [0; 1792],
            hints: [[false; 256]; 8],
            last: [0; 8],
            seen: [false; 8],
            next_row: 0,
        })
    }

    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, DecodeError> {
        if row.len() != WIDTH {
            return Err(DecodeError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(DecodeError::Exhausted);
        }
        let at = self.next_row;
        let w = self.witness;
        let cuts = self.cuts;
        // Zero every owned dormant auxiliary, preserving all other families.
        row[T1..SIGN_BITS].fill(BabyBear::ZERO);
        for (i, value) in self.t1.iter().enumerate() {
            row[T1 + i] = BabyBear::from_u32(*value);
        }
        for (i, value) in self.z.iter().enumerate() {
            row[Z_VALUES + i] = BabyBear::from_u32(*value);
        }
        for i in 0..8 {
            bits(row, CUTS + 7 * i, cuts[i] as u32, 7);
            bits(row, CUT_COMPLEMENTS + 7 * i, (75 - cuts[i]) as u32, 7);
            if i > 0 {
                bits(
                    row,
                    CUT_DIFFERENCES + 7 * (i - 1),
                    (cuts[i] - cuts[i - 1]) as u32,
                    7,
                );
            }
            bits(row, LAST + 8 * i, self.last[i] as u32, 8);
            row[SEEN + i] = BabyBear::from_bool(self.seen[i]);
            for k in 0..256 {
                row[HINTS + 256 * i + k] = BabyBear::from_bool(self.hints[i][k]);
            }
        }
        if at < 256 {
            let source = &w.key[32 + 10 * at..32 + 10 * at + 10];
            for (i, byte) in source.iter().enumerate() {
                bits(row, T1_MESSAGE + 8 * i, u32::from(*byte), 8);
            }
            for window in 0..2 {
                let encoded = word5(&source[5 * window..5 * window + 5]);
                for coefficient in 0..4 {
                    self.t1[8 * at + 4 * window + coefficient] =
                        ((encoded >> (10 * coefficient)) & 1023) as u32;
                }
            }
        }
        if at < 448 {
            let source = &w.signature[64 + 10 * at..64 + 10 * at + 10];
            for (i, byte) in source.iter().enumerate() {
                bits(row, Z_MESSAGE + 8 * i, u32::from(*byte), 8);
            }
            for window in 0..2 {
                let encoded = word5(&source[5 * window..5 * window + 5]);
                let base = Z_AUX + window * packing::Z_AUX_WIDTH;
                for coefficient in 0..2 {
                    let d = ((encoded >> (20 * coefficient)) & 0xfffff) as u32;
                    let normal = (524_288i64 - i64::from(d)).rem_euclid(i64::from(MODULUS)) as u32;
                    bits(row, base + packing::LOWER + 20 * coefficient, d - 121, 20);
                    bits(
                        row,
                        base + packing::UPPER + 20 * coefficient,
                        1_048_455 - d,
                        20,
                    );
                    bits(row, base + packing::NORMAL + 23 * coefficient, normal, 23);
                    bits(
                        row,
                        base + packing::COMPLEMENTS + 23 * coefficient,
                        MODULUS - 1 - normal,
                        23,
                    );
                    row[base + packing::NEGATIVE + coefficient] = BabyBear::from_bool(d > 524_288);
                    self.z[4 * at + 2 * window + coefficient] = normal;
                }
            }
        }
        if at < 75 {
            let index = usize::from(w.signature[4544 + at]);
            bits(row, HINT_MESSAGE, index as u32, 8);
            let active = at < cuts[7];
            row[HINT_ACTIVE] = BabyBear::from_bool(active);
            if active {
                bits(row, ACTIVE_UPPER, (cuts[7] - at - 1) as u32, 7);
            } else {
                bits(row, ACTIVE_LOWER, (at - cuts[7]) as u32, 7);
            }
            if active {
                let group = (0..8)
                    .find(|i| {
                        let previous = if *i == 0 { 0 } else { cuts[*i - 1] };
                        previous <= at && at < cuts[*i]
                    })
                    .unwrap();
                let previous = if group == 0 { 0 } else { cuts[group - 1] };
                row[GROUP + group] = BabyBear::ONE;
                row[ONE_HOT + index] = BabyBear::ONE;
                bits(row, SEGMENT_LOWER + 7 * group, (at - previous) as u32, 7);
                bits(
                    row,
                    SEGMENT_UPPER + 7 * group,
                    (cuts[group] - at - 1) as u32,
                    7,
                );
                if self.seen[group] {
                    bits(
                        row,
                        ORDER + 8 * group,
                        (index - self.last[group] - 1) as u32,
                        8,
                    );
                }
                self.last[group] = index;
                self.seen[group] = true;
                self.hints[group][index] = true;
            }
        }
        self.next_row += 1;
        Ok(at)
    }
}

// The unchanged retained loop is a bounded source-equivalence oracle only.
pub(crate) fn reference_prefix(inputs: &BoundInputs) -> Vec<BabyBear> {
    const ROWS: usize = 449;
    let mut values = vec![BabyBear::ZERO; ROWS * WIDTH];
    reference::fill(&mut values, &inputs._witness);
    values
}
