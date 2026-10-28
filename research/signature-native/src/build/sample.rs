//! Private q-normal SampleInBall registers and exact consumed byte cursor.
use super::bits;
use crate::{layout::*, program, MODULUS};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

pub(super) fn fill(values: &mut [BabyBear]) {
    let mut plus = [false; 256];
    let mut minus = [false; 256];
    let mut accepted = 0;
    let mut cursor = 8;
    for (at, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        for byte in 0..8 {
            let value = row[CHALLENGE_XOF + byte].as_canonical_u32();
            bits(row, SIGN_BITS + 8 * byte, value, 8);
        }
        row[COUNT + accepted] = BabyBear::ONE;
        bits(row, CURSOR, cursor, 9);
        for i in 0..256 {
            row[PLUS + i] = BabyBear::from_bool(plus[i]);
            row[MINUS + i] = BabyBear::from_bool(minus[i]);
            // This is 0,1,q-1 in BabyBear, never BabyBear's own -1.
            row[CHALLENGE + i] =
                BabyBear::from_u32(u32::from(plus[i]) + u32::from(minus[i]) * (MODULUS - 1));
        }
        if (program::SAMPLE_START..program::SAMPLE_END).contains(&at) && accepted < 60 {
            let candidate = row[CHALLENGE_XOF + 8 + at - program::SAMPLE_START].as_canonical_u32();
            let destination = 196 + accepted;
            bits(row, CANDIDATE, candidate, 8);
            if (candidate as usize) <= destination {
                let index = candidate as usize;
                row[TAKE] = BabyBear::ONE;
                bits(row, LOWER, (destination - index) as u32, 8);
                row[INDEX + index] = BabyBear::ONE;
                row[OLD_PLUS] = BabyBear::from_bool(plus[index]);
                row[OLD_MINUS] = BabyBear::from_bool(minus[index]);
                let negative =
                    (row[CHALLENGE_XOF + accepted / 8].as_canonical_u32() >> (accepted % 8)) & 1
                        != 0;
                let old_plus = plus[index];
                let old_minus = minus[index];
                plus[destination] = old_plus;
                minus[destination] = old_minus;
                plus[index] = !negative;
                minus[index] = negative;
                accepted += 1;
            } else {
                bits(row, UPPER, candidate - destination as u32 - 1, 8);
            }
            cursor += 1;
        }
    }
    assert_eq!(
        accepted, 60,
        "Preflight and actual source challenge class disagree"
    );
}
