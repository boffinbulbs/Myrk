use crate::reconstructed_row::air::*;
use core::borrow::Borrow;
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};

pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    eval_lifetime(builder);
    let main = builder.main();
    let row = main.current_slice();
    let next = main.next_slice();
    let public = builder.public_values().to_vec();
    let first: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();
    let last: &KeccakCols<AB::Var> = row[3 * NUM_KECCAK_COLS..4 * NUM_KECCAK_COLS].borrow();
    let next_first: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
    let initial = sum_clock::<AB>(row, (0..7).flat_map(|c| c * 42..c * 42 + 6));
    let active_hash = sum_clock::<AB>(row, (0..7).flat_map(|c| c * 42..c * 42 + 36));
    for bit in &row[MESSAGE..RHO] {
        builder.assert_bool(*bit);
    }
    for byte in 0..168 {
        let expected = match byte {
            0..=31 => initial.clone() * row[RHO + byte],
            32 => (0..7)
                .map(|c| sum_clock::<AB>(row, c * 42..c * 42 + 6) * BabyBear::from_usize(c))
                .sum(),
            33 => initial.clone() * Into::<AB::Expr>::into(public[0]),
            34 => initial.clone() * BabyBear::from_u8(31),
            167 => initial.clone() * BabyBear::from_u8(128),
            _ => AB::Expr::ZERO,
        };
        builder.assert_eq(
            packed::<AB>(&row[MESSAGE + byte * 8..MESSAGE + (byte + 1) * 8]),
            expected,
        );
    }
    for limb in 0..100 {
        if limb < 84 {
            let output = packed::<AB>(&row[OUTPUT + limb * 16..OUTPUT + (limb + 1) * 16]);
            builder.when(active_hash.clone()).assert_eq(
                output,
                last.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
            );
        }
        let preimage = if limb < 84 {
            packed::<AB>(&row[MESSAGE + limb * 16..MESSAGE + (limb + 1) * 16])
        } else {
            AB::Expr::ZERO
        };
        let starts = sum_clock::<AB>(row, (0..7).map(|c| c * 42));
        builder.when(starts).assert_eq(
            first.preimage[limb / 20][(limb / 4) % 5][limb % 4],
            preimage,
        );
        let joins = sum_clock::<AB>(
            row,
            (0..7).flat_map(|c| (0..5).map(move |b| c * 42 + b * 6 + 5)),
        );
        builder.when_transition().when(joins).assert_eq(
            next_first.preimage[limb / 20][(limb / 4) % 5][limb % 4],
            last.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
        );
    }
    for bit in &row[OUTPUT..RHO] {
        builder
            .when(AB::Expr::ONE - active_hash.clone())
            .assert_zero(*bit);
    }
    for c in 0..7 {
        for block in 0..6 {
            for byte in 0..168 {
                builder.when(row[CLOCK + c * 42 + block * 6 + 5]).assert_eq(
                    row[XOF + block * 168 + byte],
                    packed::<AB>(&row[OUTPUT + byte * 8..OUTPUT + (byte + 1) * 8]),
                );
            }
        }
    }
    for c in 0..7 {
        builder
            .when(row[CLOCK + c * 42])
            .assert_one(first.step_flags[0]);
        for block in 0..6 {
            builder
                .when(row[CLOCK + c * 42 + block * 6 + 5])
                .assert_one(last.step_flags[23]);
        }
    }
}

pub(crate) fn eval_lifetime<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let row = main.current_slice();
    let next = main.next_slice();
    for column in XOF..ZHAT {
        builder
            .when_transition()
            .assert_zero((AB::Expr::ONE - reset::<AB>(row)) * (next[column] - row[column]));
    }
}
