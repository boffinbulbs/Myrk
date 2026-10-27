use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use super::{Error, MODULUS, Statement, Witness, challenge, packing};

pub const HEIGHT: usize = challenge::HEIGHT;
pub const PUBLIC_VALUES: usize = challenge::PUBLIC_VALUES;
pub const SIGNATURE_TAIL: usize = challenge::WIDTH;
pub const Z_PROGRAM: usize = SIGNATURE_TAIL + 4563;
pub const Z_MESSAGE: usize = Z_PROGRAM + 449;
pub const Z_AUX: usize = Z_MESSAGE + 80;
pub const Z_VALUES: usize = Z_AUX + 2 * packing::Z_AUX_WIDTH;
pub const HINT_START: usize = Z_VALUES + 1792;
pub const PADDING: usize = HINT_START + 75;
pub const CUTS: usize = PADDING + 1;
pub const CUT_COMPLEMENTS: usize = CUTS + 56;
pub const CUT_DIFFERENCES: usize = CUT_COMPLEMENTS + 56;
pub const MESSAGE: usize = CUT_DIFFERENCES + 49;
pub const ACTIVE: usize = MESSAGE + 8;
pub const ACTIVE_LOWER: usize = ACTIVE + 1;
pub const ACTIVE_UPPER: usize = ACTIVE_LOWER + 7;
pub const GROUP: usize = ACTIVE_UPPER + 7;
pub const SEGMENT_LOWER: usize = GROUP + 8;
pub const SEGMENT_UPPER: usize = SEGMENT_LOWER + 56;
pub const ONE_HOT: usize = SEGMENT_UPPER + 56;
pub const HINTS: usize = ONE_HOT + 256;
pub const LAST: usize = HINTS + 2048;
pub const SEEN: usize = LAST + 64;
pub const ORDER: usize = SEEN + 8;
pub const WIDTH: usize = ORDER + 64;

pub struct SignatureChallengeAir;
impl<F> BaseAir<F> for SignatureChallengeAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

fn fixed_program<AB: AirBuilder<F = BabyBear>>(builder: &mut AB, start: usize, events: usize) {
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    let mut sum = AB::Expr::ZERO;
    for position in 0..=events {
        let value = local[start + position];
        builder.assert_bool(value);
        sum += value.into();
        builder
            .when_first_row()
            .assert_eq(value, BabyBear::from_bool(position == 0));
        let predecessor: AB::Expr = if position == events {
            local[start + position - 1].into() + value
        } else if position > 0 {
            local[start + position - 1].into()
        } else {
            AB::Expr::ZERO
        };
        builder
            .when_transition()
            .assert_eq(next[start + position], predecessor);
    }
    builder.assert_one(sum);
    builder.when_last_row().assert_one(local[start + events]);
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for SignatureChallengeAir {
    fn eval(&self, builder: &mut AB) {
        challenge::ChallengeSamplerAir.eval(builder);
        fixed_program(builder, Z_PROGRAM, 448);
        fixed_program(builder, HINT_START, 75);
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        for column in SIGNATURE_TAIL..Z_PROGRAM {
            builder
                .when_transition()
                .assert_eq(local[column], next[column]);
        }
        let z_phase = AB::Expr::ONE - local[Z_PROGRAM + 448];
        for byte in 0..10 {
            let bits = &local[Z_MESSAGE + 8 * byte..Z_MESSAGE + 8 * (byte + 1)];
            for bit in bits {
                builder.assert_bool(*bit);
            }
            let expected: AB::Expr = (0..448)
                .map(|position| {
                    local[Z_PROGRAM + position] * local[SIGNATURE_TAIL + 10 * position + byte]
                })
                .sum();
            builder.assert_eq(packing::packed::<AB>(bits), expected);
        }
        let first = packing::decode_z_pair(
            &mut builder.when(z_phase.clone()),
            &local[Z_MESSAGE..Z_MESSAGE + 40],
            &local[Z_AUX..Z_AUX + packing::Z_AUX_WIDTH],
        );
        let second = packing::decode_z_pair(
            &mut builder.when(z_phase.clone()),
            &local[Z_MESSAGE + 40..Z_AUX],
            &local[Z_AUX + packing::Z_AUX_WIDTH..Z_VALUES],
        );
        for bit in &local[Z_AUX..Z_VALUES] {
            builder
                .when(AB::Expr::ONE - z_phase.clone())
                .assert_zero(*bit);
        }
        let normal = [
            first[0].clone(),
            first[1].clone(),
            second[0].clone(),
            second[1].clone(),
        ];
        for index in 0..1792 {
            let column = Z_VALUES + index;
            let selector = local[Z_PROGRAM + index / 4];
            builder.when_first_row().assert_zero(local[column]);
            builder.when_transition().assert_eq(
                next[column],
                local[column].into() + selector * (normal[index % 4].clone() - local[column]),
            );
        }
        for bit in &local[CUTS..WIDTH] {
            builder.assert_bool(*bit);
        }
        let hint_byte: AB::Expr = (0..75)
            .map(|position| local[HINT_START + position] * local[SIGNATURE_TAIL + 4480 + position])
            .sum();
        builder.assert_eq(
            packing::packed::<AB>(&local[MESSAGE..MESSAGE + 8]),
            hint_byte,
        );
        let cuts: [AB::Expr; 8] = core::array::from_fn(|i| {
            packing::packed::<AB>(&local[CUTS + i * 7..CUTS + (i + 1) * 7])
        });
        for i in 0..8 {
            let complement = packing::packed::<AB>(
                &local[CUT_COMPLEMENTS + i * 7..CUT_COMPLEMENTS + (i + 1) * 7],
            );
            builder.assert_eq(cuts[i].clone() + complement, BabyBear::from_u8(75));
            builder.assert_eq(cuts[i].clone(), local[SIGNATURE_TAIL + 4555 + i]);
            if i > 0 {
                let difference = packing::packed::<AB>(
                    &local[CUT_DIFFERENCES + (i - 1) * 7..CUT_DIFFERENCES + i * 7],
                );
                builder.assert_eq(cuts[i].clone(), cuts[i - 1].clone() + difference);
            }
        }
        for column in CUTS..MESSAGE {
            builder
                .when_transition()
                .assert_eq(local[column], next[column]);
        }
        let hint_phase: AB::Expr = local[HINT_START..PADDING]
            .iter()
            .copied()
            .map(Into::into)
            .sum();
        let position: AB::Expr = (0..75)
            .map(|j| local[HINT_START + j] * BabyBear::from_u8(j as u8))
            .sum();
        let active: AB::Expr = local[ACTIVE].into();
        let inactive = hint_phase.clone() - active.clone();
        builder.assert_zero(active.clone() * (AB::Expr::ONE - hint_phase.clone()));
        let lower = packing::packed::<AB>(&local[ACTIVE_LOWER..ACTIVE_UPPER]);
        let upper = packing::packed::<AB>(&local[ACTIVE_UPPER..GROUP]);
        builder.when(active.clone()).assert_eq(
            position.clone() + AB::Expr::ONE + upper.clone(),
            cuts[7].clone(),
        );
        builder
            .when(inactive.clone())
            .assert_eq(cuts[7].clone() + lower.clone(), position.clone());
        builder.when(active.clone()).assert_zero(lower.clone());
        builder.when(inactive.clone()).assert_zero(upper.clone());
        builder
            .when(AB::Expr::ONE - hint_phase.clone())
            .assert_zero(lower);
        builder
            .when(AB::Expr::ONE - hint_phase.clone())
            .assert_zero(upper);
        let group_sum: AB::Expr = local[GROUP..SEGMENT_LOWER]
            .iter()
            .copied()
            .map(Into::into)
            .sum();
        builder.assert_eq(group_sum, active.clone());
        let index = packing::packed::<AB>(&local[MESSAGE..MESSAGE + 8]);
        let one_hot_sum: AB::Expr = local[ONE_HOT..HINTS].iter().copied().map(Into::into).sum();
        let one_hot_index: AB::Expr = (0..256)
            .map(|k| local[ONE_HOT + k] * BabyBear::from_u16(k as u16))
            .sum();
        builder.assert_eq(one_hot_sum, active.clone());
        builder.assert_eq(one_hot_index, active * index.clone());
        builder.when(inactive).assert_zero(index.clone());
        for i in 0..8 {
            let selected: AB::Expr = local[GROUP + i].into();
            let segment_lower =
                packing::packed::<AB>(&local[SEGMENT_LOWER + i * 7..SEGMENT_LOWER + (i + 1) * 7]);
            let segment_upper =
                packing::packed::<AB>(&local[SEGMENT_UPPER + i * 7..SEGMENT_UPPER + (i + 1) * 7]);
            let previous = if i == 0 {
                AB::Expr::ZERO
            } else {
                cuts[i - 1].clone()
            };
            builder
                .when(selected.clone())
                .assert_eq(previous + segment_lower.clone(), position.clone());
            builder.when(selected.clone()).assert_eq(
                position.clone() + AB::Expr::ONE + segment_upper.clone(),
                cuts[i].clone(),
            );
            builder
                .when(AB::Expr::ONE - selected.clone())
                .assert_zero(segment_lower);
            builder
                .when(AB::Expr::ONE - selected.clone())
                .assert_zero(segment_upper);
            let last = packing::packed::<AB>(&local[LAST + i * 8..LAST + (i + 1) * 8]);
            let seen: AB::Expr = local[SEEN + i].into();
            let order = packing::packed::<AB>(&local[ORDER + i * 8..ORDER + (i + 1) * 8]);
            builder
                .when(selected.clone() * seen.clone())
                .assert_eq(index.clone(), last + AB::Expr::ONE + order.clone());
            builder
                .when(AB::Expr::ONE - selected.clone() * seen.clone())
                .assert_zero(order);
            builder.when_first_row().assert_zero(local[SEEN + i]);
            builder.when_transition().assert_eq(
                next[SEEN + i],
                seen.clone() + selected.clone() * (AB::Expr::ONE - seen),
            );
            for bit in 0..8 {
                let old: AB::Expr = local[LAST + i * 8 + bit].into();
                builder
                    .when_first_row()
                    .assert_zero(local[LAST + i * 8 + bit]);
                builder.when_transition().assert_eq(
                    next[LAST + i * 8 + bit],
                    old.clone() + selected.clone() * (local[MESSAGE + bit].into() - old),
                );
            }
            for k in 0..256 {
                let at = HINTS + i * 256 + k;
                builder.when_first_row().assert_zero(local[at]);
                builder.when_transition().assert_eq(
                    next[at],
                    local[at].into() + selected.clone() * local[ONE_HOT + k],
                );
            }
        }
    }
}

pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    challenge::public_values(statement)
}

fn bits(row: &mut [BabyBear], start: usize, value: i64, width: usize) {
    for bit in 0..width {
        row[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
    }
}

pub fn trace(witness: &Witness, statement: &Statement) -> Result<RowMajorMatrix<BabyBear>, Error> {
    let core_witness = super::super::Witness::from_challenge_seed(witness.seed);
    let core = challenge::trace(&core_witness, statement)?;
    let cuts: [i64; 8] = core::array::from_fn(|i| i64::from(witness.signature_tail[4555 + i]));
    let mut z = [0u32; 1792];
    let mut hints = [[false; 256]; 8];
    let mut last = [0i64; 8];
    let mut seen = [false; 8];
    let mut values = vec![BabyBear::ZERO; WIDTH * HEIGHT];
    for (at, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        row[..challenge::WIDTH].copy_from_slice(&core.row_slice(at).unwrap());
        for (byte, value) in witness.signature_tail.iter().enumerate() {
            row[SIGNATURE_TAIL + byte] = BabyBear::from_u8(*value);
        }
        row[Z_PROGRAM + at.min(448)] = BabyBear::ONE;
        for index in 0..1792 {
            row[Z_VALUES + index] = BabyBear::from_u32(z[index]);
        }
        if at < 448 {
            let data = &witness.signature_tail[at * 10..at * 10 + 10];
            for (byte, value) in data.iter().enumerate() {
                bits(row, Z_MESSAGE + byte * 8, i64::from(*value), 8);
            }
            for window in 0..2 {
                let mut encoded = [0u8; 8];
                encoded[..5].copy_from_slice(&data[window * 5..window * 5 + 5]);
                let word = u64::from_le_bytes(encoded);
                let aux = Z_AUX + window * packing::Z_AUX_WIDTH;
                for coefficient in 0..2 {
                    let d = ((word >> (20 * coefficient)) & 0xfffff) as i64;
                    let normal = (524288 - d).rem_euclid(i64::from(MODULUS));
                    bits(row, aux + packing::LOWER + coefficient * 20, d - 121, 20);
                    bits(
                        row,
                        aux + packing::UPPER + coefficient * 20,
                        1048455 - d,
                        20,
                    );
                    bits(row, aux + packing::NORMAL + coefficient * 23, normal, 23);
                    bits(
                        row,
                        aux + packing::COMPLEMENTS + coefficient * 23,
                        i64::from(MODULUS) - 1 - normal,
                        23,
                    );
                    row[aux + packing::NEGATIVE + coefficient] = BabyBear::from_bool(d > 524288);
                    z[at * 4 + window * 2 + coefficient] = normal as u32;
                }
            }
        }
        row[HINT_START + at.min(75)] = BabyBear::ONE;
        for i in 0..8 {
            bits(row, CUTS + i * 7, cuts[i], 7);
            bits(row, CUT_COMPLEMENTS + i * 7, 75 - cuts[i], 7);
            if i > 0 {
                bits(row, CUT_DIFFERENCES + (i - 1) * 7, cuts[i] - cuts[i - 1], 7);
            }
            bits(row, LAST + i * 8, last[i], 8);
            row[SEEN + i] = BabyBear::from_bool(seen[i]);
            for k in 0..256 {
                row[HINTS + i * 256 + k] = BabyBear::from_bool(hints[i][k]);
            }
        }
        if at < 75 {
            let j = at as i64;
            let index = usize::from(witness.signature_tail[4480 + at]);
            bits(row, MESSAGE, index as i64, 8);
            let active = j < cuts[7];
            row[ACTIVE] = BabyBear::from_bool(active);
            if active {
                bits(row, ACTIVE_UPPER, cuts[7] - j - 1, 7);
            } else {
                bits(row, ACTIVE_LOWER, j - cuts[7], 7);
            }
            if active
                && let Some(i) = (0..8).find(|i| {
                    let previous = if *i == 0 { 0 } else { cuts[*i - 1] };
                    previous <= j && j < cuts[*i]
                })
            {
                row[GROUP + i] = BabyBear::ONE;
                row[ONE_HOT + index] = BabyBear::ONE;
                let previous = if i == 0 { 0 } else { cuts[i - 1] };
                bits(row, SEGMENT_LOWER + i * 7, j - previous, 7);
                bits(row, SEGMENT_UPPER + i * 7, cuts[i] - j - 1, 7);
                if seen[i] {
                    bits(row, ORDER + i * 8, index as i64 - last[i] - 1, 8);
                }
                last[i] = index as i64;
                seen[i] = true;
                hints[i][index] = true;
            }
        }
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}
