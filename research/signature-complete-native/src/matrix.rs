//! Causal six block matrix sampling and source connected integer accumulation.
//! Adapted from the retained Thorum matrix sampler and reconstructed row kernels.
use crate::{build, full_program as fp, layout::*, mul, ntt, program};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |a, b| a.double() + *b)
}
pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(b: &mut AB) {
    let main = b.main();
    let row = main.current_slice();
    let next = main.next_slice();
    let mrow: [AB::Expr; 8] =
        core::array::from_fn(|i| (0..7).map(|j| fp::sample_selector::<AB>(row, i, j)).sum());
    let mcol: [AB::Expr; 7] =
        core::array::from_fn(|j| (0..8).map(|i| fp::sample_selector::<AB>(row, i, j)).sum());
    let matrix: AB::Expr = mrow.iter().cloned().sum();
    let point = program::range::<AB>(row, fp::POINT_START, fp::POINT_END);
    let idle = AB::Expr::ONE - matrix.clone() - point.clone();
    let reload: AB::Expr = (0..55)
        .map(|s| program::at::<AB>(row, fp::MATRIX_START + 48 * s + 47))
        .sum();
    for state in 0..9 {
        let base = MATRIX_COUNT + 257 * state;
        let mut sum = AB::Expr::ZERO;
        for k in 0..257 {
            b.assert_bool(row[base + k]);
            sum += row[base + k].into();
        }
        b.assert_one(sum);
        for bit in &row[MATRIX_CURSOR + 10 * state..MATRIX_CURSOR + 10 * (state + 1)] {
            b.assert_bool(*bit);
        }
    }
    for k in 0..257 {
        b.when_first_row()
            .assert_eq(row[MATRIX_COUNT + k], BabyBear::from_bool(k == 0));
        b.when_transition().assert_eq(
            next[MATRIX_COUNT + k],
            (AB::Expr::ONE - reload.clone()) * row[MATRIX_COUNT + 8 * 257 + k]
                + reload.clone() * BabyBear::from_bool(k == 0),
        );
    }
    b.when_first_row()
        .assert_zero(packed::<AB>(&row[MATRIX_CURSOR..MATRIX_CURSOR + 10]));
    b.when_transition().assert_eq(
        packed::<AB>(&next[MATRIX_CURSOR..MATRIX_CURSOR + 10]),
        (AB::Expr::ONE - reload) * packed::<AB>(&row[MATRIX_CURSOR + 80..MATRIX_CURSOR + 90]),
    );
    for stream in 0..56 {
        b.when(program::at::<AB>(row, fp::MATRIX_START + 48 * stream + 47))
            .assert_one(row[MATRIX_COUNT + 8 * 257 + 256]);
    }
    b.when_last_row().assert_one(row[MATRIX_COUNT + 256]);
    for s in 0..8 {
        let count = MATRIX_COUNT + s * 257;
        let active = matrix.clone() * (AB::Expr::ONE - row[count + 256]);
        let take: AB::Expr = row[MATRIX_TAKE + s].into();
        b.assert_bool(row[MATRIX_TAKE + s]);
        b.assert_zero(take.clone() * (AB::Expr::ONE - active.clone()));
        for k in 0..257 {
            let previous = if k == 0 {
                AB::Expr::ZERO
            } else {
                row[count + k - 1].into()
            };
            b.assert_eq(
                row[count + 257 + k],
                (AB::Expr::ONE - take.clone()) * row[count + k] + take.clone() * previous,
            );
        }
        for bit in row[MATRIX_CANDIDATE + 24 * s..MATRIX_CANDIDATE + 24 * (s + 1)]
            .iter()
            .chain(&row[MATRIX_SLACK + 23 * s..MATRIX_SLACK + 23 * (s + 1)])
        {
            b.assert_bool(*bit);
            b.when(AB::Expr::ONE - active.clone()).assert_zero(*bit);
        }
        for byte in 0..3 {
            let source: AB::Expr = (0..56)
                .flat_map(|stream| (0..42).map(move |u| (stream, u)))
                .map(|(stream, u)| {
                    program::at::<AB>(row, fp::MATRIX_START + 48 * stream + 6 + u)
                        * row[MATRIX_XOF + 24 * u + 3 * s + byte]
                })
                .sum();
            let start = MATRIX_CANDIDATE + 24 * s + 8 * byte;
            b.assert_eq(
                packed::<AB>(&row[start..start + 8]),
                (AB::Expr::ONE - row[count + 256]) * source,
            );
        }
        let candidate =
            packed::<AB>(&row[MATRIX_CANDIDATE + 24 * s..MATRIX_CANDIDATE + 24 * s + 23]);
        let slack = packed::<AB>(&row[MATRIX_SLACK + 23 * s..MATRIX_SLACK + 23 * (s + 1)]);
        b.when(take.clone()).assert_eq(
            candidate.clone() + slack.clone(),
            BabyBear::from_u32(mul::MODULUS - 1),
        );
        b.when(active.clone() - take)
            .assert_eq(candidate, slack + BabyBear::from_u32(mul::MODULUS));
        let cur = packed::<AB>(&row[MATRIX_CURSOR + 10 * s..MATRIX_CURSOR + 10 * (s + 1)]);
        b.assert_eq(
            packed::<AB>(&row[MATRIX_CURSOR + 10 * (s + 1)..MATRIX_CURSOR + 10 * (s + 2)]),
            cur.clone() + active.clone() * BabyBear::from_u8(3),
        );
        let expected: AB::Expr = (0..56)
            .flat_map(|stream| (0..42).map(move |u| (stream, u)))
            .map(|(stream, u)| {
                program::at::<AB>(row, fp::MATRIX_START + 48 * stream + 6 + u)
                    * BabyBear::from_usize(24 * u + 3 * s)
            })
            .sum();
        b.when(active).assert_eq(cur, expected);
    }
    for i in 0..8 {
        for s in 0..8 {
            b.assert_bool(row[MATRIX_ENABLE + 8 * i + s]);
            b.assert_eq(
                row[MATRIX_ENABLE + 8 * i + s],
                mrow[i].clone() * row[MATRIX_TAKE + s],
            );
        }
    }
    // One unconditional matrix/point/idle operand mux. No additional phase
    // gate is applied around the cubic column/count/private polynomial read.
    for bit in &row[EXTRA_WRITES..EXTRA_FLAGS] {
        b.assert_bool(*bit);
    }
    let writes: [AB::Expr; 16] = core::array::from_fn(|s| {
        packed::<AB>(&row[EXTRA_WRITES + 46 * s..EXTRA_WRITES + 46 * s + 23])
    });
    for s in 0..16 {
        b.assert_eq(
            writes[s].clone()
                + packed::<AB>(&row[EXTRA_WRITES + 46 * s + 23..EXTRA_WRITES + 46 * (s + 1)]),
            BabyBear::from_u32(mul::MODULUS - 1),
        );
    }
    for flag in &row[EXTRA_FLAGS..ACCUMULATOR] {
        b.assert_bool(*flag);
    }
    for s in 0..8 {
        let product = mul::eval_mul(
            b,
            &row[EXTRA_PRODUCTS + s * mul::WIDTH..EXTRA_PRODUCTS + (s + 1) * mul::WIDTH],
        );
        let candidate =
            packed::<AB>(&row[MATRIX_CANDIDATE + 24 * s..MATRIX_CANDIDATE + 24 * s + 23]);
        let mut x = row[MATRIX_TAKE + s] * candidate;
        let mut y = AB::Expr::ZERO;
        let mut old = AB::Expr::ZERO;
        for j in 0..7 {
            let z: AB::Expr = (0..256)
                .map(|k| row[MATRIX_COUNT + s * 257 + k] * row[NTT_OUTPUT + 256 * j + k])
                .sum();
            y += mcol[j].clone() * z;
        }
        for i in 0..8 {
            let selected: AB::Expr = (0..256)
                .map(|k| row[MATRIX_COUNT + s * 257 + k] * row[ACCUMULATOR + 256 * i + k])
                .sum();
            old += mrow[i].clone() * selected;
            for g in 0..32 {
                let p = fp::point_selector::<AB>(row, i, g);
                let k = 8 * g + s;
                x += p.clone() * row[NTT_OUTPUT + 7 * 256 + k];
                y += p.clone() * row[NTT_OUTPUT + (8 + i) * 256 + k];
                old += p * row[ACCUMULATOR + 256 * i + k];
            }
        }
        b.assert_eq(product[0].clone(), x);
        b.assert_eq(product[1].clone(), y);
        b.assert_eq(writes[2 * s].clone(), old);
        b.when(matrix.clone()).assert_eq(
            writes[2 * s + 1].clone(),
            writes[2 * s].clone() + product[3].clone()
                - row[EXTRA_FLAGS + 2 * s] * BabyBear::from_u32(mul::MODULUS),
        );
        b.when(point.clone()).assert_eq(
            writes[2 * s + 1].clone(),
            writes[2 * s].clone() - product[3].clone()
                + row[EXTRA_FLAGS + 2 * s] * BabyBear::from_u32(mul::MODULUS),
        );
        b.when(idle.clone()).assert_zero(writes[2 * s + 1].clone());
        b.when(idle.clone()).assert_zero(row[EXTRA_FLAGS + 2 * s]);
        b.assert_zero(row[EXTRA_FLAGS + 2 * s + 1]);
    }
    for i in 0..8 {
        for k in 0..256 {
            let col = ACCUMULATOR + 256 * i + k;
            b.when_first_row().assert_zero(row[col]);
            let delta: AB::Expr = (0..8)
                .map(|s| {
                    row[MATRIX_ENABLE + 8 * i + s]
                        * row[MATRIX_COUNT + s * 257 + k]
                        * (writes[2 * s + 1].clone() - row[col])
                })
                .sum();
            let correction = fp::point_selector::<AB>(row, i, k / 8)
                * (writes[2 * (k % 8) + 1].clone() - row[col]);
            // Cubic delta becomes degree four after the outer transition gate.
            b.when_transition()
                .assert_eq(next[col], row[col].into() + delta + correction);
        }
    }
    eval_xof(b);
}
fn eval_xof<AB: AirBuilder<F = BabyBear>>(b: &mut AB) {
    let main = b.main();
    let row = main.current_slice();
    let next = main.next_slice();
    let reset: AB::Expr = (0..56)
        .map(|s| program::at::<AB>(row, fp::MATRIX_START + 48 * s + 47))
        .sum();
    for byte in 0..1008 {
        let col = MATRIX_XOF + byte;
        b.when_first_row().assert_zero(row[col]);
        let write: AB::Expr = (0..56)
            .map(|s| program::at::<AB>(row, fp::MATRIX_START + 48 * s + 6 * (byte / 168) + 5))
            .sum();
        let start = OUTPUT + 8 * (byte % 168);
        let producer = packed::<AB>(&row[start..start + 8]);
        b.when_transition().assert_eq(
            next[col],
            row[col].into() + write * (producer - row[col]) - reset.clone() * row[col],
        );
    }
}
fn read_bits(row: &[BabyBear], at: usize, n: usize) -> u32 {
    (0..n).map(|i| row[at + i].as_canonical_u32() << i).sum()
}
pub(crate) fn fill_xof(values: &mut [BabyBear]) {
    let mut bank = [0u8; 1008];
    for (at, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        for (i, v) in bank.iter().enumerate() {
            row[MATRIX_XOF + i] = BabyBear::from_u8(*v);
        }
        if let Some((_, _, local)) = fp::matrix(at) {
            if local < 36 && local % 6 == 5 {
                for byte in 0..168 {
                    bank[(local / 6) * 168 + byte] = read_bits(row, OUTPUT + 8 * byte, 8) as u8;
                }
            }
            if local == 47 {
                bank = [0; 1008];
            }
        }
    }
}
pub(crate) fn fill(values: &mut [BabyBear]) {
    let mut acc = [0u32; 2048];
    let mut count = 0usize;
    let mut cursor = 0u32;
    for (at, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        for (i, v) in acc.iter().enumerate() {
            row[ACCUMULATOR + i] = BabyBear::from_u32(*v);
        }
        let mut counts = [count; 9];
        let mut cursors = [cursor; 9];
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
                        y = row[NTT_OUTPUT + 256 * j + k].as_canonical_u32();
                        writes[2 * s] = acc[256 * i + k];
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
                        acc[256 * i + k] = writes[2 * s + 1];
                    }
                }
            } else if let Some((i, g)) = fp::point(at) {
                let k = 8 * g + s;
                products[s] = ntt::product(
                    row[NTT_OUTPUT + 7 * 256 + k].as_canonical_u32(),
                    row[NTT_OUTPUT + (8 + i) * 256 + k].as_canonical_u32(),
                );
                let old = acc[256 * i + k];
                let product = products[s].values[3];
                let borrow = old < product;
                writes[2 * s] = old;
                writes[2 * s + 1] = (u64::from(old)
                    + if borrow { u64::from(mul::MODULUS) } else { 0 }
                    - u64::from(product)) as u32;
                flags[2 * s] = borrow;
                acc[256 * i + k] = writes[2 * s + 1];
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
        count = counts[8];
        cursor = cursors[8];
        if let Some((_, _, local)) = fp::matrix(at) {
            if local == 47 {
                assert_eq!(
                    count, 256,
                    "Matrix capacity preflight and actual bank disagree"
                );
                if at + 1 < fp::MATRIX_END {
                    count = 0;
                    cursor = 0;
                }
            }
        }
    }
}
