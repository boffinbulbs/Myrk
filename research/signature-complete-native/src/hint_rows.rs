//! Same normalized inverse coefficients and signature hints produce ordered private w1.
use crate::{build, full_program as fp, hints, layout::*, ntt, program};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(b: &mut AB) {
    let main = b.main();
    let row = main.current_slice();
    let next = main.next_slice();
    let used: [hints::Values<AB::Expr>; 8] = core::array::from_fn(|s| {
        hints::eval_use_hint(
            b,
            &row[USE_HINT + s * hints::WIDTH..USE_HINT + (s + 1) * hints::WIDTH],
        )
    });
    for s in 0..8 {
        let mut input = AB::Expr::ZERO;
        let mut hint = AB::Expr::ZERO;
        for i in 0..8 {
            for g in 0..32 {
                let select = program::at::<AB>(row, fp::INVERSE_START + 224 * i + 192 + g);
                input += select.clone() * row[NTT_SCRATCH + 8 * g + s];
                hint += select * row[HINTS + 256 * i + 8 * g + s];
            }
        }
        b.assert_eq(used[s].input.clone(), input);
        b.assert_eq(used[s].hint.clone(), hint);
    }
    for i in 0..8 {
        for byte in 0..128 {
            let col = W1 + 128 * i + byte;
            let pair = byte % 4;
            let g = byte / 4;
            b.when_first_row().assert_zero(row[col]);
            let packed = used[2 * pair].output.clone()
                + used[2 * pair + 1].output.clone() * BabyBear::from_u8(16);
            b.when_transition().assert_eq(
                next[col],
                row[col].into()
                    + program::at::<AB>(row, fp::INVERSE_START + 224 * i + 192 + g)
                        * (packed - row[col]),
            );
        }
    }
}
// Retained integer Decompose/UseHint witness encoding from the public row builder.
fn encode(row: &mut [BabyBear], s: usize, input: u32, hint: u8) -> u8 {
    let r = i64::from(input);
    let shifted = r + i64::from(hints::GAMMA2) - 1;
    let n = shifted / i64::from(hints::ALPHA);
    let u = shifted % i64::from(hints::ALPHA);
    let edge = i64::from(n == 16);
    let high = n % 16;
    let low = u - i64::from(hints::GAMMA2) + 1 - edge;
    let positive = i64::from(low > 0);
    let slack = if positive == 1 {
        u - i64::from(hints::GAMMA2) - edge
    } else {
        i64::from(hints::GAMMA2) + edge - 1 - u
    };
    let raw = high + i64::from(hint) * (2 * positive - 1);
    let borrow = i64::from(raw < 0);
    let overflow = i64::from(raw > 15);
    let output = raw + 16 * (borrow - overflow);
    let start = USE_HINT + s * hints::WIDTH;
    for (offset, value, bits) in [
        (hints::R, r, 23),
        (hints::R_COMPLEMENT, i64::from(hints::MODULUS) - 1 - r, 23),
        (hints::N, n, 5),
        (hints::N_COMPLEMENT, 16 - n, 5),
        (hints::U, u, 19),
        (hints::U_COMPLEMENT, i64::from(hints::ALPHA) - 1 - u, 19),
        (hints::HIGH, high, 4),
        (hints::OUTPUT, output, 4),
        (hints::SIGN_SLACK, slack, 18),
    ] {
        build::bits(row, start + offset, value as u32, bits);
    }
    for (offset, value) in [
        (hints::EDGE, edge),
        (hints::POSITIVE, positive),
        (hints::HINT, i64::from(hint)),
        (hints::BORROW, borrow),
        (hints::OVERFLOW, overflow),
    ] {
        row[start + offset] = BabyBear::from_bool(value != 0);
    }
    output as u8
}
pub(crate) fn fill(values: &mut [BabyBear]) {
    let mut packed = [0u8; 1024];
    for (at, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        for (i, v) in packed.iter().enumerate() {
            row[W1 + i] = BabyBear::from_u8(*v);
        }
        let output = ntt::inverse_operation(at).and_then(|(i, op)| match op {
            ntt::InverseOp::Output(g) => Some((i, g)),
            _ => None,
        });
        let mut used = [0u8; 8];
        for s in 0..8 {
            let (input, hint) = if let Some((i, g)) = output {
                (
                    row[NTT_SCRATCH + 8 * g + s].as_canonical_u32(),
                    row[HINTS + 256 * i + 8 * g + s].as_canonical_u32() as u8,
                )
            } else {
                (0, 0)
            };
            used[s] = encode(row, s, input, hint);
        }
        if let Some((i, g)) = output {
            for p in 0..4 {
                packed[128 * i + 4 * g + p] = used[2 * p] + 16 * used[2 * p + 1];
            }
        }
    }
}
