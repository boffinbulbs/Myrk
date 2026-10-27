use super::super::*;
use super::{HEIGHT, PUBLIC_VALUES, Statement};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_matrix::dense::RowMajorMatrix;

pub(super) struct ProofAir;
impl<F> BaseAir<F> for ProofAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for ProofAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let values = eval_use_hint(builder, local);
        let public = builder.public_values().to_vec();
        for (byte, expected) in public[..4].iter().copied().enumerate() {
            let start = byte * 8;
            let actual = if start < 23 {
                super::super::packed::<AB>(&local[start..(start + 8).min(23)])
            } else {
                AB::Expr::ZERO
            };
            builder.assert_eq(expected, actual);
        }
        builder.assert_eq(values.hint, public[4]);
        builder.assert_eq(values.output, public[5]);
        for i in 0..WIDTH {
            builder.when_transition().assert_eq(local[i], next[i]);
        }
    }
}
pub(super) fn public_values(statement: &Statement) -> Vec<BabyBear> {
    statement
        .r
        .to_le_bytes()
        .into_iter()
        .chain([statement.hint, statement.output])
        .chain(statement.context)
        .map(BabyBear::from_u8)
        .collect()
}
pub(super) fn trace(statement: &Statement) -> RowMajorMatrix<BabyBear> {
    RowMajorMatrix::new(
        row_for_input(statement.r, statement.hint).repeat(HEIGHT),
        WIDTH,
    )
}

pub(super) fn bits(row: &mut [BabyBear], start: usize, value: i64, count: usize) {
    let word = value as u64;
    for bit in 0..count {
        row[start + bit] = BabyBear::from_bool((word >> bit) & 1 != 0);
    }
}

pub(super) fn row_for_input(input: u32, hint: u8) -> Vec<BabyBear> {
    let r = i64::from(input);
    let shifted = r + i64::from(GAMMA2) - 1;
    let n = shifted / i64::from(ALPHA);
    let u = shifted % i64::from(ALPHA);
    let edge = i64::from(n == 16);
    let high = n % 16;
    let low = u - i64::from(GAMMA2) + 1 - edge;
    let positive = i64::from(low > 0);
    let sign_slack = if positive == 1 {
        u - i64::from(GAMMA2) - edge
    } else {
        i64::from(GAMMA2) + edge - 1 - u
    };
    let raw = high + i64::from(hint == 1) * (2 * positive - 1);
    let borrow = i64::from(raw < 0);
    let overflow = i64::from(raw > 15);
    let output = raw + 16 * (borrow - overflow);
    let mut row = vec![BabyBear::ZERO; WIDTH];
    for (offset, value, count) in [
        (R, r, 23),
        (R_COMPLEMENT, i64::from(MODULUS) - 1 - r, 23),
        (N, n, 5),
        (N_COMPLEMENT, 16 - n, 5),
        (U, u, 19),
        (U_COMPLEMENT, i64::from(ALPHA) - 1 - u, 19),
        (HIGH, high, 4),
        (OUTPUT, output, 4),
        (SIGN_SLACK, sign_slack, 18),
    ] {
        bits(&mut row, offset, value, count);
    }
    row[EDGE] = BabyBear::from_bool(edge == 1);
    row[POSITIVE] = BabyBear::from_bool(positive == 1);
    row[HINT] = BabyBear::from_u8(hint);
    row[BORROW] = BabyBear::from_bool(borrow == 1);
    row[OVERFLOW] = BabyBear::from_bool(overflow == 1);
    row
}
