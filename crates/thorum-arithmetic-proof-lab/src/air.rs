use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{Statement, Witness, mul};

pub const HEIGHT: usize = 256;
pub const WIDTH: usize = mul::WIDTH;
pub const PUBLIC_VALUES: usize = 12 + 64;

pub struct MultiplicationAir;
impl<F> BaseAir<F> for MultiplicationAir {
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
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for MultiplicationAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let _values = mul::eval_mul(builder, local);
        for column in 0..WIDTH {
            builder
                .when_transition()
                .assert_eq(local[column], next[column]);
        }
        let public = builder.public_values().to_vec();
        // Bind public bytes individually. A packed field equality alone would
        // permit the public integer to differ by the BabyBear modulus.
        for (public_value, slot) in [0, 1, 3].into_iter().enumerate() {
            for byte in 0..4 {
                let start = byte * 8;
                let expected = if start < 23 {
                    mul::packed::<AB>(&local[slot * 23 + start..slot * 23 + (start + 8).min(23)])
                } else {
                    AB::Expr::ZERO
                };
                builder.assert_eq(public[public_value * 4 + byte], expected);
            }
        }
    }
}

pub(crate) fn trace_with_values(
    values: [u32; 4],
    carry0: i32,
    carry1: i32,
) -> RowMajorMatrix<BabyBear> {
    let mut row = vec![BabyBear::ZERO; WIDTH];
    let mut write = |offset, value: u32, count| {
        for bit in 0..count {
            row[offset + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
        }
    };
    for (i, value) in values.into_iter().enumerate() {
        write(i * 23, value, 23);
        write(
            mul::COMPLEMENTS + i * 23,
            (mul::MODULUS - 1).wrapping_sub(value),
            23,
        );
    }
    write(mul::CARRY0, carry0.wrapping_add(2) as u32, 13);
    write(mul::CARRY1, carry1.wrapping_add(4096) as u32, 14);
    RowMajorMatrix::new(row.repeat(HEIGHT), WIDTH)
}
pub fn trace(witness: &Witness, statement: &Statement) -> RowMajorMatrix<BabyBear> {
    trace_with_values(
        [statement.x, statement.y, witness.quotient, statement.z],
        witness.carry0,
        witness.carry1,
    )
}
pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    [statement.x, statement.y, statement.z]
        .into_iter()
        .flat_map(|v| v.to_le_bytes().map(BabyBear::from_u8))
        .chain(statement.context.map(BabyBear::from_u8))
        .collect()
}
