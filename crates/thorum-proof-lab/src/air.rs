use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

pub const HEIGHT: usize = 256;
pub const WIDTH: usize = 77;
pub const PUBLIC_VALUES: usize = 128;
pub const PHASE: usize = 0;
pub const SELECTOR: usize = 4;
pub const A0: usize = 68;
pub const A1: usize = 69;
pub const B0: usize = 70;
pub const B1: usize = 71;
pub const SUM: usize = 72;
pub const CARRY_A: usize = 73;
pub const NEXT_A: usize = 74;
pub const CARRY_B: usize = 75;
pub const NEXT_B: usize = 76;

pub struct ConservationAir;

impl<F> BaseAir<F> for ConservationAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder> Air<AB> for ConservationAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let phase3: AB::Expr = local[3].into();
        let one = AB::Expr::ONE;
        for value in &local[PHASE..SELECTOR + 64] {
            builder.assert_bool(*value);
        }
        builder.assert_eq(
            local[..4].iter().copied().map(Into::into).sum::<AB::Expr>(),
            one.clone(),
        );
        builder.assert_eq(
            local[SELECTOR..SELECTOR + 64]
                .iter()
                .copied()
                .map(Into::into)
                .sum::<AB::Expr>(),
            one.clone(),
        );
        builder.when_first_row().assert_one(local[0]);
        builder.when_first_row().assert_one(local[SELECTOR]);
        builder.when_last_row().assert_one(local[3]);
        builder.when_last_row().assert_one(local[SELECTOR + 63]);
        for phase in 0..4 {
            builder
                .when_transition()
                .assert_eq(next[(phase + 1) % 4], local[phase]);
        }
        for bit in 0..64 {
            let current: AB::Expr = local[SELECTOR + bit].into();
            let previous: AB::Expr = local[SELECTOR + (bit + 63) % 64].into();
            builder.when_transition().assert_eq(
                next[SELECTOR + bit],
                current.clone() + phase3.clone() * (previous - current),
            );
        }
        for column in A0..WIDTH {
            builder
                .when_transition()
                .when(one.clone() - phase3.clone())
                .assert_eq(next[column], local[column]);
        }
        builder
            .when_transition()
            .when(phase3.clone())
            .assert_eq(next[CARRY_A], local[NEXT_A]);
        builder
            .when_transition()
            .when(phase3)
            .assert_eq(next[CARRY_B], local[NEXT_B]);
        for column in [A0, A1, B0, B1, SUM, CARRY_A, NEXT_A] {
            builder.assert_bool(local[column]);
        }
        for column in [CARRY_B, NEXT_B] {
            let value: AB::Expr = local[column].into();
            builder.assert_zero(
                value.clone() * (value.clone() - one.clone()) * (value - AB::Expr::TWO),
            );
        }
        builder.when_first_row().assert_zero(local[CARRY_A]);
        builder.when_first_row().assert_zero(local[CARRY_B]);
        builder.when_last_row().assert_zero(local[NEXT_A]);
        builder.when_last_row().assert_zero(local[NEXT_B]);
        let fee_bit = (0..64)
            .map(|bit| {
                let selector: AB::Expr = local[SELECTOR + bit].into();
                let public_bit: AB::Expr = builder.public_values()[bit].into();
                selector * public_bit
            })
            .sum::<AB::Expr>();
        // These equations also apply on the final row.
        builder.assert_eq(
            local[A0] + local[A1] + local[CARRY_A],
            local[SUM] + local[NEXT_A] * AB::F::TWO,
        );
        builder.assert_eq(
            local[B0] + local[B1] + local[CARRY_B] + fee_bit,
            local[SUM] + local[NEXT_B] * AB::F::TWO,
        );
    }
}

// Trace construction intentionally does not reject incorrect equality or totals.
// Invalid witnesses are tested against the actual constraints, including carries.
pub fn trace(amounts: [u64; 4], fee: u64) -> RowMajorMatrix<BabyBear> {
    let mut rows = vec![BabyBear::ZERO; HEIGHT * WIDTH];
    let mut carry_a = 0u64;
    let mut carry_b = 0u64;
    for bit in 0..64 {
        let bits = amounts.map(|amount| (amount >> bit) & 1);
        let sum_a = bits[0] + bits[1] + carry_a;
        let sum_b = bits[2] + bits[3] + ((fee >> bit) & 1) + carry_b;
        let data = [
            bits[0],
            bits[1],
            bits[2],
            bits[3],
            sum_a & 1,
            carry_a,
            sum_a / 2,
            carry_b,
            sum_b / 2,
        ];
        for phase in 0..4 {
            let row = &mut rows[(4 * bit + phase) * WIDTH..(4 * bit + phase + 1) * WIDTH];
            row[phase] = BabyBear::ONE;
            row[SELECTOR + bit] = BabyBear::ONE;
            for (target, value) in row[A0..].iter_mut().zip(data) {
                *target = BabyBear::from_u64(value);
            }
        }
        carry_a = sum_a / 2;
        carry_b = sum_b / 2;
    }
    RowMajorMatrix::new(rows, WIDTH)
}

pub fn public_values(fee: u64, context: &[u8; 64]) -> Vec<BabyBear> {
    (0..64)
        .map(|bit| BabyBear::from_u64((fee >> bit) & 1))
        .chain(context.iter().map(|byte| BabyBear::from_u8(*byte)))
        .collect()
}
