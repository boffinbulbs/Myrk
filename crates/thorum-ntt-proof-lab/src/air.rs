use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{Mode, Statement, Witness, mul, ntt};

pub const HEIGHT: usize = 256;
pub const SELECTORS: usize = 0;
pub const PADDING: usize = 10;
pub const POLYNOMIAL: usize = 11;
pub const COMPLEMENTS: usize = POLYNOMIAL + 256 * 23;
pub const PRODUCTS: usize = COMPLEMENTS + 256 * 23;
pub const CARRIES: usize = PRODUCTS + 128 * mul::WIDTH;
pub const WIDTH: usize = CARRIES + 256;
pub const PUBLIC_VALUES: usize = 1 + 1024 + 1024 + 64;

pub struct NttAir {
    mode: Mode,
}
impl NttAir {
    pub fn new(statement: &Statement) -> Self {
        Self {
            mode: statement.mode,
        }
    }
}
impl<F> BaseAir<F> for NttAir {
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
fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit)
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for NttAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let public = builder.public_values().to_vec();
        let stages = if self.mode == Mode::Forward { 8 } else { 10 };
        builder.assert_eq(public[0], BabyBear::from_u8(self.mode as u8));
        let mut selector_sum = AB::Expr::ZERO;
        for i in 0..=PADDING {
            let selector = local[SELECTORS + i];
            selector_sum += selector.into();
            builder.assert_bool(selector);
            builder
                .when_first_row()
                .assert_eq(selector, BabyBear::from_bool(i == 0));
            let advance: AB::Expr = if i == PADDING {
                local[stages - 1].into() + local[PADDING]
            } else if i > 0 && i < stages {
                local[i - 1].into()
            } else {
                AB::Expr::ZERO
            };
            builder.when_transition().assert_eq(next[i], advance);
        }
        builder.assert_one(selector_sum);
        builder.when_last_row().assert_one(local[PADDING]);
        for value in &local[POLYNOMIAL..PRODUCTS] {
            builder.assert_bool(*value);
        }
        let polynomial: [AB::Expr; 256] = core::array::from_fn(|i| {
            packed::<AB>(&local[POLYNOMIAL + i * 23..POLYNOMIAL + (i + 1) * 23])
        });
        let next_polynomial: [AB::Expr; 256] = core::array::from_fn(|i| {
            packed::<AB>(&next[POLYNOMIAL + i * 23..POLYNOMIAL + (i + 1) * 23])
        });
        for i in 0..256 {
            let complement = packed::<AB>(&local[COMPLEMENTS + i * 23..COMPLEMENTS + (i + 1) * 23]);
            builder.assert_eq(
                polynomial[i].clone() + complement,
                BabyBear::from_u32(mul::MODULUS - 1),
            );
            builder
                .when_transition()
                .when(local[PADDING])
                .assert_eq(polynomial[i].clone(), next_polynomial[i].clone());
        }
        let products: Vec<_> = (0..128)
            .map(|slot| {
                mul::eval_mul(
                    builder,
                    &local[PRODUCTS + slot * mul::WIDTH..PRODUCTS + (slot + 1) * mul::WIDTH],
                )
            })
            .collect();
        for carry in &local[CARRIES..WIDTH] {
            builder.assert_bool(*carry);
        }
        for stage in 0..8 {
            let selector = local[stage];
            for (slot, (left, right, twiddle)) in
                ntt::butterflies(self.mode, stage).into_iter().enumerate()
            {
                let product = &products[slot];
                builder
                    .when(selector)
                    .assert_eq(product[0].clone(), BabyBear::from_u32(twiddle));
                let add: AB::Expr = local[CARRIES + slot * 2].into();
                let borrow: AB::Expr = local[CARRIES + slot * 2 + 1].into();
                let a = polynomial[left].clone();
                let b = polynomial[right].clone();
                match self.mode {
                    Mode::Forward => {
                        builder.when(selector).assert_eq(product[1].clone(), b);
                        builder.when_transition().when(selector).assert_eq(
                            next_polynomial[left].clone(),
                            a.clone() + product[3].clone() - add * BabyBear::from_u32(mul::MODULUS),
                        );
                        builder.when_transition().when(selector).assert_eq(
                            next_polynomial[right].clone(),
                            a - product[3].clone() + borrow * BabyBear::from_u32(mul::MODULUS),
                        );
                    }
                    Mode::Inverse => {
                        builder.when(selector).assert_eq(
                            product[1].clone(),
                            a.clone() - b.clone() + borrow * BabyBear::from_u32(mul::MODULUS),
                        );
                        builder.when_transition().when(selector).assert_eq(
                            next_polynomial[left].clone(),
                            a + b - add * BabyBear::from_u32(mul::MODULUS),
                        );
                        builder
                            .when_transition()
                            .when(selector)
                            .assert_eq(next_polynomial[right].clone(), product[3].clone());
                    }
                }
            }
        }
        if self.mode == Mode::Inverse {
            for half in 0..2 {
                let selector = local[8 + half];
                for (slot, product) in products.iter().enumerate() {
                    let index = half * 128 + slot;
                    builder
                        .when(selector)
                        .assert_eq(product[0].clone(), BabyBear::from_u32(ntt::INVERSE_256));
                    builder
                        .when(selector)
                        .assert_eq(product[1].clone(), polynomial[index].clone());
                    builder
                        .when_transition()
                        .when(selector)
                        .assert_eq(product[3].clone(), next_polynomial[index].clone());
                    let held = (1 - half) * 128 + slot;
                    builder
                        .when_transition()
                        .when(selector)
                        .assert_eq(polynomial[held].clone(), next_polynomial[held].clone());
                }
            }
        }
        let non_butterfly: AB::Expr = local[8].into() + local[9] + local[PADDING];
        for carry in &local[CARRIES..WIDTH] {
            builder.when(non_butterfly.clone()).assert_zero(*carry);
        }
        for product in &products {
            for value in product {
                builder.when(local[PADDING]).assert_zero(value.clone());
            }
        }
        // Each byte is constrained separately. Packing a public u32 into one
        // BabyBear equality would permit an alias differing by its modulus.
        for i in 0..256 {
            for byte in 0..4 {
                let start = byte * 8;
                let expected = if start < 23 {
                    packed::<AB>(
                        &local[POLYNOMIAL + i * 23 + start
                            ..POLYNOMIAL + i * 23 + (start + 8).min(23)],
                    )
                } else {
                    AB::Expr::ZERO
                };
                builder
                    .when_first_row()
                    .assert_eq(public[1 + i * 4 + byte], expected.clone());
                builder
                    .when(local[PADDING])
                    .assert_eq(public[1025 + i * 4 + byte], expected);
            }
        }
    }
}

fn encoded_product(product: &ntt::Product, row: &mut [BabyBear]) {
    let mut write = |offset, value: u32, count| {
        for bit in 0..count {
            row[offset + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
        }
    };
    for (i, value) in product.values.into_iter().enumerate() {
        write(i * 23, value, 23);
        write(
            mul::COMPLEMENTS + i * 23,
            (mul::MODULUS - 1).wrapping_sub(value),
            23,
        );
    }
    write(mul::CARRY0, product.carry0.wrapping_add(2) as u32, 13);
    write(mul::CARRY1, product.carry1.wrapping_add(4096) as u32, 14);
}
pub(crate) fn trace_with_rows(mode: Mode, rows: &[ntt::Row]) -> RowMajorMatrix<BabyBear> {
    let stages = if mode == Mode::Forward { 8 } else { 10 };
    assert_eq!(rows.len(), stages + 1);
    let mut values = vec![BabyBear::ZERO; WIDTH * HEIGHT];
    for (row_index, output) in values.chunks_exact_mut(WIDTH).enumerate() {
        let index = row_index.min(stages);
        let data = &rows[index];
        output[if index == stages { PADDING } else { index }] = BabyBear::ONE;
        for (i, value) in data.polynomial.into_iter().enumerate() {
            for bit in 0..23 {
                output[POLYNOMIAL + i * 23 + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
                output[COMPLEMENTS + i * 23 + bit] =
                    BabyBear::from_bool(((mul::MODULUS - 1).wrapping_sub(value) >> bit) & 1 != 0);
            }
        }
        for slot in 0..128 {
            encoded_product(
                &data.products[slot],
                &mut output[PRODUCTS + slot * mul::WIDTH..PRODUCTS + (slot + 1) * mul::WIDTH],
            );
            output[CARRIES + slot * 2] = BabyBear::from_bool(data.carries[slot][0]);
            output[CARRIES + slot * 2 + 1] = BabyBear::from_bool(data.carries[slot][1]);
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}
pub fn trace(witness: &Witness, statement: &Statement) -> RowMajorMatrix<BabyBear> {
    trace_with_rows(statement.mode, &ntt::rows(witness, statement))
}
pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    core::iter::once(BabyBear::from_u8(statement.mode as u8))
        .chain(
            statement
                .input
                .iter()
                .chain(&statement.output)
                .flat_map(|v| v.to_le_bytes().map(BabyBear::from_u8)),
        )
        .chain(statement.context.map(BabyBear::from_u8))
        .collect()
}
