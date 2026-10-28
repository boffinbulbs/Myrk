use crate::reconstructed_row::{
    MODULUS,
    air::*,
    hints, mul, ntt, packing,
    program::{self, Kind},
};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(air: &ReconstructedRowAir, builder: &mut AB) {
    let main = builder.main();
    let row = main.current_slice();
    let next = main.next_slice();
    for bit in &row[WRITES..T1_BITS] {
        builder.assert_bool(*bit);
    }
    let writes: [AB::Expr; 16] = core::array::from_fn(|slot| {
        packed::<AB>(&row[WRITES + slot * 46..WRITES + slot * 46 + 23])
    });
    for (slot, value) in writes.iter().enumerate() {
        builder.assert_eq(
            value.clone() + packed::<AB>(&row[WRITES + slot * 46 + 23..WRITES + (slot + 1) * 46]),
            BabyBear::from_u32(MODULUS - 1),
        );
    }
    let products: Vec<_> = (0..8)
        .map(|lane| {
            mul::eval_mul(
                builder,
                &row[PRODUCTS + lane * mul::WIDTH..PRODUCTS + (lane + 1) * mul::WIDTH],
            )
        })
        .collect();
    let matrix = sum_clock::<AB>(row, 0..program::MATRIX_END);
    for lane in 0..8 {
        let count = COUNT + lane * 257;
        let candidate = packed::<AB>(&row[CANDIDATE + lane * 24..CANDIDATE + lane * 24 + 23]);
        let mut x = row[TAKE + lane] * candidate;
        let mut y: AB::Expr = (0..7)
            .map(|column| {
                let source: AB::Expr = (0..256)
                    .map(|index| row[count + index] * row[ZHAT + column * 256 + index])
                    .sum();
                sum_clock::<AB>(row, column * 42..column * 42 + 42) * source
            })
            .sum();
        let selected_old: AB::Expr = (0..256)
            .map(|index| row[count + index] * row[ACCUMULATOR + index])
            .sum();
        builder
            .when(matrix.clone())
            .assert_eq(writes[lane * 2].clone(), selected_old);
        builder.when(matrix.clone()).assert_eq(
            writes[lane * 2].clone() + products[lane][3].clone(),
            writes[lane * 2 + 1].clone() + row[FLAGS + lane * 2] * BabyBear::from_u32(MODULUS),
        );
        builder
            .when(matrix.clone())
            .assert_zero(row[FLAGS + lane * 2 + 1]);
        for (pc, instruction) in air.instructions.iter().enumerate() {
            let p = row[CLOCK + pc];
            match instruction.kind {
                Kind::Forward => {
                    let (_, right, twiddle) = instruction.butterflies[lane];
                    x += p * BabyBear::from_u32(twiddle);
                    y += p * row[WORK + right];
                }
                Kind::Inverse => {
                    let (left, right, twiddle) = instruction.butterflies[lane];
                    x += p * BabyBear::from_u32(twiddle);
                    y += p
                        * (row[ACCUMULATOR + left] - row[ACCUMULATOR + right]
                            + row[FLAGS + lane * 2 + 1] * BabyBear::from_u32(MODULUS));
                }
                Kind::Point(group) => {
                    x += p * row[CHAT + group * 8 + lane];
                    y += p * row[WORK + group * 8 + lane];
                }
                Kind::Normalize(group) => {
                    x += p * BabyBear::from_u32(ntt::INVERSE_256);
                    y += p * row[ACCUMULATOR + group * 8 + lane];
                }
                _ => {}
            }
        }
        builder.assert_eq(products[lane][0].clone(), x);
        builder.assert_eq(products[lane][1].clone(), y);
    }
    for (pc, instruction) in air.instructions.iter().enumerate() {
        let p = row[CLOCK + pc];
        match instruction.kind {
            Kind::Forward | Kind::Inverse => {
                let bank = if matches!(instruction.kind, Kind::Forward) {
                    WORK
                } else {
                    ACCUMULATOR
                };
                for (lane, product) in products.iter().enumerate() {
                    let (left, right, _) = instruction.butterflies[lane];
                    let a: AB::Expr = row[bank + left].into();
                    let b: AB::Expr = row[bank + right].into();
                    let add = row[FLAGS + lane * 2];
                    let borrow = row[FLAGS + lane * 2 + 1];
                    if matches!(instruction.kind, Kind::Forward) {
                        builder.when(p).assert_eq(
                            writes[lane * 2].clone(),
                            a.clone() + product[3].clone() - add * BabyBear::from_u32(MODULUS),
                        );
                        builder.when(p).assert_eq(
                            writes[lane * 2 + 1].clone(),
                            a - product[3].clone() + borrow * BabyBear::from_u32(MODULUS),
                        );
                    } else {
                        builder.when(p).assert_eq(
                            writes[lane * 2].clone(),
                            a + b - add * BabyBear::from_u32(MODULUS),
                        );
                        builder
                            .when(p)
                            .assert_eq(writes[lane * 2 + 1].clone(), product[3].clone());
                    }
                }
            }
            Kind::Point(group) => {
                for (lane, product) in products.iter().enumerate() {
                    builder.when(p).assert_eq(
                        writes[lane * 2].clone(),
                        row[ACCUMULATOR + group * 8 + lane],
                    );
                    builder.when(p).assert_eq(
                        writes[lane * 2 + 1].clone(),
                        writes[lane * 2].clone() - product[3].clone()
                            + row[FLAGS + lane * 2] * BabyBear::from_u32(MODULUS),
                    );
                    builder.when(p).assert_zero(row[FLAGS + lane * 2 + 1]);
                }
            }
            Kind::Normalize(_) => {
                for lane in 0..8 {
                    builder
                        .when(p)
                        .assert_eq(writes[lane].clone(), products[lane][3].clone());
                }
                for value in &writes[8..] {
                    builder.when(p).assert_zero(value.clone());
                }
                for flag in &row[FLAGS..T1_BITS] {
                    builder.when(p).assert_zero(*flag);
                }
            }
            Kind::Hint(_) | Kind::Pad => {
                for value in &writes {
                    builder.when(p).assert_zero(value.clone());
                }
                for flag in &row[FLAGS..T1_BITS] {
                    builder.when(p).assert_zero(*flag);
                }
            }
            Kind::Matrix { .. } => {}
        }
    }
    let scaled: Vec<_> = (0..2)
        .flat_map(|pair| {
            packing::scaled_t1(
                builder,
                &row[T1_BITS + pair * 40..T1_BITS + (pair + 1) * 40],
            )
        })
        .collect();
    for lane in 0..8 {
        let source: AB::Expr = (0..32)
            .map(|group| row[CLOCK + group] * row[T1 + group * 8 + lane])
            .sum();
        builder.assert_eq(
            packed::<AB>(&row[T1_BITS + lane * 10..T1_BITS + (lane + 1) * 10]),
            source,
        );
    }
    for index in 0..256 {
        let matrix_change: AB::Expr = (0..8)
            .map(|lane| {
                row[TAKE + lane]
                    * row[COUNT + lane * 257 + index]
                    * (writes[lane * 2 + 1].clone() - row[ACCUMULATOR + index])
            })
            .sum();
        let routed_a: AB::Expr = air.a_routes[index]
            .iter()
            .map(|&(pc, slot)| row[CLOCK + pc] * (writes[slot].clone() - row[ACCUMULATOR + index]))
            .sum();
        builder.when_transition().assert_eq(
            next[ACCUMULATOR + index],
            row[ACCUMULATOR + index].into() + matrix_change + routed_a,
        );
        let routed_w: AB::Expr = air.w_routes[index]
            .iter()
            .map(|&(pc, slot)| row[CLOCK + pc] * (writes[slot].clone() - row[WORK + index]))
            .sum();
        let load = row[CLOCK + index / 8] * (scaled[index % 8].clone() - row[WORK + index]);
        builder.when_transition().assert_eq(
            next[WORK + index],
            row[WORK + index].into() + load + routed_w,
        );
    }
    let used: Vec<_> = (0..8)
        .map(|lane| {
            hints::eval_use_hint(
                builder,
                &row[USE_HINT + lane * hints::WIDTH..USE_HINT + (lane + 1) * hints::WIDTH],
            )
        })
        .collect();
    for (lane, value) in used.iter().enumerate() {
        let input: AB::Expr = (0..32)
            .map(|group| {
                row[CLOCK + program::NORMALIZE_END + group] * row[ACCUMULATOR + group * 8 + lane]
            })
            .sum();
        let hint: AB::Expr = (0..32)
            .map(|group| {
                row[CLOCK + program::NORMALIZE_END + group] * row[HINTS + group * 8 + lane]
            })
            .sum();
        builder.assert_eq(value.input.clone(), input);
        builder.assert_eq(value.hint.clone(), hint);
        let _ = (&value.high, &value.low, &value.positive);
    }
    for index in 0..128 {
        let lane = (index % 4) * 2;
        let packed =
            used[lane].output.clone() + used[lane + 1].output.clone() * BabyBear::from_u8(16);
        builder.when_transition().assert_eq(
            next[W1 + index],
            row[W1 + index].into()
                + row[CLOCK + program::NORMALIZE_END + index / 4] * (packed - row[W1 + index]),
        );
    }
}
