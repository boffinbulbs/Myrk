use crate::reconstructed_row::{MODULUS, air::*};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let row = main.current_slice();
    let next = main.next_slice();
    for state in 0..=8 {
        let mut total = AB::Expr::ZERO;
        for index in 0..=256 {
            let c = row[COUNT + state * 257 + index];
            builder.assert_bool(c);
            total += c.into();
            if state == 0 {
                builder
                    .when_first_row()
                    .assert_eq(c, BabyBear::from_bool(index == 0));
            }
        }
        builder.assert_one(total);
        for bit in &row[CURSOR + state * 10..CURSOR + (state + 1) * 10] {
            builder.assert_bool(*bit);
        }
    }
    builder
        .when_first_row()
        .assert_zero(packed::<AB>(&row[CURSOR..CURSOR + 10]));
    let boundary = sum_clock::<AB>(row, (0..7).map(|c| c * 42 + 41));
    builder
        .when(boundary)
        .assert_one(row[COUNT + 8 * 257 + 256]);
    builder.when_last_row().assert_one(row[COUNT + 256]);
    let reload = reset::<AB>(row);
    for index in 0..=256 {
        builder.when_transition().assert_eq(
            next[COUNT + index],
            (AB::Expr::ONE - reload.clone()) * row[COUNT + 8 * 257 + index]
                + reload.clone() * BabyBear::from_bool(index == 0),
        );
    }
    builder.when_transition().assert_eq(
        packed::<AB>(&next[CURSOR..CURSOR + 10]),
        (AB::Expr::ONE - reload) * packed::<AB>(&row[CURSOR + 8 * 10..CURSOR + 9 * 10]),
    );
    for lane in 0..8 {
        let start = COUNT + lane * 257;
        let active = AB::Expr::ONE - row[start + 256];
        let take: AB::Expr = row[TAKE + lane].into();
        builder.assert_bool(row[TAKE + lane]);
        builder.assert_zero(take.clone() * row[start + 256]);
        for index in 0..=256 {
            let previous: AB::Expr = if index > 0 {
                row[start + index - 1].into()
            } else {
                AB::Expr::ZERO
            };
            builder.assert_eq(
                row[start + 257 + index],
                (AB::Expr::ONE - take.clone()) * row[start + index] + take.clone() * previous,
            );
        }
        for bit in row[CANDIDATE + lane * 24..CANDIDATE + (lane + 1) * 24]
            .iter()
            .chain(&row[SLACK + lane * 23..SLACK + (lane + 1) * 23])
        {
            builder.assert_bool(*bit);
            builder
                .when(AB::Expr::ONE - active.clone())
                .assert_zero(*bit);
        }
        for byte in 0..3 {
            let source: AB::Expr = (0..42)
                .map(|local| {
                    sum_clock::<AB>(row, (0..7).map(|c| c * 42 + local))
                        * row[XOF + local * 24 + lane * 3 + byte]
                })
                .sum();
            builder.when(active.clone()).assert_eq(
                packed::<AB>(
                    &row[CANDIDATE + lane * 24 + byte * 8..CANDIDATE + lane * 24 + (byte + 1) * 8],
                ),
                source,
            );
        }
        let candidate = packed::<AB>(&row[CANDIDATE + lane * 24..CANDIDATE + lane * 24 + 23]);
        let slack = packed::<AB>(&row[SLACK + lane * 23..SLACK + (lane + 1) * 23]);
        builder.when(take.clone()).assert_eq(
            candidate.clone() + slack.clone(),
            BabyBear::from_u32(MODULUS - 1),
        );
        builder
            .when(active.clone() - take)
            .assert_eq(candidate, slack + BabyBear::from_u32(MODULUS));
        let cursor = packed::<AB>(&row[CURSOR + lane * 10..CURSOR + (lane + 1) * 10]);
        builder.assert_eq(
            packed::<AB>(&row[CURSOR + (lane + 1) * 10..CURSOR + (lane + 2) * 10]),
            cursor.clone() + active.clone() * BabyBear::from_u8(3),
        );
        let expected: AB::Expr = (0..42)
            .map(|local| {
                sum_clock::<AB>(row, (0..7).map(|c| c * 42 + local))
                    * BabyBear::from_usize(local * 24 + lane * 3)
            })
            .sum();
        builder.when(active).assert_eq(cursor, expected);
    }
}
