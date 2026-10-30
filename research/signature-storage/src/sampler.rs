//! Actual sequential SampleInBall state from the same signature seed XOF.
//! No public challenge polynomial or diagnostic statement is consumed.
use crate::{layout::*, packing, program, MODULUS};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    for bit in &local[SIGN_BITS..PLUS] {
        builder.assert_bool(*bit);
    }
    for byte in 0..8 {
        builder.assert_eq(
            local[CHALLENGE_XOF + byte],
            packing::packed::<AB>(&local[SIGN_BITS + 8 * byte..SIGN_BITS + 8 * (byte + 1)]),
        );
    }
    let phase = program::range::<AB>(local, program::SAMPLE_START, program::SAMPLE_END);
    let take: AB::Expr = local[TAKE].into();
    builder.assert_bool(local[TAKE]);
    builder.assert_zero(take.clone() * (AB::Expr::ONE - phase.clone()));
    builder.assert_zero(take.clone() * local[COUNT + 60]);
    let active = crate::activity::bind(builder, local[ACTIVE_CHALLENGE], phase, local[COUNT + 60]);
    let mut count_sum = AB::Expr::ZERO;
    let mut accepted = AB::Expr::ZERO;
    for step in 0..=60 {
        let selector = local[COUNT + step];
        builder.assert_bool(selector);
        count_sum += selector.into();
        accepted += selector * BabyBear::from_usize(step);
        builder
            .when_first_row()
            .assert_eq(selector, BabyBear::from_bool(step == 0));
        let previous = if step == 0 {
            AB::Expr::ZERO
        } else {
            Into::<AB::Expr>::into(local[COUNT + step - 1])
        };
        builder.when_transition().assert_eq(
            next[COUNT + step],
            (AB::Expr::ONE - take.clone()) * selector + take.clone() * previous,
        );
    }
    builder.assert_one(count_sum);
    builder
        .when(program::at::<AB>(local, program::SAMPLE_END))
        .assert_one(local[COUNT + 60]);
    builder.when_last_row().assert_one(local[COUNT + 60]);
    for bit in &local[CANDIDATE..INDEX] {
        builder.assert_bool(*bit);
        builder
            .when(AB::Expr::ONE - active.clone())
            .assert_zero(*bit);
    }
    let candidate = packing::packed::<AB>(&local[CANDIDATE..LOWER]);
    let source: AB::Expr = (0..264)
        .map(|event| program::at::<AB>(local, 12 + event) * local[CHALLENGE_XOF + 8 + event])
        .sum();
    builder
        .when(active.clone())
        .assert_eq(candidate.clone(), source);
    let destination: AB::Expr = BabyBear::from_u32(196).into();
    let destination = destination
        + (0..60)
            .map(|step| local[COUNT + step] * BabyBear::from_usize(step))
            .sum::<AB::Expr>();
    let lower = packing::packed::<AB>(&local[LOWER..UPPER]);
    let upper = packing::packed::<AB>(&local[UPPER..INDEX]);
    builder
        .when(take.clone())
        .assert_eq(candidate.clone() + lower.clone(), destination.clone());
    builder.when(take.clone()).assert_zero(upper.clone());
    builder
        .when(active.clone() - take.clone())
        .assert_eq(destination + AB::Expr::ONE + upper, candidate.clone());
    builder
        .when(active.clone() - take.clone())
        .assert_zero(lower);
    let mut index_sum = AB::Expr::ZERO;
    let mut index_value = AB::Expr::ZERO;
    let mut old_plus = AB::Expr::ZERO;
    let mut old_minus = AB::Expr::ZERO;
    let mut weight = AB::Expr::ZERO;
    for i in 0..256 {
        let select = local[INDEX + i];
        let plus = local[PLUS + i];
        let minus = local[MINUS + i];
        builder.assert_bool(select);
        builder.assert_bool(plus);
        builder.assert_bool(minus);
        builder.assert_zero(plus * minus);
        builder.when_first_row().assert_zero(plus);
        builder.when_first_row().assert_zero(minus);
        index_sum += select.into();
        index_value += select * BabyBear::from_usize(i);
        old_plus += select * plus;
        old_minus += select * minus;
        weight += plus.into() + minus;
    }
    builder.assert_eq(index_sum, take.clone());
    builder.assert_eq(index_value, take.clone() * candidate);
    builder.assert_eq(local[OLD_PLUS], old_plus);
    builder.assert_eq(local[OLD_MINUS], old_minus);
    builder.assert_bool(local[OLD_PLUS]);
    builder.assert_bool(local[OLD_MINUS]);
    builder.assert_eq(weight, accepted);
    let sign: AB::Expr = (0..60)
        .map(|step| local[COUNT + step] * local[SIGN_BITS + step])
        .sum();
    for i in 0..256 {
        let destination = if i >= 196 {
            Into::<AB::Expr>::into(local[COUNT + i - 196])
        } else {
            AB::Expr::ZERO
        };
        let plus: AB::Expr = local[PLUS + i].into();
        let minus: AB::Expr = local[MINUS + i].into();
        builder.when_transition().assert_eq(
            next[PLUS + i],
            plus.clone()
                + take.clone() * destination.clone() * (local[OLD_PLUS] - local[PLUS + i])
                + local[INDEX + i] * (AB::Expr::ONE - sign.clone() - plus.clone()),
        );
        builder.when_transition().assert_eq(
            next[MINUS + i],
            minus.clone()
                + take.clone() * destination * (local[OLD_MINUS] - local[MINUS + i])
                + local[INDEX + i] * (sign.clone() - minus.clone()),
        );
        builder.assert_eq(
            local[CHALLENGE + i],
            plus + minus * BabyBear::from_u32(MODULUS - 1),
        );
    }
    for bit in 0..9 {
        builder.assert_bool(local[CURSOR + bit]);
        builder.when_first_row().assert_eq(
            local[CURSOR + bit],
            BabyBear::from_bool((8 >> bit) & 1 == 1),
        );
    }
    let cursor = packing::packed::<AB>(&local[CURSOR..CURSOR + 9]);
    builder.when_transition().assert_eq(
        packing::packed::<AB>(&next[CURSOR..CURSOR + 9]),
        cursor.clone() + active.clone(),
    );
    let expected_cursor: AB::Expr = (0..264)
        .map(|event| program::at::<AB>(local, 12 + event) * BabyBear::from_usize(8 + event))
        .sum();
    builder.when(active).assert_eq(cursor, expected_cursor);
}
