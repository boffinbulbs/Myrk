//! Canonical signature decoding equations routed by the one global clock.
//! Adapted from the pinned Thorum signature source, without its child AIR.
use crate::{layout::*, packing, program};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    let z_phase = program::range::<AB>(local, 0, 448);
    for byte in 0..10 {
        let bits = &local[Z_MESSAGE + 8 * byte..Z_MESSAGE + 8 * (byte + 1)];
        for bit in bits {
            builder.assert_bool(*bit);
        }
        let expected: AB::Expr = (0..448)
            .map(|position| {
                program::at::<AB>(local, position)
                    * crate::packed::byte_at::<AB>(
                        local,
                        position,
                        crate::packed::Bank::Signature,
                        64 + 10 * position + byte,
                    )
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
        let selector = program::at::<AB>(local, index / 4);
        builder.when_first_row().assert_zero(local[column]);
        builder.when_transition().assert_eq(
            next[column],
            local[column].into() + selector * (normal[index % 4].clone() - local[column]),
        );
    }
    for bit in &local[CUTS..SIGN_BITS] {
        builder.assert_bool(*bit);
    }
    let hint_byte: AB::Expr = (0..75)
        .map(|position| {
            program::at::<AB>(local, position)
                * crate::packed::byte_at::<AB>(
                    local,
                    position,
                    crate::packed::Bank::Signature,
                    4544 + position,
                )
        })
        .sum();
    builder.assert_eq(
        packing::packed::<AB>(&local[HINT_MESSAGE..HINT_MESSAGE + 8]),
        hint_byte,
    );
    let cuts: [AB::Expr; 8] =
        core::array::from_fn(|i| packing::packed::<AB>(&local[CUTS + i * 7..CUTS + (i + 1) * 7]));
    for i in 0..8 {
        let complement =
            packing::packed::<AB>(&local[CUT_COMPLEMENTS + i * 7..CUT_COMPLEMENTS + (i + 1) * 7]);
        builder.assert_eq(cuts[i].clone() + complement, BabyBear::from_u8(75));
        builder.assert_eq(
            cuts[i].clone(),
            crate::packed::byte_all::<AB>(local, crate::packed::Bank::Signature, 4619 + i),
        );
        if i > 0 {
            let difference = packing::packed::<AB>(
                &local[CUT_DIFFERENCES + (i - 1) * 7..CUT_DIFFERENCES + i * 7],
            );
            builder.assert_eq(cuts[i].clone(), cuts[i - 1].clone() + difference);
        }
    }
    for column in CUTS..HINT_MESSAGE {
        builder
            .when_transition()
            .assert_eq(local[column], next[column]);
    }
    let hint_phase = program::range::<AB>(local, 0, 75);
    let position: AB::Expr = (0..75)
        .map(|j| program::at::<AB>(local, j) * BabyBear::from_u8(j as u8))
        .sum();
    let active: AB::Expr = local[HINT_ACTIVE].into();
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
    let index = packing::packed::<AB>(&local[HINT_MESSAGE..HINT_MESSAGE + 8]);
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
                old.clone() + selected.clone() * (local[HINT_MESSAGE + bit].into() - old),
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
