//! Two arithmetic interpretations bound to the original global clock.
use crate::{full_program as fp, hints, layout::*, ntt, program};
use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

const _: () = {
    assert!(ntt::START == 450 && ntt::TRANSFORMS == 16);
    assert!(ntt::ROWS_PER_TRANSFORM == 192 && ntt::END == fp::INVERSE_START);
    assert!(fp::INVERSE_START == 3522 && fp::INVERSE_END == 5314);
    assert!(USE_HINT + 8 * hints::WIDTH < W1);
};

pub(crate) fn eval<AB: AirBuilder>(builder: &mut AB, row: &[AB::Var]) {
    let product: AB::Expr = row[PRODUCT_MODE].into();
    let hint: AB::Expr = row[HINT_MODE].into();
    let mut expected_product = AB::Expr::ZERO;
    let mut expected_hint = AB::Expr::ZERO;
    for t in 0..ntt::TRANSFORMS {
        let start = ntt::START + ntt::ROWS_PER_TRANSFORM * t;
        expected_product += program::range::<AB>(row, start + 32, start + 160);
    }
    for i in 0..8 {
        let start = fp::INVERSE_START + 224 * i;
        expected_product += program::range::<AB>(row, start + 32, start + 192);
        expected_hint += program::range::<AB>(row, start + 192, start + 224);
    }
    builder.assert_bool(row[PRODUCT_MODE]);
    builder.assert_bool(row[HINT_MODE]);
    builder.assert_eq(product.clone(), expected_product);
    builder.assert_eq(hint.clone(), expected_hint);
    builder.assert_zero(product.clone() * hint.clone());
    let idle = AB::Expr::ONE - product - hint.clone();
    for cell in &row[USE_HINT..W1] {
        builder.when(idle.clone()).assert_zero(*cell);
    }
    for cell in &row[USE_HINT + 8 * hints::WIDTH..W1] {
        builder.when(hint.clone()).assert_zero(*cell);
    }
}

pub(crate) fn fill(row: &mut [BabyBear], at: usize) {
    assert!(at < HEIGHT && row.len() == WIDTH);
    let product = matches!(ntt::operation(at), Some((_, ntt::Op::Butterfly { .. })))
        || matches!(
            ntt::inverse_operation(at),
            Some((
                _,
                ntt::InverseOp::Butterfly { .. } | ntt::InverseOp::Normalize(_)
            ))
        );
    let hint = matches!(
        ntt::inverse_operation(at),
        Some((_, ntt::InverseOp::Output(_)))
    );
    row[PRODUCT_MODE] = BabyBear::from_bool(product);
    row[HINT_MODE] = BabyBear::from_bool(hint);
}
