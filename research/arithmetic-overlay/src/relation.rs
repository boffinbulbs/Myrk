use super::{clock, hints, layout::*, mul, schedule};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub struct OverlayAir;
impl<F> BaseAir<F> for OverlayAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for OverlayAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let public = builder.public_values().to_vec();
        clock::eval(builder, row, next, 0, LOW, HIGH);
        let product_mode: AB::Expr = row[PRODUCT_MODE].into();
        let hint_mode: AB::Expr = row[HINT_MODE].into();
        let (expected_product, expected_hint) = schedule::selectors::<AB>(row);
        builder.assert_bool(row[PRODUCT_MODE]);
        builder.assert_bool(row[HINT_MODE]);
        builder.assert_eq(product_mode.clone(), expected_product);
        builder.assert_eq(hint_mode.clone(), expected_hint);
        builder.assert_zero(product_mode.clone() * hint_mode.clone());
        for column in SOURCE..PRODUCT_SINK {
            builder
                .when_transition()
                .assert_eq(next[column], row[column]);
        }
        let idle = AB::Expr::ONE - product_mode.clone() - hint_mode.clone();
        for cell in &row[BANK..SOURCE] {
            builder.when(idle.clone()).assert_zero(*cell);
        }
        for cell in &row[BANK + HINT_WIDTH..SOURCE] {
            builder.when(hint_mode.clone()).assert_zero(*cell);
        }
        for slot in 0..8 {
            let at = BANK + slot * mul::WIDTH;
            let product = mul::eval_mul(
                &mut builder.when(product_mode.clone()),
                &row[at..at + mul::WIDTH],
            );
            let at = BANK + slot * hints::WIDTH;
            let hint = hints::eval_use_hint(
                &mut builder.when(hint_mode.clone()),
                &row[at..at + hints::WIDTH],
            );
            let source = SOURCE + 4 * slot;
            builder
                .when(product_mode.clone())
                .assert_eq(product[0].clone(), row[source]);
            builder
                .when(product_mode.clone())
                .assert_eq(product[1].clone(), row[source + 1]);
            builder
                .when(hint_mode.clone())
                .assert_eq(hint.input, row[source + 2]);
            builder
                .when(hint_mode.clone())
                .assert_eq(hint.hint, row[source + 3]);
            // Inactive branch expressions are never used without their mode.
            for (sink, value, mode, expected) in [
                (
                    PRODUCT_SINK + slot,
                    product[3].clone(),
                    product_mode.clone(),
                    public[slot],
                ),
                (
                    HINT_SINK + slot,
                    hint.output,
                    hint_mode.clone(),
                    public[8 + slot],
                ),
            ] {
                builder.when_first_row().assert_zero(row[sink]);
                builder
                    .when_transition()
                    .assert_eq(next[sink], row[sink].into() + mode * (value - row[sink]));
                builder.when_last_row().assert_eq(row[sink], expected);
            }
        }
    }
}
