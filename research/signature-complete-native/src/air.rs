use crate::{decoding, hint_rows, keccak, layout::*, matrix, ntt, program, sampler, sources};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

/// Complete bounded native signature and note owner equations.
pub struct FullPrivateSignatureOwnerAir;
impl<F> BaseAir<F> for FullPrivateSignatureOwnerAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for FullPrivateSignatureOwnerAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let mut total = AB::Expr::ZERO;
        for pc in 0..HEIGHT {
            let value = local[CLOCK + pc];
            builder.assert_bool(value);
            total += value.into();
            builder
                .when_first_row()
                .assert_eq(value, BabyBear::from_bool(pc == 0));
            let predecessor = if pc == 0 {
                AB::Expr::ZERO
            } else {
                program::at::<AB>(local, pc - 1)
            };
            builder
                .when_transition()
                .assert_eq(next[CLOCK + pc], predecessor);
        }
        builder.assert_one(total);
        builder
            .when_last_row()
            .assert_one(local[CLOCK + HEIGHT - 1]);
        for column in KEY..MESSAGE {
            builder
                .when_transition()
                .assert_eq(next[column], local[column]);
        }
        // Every Keccak slot and internal join executes on every physical row.
        keccak::eval(builder);
        sources::eval(builder);
        decoding::eval(builder);
        sampler::eval(builder);
        ntt::eval(builder);
        matrix::eval(builder);
        hint_rows::eval(builder);
    }
}
