use crate::{decoding, keccak, layout::*, ntt, program, sampler, sources};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

/// Initial sources and sixteen direct forward transforms. Signature verification is unfinished.
pub struct PrivateForwardNttAir;
impl<F> BaseAir<F> for PrivateForwardNttAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for PrivateForwardNttAir {
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
    }
}
