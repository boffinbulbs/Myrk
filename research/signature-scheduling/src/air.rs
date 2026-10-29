use crate::{decoding, hint_rows, keccak, layout::*, matrix, ntt, sampler, sources};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;

/// Complete bounded native signature and note owner equations.
pub struct FactorSignatureOwnerAir;
impl<F> BaseAir<F> for FactorSignatureOwnerAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for FactorSignatureOwnerAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        crate::clock::eval(builder, local, next, CLOCK, CLOCK_LOW, CLOCK_HIGH);
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
