use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

pub struct QuarticAir;

impl<F> BaseAir<F> for QuarticAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
}

impl<AB: AirBuilder> Air<AB> for QuarticAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.current_slice();
        let next = main.next_slice();
        let a: AB::Expr = current[0].into();
        let square = a.clone() * a.clone();
        builder.assert_eq(current[1], square.clone() * square);
        builder.when_transition().assert_eq(next[0], a + AB::F::ONE);
        let first = builder.public_values()[0];
        let last = builder.public_values()[1];
        builder.when_first_row().assert_eq(current[0], first);
        builder.when_last_row().assert_eq(current[0], last);
    }
}

pub fn trace() -> RowMajorMatrix<BabyBear> {
    let values = (0..256)
        .flat_map(|row| {
            let a = BabyBear::from_u32(5 + row);
            [a, a.square().square()]
        })
        .collect();
    RowMajorMatrix::new(values, 2)
}

pub fn public() -> Vec<BabyBear> {
    vec![BabyBear::from_u32(5), BabyBear::from_u32(260)]
}
