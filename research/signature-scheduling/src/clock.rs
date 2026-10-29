//! Factorized fixed schedule with a nonwrapping high bank.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

fn shape(low: usize, high: usize) {
    assert!(low >= 2 && high >= 2 && low.is_power_of_two() && high.is_power_of_two());
    assert!(low.checked_mul(high).is_some_and(|size| size <= 8192));
}

pub fn at<AB: AirBuilder>(
    row: &[AB::Var],
    offset: usize,
    low: usize,
    high: usize,
    position: usize,
) -> AB::Expr {
    shape(low, high);
    assert!(position < low * high && offset + low + high <= row.len());
    let lower: AB::Expr = row[offset + position % low].into();
    lower * row[offset + low + position / low]
}

pub fn interval<AB: AirBuilder>(
    row: &[AB::Var],
    offset: usize,
    low: usize,
    high: usize,
    from: usize,
    to: usize,
) -> AB::Expr {
    shape(low, high);
    assert!(from <= to && to <= low * high);
    (from..to)
        .map(|position| at::<AB>(row, offset, low, high, position))
        .sum()
}

pub fn eval<AB: AirBuilder>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    offset: usize,
    low: usize,
    high: usize,
) {
    shape(low, high);
    assert!(offset + low + high <= local.len() && offset + low + high <= next.len());
    let mut low_total = AB::Expr::ZERO;
    let mut high_total = AB::Expr::ZERO;
    for index in 0..low {
        let value = local[offset + index];
        builder.assert_bool(value);
        low_total += value.into();
        builder
            .when_first_row()
            .assert_eq(value, AB::F::from_bool(index == 0));
        builder.when_transition().assert_eq(
            next[offset + index],
            local[offset + (index + low - 1) % low],
        );
    }
    let carry = local[offset + low - 1];
    for index in 0..high {
        let value = local[offset + low + index];
        builder.assert_bool(value);
        high_total += value.into();
        builder
            .when_first_row()
            .assert_eq(value, AB::F::from_bool(index == 0));
        let previous = if index == 0 {
            AB::Expr::ZERO
        } else {
            local[offset + low + index - 1].into()
        };
        let current: AB::Expr = value.into();
        builder.when_transition().assert_eq(
            next[offset + low + index],
            current.clone() + (previous - current) * carry,
        );
    }
    builder.assert_one(low_total);
    builder.assert_one(high_total);
    builder.when_last_row().assert_one(local[offset + low - 1]);
    builder
        .when_last_row()
        .assert_one(local[offset + low + high - 1]);
}

pub struct FactorClockAir<const LOW: usize, const HIGH: usize>;
impl<F, const LOW: usize, const HIGH: usize> BaseAir<F> for FactorClockAir<LOW, HIGH> {
    fn width(&self) -> usize {
        shape(LOW, HIGH);
        LOW + HIGH
    }
}
impl<AB: AirBuilder<F = BabyBear>, const LOW: usize, const HIGH: usize> Air<AB>
    for FactorClockAir<LOW, HIGH>
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        eval(
            builder,
            main.current_slice(),
            main.next_slice(),
            0,
            LOW,
            HIGH,
        );
    }
}

pub fn trace(low: usize, high: usize) -> RowMajorMatrix<BabyBear> {
    shape(low, high);
    let width = low + high;
    let mut values = vec![BabyBear::ZERO; low * high * width];
    for position in 0..low * high {
        values[position * width + position % low] = BabyBear::ONE;
        values[position * width + low + position / low] = BabyBear::ONE;
    }
    RowMajorMatrix::new(values, width)
}
