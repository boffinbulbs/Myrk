use super::*;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::Field;

const FIELD_MODULUS: u32 = 2_013_265_921;

fn fixture(x: u32, y: u32) -> (Witness, Statement) {
    let result = (u64::from(x) * u64::from(y) % u64::from(mul::MODULUS)) as u32;
    (
        Witness::for_operands(x, y).unwrap(),
        Statement::new(x, y, result, [0x45; 64]).unwrap(),
    )
}

fn check_air(trace: &RowMajorMatrix<BabyBear>, statement: &Statement) -> bool {
    // This intentionally bypasses the typed statement's host validation.
    check_all_constraints(
        &MultiplicationAir,
        trace,
        &public_values(statement),
        Some(1),
    )
    .is_ok()
}

fn floor_carries(values: [u32; 4]) -> (i32, i32) {
    let [x, y, k, z] = values;
    let low = |v: u32| i64::from(v & 4095);
    let high = |v: u32| i64::from(v >> 12);
    let carry0 = (low(x) * low(y) - low(k) - low(z)).div_euclid(4096);
    let carry1 = (low(x) * high(y) + high(x) * low(y) - 2046 * low(k) - high(k) - high(z) + carry0)
        .div_euclid(4096);
    (carry0 as i32, carry1 as i32)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Attack {
    NegativeFieldAlias,
    PositiveFieldAlias,
    CarryFieldAlias,
    PublicIntegerAlias,
    QuotientAtModulus,
    NonbooleanOperand,
    NonbooleanComplement,
    NonbooleanCarry,
    ComplementMismatch,
    CarryMismatch,
}

pub(crate) fn attack_trace(attack: Attack) -> (RowMajorMatrix<BabyBear>, Statement) {
    if matches!(
        attack,
        Attack::NegativeFieldAlias | Attack::PositiveFieldAlias | Attack::CarryFieldAlias
    ) {
        let values = if matches!(attack, Attack::NegativeFieldAlias) {
            [0, 0, 240, 1_965_841]
        } else {
            [8_380_416, 8_380_416, 8_380_174, 6_414_577]
        };
        let [x, y, k, z] = values;
        let residual =
            i64::from(x) * i64::from(y) - i64::from(mul::MODULUS) * i64::from(k) - i64::from(z);
        assert_eq!(residual.abs(), i64::from(FIELD_MODULUS));
        assert!(values.iter().all(|v| *v < mul::MODULUS));
        let (c0, c1) = floor_carries(values);
        let mut trace = air::trace_with_values(values, c0, c1);
        if matches!(attack, Attack::CarryFieldAlias) {
            let low = |v: u32| BabyBear::from_u32(v & 4095);
            let high = |v: u32| BabyBear::from_u32(v >> 12);
            let base = BabyBear::from_u32(4096);
            let c0 = (low(x) * low(y) - low(k) - low(z)) * base.inverse();
            let c1 = (low(x) * high(y) + high(x) * low(y)
                - BabyBear::from_u32(2046) * low(k)
                - high(k)
                - high(z)
                + c0)
                * base.inverse();
            assert_eq!(
                high(x) * high(y) - BabyBear::from_u32(2046) * high(k) + c1,
                BabyBear::ZERO
            );
            assert!(c0 + BabyBear::TWO != BabyBear::ZERO && c0 + BabyBear::TWO != BabyBear::ONE);
            for row in trace.values.chunks_exact_mut(air::WIDTH) {
                row[mul::CARRY0..].fill(BabyBear::ZERO);
                row[mul::CARRY0] = c0 + BabyBear::TWO;
                row[mul::CARRY1] = c1 + BabyBear::from_u32(4096);
            }
            // All three residuals are now zero in the field. Only the bit
            // restrictions prevent treating these field values as carries.
        }
        return (trace, Statement::new(x, y, z, [0x45; 64]).unwrap());
    }
    let (witness, mut statement) = fixture(2, 3);
    let mut trace = trace(&witness, &statement);
    if matches!(attack, Attack::PublicIntegerAlias) {
        statement.x += FIELD_MODULUS;
        assert_eq!(BabyBear::from_u32(statement.x), BabyBear::from_u32(2));
        return (trace, statement);
    }
    if matches!(attack, Attack::QuotientAtModulus) {
        let values = [2, 3, mul::MODULUS, 6];
        let (c0, c1) = floor_carries(values);
        trace = air::trace_with_values(values, c0, c1);
        return (trace, statement);
    }
    for row in trace.values.chunks_exact_mut(air::WIDTH) {
        match attack {
            Attack::NonbooleanOperand => {
                row[0] += BabyBear::TWO;
                row[1] -= BabyBear::ONE;
            }
            Attack::NonbooleanComplement => {
                row[mul::COMPLEMENTS] += BabyBear::TWO;
                row[mul::COMPLEMENTS + 1] -= BabyBear::ONE;
            }
            Attack::NonbooleanCarry => {
                row[mul::CARRY0] += BabyBear::TWO;
                row[mul::CARRY0 + 1] -= BabyBear::ONE;
            }
            Attack::ComplementMismatch => row[mul::COMPLEMENTS] += BabyBear::ONE,
            Attack::CarryMismatch => row[mul::CARRY0] += BabyBear::ONE,
            _ => unreachable!(),
        }
    }
    (trace, statement)
}

#[test]
fn canonical_field_alias_and_bit_range_attacks_fail_the_actual_air() {
    for attack in [
        Attack::NegativeFieldAlias,
        Attack::PositiveFieldAlias,
        Attack::CarryFieldAlias,
        Attack::PublicIntegerAlias,
        Attack::QuotientAtModulus,
        Attack::NonbooleanOperand,
        Attack::NonbooleanComplement,
        Attack::NonbooleanCarry,
        Attack::ComplementMismatch,
        Attack::CarryMismatch,
    ] {
        let (trace, statement) = attack_trace(attack);
        assert!(!check_air(&trace, &statement), "{attack:?}");
    }
}

#[test]
fn valid_negative_carry_and_extreme_witnesses_pass_the_actual_air() {
    let mut saw_negative = false;
    for x in [0, 1, 4095, 4096, 4097, mul::MODULUS - 2, mul::MODULUS - 1] {
        for y in [0, 1, 4095, 4096, 4097, mul::MODULUS - 2, mul::MODULUS - 1] {
            let (witness, statement) = fixture(x, y);
            saw_negative |= witness.carry0 < 0 || witness.carry1 < 0;
            assert!((-1..=4094).contains(&witness.carry0));
            assert!((-2046..=4092).contains(&witness.carry1));
            assert!(check_air(&trace(&witness, &statement), &statement));
        }
    }
    assert!(saw_negative);
}

struct PrivateRowsAir;
impl<F> BaseAir<F> for PrivateRowsAir {
    fn width(&self) -> usize {
        mul::WIDTH
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for PrivateRowsAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let _values = mul::eval_mul(builder, main.current_slice());
    }
}

#[test]
fn a_private_gadget_is_row_local_and_requires_explicit_composed_dataflow() {
    let (first_witness, statement) = fixture(2, 3);
    let (second_witness, other) = fixture(4096, 4096);
    let mut mixed = trace(&first_witness, &statement);
    let second = trace(&second_witness, &other);
    let split = air::HEIGHT / 2 * air::WIDTH;
    mixed.values[split..].copy_from_slice(&second.values[split..]);
    assert!(check_all_constraints(&PrivateRowsAir, &mixed, &[], Some(1)).is_ok());
    assert!(!check_air(&mixed, &statement));
}
