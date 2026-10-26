//! Bounded integer constraints for multiplication modulo 8380417.
//! A caller supplies the surrounding dataflow and trace layout.

use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub const MODULUS: u32 = 8_380_417;
pub const RADIX: u32 = 4096;
pub const VALUE_BITS: usize = 23;
pub const VALUES: usize = 0;
pub const COMPLEMENTS: usize = 4 * VALUE_BITS;
pub const CARRY0: usize = COMPLEMENTS + 4 * VALUE_BITS;
pub const CARRY1: usize = CARRY0 + 13;
pub const WIDTH: usize = CARRY1 + 14;

pub(crate) fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit)
}

/// Values have fixed order x, y, quotient, result. Every value and its
/// complement has 23 Boolean bits. The signed carries have bounded offsets.
/// The three radix 4096 residuals are strictly between minus p and p, making
/// their BabyBear equalities exact integer equalities.
pub fn eval_mul<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    local: &[AB::Var],
) -> [AB::Expr; 4] {
    assert_eq!(local.len(), WIDTH);
    for bit in local {
        builder.assert_bool(*bit);
    }
    let values: [AB::Expr; 4] =
        core::array::from_fn(|i| packed::<AB>(&local[i * 23..(i + 1) * 23]));
    for i in 0..4 {
        let complement = packed::<AB>(&local[COMPLEMENTS + i * 23..COMPLEMENTS + (i + 1) * 23]);
        builder.assert_eq(values[i].clone() + complement, AB::F::from_u32(MODULUS - 1));
    }
    let lows: [AB::Expr; 4] = core::array::from_fn(|i| packed::<AB>(&local[i * 23..i * 23 + 12]));
    let highs: [AB::Expr; 4] =
        core::array::from_fn(|i| packed::<AB>(&local[i * 23 + 12..(i + 1) * 23]));
    let carry0 = packed::<AB>(&local[CARRY0..CARRY1]) - AB::F::from_u8(2);
    let carry1 = packed::<AB>(&local[CARRY1..WIDTH]) - AB::F::from_u32(4096);
    builder.assert_zero(
        lows[0].clone() * lows[1].clone()
            - lows[2].clone()
            - lows[3].clone()
            - carry0.clone() * AB::F::from_u32(RADIX),
    );
    builder.assert_zero(
        lows[0].clone() * highs[1].clone() + highs[0].clone() * lows[1].clone()
            - lows[2].clone() * AB::F::from_u32(2046)
            - highs[2].clone()
            - highs[3].clone()
            + carry0
            - carry1.clone() * AB::F::from_u32(RADIX),
    );
    builder.assert_zero(
        highs[0].clone() * highs[1].clone() - highs[2].clone() * AB::F::from_u32(2046) + carry1,
    );
    values
}
