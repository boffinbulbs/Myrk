//! Shared Boolean byte windows for canonical ML DSA87 coefficients.
//! Composed consumers must reuse these exact constrained expressions.

use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub const LOWER: usize = 0;
pub const UPPER: usize = 40;
pub const NORMAL: usize = 80;
pub const COMPLEMENTS: usize = 126;
pub const NEGATIVE: usize = 172;
pub const Z_AUX_WIDTH: usize = 174;

pub(crate) fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit)
}
pub fn decode_t1<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    bits: &[AB::Var],
) -> [AB::Expr; 4] {
    assert_eq!(bits.len(), 40);
    for bit in bits {
        builder.assert_bool(*bit);
    }
    core::array::from_fn(|i| packed::<AB>(&bits[i * 10..(i + 1) * 10]))
}
pub fn scaled_t1<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    bits: &[AB::Var],
) -> [AB::Expr; 4] {
    decode_t1(builder, bits).map(|v| v * BabyBear::from_u32(8192))
}
pub fn decode_z_pair<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    bits: &[AB::Var],
    aux: &[AB::Var],
) -> [AB::Expr; 2] {
    assert_eq!(bits.len(), 40);
    assert_eq!(aux.len(), Z_AUX_WIDTH);
    for bit in bits.iter().chain(aux) {
        builder.assert_bool(*bit);
    }
    core::array::from_fn(|i| {
        let d = packed::<AB>(&bits[i * 20..(i + 1) * 20]);
        let lower = packed::<AB>(&aux[LOWER + i * 20..LOWER + (i + 1) * 20]);
        let upper = packed::<AB>(&aux[UPPER + i * 20..UPPER + (i + 1) * 20]);
        let normal = packed::<AB>(&aux[NORMAL + i * 23..NORMAL + (i + 1) * 23]);
        let complement = packed::<AB>(&aux[COMPLEMENTS + i * 23..COMPLEMENTS + (i + 1) * 23]);
        let negative: AB::Expr = aux[NEGATIVE + i].into();
        builder.assert_eq(d.clone(), lower + BabyBear::from_u32(121));
        builder.assert_eq(d.clone() + upper, BabyBear::from_u32(1_048_455));
        builder.assert_eq(
            normal.clone() + complement,
            BabyBear::from_u32(crate::mul::MODULUS - 1),
        );
        builder.assert_eq(
            normal.clone(),
            AB::Expr::from(BabyBear::from_u32(524_288)) - d
                + negative * BabyBear::from_u32(crate::mul::MODULUS),
        );
        normal
    })
}

#[cfg(test)]
mod tests;
