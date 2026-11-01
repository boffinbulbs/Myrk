//! Exact intervals from the retained packed relation's single global clock.
use super::{clock, layout::*};
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;

pub const FORWARD_START: usize = 450;
pub const FORWARD_STRIDE: usize = 192;
pub const INVERSE_START: usize = 3522;
pub const INVERSE_STRIDE: usize = 224;

pub fn modes_at(row: usize) -> (bool, bool) {
    assert!(row < HEIGHT);
    if (FORWARD_START..FORWARD_START + 16 * FORWARD_STRIDE).contains(&row) {
        return (
            (32..160).contains(&((row - FORWARD_START) % FORWARD_STRIDE)),
            false,
        );
    }
    if (INVERSE_START..INVERSE_START + 8 * INVERSE_STRIDE).contains(&row) {
        let local = (row - INVERSE_START) % INVERSE_STRIDE;
        return ((32..192).contains(&local), local >= 192);
    }
    (false, false)
}

pub fn selectors<AB: AirBuilder>(row: &[AB::Var]) -> (AB::Expr, AB::Expr) {
    let mut product = AB::Expr::ZERO;
    let mut hint = AB::Expr::ZERO;
    for transform in 0..16 {
        let start = FORWARD_START + FORWARD_STRIDE * transform;
        product += clock::interval::<AB>(row, 0, LOW, HIGH, start + 32, start + 160);
    }
    for transform in 0..8 {
        let start = INVERSE_START + INVERSE_STRIDE * transform;
        product += clock::interval::<AB>(row, 0, LOW, HIGH, start + 32, start + 192);
        hint += clock::interval::<AB>(row, 0, LOW, HIGH, start + 192, start + 224);
    }
    (product, hint)
}
