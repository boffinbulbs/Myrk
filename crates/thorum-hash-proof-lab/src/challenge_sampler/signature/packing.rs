//! Reused strict response constraints and local Boolean bit packing.

use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
pub(crate) use thorum_arithmetic_proof_lab::packing::{
    COMPLEMENTS, LOWER, NEGATIVE, NORMAL, UPPER, Z_AUX_WIDTH, decode_z_pair,
};

pub(crate) fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit)
}
