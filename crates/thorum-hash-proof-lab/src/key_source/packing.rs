use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;

pub(crate) fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit)
}

pub(crate) use thorum_arithmetic_proof_lab::packing::decode_t1;
