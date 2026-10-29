//! Bounded integer Decompose and UseHint constraints for ML DSA87.
//! Consumers must connect the same canonical inverse output and decoded hint.

#![forbid(unsafe_code)]

use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub const MODULUS: u32 = 8_380_417;
pub const ALPHA: u32 = 523_776;
pub const GAMMA2: u32 = 261_888;
pub const R: usize = 0;
pub const R_COMPLEMENT: usize = R + 23;
pub const N: usize = R_COMPLEMENT + 23;
pub const N_COMPLEMENT: usize = N + 5;
pub const U: usize = N_COMPLEMENT + 5;
pub const U_COMPLEMENT: usize = U + 19;
pub const HIGH: usize = U_COMPLEMENT + 19;
pub const EDGE: usize = HIGH + 4;
pub const POSITIVE: usize = EDGE + 1;
pub const HINT: usize = POSITIVE + 1;
pub const OUTPUT: usize = HINT + 1;
pub const SIGN_SLACK: usize = OUTPUT + 4;
pub const BORROW: usize = SIGN_SLACK + 18;
pub const OVERFLOW: usize = BORROW + 1;
pub const WIDTH: usize = OVERFLOW + 1;

/// Every expression comes from the same constrained bit slice. The low part is
/// a signed field expression in the integer interval [-GAMMA2,GAMMA2]. It is not
/// an independently encoded canonical residue for later modular arithmetic.
#[expect(
    dead_code,
    reason = "Retain shared Decompose diagnostic outputs for source provenance"
)]
pub struct Values<E> {
    pub input: E,
    pub hint: E,
    pub high: E,
    pub low: E,
    pub positive: E,
    pub output: E,
}

fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit)
}

/// Exact FIPS 204 Algorithms36 and40 for q=8380417 and gamma2=(q-1)/32.
/// All scalar residuals are strictly between minus p and p. Boolean and bounded
/// integer encodings therefore exclude nonzero BabyBear characteristic aliases.
pub fn eval_use_hint<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    local: &[AB::Var],
) -> Values<AB::Expr> {
    assert_eq!(local.len(), WIDTH);
    for value in local {
        builder.assert_bool(*value);
    }
    let input = packed::<AB>(&local[R..R_COMPLEMENT]);
    let r_complement = packed::<AB>(&local[R_COMPLEMENT..N]);
    let n = packed::<AB>(&local[N..N_COMPLEMENT]);
    let n_complement = packed::<AB>(&local[N_COMPLEMENT..U]);
    let u = packed::<AB>(&local[U..U_COMPLEMENT]);
    let u_complement = packed::<AB>(&local[U_COMPLEMENT..HIGH]);
    let high = packed::<AB>(&local[HIGH..EDGE]);
    let edge: AB::Expr = local[EDGE].into();
    let positive: AB::Expr = local[POSITIVE].into();
    let hint: AB::Expr = local[HINT].into();
    let output = packed::<AB>(&local[OUTPUT..SIGN_SLACK]);
    let sign_slack = packed::<AB>(&local[SIGN_SLACK..BORROW]);
    let borrow: AB::Expr = local[BORROW].into();
    let overflow: AB::Expr = local[OVERFLOW].into();

    builder.assert_eq(
        input.clone() + r_complement,
        BabyBear::from_u32(MODULUS - 1),
    );
    builder.assert_eq(n.clone() + n_complement, BabyBear::from_u8(16));
    builder.assert_eq(u.clone() + u_complement, BabyBear::from_u32(ALPHA - 1));
    builder.assert_eq(
        input.clone() + BabyBear::from_u32(GAMMA2 - 1),
        n.clone() * BabyBear::from_u32(ALPHA) + u.clone(),
    );
    builder.assert_eq(n, high.clone() + edge.clone() * BabyBear::from_u8(16));
    let low = u.clone() - BabyBear::from_u32(GAMMA2 - 1) - edge.clone();
    builder.when(positive.clone()).assert_eq(
        u.clone(),
        edge.clone() + BabyBear::from_u32(GAMMA2) + sign_slack.clone(),
    );
    builder
        .when(AB::Expr::ONE - positive.clone())
        .assert_eq(u + sign_slack, edge + BabyBear::from_u32(GAMMA2 - 1));
    builder.assert_zero(borrow.clone() * overflow.clone());
    builder.assert_eq(
        output.clone(),
        high.clone()
            + hint.clone() * (positive.clone().double() - AB::Expr::ONE)
            + (borrow - overflow) * BabyBear::from_u8(16),
    );
    Values {
        input,
        hint,
        high,
        low,
        positive,
        output,
    }
}
