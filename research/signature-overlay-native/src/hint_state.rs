//! Private hint reconstruction from actual current inverse and decoded flags.
use crate::{build, hints, layout::*, ntt};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
// Retained integer Decompose/UseHint witness encoding from the public row builder.
fn encode(row: &mut [BabyBear], s: usize, input: u32, hint: u8) -> u8 {
    let r = i64::from(input);
    let shifted = r + i64::from(hints::GAMMA2) - 1;
    let n = shifted / i64::from(hints::ALPHA);
    let u = shifted % i64::from(hints::ALPHA);
    let edge = i64::from(n == 16);
    let high = n % 16;
    let low = u - i64::from(hints::GAMMA2) + 1 - edge;
    let positive = i64::from(low > 0);
    let slack = if positive == 1 {
        u - i64::from(hints::GAMMA2) - edge
    } else {
        i64::from(hints::GAMMA2) + edge - 1 - u
    };
    let raw = high + i64::from(hint) * (2 * positive - 1);
    let borrow = i64::from(raw < 0);
    let overflow = i64::from(raw > 15);
    let output = raw + 16 * (borrow - overflow);
    let start = USE_HINT + s * hints::WIDTH;
    for (offset, value, bits) in [
        (hints::R, r, 23),
        (hints::R_COMPLEMENT, i64::from(hints::MODULUS) - 1 - r, 23),
        (hints::N, n, 5),
        (hints::N_COMPLEMENT, 16 - n, 5),
        (hints::U, u, 19),
        (hints::U_COMPLEMENT, i64::from(hints::ALPHA) - 1 - u, 19),
        (hints::HIGH, high, 4),
        (hints::OUTPUT, output, 4),
        (hints::SIGN_SLACK, slack, 18),
    ] {
        build::bits(row, start + offset, value as u32, bits);
    }
    for (offset, value) in [
        (hints::EDGE, edge),
        (hints::POSITIVE, positive),
        (hints::HINT, i64::from(hint)),
        (hints::BORROW, borrow),
        (hints::OVERFLOW, overflow),
    ] {
        row[start + offset] = BabyBear::from_bool(value != 0);
    }
    output as u8
}
#[derive(Debug)]
pub(crate) enum HintError {
    RowShape,
    Exhausted,
    Incomplete,
}
pub(crate) struct HintState {
    packed: [u8; 1024],
    next_row: usize,
    completed: usize,
}
impl HintState {
    pub(crate) fn new() -> Self {
        Self {
            packed: [0; 1024],
            next_row: 0,
            completed: 0,
        }
    }
    pub(crate) fn owns(at: usize, column: usize) -> bool {
        (W1..ACTIVE_CHALLENGE).contains(&column)
            || (matches!(
                ntt::inverse_operation(at),
                Some((_, ntt::InverseOp::Output(_)))
            ) && (USE_HINT..W1).contains(&column))
    }
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, HintError> {
        if row.len() != WIDTH {
            return Err(HintError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(HintError::Exhausted);
        }
        let at = self.next_row;
        row[W1..ACTIVE_CHALLENGE].fill(BabyBear::ZERO);
        for (i, v) in self.packed.iter().enumerate() {
            row[W1 + i] = BabyBear::from_u8(*v);
        }
        let output = ntt::inverse_operation(at).and_then(|(i, op)| match op {
            ntt::InverseOp::Output(g) => Some((i, g)),
            _ => None,
        });
        if let Some((i, g)) = output {
            row[USE_HINT..W1].fill(BabyBear::ZERO);
            let used: [u8; 8] = core::array::from_fn(|s| {
                let input = row[NTT_SCRATCH + 8 * g + s].as_canonical_u32();
                let hint = row[HINTS + 256 * i + 8 * g + s].as_canonical_u32() as u8;
                encode(row, s, input, hint)
            });
            for p in 0..4 {
                self.packed[128 * i + 4 * g + p] = used[2 * p] + 16 * used[2 * p + 1];
            }
        }
        if matches!(
            ntt::inverse_operation(at),
            Some((_, ntt::InverseOp::Output(31)))
        ) {
            self.completed += 1;
        }
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), HintError> {
        if self.next_row != HEIGHT || self.completed != 8 {
            return Err(HintError::Incomplete);
        }
        Ok(())
    }
}
