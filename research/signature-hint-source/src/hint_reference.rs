//! Explicit original-body reference with independent current-phase literals.
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
pub(crate) enum ReferenceError {
    Sequence,
    Exhausted,
}
pub(crate) struct Inputs {
    pub r: [[u32; 256]; 8],
    pub h: [[u8; 256]; 8],
}
pub(crate) struct HintReference {
    packed: [u8; 1024],
    inputs: Inputs,
    next_row: usize,
    row: Vec<BabyBear>,
}
impl HintReference {
    pub(crate) fn new(inputs: Inputs) -> Self {
        Self {
            packed: [0; 1024],
            inputs,
            next_row: 0,
            row: vec![BabyBear::ZERO; WIDTH],
        }
    }
    pub(crate) fn prepared(&self) -> usize {
        self.next_row
    }
    pub(crate) fn pristine(&self) -> bool {
        self.next_row == 0
            && self.packed == [0; 1024]
            && self.row.iter().all(|v| *v == BabyBear::ZERO)
    }
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn prepare(&mut self, at: usize) -> Result<(), ReferenceError> {
        if self.next_row == HEIGHT {
            return Err(ReferenceError::Exhausted);
        }
        if at != self.next_row {
            return Err(ReferenceError::Sequence);
        }
        self.row.fill(BabyBear::ZERO);
        let row = &mut self.row;
        if let Some((i, ntt::InverseOp::Output(g))) = ntt::inverse_operation(at) {
            for slot in 0..8 {
                let k = 8 * g + slot;
                row[NTT_SCRATCH + k] = BabyBear::from_u32(self.inputs.r[i][k]);
                row[HINTS + 256 * i + k] = BabyBear::from_u8(self.inputs.h[i][k]);
            }
        }
        for (i, v) in self.packed.iter().enumerate() {
            row[W1 + i] = BabyBear::from_u8(*v);
        }
        let output = ntt::inverse_operation(at).and_then(|(i, op)| match op {
            ntt::InverseOp::Output(g) => Some((i, g)),
            _ => None,
        });
        let mut used = [0u8; 8];
        for s in 0..8 {
            let (input, hint) = if let Some((i, g)) = output {
                (
                    row[NTT_SCRATCH + 8 * g + s].as_canonical_u32(),
                    row[HINTS + 256 * i + 8 * g + s].as_canonical_u32() as u8,
                )
            } else {
                (0, 0)
            };
            used[s] = encode(row, s, input, hint);
        }
        if let Some((i, g)) = output {
            for p in 0..4 {
                self.packed[128 * i + 4 * g + p] = used[2 * p] + 16 * used[2 * p + 1];
            }
        }
        self.next_row += 1;
        Ok(())
    }
    pub(crate) fn row(&self, at: usize) -> &[BabyBear] {
        assert_eq!(at + 1, self.next_row);
        &self.row
    }
}
