//! Private inverse cursor over actual current accumulator fields.
use crate::{
    full_program as fp,
    layout::*,
    mul,
    ntt::{self, InverseOp},
};
use ntt::{encode_product, encode_write, inverse_butterfly, inverse_operation, product};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

#[derive(Debug)]
pub(crate) enum InverseError {
    RowShape,
    Exhausted,
    Incomplete,
}
pub(crate) struct InverseState {
    bank: [u32; 256],
    next_row: usize,
    seeded: bool,
    completed: usize,
}
impl InverseState {
    pub(crate) fn new() -> Self {
        Self {
            bank: [0; 256],
            next_row: 0,
            seeded: false,
            completed: 0,
        }
    }
    pub(crate) fn owns(at: usize, column: usize) -> bool {
        at >= fp::INVERSE_START && (NTT_SCRATCH..FORWARD_WIDTH).contains(&column)
    }
    // Preserve the retained inverse row body's indexed operation order.
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, InverseError> {
        if row.len() != WIDTH {
            return Err(InverseError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(InverseError::Exhausted);
        }
        let at = self.next_row;
        if at < fp::INVERSE_START {
            self.next_row += 1;
            return Ok(at);
        }
        if at == fp::INVERSE_START {
            self.bank = core::array::from_fn(|k| row[NTT_SCRATCH + k].as_canonical_u32());
            self.seeded = true;
        }
        row[NTT_SCRATCH..FORWARD_WIDTH].fill(BabyBear::ZERO);
        for (k, v) in self.bank.iter().enumerate() {
            row[NTT_SCRATCH + k] = BabyBear::from_u32(*v);
        }
        let mut writes = [0u32; 16];
        let mut products = [product(0, 0); 8];
        let mut flags = [false; 16];
        if let Some((i, op)) = inverse_operation(at) {
            match op {
                InverseOp::Initialize(g) => {
                    for s in 0..8 {
                        writes[s] = row[ACCUMULATOR + 256 * i + 8 * g + s].as_canonical_u32();
                        self.bank[8 * g + s] = writes[s];
                    }
                }
                InverseOp::Output(g) => {
                    for s in 0..8 {
                        writes[s] = self.bank[8 * g + s];
                    }
                }
                InverseOp::Normalize(g) => {
                    for s in 0..8 {
                        products[s] = product(8_347_681, self.bank[8 * g + s]);
                        writes[s] = products[s].values[3];
                        self.bank[8 * g + s] = writes[s];
                    }
                }
                InverseOp::Butterfly { layer, chunk } => {
                    for s in 0..8 {
                        let (left, right, twiddle) = inverse_butterfly(layer, 8 * chunk + s);
                        let (a, b) = (self.bank[left], self.bank[right]);
                        let add = a + b >= mul::MODULUS;
                        let borrow = a < b;
                        let difference = (u64::from(a)
                            + if borrow { u64::from(mul::MODULUS) } else { 0 }
                            - u64::from(b)) as u32;
                        products[s] = product(twiddle, difference);
                        flags[2 * s] = add;
                        flags[2 * s + 1] = borrow;
                        writes[2 * s] = a + b - if add { mul::MODULUS } else { 0 };
                        writes[2 * s + 1] = products[s].values[3];
                        self.bank[left] = writes[2 * s];
                        self.bank[right] = writes[2 * s + 1];
                    }
                }
            }
        }
        for s in 0..8 {
            encode_product(
                products[s],
                &mut row[NTT_PRODUCTS + s * mul::WIDTH..NTT_PRODUCTS + (s + 1) * mul::WIDTH],
            );
        }
        for s in 0..16 {
            encode_write(
                writes[s],
                &mut row[NTT_WRITES + 46 * s..NTT_WRITES + 46 * (s + 1)],
            );
            row[NTT_FLAGS + s] = BabyBear::from_bool(flags[s]);
        }
        if matches!(inverse_operation(at), Some((_, InverseOp::Output(31)))) {
            self.completed += 1;
        }
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), InverseError> {
        if self.next_row != HEIGHT || !self.seeded || self.completed != 8 {
            return Err(InverseError::Incomplete);
        }
        Ok(())
    }
}
