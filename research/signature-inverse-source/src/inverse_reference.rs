//! Original inverse row body with independent saved seed and phase inputs.
use crate::{
    full_program as fp,
    layout::*,
    mul,
    ntt::{encode_product, encode_write, inverse_butterfly, inverse_operation, product, InverseOp},
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
#[derive(Debug)]
pub(crate) enum ReferenceError {
    Sequence,
    Exhausted,
}
pub(crate) struct InverseReference {
    bank: [u32; 256],
    inputs: [[u32; 256]; 8],
    next_row: usize,
    row: Vec<BabyBear>,
}
impl InverseReference {
    pub(crate) fn new(seed: [u32; 256], inputs: [[u32; 256]; 8]) -> Self {
        Self {
            bank: seed,
            inputs,
            next_row: 0,
            row: vec![BabyBear::ZERO; WIDTH],
        }
    }
    pub(crate) fn prepared(&self) -> usize {
        self.next_row
    }
    pub(crate) fn pristine(&self) -> bool {
        self.next_row == 0 && self.row.iter().all(|v| *v == BabyBear::ZERO)
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
        if at < fp::INVERSE_START {
            self.next_row += 1;
            return Ok(());
        }
        let row = &mut self.row;
        if let Some((i, InverseOp::Initialize(g))) = inverse_operation(at) {
            for slot in 0..8 {
                row[ACCUMULATOR + 256 * i + 8 * g + slot] =
                    BabyBear::from_u32(self.inputs[i][8 * g + slot]);
            }
        }
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

        self.next_row += 1;
        Ok(())
    }
    pub(crate) fn row(&self, at: usize) -> &[BabyBear] {
        assert_eq!(at + 1, self.next_row);
        &self.row
    }
}
