//! Private forward cursor over the actual composed current source row.
use crate::{
    layout::*,
    mul,
    ntt::{self, Op},
};
use ntt::{butterfly, encode_product, encode_write, operation, product, source};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

#[derive(Debug)]
pub(crate) enum ForwardError {
    RowShape,
    Exhausted,
    Incomplete,
}
pub(crate) struct ForwardState {
    bank: [u32; 256],
    outputs: [u32; 9 * 256],
    next_row: usize,
}
impl ForwardState {
    pub(crate) fn new() -> Self {
        Self {
            bank: [0; 256],
            outputs: [0; 9 * 256],
            next_row: 0,
        }
    }
    pub(crate) fn owns(column: usize) -> bool {
        (NTT_OUTPUT..FORWARD_WIDTH).contains(&column) || (USE_HINT..W1).contains(&column)
    }
    // Preserve the retained operation body's indexed write order.
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, ForwardError> {
        if row.len() != WIDTH {
            return Err(ForwardError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(ForwardError::Exhausted);
        }
        let row_index = self.next_row;
        // Every assigned slot is reinitialized, including dormant witnesses.
        row[NTT_OUTPUT..FORWARD_WIDTH].fill(BabyBear::ZERO);
        row[USE_HINT..W1].fill(BabyBear::ZERO);
        for (i, value) in self.bank.iter().enumerate() {
            row[NTT_SCRATCH + i] = BabyBear::from_u32(*value);
        }
        for (i, value) in self.outputs.iter().enumerate() {
            row[NTT_OUTPUT + i] = BabyBear::from_u32(*value);
        }
        let mut writes = [0u32; 16];
        let mut products = [product(0, 0); 8];
        let mut product_active = false;
        let mut flags = [[false; 2]; 8];
        if let Some((t, op)) = operation(row_index) {
            match op {
                Op::Initialize(group) => {
                    for slot in 0..8 {
                        let (column, factor) = source(t, group * 8 + slot);
                        writes[slot] = row[column].as_canonical_u32() * factor;
                        self.bank[group * 8 + slot] = writes[slot];
                    }
                }
                Op::Output(group) => {
                    for slot in 0..8 {
                        writes[slot] = self.bank[group * 8 + slot];
                        self.outputs[256 * OUTPUT_BANKS[t] + group * 8 + slot] = writes[slot];
                    }
                }
                Op::Butterfly { layer, chunk } => {
                    product_active = true;
                    for slot in 0..8 {
                        let (left, right, twiddle) = butterfly(layer, 8 * chunk + slot);
                        let a = self.bank[left];
                        products[slot] = product(twiddle, self.bank[right]);
                        let b = products[slot].values[3];
                        let add = a + b >= mul::MODULUS;
                        let borrow = a < b;
                        flags[slot] = [add, borrow];
                        writes[2 * slot] = a + b - if add { mul::MODULUS } else { 0 };
                        writes[2 * slot + 1] = (u64::from(a)
                            + if borrow { u64::from(mul::MODULUS) } else { 0 }
                            - u64::from(b)) as u32;
                        self.bank[left] = writes[2 * slot];
                        self.bank[right] = writes[2 * slot + 1];
                    }
                }
            }
        }
        for slot in 0..8 {
            if product_active {
                encode_product(
                    products[slot],
                    &mut row
                        [NTT_PRODUCTS + slot * mul::WIDTH..NTT_PRODUCTS + (slot + 1) * mul::WIDTH],
                );
            }
            row[NTT_FLAGS + 2 * slot] = BabyBear::from_bool(flags[slot][0]);
            row[NTT_FLAGS + 2 * slot + 1] = BabyBear::from_bool(flags[slot][1]);
        }
        for slot in 0..16 {
            encode_write(
                writes[slot],
                &mut row[NTT_WRITES + slot * 46..NTT_WRITES + (slot + 1) * 46],
            );
        }

        self.next_row += 1;
        Ok(row_index)
    }
    pub(crate) fn finish(&self) -> Result<(), ForwardError> {
        if self.next_row != HEIGHT {
            return Err(ForwardError::Incomplete);
        }
        Ok(())
    }
}
