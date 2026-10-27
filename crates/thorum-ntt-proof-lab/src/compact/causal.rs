//! Valid local modular arithmetic with deliberately disconnected state flow.

use super::*;
use air::{Kind, encode_product, encode_write};
use p3_matrix::dense::RowMajorMatrix;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Attack {
    WrongTwiddle,
    DetachedMultiplicand,
    UnauthorizedBankWrite,
    MissingNormalization,
    DetachedOutputRead,
    ChangedFirstOutputBank,
    ChangedPaddingBank,
    UninitializedBank,
}

pub(crate) fn attack_trace(mode: Mode, attack: Attack) -> (RowMajorMatrix<BabyBear>, Statement) {
    let input =
        core::array::from_fn(|i| ((i as u64 * 81731 + 9001) % u64::from(mul::MODULUS)) as u32);
    let program = air::program(mode);
    let output_start = if mode == Mode::Forward { 160 } else { 192 };
    let mut bank = [0u32; 256];
    let mut values = vec![BabyBear::ZERO; air::WIDTH * air::HEIGHT];
    let mut declared_output = [0u32; 256];
    for (row_index, row) in values.chunks_exact_mut(air::WIDTH).enumerate() {
        if matches!(attack, Attack::UnauthorizedBankWrite) && row_index == 33 {
            bank[255] = (bank[255] + 1) % mul::MODULUS;
        }
        if matches!(attack, Attack::ChangedFirstOutputBank) && row_index == output_start {
            bank[0] = (bank[0] + 1) % mul::MODULUS;
        }
        if matches!(attack, Attack::ChangedPaddingBank) && row_index == program.len() {
            bank[0] = (bank[0] + 1) % mul::MODULUS;
        }
        if matches!(attack, Attack::UninitializedBank) && row_index == 0 {
            bank[255] = 1;
        }
        row[if row_index < program.len() {
            row_index
        } else {
            air::PAD
        }] = BabyBear::ONE;
        for (index, value) in bank.iter().enumerate() {
            row[air::BANK + index] = BabyBear::from_u32(*value);
        }
        let mut writes = [0u32; 16];
        let mut products = [ntt::product(0, 0); 8];
        let mut flags = [[false; 2]; 8];
        if let Some(instruction) = program.get(row_index) {
            match instruction.kind {
                Kind::Initialize(group) => {
                    writes[..8].copy_from_slice(&input[group * 8..(group + 1) * 8])
                }
                Kind::Output(group) => {
                    writes[..8].copy_from_slice(&bank[group * 8..(group + 1) * 8]);
                    if matches!(attack, Attack::DetachedOutputRead) && group == 0 {
                        writes[0] = bank[1];
                    }
                    declared_output[group * 8..(group + 1) * 8].copy_from_slice(&writes[..8]);
                }
                Kind::Normalize(group) => {
                    for slot in 0..8 {
                        let factor = if matches!(attack, Attack::MissingNormalization) && group == 0
                        {
                            1
                        } else {
                            ntt::INVERSE_256
                        };
                        products[slot] = ntt::product(factor, bank[group * 8 + slot]);
                        writes[slot] = products[slot].values[3];
                    }
                }
                Kind::Butterfly { .. } => {
                    for slot in 0..8 {
                        let (left, right, mut twiddle) = instruction.butterflies[slot];
                        let (a, b) = (bank[left], bank[right]);
                        if matches!(attack, Attack::WrongTwiddle) && row_index == 32 && slot == 0 {
                            twiddle = (twiddle + 1) % mul::MODULUS;
                        }
                        let second = if matches!(attack, Attack::DetachedMultiplicand)
                            && row_index == 32
                            && slot == 0
                        {
                            (b + 1) % mul::MODULUS
                        } else {
                            b
                        };
                        match mode {
                            Mode::Forward => {
                                products[slot] = ntt::product(twiddle, second);
                                let t = products[slot].values[3];
                                flags[slot] = [a + t >= mul::MODULUS, a < t];
                                writes[slot * 2] = (a + t) % mul::MODULUS;
                                writes[slot * 2 + 1] = ((u64::from(a) + u64::from(mul::MODULUS)
                                    - u64::from(t))
                                    % u64::from(mul::MODULUS))
                                    as u32;
                            }
                            Mode::Inverse => {
                                let difference = ((u64::from(a) + u64::from(mul::MODULUS)
                                    - u64::from(second))
                                    % u64::from(mul::MODULUS))
                                    as u32;
                                products[slot] = ntt::product(twiddle, difference);
                                flags[slot] = [a + b >= mul::MODULUS, a < second];
                                writes[slot * 2] = (a + b) % mul::MODULUS;
                                writes[slot * 2 + 1] = products[slot].values[3];
                            }
                        }
                    }
                }
            }
            for (slot, destination) in instruction.destinations.iter().enumerate() {
                if let Some(index) = destination {
                    bank[*index] = writes[slot];
                }
            }
        }
        for slot in 0..8 {
            let product = products[slot];
            assert_eq!(
                u64::from(product.values[0]) * u64::from(product.values[1]),
                u64::from(mul::MODULUS) * u64::from(product.values[2])
                    + u64::from(product.values[3])
            );
            encode_product(
                &product,
                &mut row
                    [air::PRODUCTS + slot * mul::WIDTH..air::PRODUCTS + (slot + 1) * mul::WIDTH],
            );
            row[air::FLAGS + slot * 2] = BabyBear::from_bool(flags[slot][0]);
            row[air::FLAGS + slot * 2 + 1] = BabyBear::from_bool(flags[slot][1]);
        }
        for slot in 0..16 {
            encode_write(
                writes[slot],
                &mut row[air::WRITES + slot * 46..air::WRITES + (slot + 1) * 46],
            );
        }
    }
    (
        RowMajorMatrix::new(values, air::WIDTH),
        Statement::new(mode, input, declared_output, [0x71; 64]).unwrap(),
    )
}
