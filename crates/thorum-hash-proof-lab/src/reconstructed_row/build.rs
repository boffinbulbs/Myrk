use crate::reconstructed_row::{
    Error, MODULUS, Statement, Witness,
    air::*,
    hints, keccak, mul, ntt,
    program::{self, Kind},
};
use core::borrow::Borrow;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
#[cfg(test)]
pub(crate) mod replay;

pub(crate) fn bits(row: &mut [BabyBear], start: usize, value: u32, count: usize) {
    for bit in 0..count {
        row[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
    }
}
fn message(witness: &Witness, statement: &Statement, column: usize) -> [u8; 168] {
    let mut message = [0u8; 168];
    message[..32].copy_from_slice(&witness.rho);
    message[32] = column as u8;
    message[33] = statement.row;
    message[34] = 31;
    message[167] = 128;
    message
}
pub(crate) fn expansion(
    witness: &Witness,
    statement: &Statement,
    column: usize,
) -> (Vec<[u64; 25]>, [u8; 1008]) {
    let mut state = [0u64; 25];
    for (lane, raw) in message(witness, statement, column)
        .chunks_exact(8)
        .enumerate()
    {
        state[lane] = u64::from_le_bytes(raw.try_into().unwrap());
    }
    let mut inputs = Vec::new();
    let mut output = [0u8; 1008];
    for block in 0..6 {
        inputs.push(state);
        state = keccak::state_after(state);
        for (lane, value) in state.iter().take(21).enumerate() {
            output[block * 168 + lane * 8..block * 168 + lane * 8 + 8]
                .copy_from_slice(&value.to_le_bytes());
        }
    }
    (inputs, output)
}
fn encode_product(row: &mut [BabyBear], lane: usize, product: &ntt::Product) {
    let start = PRODUCTS + lane * mul::WIDTH;
    for (index, value) in product.values.iter().enumerate() {
        bits(row, start + mul::VALUES + index * 23, *value, 23);
        bits(
            row,
            start + mul::COMPLEMENTS + index * 23,
            MODULUS - 1 - value,
            23,
        );
    }
    bits(row, start + mul::CARRY0, (product.carry0 + 2) as u32, 13);
    bits(row, start + mul::CARRY1, (product.carry1 + 4096) as u32, 14);
}
fn encode_hint(row: &mut [BabyBear], lane: usize, input: u32, hint: u8) -> u8 {
    let r = i64::from(input);
    let shifted = r + i64::from(hints::GAMMA2) - 1;
    let n = shifted / i64::from(hints::ALPHA);
    let u = shifted % i64::from(hints::ALPHA);
    let edge = i64::from(n == 16);
    let high = n % 16;
    let low = u - i64::from(hints::GAMMA2) + 1 - edge;
    let positive = i64::from(low > 0);
    let sign_slack = if positive == 1 {
        u - i64::from(hints::GAMMA2) - edge
    } else {
        i64::from(hints::GAMMA2) + edge - 1 - u
    };
    let raw = high + i64::from(hint) * (2 * positive - 1);
    let borrow = i64::from(raw < 0);
    let overflow = i64::from(raw > 15);
    let output = raw + 16 * (borrow - overflow);
    let start = USE_HINT + lane * hints::WIDTH;
    for (offset, value, count) in [
        (hints::R, r, 23),
        (hints::R_COMPLEMENT, i64::from(MODULUS) - 1 - r, 23),
        (hints::N, n, 5),
        (hints::N_COMPLEMENT, 16 - n, 5),
        (hints::U, u, 19),
        (hints::U_COMPLEMENT, i64::from(hints::ALPHA) - 1 - u, 19),
        (hints::HIGH, high, 4),
        (hints::OUTPUT, output, 4),
        (hints::SIGN_SLACK, sign_slack, 18),
    ] {
        bits(row, start + offset, value as u32, count);
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

pub fn trace(witness: &Witness, statement: &Statement) -> Result<RowMajorMatrix<BabyBear>, Error> {
    if witness
        .zhat
        .iter()
        .flatten()
        .chain(&witness.chat)
        .any(|v| *v >= MODULUS)
        || witness.t1.iter().any(|v| *v > 1023)
        || witness.hints.iter().any(|v| *v > 1)
    {
        return Err(Error::InvalidWitness);
    }
    let expansions: Vec<_> = (0..7)
        .map(|column| expansion(witness, statement, column))
        .collect();
    let inputs = expansions.iter().map(|(v, _)| v.clone()).collect();
    let streams = core::array::from_fn(|column| expansions[column].1);
    trace_with_columns(witness, statement, inputs, streams, false)
}
pub(crate) fn trace_with_columns(
    witness: &Witness,
    statement: &Statement,
    column_inputs: Vec<Vec<[u64; 25]>>,
    streams: [[u8; 1008]; 7],
    allow_incomplete: bool,
) -> Result<RowMajorMatrix<BabyBear>, Error> {
    assert_eq!(column_inputs.len(), 7);
    for stream in &streams {
        let accepted = stream
            .chunks_exact(3)
            .filter(|raw| {
                u32::from(raw[0]) + (u32::from(raw[1]) << 8) + (u32::from(raw[2] & 127) << 16)
                    < MODULUS
            })
            .count();
        if accepted < 256 && !allow_incomplete {
            return Err(Error::UnsupportedCapacity);
        }
    }
    let mut inputs = vec![[0u64; 25]; 170];
    for column in 0..7 {
        assert_eq!(column_inputs[column].len(), 6);
        for block in 0..6 {
            inputs[column * 7 + block] = column_inputs[column][block];
        }
    }
    let logical = generate_trace_rows::<BabyBear>(inputs, 0);
    assert_eq!(logical.height(), HEIGHT * 4);
    let instructions = program::instructions();
    let mut values = vec![BabyBear::ZERO; HEIGHT * WIDTH];
    let mut a = [0u32; 256];
    let mut w = [0u32; 256];
    let mut packed = [0u8; 128];
    let mut count = 0usize;
    let mut cursor = 0u32;
    for at in 0..HEIGHT {
        let row = &mut values[at * WIDTH..(at + 1) * WIDTH];
        for lane in 0..4 {
            row[lane * NUM_KECCAK_COLS..(lane + 1) * NUM_KECCAK_COLS]
                .copy_from_slice(&logical.row_slice(at * 4 + lane).unwrap());
        }
        row[CLOCK + at] = BabyBear::ONE;
        bits(row, ROW_BITS, u32::from(statement.row), 3);
        for (index, value) in witness.rho.iter().enumerate() {
            row[RHO + index] = BabyBear::from_u8(*value);
        }
        for index in 0..256 {
            for column in 0..7 {
                row[ZHAT + column * 256 + index] = BabyBear::from_u32(witness.zhat[column][index]);
            }
            row[T1 + index] = BabyBear::from_u16(witness.t1[index]);
            row[CHAT + index] = BabyBear::from_u32(witness.chat[index]);
            row[HINTS + index] = BabyBear::from_u8(witness.hints[index]);
            row[ACCUMULATOR + index] = BabyBear::from_u32(a[index]);
            row[WORK + index] = BabyBear::from_u32(w[index]);
        }
        for (index, value) in packed.iter().enumerate() {
            row[W1 + index] = BabyBear::from_u8(*value);
        }
        let current_column = (at / 42).min(6);
        for (byte, value) in streams[current_column].iter().enumerate() {
            row[XOF + byte] = BabyBear::from_u8(*value);
        }
        if at < 294 {
            let local = at % 42;
            if local < 6 {
                for (byte, value) in message(witness, statement, current_column)
                    .iter()
                    .enumerate()
                {
                    bits(row, MESSAGE + byte * 8, u32::from(*value), 8);
                }
            }
            if local < 36 {
                let k: &KeccakCols<BabyBear> =
                    row[3 * NUM_KECCAK_COLS..4 * NUM_KECCAK_COLS].borrow();
                let output: [u32; 84] = core::array::from_fn(|limb| {
                    k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32()
                });
                for (limb, value) in output.iter().enumerate() {
                    bits(row, OUTPUT + limb * 16, *value, 16);
                }
            }
        }
        if at < 32 {
            for lane in 0..8 {
                let input = u32::from(witness.t1[at * 8 + lane]);
                bits(row, T1_BITS + lane * 10, input, 10);
                w[at * 8 + lane] = 8192 * input;
            }
        }
        let mut products = [ntt::product(0, 0); 8];
        let mut writes = [0u32; 16];
        let mut flags = [false; 16];
        row[COUNT + count] = BabyBear::ONE;
        bits(row, CURSOR, cursor, 10);
        for lane in 0..8 {
            let active = at < 294 && count < 256;
            let mut candidate = 0;
            let mut take = false;
            if active {
                let raw =
                    &streams[current_column][at % 42 * 24 + lane * 3..at % 42 * 24 + lane * 3 + 3];
                for (byte, value) in raw.iter().enumerate() {
                    bits(row, CANDIDATE + lane * 24 + byte * 8, u32::from(*value), 8);
                }
                candidate =
                    u32::from(raw[0]) + (u32::from(raw[1]) << 8) + (u32::from(raw[2] & 127) << 16);
                take = candidate < MODULUS;
                bits(
                    row,
                    SLACK + lane * 23,
                    if take {
                        MODULUS - 1 - candidate
                    } else {
                        candidate - MODULUS
                    },
                    23,
                );
                cursor += 3;
            }
            row[TAKE + lane] = BabyBear::from_bool(take);
            if at < 294 {
                let y = if count < 256 {
                    witness.zhat[current_column][count]
                } else {
                    0
                };
                let old = if count < 256 { a[count] } else { 0 };
                products[lane] = ntt::product(if take { candidate } else { 0 }, y);
                let total = old + products[lane].values[3];
                flags[lane * 2] = total >= MODULUS;
                writes[lane * 2] = old;
                writes[lane * 2 + 1] = total - if flags[lane * 2] { MODULUS } else { 0 };
                if take {
                    a[count] = writes[lane * 2 + 1];
                    count += 1;
                }
            }
            row[COUNT + (lane + 1) * 257 + count] = BabyBear::ONE;
            bits(row, CURSOR + (lane + 1) * 10, cursor, 10);
        }
        match instructions[at].kind {
            Kind::Forward | Kind::Inverse => {
                let forward = matches!(instructions[at].kind, Kind::Forward);
                let bank = if forward { &mut w } else { &mut a };
                for lane in 0..8 {
                    let (left, right, twiddle) = instructions[at].butterflies[lane];
                    let (left_value, right_value) = (bank[left], bank[right]);
                    if forward {
                        products[lane] = ntt::product(twiddle, right_value);
                        let t = products[lane].values[3];
                        flags[lane * 2] = left_value + t >= MODULUS;
                        flags[lane * 2 + 1] = left_value < t;
                        writes[lane * 2] =
                            left_value + t - if flags[lane * 2] { MODULUS } else { 0 };
                        writes[lane * 2 + 1] = (u64::from(left_value)
                            + if flags[lane * 2 + 1] {
                                u64::from(MODULUS)
                            } else {
                                0
                            }
                            - u64::from(t)) as u32;
                    } else {
                        flags[lane * 2] = left_value + right_value >= MODULUS;
                        flags[lane * 2 + 1] = left_value < right_value;
                        let difference = (u64::from(left_value)
                            + if flags[lane * 2 + 1] {
                                u64::from(MODULUS)
                            } else {
                                0
                            }
                            - u64::from(right_value))
                            as u32;
                        products[lane] = ntt::product(twiddle, difference);
                        writes[lane * 2] =
                            left_value + right_value - if flags[lane * 2] { MODULUS } else { 0 };
                        writes[lane * 2 + 1] = products[lane].values[3];
                    }
                    bank[left] = writes[lane * 2];
                    bank[right] = writes[lane * 2 + 1];
                }
            }
            Kind::Point(group) => {
                for lane in 0..8 {
                    let index = group * 8 + lane;
                    products[lane] = ntt::product(witness.chat[index], w[index]);
                    writes[lane * 2] = a[index];
                    flags[lane * 2] = a[index] < products[lane].values[3];
                    writes[lane * 2 + 1] = (u64::from(a[index])
                        + if flags[lane * 2] {
                            u64::from(MODULUS)
                        } else {
                            0
                        }
                        - u64::from(products[lane].values[3]))
                        as u32;
                    a[index] = writes[lane * 2 + 1];
                }
            }
            Kind::Normalize(group) => {
                for lane in 0..8 {
                    let index = group * 8 + lane;
                    products[lane] = ntt::product(ntt::INVERSE_256, a[index]);
                    writes[lane] = products[lane].values[3];
                    a[index] = writes[lane];
                }
            }
            _ => {}
        }
        for (lane, product) in products.iter().enumerate() {
            encode_product(row, lane, product);
        }
        for (slot, value) in writes.iter().enumerate() {
            bits(row, WRITES + slot * 46, *value, 23);
            bits(row, WRITES + slot * 46 + 23, MODULUS - 1 - value, 23);
        }
        for (index, value) in flags.iter().enumerate() {
            row[FLAGS + index] = BabyBear::from_bool(*value);
        }
        let outputs: [u8; 8] = core::array::from_fn(|lane| {
            if let Kind::Hint(group) = instructions[at].kind {
                encode_hint(
                    row,
                    lane,
                    a[group * 8 + lane],
                    witness.hints[group * 8 + lane],
                )
            } else {
                encode_hint(row, lane, 0, 0)
            }
        });
        if let Kind::Hint(group) = instructions[at].kind {
            for pair in 0..4 {
                packed[group * 4 + pair] = outputs[pair * 2] + 16 * outputs[pair * 2 + 1];
            }
        }
        if let Kind::Matrix { local: 41, column } = instructions[at].kind {
            if count < 256 && !allow_incomplete {
                return Err(Error::UnsupportedCapacity);
            }
            if column < 6 {
                count = 0;
                cursor = 0;
            }
        }
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}
