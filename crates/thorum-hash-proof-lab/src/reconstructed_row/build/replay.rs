// Test-only false witnesses. No AIR acceptance or constraint switch is provided.
use super::*;
use serde_json::Value;

pub(crate) fn raw_trace(
    witness: &Witness,
    statement: &Statement,
    column_inputs: Vec<Vec<[u64; 25]>>,
    streams: [[u8; 1008]; 7],
    allow_incomplete: bool,
    model: &Value,
    fault_flags: (bool, bool),
) -> Result<RowMajorMatrix<BabyBear>, Error> {
    let (wrong_twiddle, skip_normalize) = fault_flags;
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
        if at == 294 {
            w = core::array::from_fn(|i| model["t1_forward"]["input"][i].as_u64().unwrap() as u32);
            a = core::array::from_fn(|i| model["matrix_sum"][i].as_u64().unwrap() as u32);
        }
        if at == 454 {
            a = core::array::from_fn(|i| model["inverse"]["input"][i].as_u64().unwrap() as u32);
        }
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
                    let (left, right, mut twiddle) = instructions[at].butterflies[lane];
                    if wrong_twiddle && at == 294 && lane == 0 {
                        twiddle = (twiddle + 1) % MODULUS;
                    }
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
                    products[lane] = ntt::product(
                        model["challenge_products_subtractions"][index]["chat_read"]
                            .as_u64()
                            .unwrap() as u32,
                        model["challenge_products_subtractions"][index]["t1hat_read"]
                            .as_u64()
                            .unwrap() as u32,
                    );
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
                    products[lane] =
                        ntt::product(if skip_normalize { 1 } else { ntt::INVERSE_256 }, a[index]);
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
                    model["hints"][group * 8 + lane]["r"].as_u64().unwrap() as u32,
                    model["hints"][group * 8 + lane]["hint_read"]
                        .as_u64()
                        .unwrap() as u8,
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
