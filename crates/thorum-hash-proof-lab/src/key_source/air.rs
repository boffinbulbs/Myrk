use crate::key_source::{KEY_BYTES, Statement, Witness, keccak, packing};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

pub const HEIGHT: usize = 1024;
pub const ROUNDS: usize = 4;
pub const LOGICAL_HEIGHT: usize = HEIGHT * ROUNDS;
pub const GENERATOR_INPUTS: usize = 170;
pub const PERMUTATIONS: usize = 114;
pub const HASH_PC: usize = ROUNDS * NUM_KECCAK_COLS;
pub const KEY: usize = HASH_PC + PERMUTATIONS + 1;
pub const MESSAGE: usize = KEY + KEY_BYTES;
pub const OUTPUT: usize = MESSAGE + 136 * 8;
pub const RHO: usize = OUTPUT + 136 * 8;
pub const OWNER: usize = RHO + 2 * 32;
pub const TR: usize = OWNER + 2 * 64;
pub const T1: usize = TR + 2 * 64;
pub const T1_PC: usize = T1 + 2 * 2048;
pub const T1_MESSAGE: usize = T1_PC + 257;
pub const WIDTH: usize = T1_MESSAGE + 80;
pub const PUBLIC_VALUES: usize = 64;

pub struct KeySlotsAir;
impl<F> BaseAir<F> for KeySlotsAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

fn sum<AB: AirBuilder>(values: &[AB::Var]) -> AB::Expr {
    values.iter().copied().map(Into::into).sum()
}

pub(crate) fn source_byte(stage: usize, byte: usize) -> Option<usize> {
    if stage >= PERMUTATIONS {
        return None;
    }
    let phase = stage % 57;
    let (block, rate) = if phase < 37 {
        (phase, 72)
    } else {
        (phase - 37, 136)
    };
    let offset = block * rate + byte;
    (byte < rate && offset < KEY_BYTES).then_some(offset)
}
pub(crate) fn padding_byte(stage: usize, byte: usize) -> u8 {
    if stage >= PERMUTATIONS {
        return 0;
    }
    let phase = stage % 57;
    if phase == 36 {
        if byte == 0 {
            6
        } else if byte == 71 {
            128
        } else {
            0
        }
    } else if phase == 56 {
        if byte == 8 {
            31
        } else if byte == 135 {
            128
        } else {
            0
        }
    } else {
        0
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for KeySlotsAir {
    fn eval(&self, builder: &mut AB) {
        keccak::eval(builder);
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let initial: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
        let final_k: &KeccakCols<AB::Var> =
            local[3 * NUM_KECCAK_COLS..4 * NUM_KECCAK_COLS].borrow();
        let next_initial: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
        let first = initial.step_flags[0];
        let last = final_k.step_flags[23];
        let mut pc_sum = AB::Expr::ZERO;
        for stage in 0..=PERMUTATIONS {
            let pc = local[HASH_PC + stage];
            builder.assert_bool(pc);
            pc_sum += pc.into();
            builder
                .when_first_row()
                .assert_eq(pc, BabyBear::from_bool(stage == 0));
            let predecessor: AB::Expr = if stage == PERMUTATIONS {
                local[HASH_PC + stage - 1].into() + pc
            } else if stage > 0 {
                local[HASH_PC + stage - 1].into()
            } else {
                AB::Expr::ZERO
            };
            builder
                .when_transition()
                .assert_eq(next[HASH_PC + stage], pc.into() + last * (predecessor - pc));
        }
        builder.assert_one(pc_sum);
        builder
            .when_last_row()
            .assert_one(local[HASH_PC + PERMUTATIONS]);

        let reload = local[HASH_PC + 56] * last;
        builder.when(reload.clone()).assert_one(local[T1_PC + 256]);
        for byte in 0..KEY_BYTES {
            builder.when_transition().assert_zero(
                (AB::Expr::ONE - reload.clone()) * (next[KEY + byte] - local[KEY + byte]),
            );
        }

        for bit in &local[MESSAGE..RHO] {
            builder.assert_bool(*bit);
        }
        for byte in 0..136 {
            let expected: AB::Expr = (0..PERMUTATIONS)
                .map(|stage| {
                    let source: AB::Expr = if let Some(offset) = source_byte(stage, byte) {
                        local[KEY + offset].into()
                    } else {
                        BabyBear::from_u8(padding_byte(stage, byte)).into()
                    };
                    local[HASH_PC + stage] * source
                })
                .sum();
            builder.assert_eq(
                packing::packed::<AB>(&local[MESSAGE + byte * 8..MESSAGE + (byte + 1) * 8]),
                expected,
            );
        }
        let owner_phase = sum::<AB>(&local[HASH_PC..HASH_PC + 37])
            + sum::<AB>(&local[HASH_PC + 57..HASH_PC + 94]);
        let tr_phase = sum::<AB>(&local[HASH_PC + 37..HASH_PC + 57])
            + sum::<AB>(&local[HASH_PC + 94..HASH_PC + 114]);
        let active = owner_phase.clone() + tr_phase.clone();
        let fresh: AB::Expr = [0, 37, 57, 94]
            .into_iter()
            .map(|stage| local[HASH_PC + stage].into())
            .sum();
        let owner_continue = sum::<AB>(&local[HASH_PC..HASH_PC + 36])
            + sum::<AB>(&local[HASH_PC + 57..HASH_PC + 93]);
        let tr_continue = sum::<AB>(&local[HASH_PC + 37..HASH_PC + 56])
            + sum::<AB>(&local[HASH_PC + 94..HASH_PC + 113]);
        for limb in 0..100 {
            let y = limb / 20;
            let x = (limb / 4) % 5;
            let l = limb % 4;
            let last_value: AB::Expr = final_k.a_prime_prime_prime(y, x, l).into();
            if limb < 68 {
                let output =
                    packing::packed::<AB>(&local[OUTPUT + limb * 16..OUTPUT + (limb + 1) * 16]);
                let enabled = if limb < 36 {
                    active.clone()
                } else {
                    tr_phase.clone()
                };
                builder
                    .when(enabled)
                    .assert_eq(output.clone(), last_value.clone());
                if limb >= 36 {
                    builder.when(owner_phase.clone()).assert_zero(output);
                }
            }
            let first_value = if limb < 68 {
                packing::packed::<AB>(&local[MESSAGE + limb * 16..MESSAGE + (limb + 1) * 16])
            } else {
                AB::Expr::ZERO
            };
            builder
                .when(first * fresh.clone())
                .assert_eq(initial.preimage[y][x][l], first_value);
            let xor = if limb < 68 {
                (0..16).rev().fold(AB::Expr::ZERO, |acc, bit| {
                    let a: AB::Expr = local[OUTPUT + limb * 16 + bit].into();
                    let b: AB::Expr = next[MESSAGE + limb * 16 + bit].into();
                    acc.double() + a.xor(&b)
                })
            } else {
                last_value.clone()
            };
            let owner_expected = if limb < 36 {
                xor.clone()
            } else {
                last_value.clone()
            };
            builder
                .when(builder.is_transition() * last * owner_continue.clone())
                .assert_eq(next_initial.preimage[y][x][l], owner_expected);
            builder
                .when(builder.is_transition() * last * tr_continue.clone())
                .assert_eq(next_initial.preimage[y][x][l], xor);
        }
        for bit in &local[OUTPUT..RHO] {
            builder
                .when(local[HASH_PC + PERMUTATIONS])
                .assert_zero(*bit);
        }

        let mut tpc_sum = AB::Expr::ZERO;
        for position in 0..=256 {
            let pc = local[T1_PC + position];
            builder.assert_bool(pc);
            tpc_sum += pc.into();
            builder
                .when_first_row()
                .assert_eq(pc, BabyBear::from_bool(position == 0));
            let predecessor: AB::Expr = if position == 256 {
                local[T1_PC + 255].into() + pc
            } else if position > 0 {
                local[T1_PC + position - 1].into()
            } else {
                AB::Expr::ZERO
            };
            builder.when_transition().assert_eq(
                next[T1_PC + position],
                (AB::Expr::ONE - reload.clone()) * predecessor
                    + reload.clone() * BabyBear::from_bool(position == 0),
            );
        }
        builder.assert_one(tpc_sum);
        builder
            .when(local[HASH_PC + PERMUTATIONS])
            .assert_one(local[T1_PC + 256]);
        for byte in 0..10 {
            let expected: AB::Expr = (0..256)
                .map(|position| local[T1_PC + position] * local[KEY + 32 + position * 10 + byte])
                .sum();
            builder.assert_eq(
                packing::packed::<AB>(&local[T1_MESSAGE + byte * 8..T1_MESSAGE + (byte + 1) * 8]),
                expected,
            );
        }
        let first_t1 = packing::decode_t1(builder, &local[T1_MESSAGE..T1_MESSAGE + 40]);
        let second_t1 = packing::decode_t1(builder, &local[T1_MESSAGE + 40..WIDTH]);
        let t1 = [
            first_t1[0].clone(),
            first_t1[1].clone(),
            first_t1[2].clone(),
            first_t1[3].clone(),
            second_t1[0].clone(),
            second_t1[1].clone(),
            second_t1[2].clone(),
            second_t1[3].clone(),
        ];
        for slot in 0..2 {
            let slot_active = sum::<AB>(&local[HASH_PC + slot * 57..HASH_PC + (slot + 1) * 57]);
            for byte in 0..32 {
                let column = RHO + slot * 32 + byte;
                let write = local[HASH_PC + slot * 57] * first;
                builder.when_first_row().assert_zero(local[column]);
                builder.when_transition().assert_eq(
                    next[column],
                    local[column].into() + write * (local[KEY + byte] - local[column]),
                );
            }
            for (bank, stage) in [(OWNER, slot * 57 + 36), (TR, slot * 57 + 56)] {
                let write = local[HASH_PC + stage] * last;
                for byte in 0..64 {
                    let column = bank + slot * 64 + byte;
                    let producer =
                        packing::packed::<AB>(&local[OUTPUT + byte * 8..OUTPUT + (byte + 1) * 8]);
                    builder.when_first_row().assert_zero(local[column]);
                    builder.when_transition().assert_eq(
                        next[column],
                        local[column].into() + write.clone() * (producer - local[column]),
                    );
                }
            }
            for index in 0..2048 {
                let column = T1 + slot * 2048 + index;
                let write = slot_active.clone() * local[T1_PC + index / 8];
                builder.when_first_row().assert_zero(local[column]);
                builder.when_transition().assert_eq(
                    next[column],
                    local[column].into() + write * (t1[index % 8].clone() - local[column]),
                );
            }
        }
    }
}

pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    statement
        .context
        .iter()
        .copied()
        .map(BabyBear::from_u8)
        .collect()
}

pub(crate) fn message(witness: &Witness, stage: usize) -> [u8; 136] {
    core::array::from_fn(|byte| {
        source_byte(stage, byte).map_or_else(
            || padding_byte(stage, byte),
            |offset| witness.keys[stage / 57][offset],
        )
    })
}
pub(crate) fn inputs(witness: &Witness) -> Vec<[u64; 25]> {
    let mut result = Vec::with_capacity(PERMUTATIONS);
    for slot in 0..2 {
        for (first, blocks, rate) in [(slot * 57, 37, 72), (slot * 57 + 37, 20, 136)] {
            let mut state = [0u64; 25];
            for block in 0..blocks {
                let message = message(witness, first + block);
                for lane in 0..rate / 8 {
                    state[lane] ^=
                        u64::from_le_bytes(message[lane * 8..lane * 8 + 8].try_into().unwrap());
                }
                result.push(state);
                state = keccak::state_after(state);
            }
        }
    }
    result
}
fn bits(row: &mut [BabyBear], start: usize, value: u32, width: usize) {
    for bit in 0..width {
        row[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
    }
}

pub fn trace(witness: &Witness) -> RowMajorMatrix<BabyBear> {
    trace_with_inputs(witness, inputs(witness))
}
pub(crate) fn trace_with_inputs(
    witness: &Witness,
    mut inputs: Vec<[u64; 25]>,
) -> RowMajorMatrix<BabyBear> {
    assert_eq!(inputs.len(), PERMUTATIONS);
    inputs.resize(GENERATOR_INPUTS, [0; 25]);
    let logical = generate_trace_rows::<BabyBear>(inputs, 0);
    assert_eq!(logical.height(), LOGICAL_HEIGHT);
    let mut rho = [[0u8; 32]; 2];
    let mut owner = [[0u8; 64]; 2];
    let mut tr = [[0u8; 64]; 2];
    let mut t1 = [[0u32; 2048]; 2];
    let mut values = vec![BabyBear::ZERO; HEIGHT * WIDTH];
    for (at, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        for slot in 0..4 {
            row[slot * NUM_KECCAK_COLS..(slot + 1) * NUM_KECCAK_COLS]
                .copy_from_slice(&logical.row_slice(at * 4 + slot).unwrap());
        }
        let stage = (at / 6).min(PERMUTATIONS);
        let key_slot = usize::from(at >= 342);
        row[HASH_PC + stage] = BabyBear::ONE;
        for (byte, value) in witness.keys[key_slot].iter().enumerate() {
            row[KEY + byte] = BabyBear::from_u8(*value);
        }
        let block = if stage < PERMUTATIONS {
            message(witness, stage)
        } else {
            [0; 136]
        };
        for (byte, value) in block.iter().enumerate() {
            bits(row, MESSAGE + byte * 8, u32::from(*value), 8);
        }
        let last = logical.row_slice(at * 4 + 3).unwrap();
        let k: &KeccakCols<BabyBear> = (*last).borrow();
        let mut output = [0u8; 136];
        if stage < PERMUTATIONS {
            let rate = if stage % 57 < 37 { 72 } else { 136 };
            for limb in 0..rate / 2 {
                let value = k
                    .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                    .as_canonical_u32();
                bits(row, OUTPUT + limb * 16, value, 16);
                output[limb * 2..limb * 2 + 2].copy_from_slice(&(value as u16).to_le_bytes());
            }
        }
        let position = if at < 342 {
            at.min(256)
        } else {
            (at - 342).min(256)
        };
        row[T1_PC + position] = BabyBear::ONE;
        for slot in 0..2 {
            for byte in 0..32 {
                row[RHO + slot * 32 + byte] = BabyBear::from_u8(rho[slot][byte]);
            }
            for byte in 0..64 {
                row[OWNER + slot * 64 + byte] = BabyBear::from_u8(owner[slot][byte]);
                row[TR + slot * 64 + byte] = BabyBear::from_u8(tr[slot][byte]);
            }
            for index in 0..2048 {
                row[T1 + slot * 2048 + index] = BabyBear::from_u32(t1[slot][index]);
            }
        }
        if position < 256 {
            let source = &witness.keys[key_slot][32 + position * 10..32 + position * 10 + 10];
            for (byte, value) in source.iter().enumerate() {
                bits(row, T1_MESSAGE + byte * 8, u32::from(*value), 8);
            }
            for window in 0..2 {
                let mut bytes = [0u8; 8];
                bytes[..5].copy_from_slice(&source[window * 5..window * 5 + 5]);
                let value = u64::from_le_bytes(bytes);
                for coefficient in 0..4 {
                    t1[key_slot][position * 8 + window * 4 + coefficient] =
                        ((value >> (coefficient * 10)) & 1023) as u32;
                }
            }
        }
        if at == 0 || at == 342 {
            rho[key_slot].copy_from_slice(&witness.keys[key_slot][..32]);
        }
        if stage < PERMUTATIONS && at % 6 == 5 {
            if stage % 57 == 36 {
                owner[key_slot].copy_from_slice(&output[..64]);
            }
            if stage % 57 == 56 {
                tr[key_slot].copy_from_slice(&output[..64]);
            }
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}
