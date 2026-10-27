use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use super::{CAPACITY, Error, MODULUS, Statement, Witness};

pub const HEIGHT: usize = 512;
pub const RATE: usize = 136;
pub const BLOCKS: usize = 2;
pub const EVENTS: usize = CAPACITY - 8;
pub const HASH_PC: usize = NUM_KECCAK_COLS;
pub const MESSAGE: usize = HASH_PC + BLOCKS + 1;
pub const OUTPUT: usize = MESSAGE + RATE * 8;
pub const SEED: usize = OUTPUT + RATE * 8;
pub const XOF: usize = SEED + 64;
pub const SIGN_BITS: usize = XOF + CAPACITY;
pub const PLUS: usize = SIGN_BITS + 64;
pub const MINUS: usize = PLUS + 256;
pub const FINAL: usize = MINUS + 256;
pub const PROGRAM: usize = FINAL + 256;
pub const COUNT: usize = PROGRAM + EVENTS + 1;
pub const CANDIDATE: usize = COUNT + 61;
pub const LOWER: usize = CANDIDATE + 8;
pub const UPPER: usize = LOWER + 8;
pub const INDEX: usize = UPPER + 8;
pub const TAKE: usize = INDEX + 256;
pub const OLD_PLUS: usize = TAKE + 1;
pub const OLD_MINUS: usize = OLD_PLUS + 1;
pub const CURSOR: usize = OLD_MINUS + 1;
pub const WIDTH: usize = CURSOR + 9;
pub const PUBLIC_VALUES: usize = 1088;

// The adapter narrows the main window to the existing pinned Keccak columns.
#[derive(Clone)]
struct KeccakWindow<W>(W);
impl<T, W: WindowAccess<T>> WindowAccess<T> for KeccakWindow<W> {
    fn current_slice(&self) -> &[T] {
        &self.0.current_slice()[..NUM_KECCAK_COLS]
    }
    fn next_slice(&self) -> &[T] {
        &self.0.next_slice()[..NUM_KECCAK_COLS]
    }
}
struct KeccakBuilder<'a, AB>(&'a mut AB);
impl<AB: AirBuilder> AirBuilder for KeccakBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = KeccakWindow<AB::MainWindow>;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        KeccakWindow(self.0.main())
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.0.preprocessed()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.0.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.0.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.0.is_transition()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.0.assert_zero(value);
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }
}

fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit)
}

pub struct ChallengeSamplerAir;
impl<F> BaseAir<F> for ChallengeSamplerAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for ChallengeSamplerAir {
    fn eval(&self, builder: &mut AB) {
        KeccakAir {}.eval(&mut KeccakBuilder(builder));
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let k: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
        let nk: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
        let first = k.step_flags[0];
        let last = k.step_flags[23];
        let mut hash_sum = AB::Expr::ZERO;
        for stage in 0..=BLOCKS {
            let selector = local[HASH_PC + stage];
            builder.assert_bool(selector);
            hash_sum += selector.into();
            builder
                .when_first_row()
                .assert_eq(selector, BabyBear::from_bool(stage == 0));
            let advance: AB::Expr = if stage == BLOCKS {
                local[HASH_PC + stage - 1].into() + selector
            } else if stage > 0 {
                local[HASH_PC + stage - 1].into()
            } else {
                AB::Expr::ZERO
            };
            builder.when_transition().assert_eq(
                next[HASH_PC + stage],
                selector.into() + last * (advance - selector),
            );
        }
        builder.assert_one(hash_sum);
        builder.when_last_row().assert_one(local[HASH_PC + BLOCKS]);
        for column in SEED..XOF {
            builder
                .when_transition()
                .assert_eq(local[column], next[column]);
        }
        for bit in &local[MESSAGE..SEED] {
            builder.assert_bool(*bit);
        }
        for byte in 0..RATE {
            let value = packed::<AB>(&local[MESSAGE + byte * 8..MESSAGE + (byte + 1) * 8]);
            let expected = match byte {
                0..=63 => local[SEED + byte].into(),
                64 => BabyBear::from_u8(31).into(),
                135 => BabyBear::from_u8(128).into(),
                _ => AB::Expr::ZERO,
            };
            builder
                .when(local[HASH_PC])
                .assert_eq(value.clone(), expected);
            builder
                .when(AB::Expr::ONE - local[HASH_PC])
                .assert_zero(value);
        }
        let active_hash = AB::Expr::ONE - local[HASH_PC + BLOCKS];
        for limb in 0..100 {
            if limb < RATE / 2 {
                let output = packed::<AB>(&local[OUTPUT + limb * 16..OUTPUT + (limb + 1) * 16]);
                builder.when(active_hash.clone()).assert_eq(
                    output,
                    k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
                );
            }
            let initial = if limb < RATE / 2 {
                packed::<AB>(&local[MESSAGE + limb * 16..MESSAGE + (limb + 1) * 16])
            } else {
                AB::Expr::ZERO
            };
            builder
                .when(first * local[HASH_PC])
                .assert_eq(k.preimage[limb / 20][(limb / 4) % 5][limb % 4], initial);
            let continuation: AB::Expr = local[HASH_PC..HASH_PC + BLOCKS - 1]
                .iter()
                .copied()
                .map(Into::into)
                .sum();
            builder
                .when(builder.is_transition() * last * continuation)
                .assert_eq(
                    nk.preimage[limb / 20][(limb / 4) % 5][limb % 4],
                    k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
                );
        }
        for bit in &local[OUTPUT..SEED] {
            builder.when(local[HASH_PC + BLOCKS]).assert_zero(*bit);
        }
        for block in 0..BLOCKS {
            for byte in 0..RATE {
                builder.when(last * local[HASH_PC + block]).assert_eq(
                    local[XOF + block * RATE + byte],
                    packed::<AB>(&local[OUTPUT + byte * 8..OUTPUT + (byte + 1) * 8]),
                );
            }
        }

        eval_sampler(builder);
    }
}

pub(crate) fn state_after(input: [u64; 25]) -> [u64; 25] {
    let trace = generate_trace_rows::<BabyBear>(vec![input], 0);
    let row = trace.row_slice(23).unwrap();
    let typed: &KeccakCols<BabyBear> = (*row).borrow();
    core::array::from_fn(|lane| {
        (0..4)
            .map(|limb| {
                u64::from(
                    typed
                        .a_prime_prime_prime(lane / 5, lane % 5, limb)
                        .as_canonical_u32(),
                ) << (16 * limb)
            })
            .sum()
    })
}

pub(crate) fn eval_sampler<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    let public = builder.public_values().to_vec();
    for column in XOF..PLUS {
        builder
            .when_transition()
            .assert_eq(local[column], next[column]);
    }
    for column in FINAL..PROGRAM {
        builder
            .when_transition()
            .assert_eq(local[column], next[column]);
    }
    for bit in &local[SIGN_BITS..PLUS] {
        builder.assert_bool(*bit);
    }
    for byte in 0..8 {
        builder.assert_eq(
            local[XOF + byte],
            packed::<AB>(&local[SIGN_BITS + byte * 8..SIGN_BITS + (byte + 1) * 8]),
        );
    }
    let mut program_sum = AB::Expr::ZERO;
    for event in 0..=EVENTS {
        let selector = local[PROGRAM + event];
        builder.assert_bool(selector);
        program_sum += selector.into();
        builder
            .when_first_row()
            .assert_eq(selector, BabyBear::from_bool(event == 0));
        let predecessor: AB::Expr = if event == EVENTS {
            local[PROGRAM + event - 1].into() + selector
        } else if event > 0 {
            local[PROGRAM + event - 1].into()
        } else {
            AB::Expr::ZERO
        };
        builder
            .when_transition()
            .assert_eq(next[PROGRAM + event], predecessor);
    }
    builder.assert_one(program_sum);
    builder.when_last_row().assert_one(local[PROGRAM + EVENTS]);
    builder
        .when(local[PROGRAM + EVENTS])
        .assert_one(local[COUNT + 60]);
    builder.assert_bool(local[TAKE]);
    let take: AB::Expr = local[TAKE].into();
    let active = AB::Expr::ONE - local[COUNT + 60];
    builder.assert_zero(take.clone() * local[COUNT + 60]);
    let mut count_sum = AB::Expr::ZERO;
    let mut accepted = AB::Expr::ZERO;
    for step in 0..=60 {
        let selector = local[COUNT + step];
        builder.assert_bool(selector);
        count_sum += selector.into();
        accepted += selector * BabyBear::from_usize(step);
        builder
            .when_first_row()
            .assert_eq(selector, BabyBear::from_bool(step == 0));
        let predecessor: AB::Expr = if step > 0 {
            local[COUNT + step - 1].into()
        } else {
            AB::Expr::ZERO
        };
        builder.when_transition().assert_eq(
            next[COUNT + step],
            (AB::Expr::ONE - take.clone()) * selector + take.clone() * predecessor,
        );
    }
    builder.assert_one(count_sum);
    builder.when_last_row().assert_one(local[COUNT + 60]);
    for bit in &local[CANDIDATE..INDEX] {
        builder.assert_bool(*bit);
        builder
            .when(AB::Expr::ONE - active.clone())
            .assert_zero(*bit);
    }
    let candidate = packed::<AB>(&local[CANDIDATE..LOWER]);
    let source: AB::Expr = (0..EVENTS)
        .map(|event| local[PROGRAM + event] * local[XOF + 8 + event])
        .sum();
    builder
        .when(active.clone())
        .assert_eq(candidate.clone(), source);
    let destination: AB::Expr = BabyBear::from_u32(196).into();
    let destination = destination
        + (0..60)
            .map(|step| local[COUNT + step] * BabyBear::from_usize(step))
            .sum::<AB::Expr>();
    let lower = packed::<AB>(&local[LOWER..UPPER]);
    let upper = packed::<AB>(&local[UPPER..INDEX]);
    builder
        .when(take.clone())
        .assert_eq(candidate.clone() + lower.clone(), destination.clone());
    builder.when(take.clone()).assert_zero(upper.clone());
    builder
        .when(active.clone() - take.clone())
        .assert_eq(destination + AB::Expr::ONE + upper, candidate.clone());
    builder
        .when(active.clone() - take.clone())
        .assert_zero(lower);
    let mut index_sum = AB::Expr::ZERO;
    let mut selected_index = AB::Expr::ZERO;
    let mut old_plus = AB::Expr::ZERO;
    let mut old_minus = AB::Expr::ZERO;
    let mut weight = AB::Expr::ZERO;
    for index in 0..256 {
        let selector = local[INDEX + index];
        let plus = local[PLUS + index];
        let minus = local[MINUS + index];
        builder.assert_bool(selector);
        builder.assert_bool(plus);
        builder.assert_bool(minus);
        builder.assert_zero(plus * minus);
        builder.when_first_row().assert_zero(plus);
        builder.when_first_row().assert_zero(minus);
        index_sum += selector.into();
        selected_index += selector * BabyBear::from_usize(index);
        old_plus += selector * plus;
        old_minus += selector * minus;
        weight += plus.into() + minus;
    }
    builder.assert_eq(index_sum, take.clone());
    builder.assert_eq(selected_index, take.clone() * candidate);
    builder.assert_eq(local[OLD_PLUS], old_plus);
    builder.assert_eq(local[OLD_MINUS], old_minus);
    builder.assert_bool(local[OLD_PLUS]);
    builder.assert_bool(local[OLD_MINUS]);
    builder.assert_eq(weight, accepted);
    let sign: AB::Expr = (0..60)
        .map(|step| local[COUNT + step] * local[SIGN_BITS + step])
        .sum();
    for index in 0..256 {
        let destination: AB::Expr = if index >= 196 {
            local[COUNT + index - 196].into()
        } else {
            AB::Expr::ZERO
        };
        let plus: AB::Expr = local[PLUS + index].into();
        let minus: AB::Expr = local[MINUS + index].into();
        builder.when_transition().assert_eq(
            next[PLUS + index],
            plus.clone()
                + take.clone() * destination.clone() * (local[OLD_PLUS] - local[PLUS + index])
                + local[INDEX + index] * (AB::Expr::ONE - sign.clone() - plus.clone()),
        );
        builder.when_transition().assert_eq(
            next[MINUS + index],
            minus.clone()
                + take.clone() * destination * (local[OLD_MINUS] - local[MINUS + index])
                + local[INDEX + index] * (sign.clone() - minus.clone()),
        );
        let normal = plus.clone() + minus.clone() * BabyBear::from_u32(MODULUS - 1);
        builder
            .when(local[COUNT + 60])
            .assert_eq(local[FINAL + index], normal);
        for byte in 0..4 {
            let one = ((1u32 >> (8 * byte)) & 255) as u8;
            let negative = (((MODULUS - 1) >> (8 * byte)) & 255) as u8;
            builder.when(local[COUNT + 60]).assert_eq(
                public[index * 4 + byte],
                plus.clone() * BabyBear::from_u8(one) + minus.clone() * BabyBear::from_u8(negative),
            );
        }
    }
    for bit in &local[CURSOR..WIDTH] {
        builder.assert_bool(*bit);
    }
    let cursor = packed::<AB>(&local[CURSOR..WIDTH]);
    builder
        .when_first_row()
        .assert_eq(cursor.clone(), BabyBear::from_u8(8));
    builder.when_transition().assert_eq(
        packed::<AB>(&next[CURSOR..WIDTH]),
        cursor.clone() + active.clone(),
    );
    let expected_cursor: AB::Expr = (0..EVENTS)
        .map(|event| local[PROGRAM + event] * BabyBear::from_usize(8 + event))
        .sum();
    builder.when(active).assert_eq(cursor, expected_cursor);
}

pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    statement
        .coefficients
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .chain(statement.context)
        .map(BabyBear::from_u8)
        .collect()
}

pub(crate) fn expansion(witness: &Witness) -> (Vec<[u64; 25]>, [u8; CAPACITY]) {
    let block = message(witness);
    let mut state = [0u64; 25];
    for (lane, bytes) in block.chunks_exact(8).enumerate() {
        state[lane] = u64::from_le_bytes(bytes.try_into().unwrap());
    }
    let mut inputs = Vec::new();
    let mut output = [0u8; CAPACITY];
    for block in 0..BLOCKS {
        inputs.push(state);
        state = state_after(state);
        for (lane, value) in state.iter().take(RATE / 8).enumerate() {
            output[block * RATE + lane * 8..block * RATE + lane * 8 + 8]
                .copy_from_slice(&value.to_le_bytes());
        }
    }
    (inputs, output)
}

fn message(witness: &Witness) -> [u8; RATE] {
    let mut block = [0u8; RATE];
    block[..64].copy_from_slice(&witness.seed);
    block[64] = 31;
    block[RATE - 1] = 128;
    block
}

pub(crate) fn bits(row: &mut [BabyBear], start: usize, value: u32, count: usize) {
    for bit in 0..count {
        row[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
    }
}

pub fn trace(witness: &Witness, statement: &Statement) -> Result<RowMajorMatrix<BabyBear>, Error> {
    statement.validate()?;
    let (inputs, output) = expansion(witness);
    trace_with_expansion(witness, inputs, output, false)
}

pub(crate) fn trace_with_expansion(
    witness: &Witness,
    mut inputs: Vec<[u64; 25]>,
    output: [u8; CAPACITY],
    allow_incomplete: bool,
) -> Result<RowMajorMatrix<BabyBear>, Error> {
    let signs = u64::from_le_bytes(output[..8].try_into().unwrap());
    let mut final_signed = [0i8; 256];
    let mut completed = 0;
    for candidate in &output[8..] {
        let i = 196 + completed;
        let j = usize::from(*candidate);
        if j <= i {
            final_signed[i] = final_signed[j];
            final_signed[j] = if (signs >> completed) & 1 == 0 { 1 } else { -1 };
            completed += 1;
            if completed == 60 {
                break;
            }
        }
    }
    if completed != 60 && !allow_incomplete {
        return Err(Error::UnsupportedCapacity);
    }
    assert_eq!(inputs.len(), BLOCKS);
    inputs.resize(17, [0; 25]);
    let keccak = generate_trace_rows::<BabyBear>(inputs, 0);
    assert_eq!(keccak.height(), HEIGHT);
    let mut values = vec![BabyBear::ZERO; WIDTH * HEIGHT];
    let mut signed = [0i8; 256];
    let mut step = 0usize;
    let mut cursor = 8u32;
    for at in 0..HEIGHT {
        let row = &mut values[at * WIDTH..(at + 1) * WIDTH];
        let kr = keccak.row_slice(at).unwrap();
        row[..NUM_KECCAK_COLS].copy_from_slice(&kr);
        let k: &KeccakCols<BabyBear> = (*kr).borrow();
        let stage = (at / 24).min(BLOCKS);
        row[HASH_PC + stage] = BabyBear::ONE;
        if stage < BLOCKS {
            if stage == 0 {
                for (byte, value) in message(witness).iter().enumerate() {
                    bits(row, MESSAGE + byte * 8, u32::from(*value), 8);
                }
            }
            for limb in 0..RATE / 2 {
                bits(
                    row,
                    OUTPUT + limb * 16,
                    k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32(),
                    16,
                );
            }
        }
        for (byte, value) in witness.seed.iter().enumerate() {
            row[SEED + byte] = BabyBear::from_u8(*value);
        }
        for (byte, value) in output.iter().enumerate() {
            row[XOF + byte] = BabyBear::from_u8(*value);
        }
        for bit in 0..64 {
            row[SIGN_BITS + bit] = BabyBear::from_bool((signs >> bit) & 1 != 0);
        }
        for index in 0..256 {
            row[PLUS + index] = BabyBear::from_bool(signed[index] == 1);
            row[MINUS + index] = BabyBear::from_bool(signed[index] == -1);
            row[FINAL + index] = BabyBear::from_u32(if final_signed[index] == -1 {
                MODULUS - 1
            } else {
                final_signed[index] as u32
            });
        }
        row[PROGRAM + at.min(EVENTS)] = BabyBear::ONE;
        row[COUNT + step] = BabyBear::ONE;
        bits(row, CURSOR, cursor, 9);
        if step < 60 && at < EVENTS {
            let i = 196 + step;
            let j = usize::from(output[8 + at]);
            bits(row, CANDIDATE, j as u32, 8);
            let take = j <= i;
            row[TAKE] = BabyBear::from_bool(take);
            if take {
                bits(row, LOWER, (i - j) as u32, 8);
                row[INDEX + j] = BabyBear::ONE;
                row[OLD_PLUS] = BabyBear::from_bool(signed[j] == 1);
                row[OLD_MINUS] = BabyBear::from_bool(signed[j] == -1);
                signed[i] = signed[j];
                signed[j] = if (signs >> step) & 1 == 0 { 1 } else { -1 };
                step += 1;
            } else {
                bits(row, UPPER, (j - i - 1) as u32, 8);
            }
            cursor += 1;
        }
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}
