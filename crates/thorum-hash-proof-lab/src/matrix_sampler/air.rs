use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use super::{CAPACITY, Error, MODULUS, Statement, Witness};

pub const HEIGHT: usize = 512;
pub const RATE: usize = 168;
pub const BLOCKS: usize = 6;
pub const EVENTS: usize = CAPACITY / 3;
pub const HASH_PC: usize = NUM_KECCAK_COLS;
pub const MESSAGE: usize = HASH_PC + BLOCKS + 1;
pub const OUTPUT: usize = MESSAGE + RATE * 8;
pub const RHO: usize = OUTPUT + RATE * 8;
pub const XOF: usize = RHO + 32;
pub const COEFFICIENTS: usize = XOF + CAPACITY;
pub const PROGRAM: usize = COEFFICIENTS + 256;
pub const COUNT: usize = PROGRAM + EVENTS + 1;
pub const CANDIDATE: usize = COUNT + 257;
pub const SLACK: usize = CANDIDATE + 24;
pub const TAKE: usize = SLACK + 23;
pub const CURSOR: usize = TAKE + 1;
pub const WIDTH: usize = CURSOR + 10;
pub const PUBLIC_VALUES: usize = 1090;

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

pub struct MatrixSamplerAir;
impl<F> BaseAir<F> for MatrixSamplerAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for MatrixSamplerAir {
    fn eval(&self, builder: &mut AB) {
        KeccakAir {}.eval(&mut KeccakBuilder(builder));
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let public = builder.public_values().to_vec();
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
        for column in RHO..XOF {
            builder
                .when_transition()
                .assert_eq(local[column], next[column]);
        }
        for bit in &local[MESSAGE..RHO] {
            builder.assert_bool(*bit);
        }
        for byte in 0..RATE {
            let value = packed::<AB>(&local[MESSAGE + byte * 8..MESSAGE + (byte + 1) * 8]);
            let expected = match byte {
                0..=31 => local[RHO + byte].into(),
                32 => public[1].into(),
                33 => public[0].into(),
                34 => BabyBear::from_u8(31).into(),
                167 => BabyBear::from_u8(128).into(),
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
        for bit in &local[OUTPUT..RHO] {
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

pub(crate) fn eval_sampler<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    let public = builder.public_values().to_vec();
    for column in XOF..PROGRAM {
        builder
            .when_transition()
            .assert_eq(local[column], next[column]);
    }
    let mut program_sum = AB::Expr::ZERO;
    for event in 0..=EVENTS {
        let selector = local[PROGRAM + event];
        builder.assert_bool(selector);
        program_sum += selector.into();
        builder
            .when_first_row()
            .assert_eq(selector, BabyBear::from_bool(event == 0));
        let predecessor = if event == EVENTS {
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
        .assert_one(local[COUNT + 256]);
    builder.assert_bool(local[TAKE]);
    let take: AB::Expr = local[TAKE].into();
    let active = AB::Expr::ONE - local[COUNT + 256];
    builder.assert_zero(take.clone() * local[COUNT + 256]);
    let mut count_sum = AB::Expr::ZERO;
    for index in 0..=256 {
        let selector = local[COUNT + index];
        builder.assert_bool(selector);
        count_sum += selector.into();
        builder
            .when_first_row()
            .assert_eq(selector, BabyBear::from_bool(index == 0));
        let predecessor = if index > 0 {
            local[COUNT + index - 1].into()
        } else {
            AB::Expr::ZERO
        };
        builder.when_transition().assert_eq(
            next[COUNT + index],
            (AB::Expr::ONE - take.clone()) * selector + take.clone() * predecessor,
        );
    }
    builder.assert_one(count_sum);
    builder.when_last_row().assert_one(local[COUNT + 256]);
    for bit in &local[CANDIDATE..TAKE] {
        builder.assert_bool(*bit);
        builder
            .when(AB::Expr::ONE - active.clone())
            .assert_zero(*bit);
    }
    for byte in 0..3 {
        let source: AB::Expr = (0..EVENTS)
            .map(|event| local[PROGRAM + event] * local[XOF + event * 3 + byte])
            .sum();
        builder.when(active.clone()).assert_eq(
            packed::<AB>(&local[CANDIDATE + byte * 8..CANDIDATE + (byte + 1) * 8]),
            source,
        );
    }
    let candidate = packed::<AB>(&local[CANDIDATE..CANDIDATE + 23]);
    let slack = packed::<AB>(&local[SLACK..TAKE]);
    builder.when(take.clone()).assert_eq(
        candidate.clone() + slack.clone(),
        BabyBear::from_u32(MODULUS - 1),
    );
    builder
        .when(active.clone() - take.clone())
        .assert_eq(candidate.clone(), slack + BabyBear::from_u32(MODULUS));
    let cursor = packed::<AB>(&local[CURSOR..WIDTH]);
    for bit in &local[CURSOR..WIDTH] {
        builder.assert_bool(*bit);
    }
    builder.when_first_row().assert_zero(cursor.clone());
    builder.when_transition().assert_eq(
        packed::<AB>(&next[CURSOR..WIDTH]),
        cursor.clone() + active.clone() * BabyBear::from_u8(3),
    );
    let expected_cursor: AB::Expr = (0..EVENTS)
        .map(|event| local[PROGRAM + event] * BabyBear::from_usize(3 * event))
        .sum();
    builder.when(active).assert_eq(cursor, expected_cursor);
    for index in 0..256 {
        let selected = take.clone() * local[COUNT + index];
        builder
            .when(selected.clone())
            .assert_eq(local[COEFFICIENTS + index], candidate.clone());
        for byte in 0..4 {
            let start = byte * 8;
            let expected = if start < 23 {
                packed::<AB>(&local[CANDIDATE + start..CANDIDATE + (start + 8).min(23)])
            } else {
                AB::Expr::ZERO
            };
            builder
                .when(selected.clone())
                .assert_eq(public[2 + index * 4 + byte], expected);
        }
    }
}

pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    [statement.row, statement.column]
        .into_iter()
        .chain(
            statement
                .coefficients
                .iter()
                .flat_map(|value| value.to_le_bytes()),
        )
        .chain(statement.context)
        .map(BabyBear::from_u8)
        .collect()
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

pub(crate) fn expansion(
    witness: &Witness,
    statement: &Statement,
) -> (Vec<[u64; 25]>, [u8; CAPACITY]) {
    let mut padded = [0u8; RATE];
    padded[..32].copy_from_slice(&witness.rho);
    padded[32] = statement.column;
    padded[33] = statement.row;
    padded[34] = 31;
    padded[167] = 128;
    let mut state = [0u64; 25];
    for (lane, bytes) in padded.chunks_exact(8).enumerate() {
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

pub(crate) fn bits(row: &mut [BabyBear], start: usize, value: u32, count: usize) {
    for bit in 0..count {
        row[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
    }
}

pub fn trace(witness: &Witness, statement: &Statement) -> Result<RowMajorMatrix<BabyBear>, Error> {
    statement.validate()?;
    let (inputs, output) = expansion(witness, statement);
    trace_with_expansion(witness, statement, inputs, output)
}

pub(crate) fn trace_with_expansion(
    witness: &Witness,
    statement: &Statement,
    inputs: Vec<[u64; 25]>,
    output: [u8; CAPACITY],
) -> Result<RowMajorMatrix<BabyBear>, Error> {
    build_trace(witness, statement, inputs, output, false)
}

#[cfg(test)]
pub(crate) fn raw_trace_with_expansion(
    witness: &Witness,
    statement: &Statement,
    inputs: Vec<[u64; 25]>,
    output: [u8; CAPACITY],
) -> Result<RowMajorMatrix<BabyBear>, Error> {
    build_trace(witness, statement, inputs, output, true)
}

fn build_trace(
    witness: &Witness,
    statement: &Statement,
    mut inputs: Vec<[u64; 25]>,
    output: [u8; CAPACITY],
    allow_incomplete: bool,
) -> Result<RowMajorMatrix<BabyBear>, Error> {
    let mut coefficients = Vec::new();
    for bytes in output.chunks_exact(3) {
        let value =
            u32::from(bytes[0]) + (u32::from(bytes[1]) << 8) + (u32::from(bytes[2] & 127) << 16);
        if value < MODULUS {
            coefficients.push(value);
        }
        if coefficients.len() == 256 {
            break;
        }
    }
    if coefficients.len() < 256 && !allow_incomplete {
        return Err(Error::UnsupportedCapacity);
    }
    assert_eq!(inputs.len(), BLOCKS);
    inputs.resize(17, [0; 25]);
    let keccak = generate_trace_rows::<BabyBear>(inputs, 0);
    assert_eq!(keccak.height(), HEIGHT);
    let mut values = vec![BabyBear::ZERO; WIDTH * HEIGHT];
    let mut count = 0usize;
    let mut cursor = 0u32;
    for at in 0..HEIGHT {
        let row = &mut values[at * WIDTH..(at + 1) * WIDTH];
        let kr = keccak.row_slice(at).unwrap();
        row[..NUM_KECCAK_COLS].copy_from_slice(&kr);
        let typed: &KeccakCols<BabyBear> = (*kr).borrow();
        let stage = (at / 24).min(BLOCKS);
        row[HASH_PC + stage] = BabyBear::ONE;
        if stage < BLOCKS {
            if stage == 0 {
                let first: Vec<u8> = inputs_for_message(witness, statement);
                for (byte, value) in first.into_iter().enumerate() {
                    bits(row, MESSAGE + byte * 8, u32::from(value), 8);
                }
            }
            for limb in 0..RATE / 2 {
                bits(
                    row,
                    OUTPUT + limb * 16,
                    typed
                        .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32(),
                    16,
                );
            }
        }
        for (byte, value) in witness.rho.iter().enumerate() {
            row[RHO + byte] = BabyBear::from_u8(*value);
        }
        for (byte, value) in output.iter().enumerate() {
            row[XOF + byte] = BabyBear::from_u8(*value);
        }
        for (index, value) in coefficients.iter().enumerate() {
            row[COEFFICIENTS + index] = BabyBear::from_u32(*value);
        }
        let event = at.min(EVENTS);
        row[PROGRAM + event] = BabyBear::ONE;
        row[COUNT + count] = BabyBear::ONE;
        bits(row, CURSOR, cursor, 10);
        if count < 256 && event < EVENTS {
            let bytes = &output[event * 3..event * 3 + 3];
            for (byte, value) in bytes.iter().enumerate() {
                bits(row, CANDIDATE + byte * 8, u32::from(*value), 8);
            }
            let value = u32::from(bytes[0])
                + (u32::from(bytes[1]) << 8)
                + (u32::from(bytes[2] & 127) << 16);
            let take = value < MODULUS;
            row[TAKE] = BabyBear::from_bool(take);
            bits(
                row,
                SLACK,
                if take {
                    MODULUS - 1 - value
                } else {
                    value - MODULUS
                },
                23,
            );
            count += usize::from(take);
            cursor += 3;
        }
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}

fn inputs_for_message(witness: &Witness, statement: &Statement) -> Vec<u8> {
    let mut block = vec![0u8; RATE];
    block[..32].copy_from_slice(&witness.rho);
    block[32] = statement.column;
    block[33] = statement.row;
    block[34] = 31;
    block[167] = 128;
    block
}
