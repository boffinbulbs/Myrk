use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{MAX_OUTPUT_BYTES, Statement, Witness};

pub const HEIGHT: usize = 1024;
pub const MAX_PERMUTATIONS: usize = 37;
pub const MAX_RATE: usize = 168;
pub(crate) const SELECTORS: usize = NUM_KECCAK_COLS;
pub(crate) const MESSAGE: usize = SELECTORS + MAX_PERMUTATIONS + 1;
pub(crate) const OUTPUT: usize = MESSAGE + MAX_RATE * 8;
pub const WIDTH: usize = OUTPUT + MAX_RATE * 8;
pub const PUBLIC_VALUES: usize = 1 + 4 + 4 + MAX_OUTPUT_BYTES + 64;
pub(crate) const PUBLIC_OUTPUT: usize = 9;

#[derive(Clone, Copy)]
pub struct HashAir {
    mode: crate::Mode,
    input_length: usize,
    output_length: usize,
}
impl HashAir {
    pub fn new(statement: &Statement) -> Self {
        Self {
            mode: statement.mode,
            input_length: statement.input_length,
            output_length: statement.output_length,
        }
    }
    pub(crate) fn absorbs(&self) -> usize {
        self.input_length / self.mode.rate() + 1
    }
    pub(crate) fn permutations(&self) -> usize {
        self.absorbs() + self.output_length.saturating_sub(1) / self.mode.rate()
    }
}

pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    let mut result = vec![BabyBear::from_u8(statement.mode as u8)];
    result.extend(
        (statement.input_length as u32)
            .to_be_bytes()
            .map(BabyBear::from_u8),
    );
    result.extend(
        (statement.output_length as u32)
            .to_be_bytes()
            .map(BabyBear::from_u8),
    );
    result.extend(statement.output.map(BabyBear::from_u8));
    result.extend(statement.context.map(BabyBear::from_u8));
    result
}

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
        self.0.assert_zero(value)
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }
}
impl<F> BaseAir<F> for HashAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }
}
fn packed<AB: AirBuilder>(local: &[AB::Var], start: usize, bits: usize) -> AB::Expr {
    (0..bits)
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + local[start + bit])
}
impl<AB: AirBuilder> Air<AB> for HashAir {
    fn eval(&self, builder: &mut AB) {
        KeccakAir {}.eval(&mut KeccakBuilder(builder));
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let keccak: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
        let next_keccak: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
        let final_round = keccak.step_flags[23];
        let first_round = keccak.step_flags[0];
        let public = builder.public_values().to_vec();
        let rate = self.mode.rate();
        let absorbs = self.absorbs();
        let permutations = self.permutations();
        builder.assert_eq(public[0], AB::F::from_u8(self.mode as u8));
        for (i, byte) in (self.input_length as u32).to_be_bytes().iter().enumerate() {
            builder.assert_eq(public[1 + i], AB::F::from_u8(*byte));
        }
        for (i, byte) in (self.output_length as u32).to_be_bytes().iter().enumerate() {
            builder.assert_eq(public[5 + i], AB::F::from_u8(*byte));
        }
        for value in &public[PUBLIC_OUTPUT + self.output_length..PUBLIC_OUTPUT + MAX_OUTPUT_BYTES] {
            builder.assert_zero(*value);
        }
        let mut sum = AB::Expr::ZERO;
        for i in 0..=MAX_PERMUTATIONS {
            let selector = local[SELECTORS + i];
            sum += selector.into();
            builder.assert_bool(selector);
            builder
                .when_first_row()
                .assert_eq(selector, AB::F::from_bool(i == 0));
            let advance: AB::Expr = if i == MAX_PERMUTATIONS {
                local[SELECTORS + permutations - 1].into() + local[SELECTORS + i]
            } else if i > 0 && i < permutations {
                local[SELECTORS + i - 1].into()
            } else {
                AB::Expr::ZERO
            };
            builder.when_transition().assert_eq(
                next[SELECTORS + i],
                selector.into() + final_round * (advance - selector),
            );
        }
        builder.assert_one(sum);
        for bit in 0..MAX_RATE * 8 {
            builder.assert_bool(local[MESSAGE + bit]);
            builder.assert_bool(local[OUTPUT + bit]);
            builder
                .when(builder.is_transition() * (AB::Expr::ONE - final_round))
                .assert_eq(local[MESSAGE + bit], next[MESSAGE + bit]);
            if bit >= rate * 8 {
                builder.assert_zero(local[MESSAGE + bit]);
                builder.assert_zero(local[OUTPUT + bit]);
            }
        }
        let first_selector = local[SELECTORS];
        for limb in 0..100 {
            let expected = if limb < rate / 2 {
                packed::<AB>(local, MESSAGE + limb * 16, 16)
            } else {
                AB::Expr::ZERO
            };
            builder.when(first_round * first_selector).assert_eq(
                keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4],
                expected,
            );
        }
        for stage in 0..MAX_PERMUTATIONS {
            let selector = local[SELECTORS + stage];
            for byte in 0..rate {
                let absolute = stage * rate + byte;
                if stage < absorbs && absolute < self.input_length {
                    continue;
                }
                let expected = if stage < absorbs {
                    let mut value = if absolute == self.input_length {
                        self.mode.suffix()
                    } else {
                        0
                    };
                    if absolute + 1 == absorbs * rate {
                        value |= 128;
                    }
                    value
                } else {
                    0
                };
                builder.when(selector).assert_eq(
                    packed::<AB>(local, MESSAGE + byte * 8, 8),
                    AB::F::from_u8(expected),
                );
            }
            if stage >= absorbs - 1 && stage < permutations {
                let offset = (stage + 1 - absorbs) * rate;
                for byte in 0..rate.min(self.output_length.saturating_sub(offset)) {
                    builder.when(final_round * selector).assert_eq(
                        packed::<AB>(local, OUTPUT + byte * 8, 8),
                        public[PUBLIC_OUTPUT + offset + byte],
                    );
                }
            }
        }
        for bit in 0..rate * 8 {
            builder
                .when(local[SELECTORS + MAX_PERMUTATIONS])
                .assert_zero(local[MESSAGE + bit]);
        }
        for limb in 0..rate / 2 {
            builder.when(final_round).assert_eq(
                packed::<AB>(local, OUTPUT + limb * 16, 16),
                keccak.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
            );
        }
        let absorb_next: AB::Expr = (0..absorbs - 1).map(|i| local[SELECTORS + i].into()).sum();
        let squeeze_next: AB::Expr = (absorbs - 1..permutations - 1)
            .map(|i| local[SELECTORS + i].into())
            .sum();
        for limb in 0..100 {
            let last: AB::Expr = keccak
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .into();
            let expected = if limb < rate / 2 {
                (0..16).rev().fold(AB::Expr::ZERO, |acc, bit| {
                    let a: AB::Expr = local[OUTPUT + limb * 16 + bit].into();
                    let b: AB::Expr = next[MESSAGE + limb * 16 + bit].into();
                    acc.double() + a.xor(&b)
                })
            } else {
                last.clone()
            };
            let input = next_keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4];
            builder
                .when(builder.is_transition() * final_round * absorb_next.clone())
                .assert_eq(input, expected);
            builder
                .when(builder.is_transition() * final_round * squeeze_next.clone())
                .assert_eq(input, last);
        }
    }
}

pub(crate) fn blocks(witness: &Witness, statement: &Statement) -> Vec<[u8; MAX_RATE]> {
    let air = HashAir::new(statement);
    let rate = statement.mode.rate();
    let mut result = vec![[0; MAX_RATE]; air.permutations()];
    for (i, byte) in witness.input.iter().copied().enumerate() {
        result[i / rate][i % rate] = byte;
    }
    result[statement.input_length / rate][statement.input_length % rate] = statement.mode.suffix();
    result[air.absorbs() - 1][rate - 1] |= 128;
    result
}
pub fn trace(witness: &Witness, statement: &Statement) -> RowMajorMatrix<BabyBear> {
    trace_with_blocks(statement, &blocks(witness, statement), &[])
}
pub(crate) fn trace_with_blocks(
    statement: &Statement,
    blocks: &[[u8; MAX_RATE]],
    overrides: &[(usize, usize, u64)],
) -> RowMajorMatrix<BabyBear> {
    let air = HashAir::new(statement);
    assert_eq!(blocks.len(), air.permutations());
    let mut inputs = Vec::new();
    let mut state = [0u64; 25];
    for (stage, block) in blocks.iter().enumerate() {
        if stage < air.absorbs() {
            for (lane, bytes) in block[..statement.mode.rate()].chunks_exact(8).enumerate() {
                state[lane] ^= u64::from_le_bytes(bytes.try_into().unwrap());
            }
        }
        for &(at, lane, mask) in overrides {
            if stage == at {
                state[lane] ^= mask;
            }
        }
        inputs.push(state);
        let subtrace = generate_trace_rows::<BabyBear>(vec![state], 0);
        let row = subtrace.row_slice(23).unwrap();
        let typed: &KeccakCols<BabyBear> = (*row).borrow();
        for (lane, word) in state.iter_mut().enumerate() {
            *word = (0..4)
                .map(|limb| {
                    (typed
                        .a_prime_prime_prime(lane / 5, lane % 5, limb)
                        .as_canonical_u32() as u64)
                        << (limb * 16)
                })
                .sum();
        }
    }
    inputs.resize(MAX_PERMUTATIONS, [0; 25]);
    let keccak = generate_trace_rows::<BabyBear>(inputs, 0);
    assert_eq!(keccak.height(), HEIGHT);
    let mut values = Vec::with_capacity(WIDTH * HEIGHT);
    for row_index in 0..HEIGHT {
        let kr = keccak.row_slice(row_index).unwrap();
        let typed: &KeccakCols<BabyBear> = (*kr).borrow();
        values.extend_from_slice(&kr);
        let permutation = row_index / 24;
        let mut extra = vec![BabyBear::ZERO; WIDTH - NUM_KECCAK_COLS];
        let active = if permutation < air.permutations() {
            permutation
        } else {
            MAX_PERMUTATIONS
        };
        extra[active] = BabyBear::ONE;
        if permutation < air.permutations() {
            for bit in 0..MAX_RATE * 8 {
                extra[MESSAGE - NUM_KECCAK_COLS + bit] =
                    BabyBear::from_bool((blocks[permutation][bit / 8] >> (bit % 8)) & 1 != 0);
            }
        }
        for limb in 0..statement.mode.rate() / 2 {
            let word = typed
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .as_canonical_u32();
            for bit in 0..16 {
                extra[OUTPUT - NUM_KECCAK_COLS + limb * 16 + bit] =
                    BabyBear::from_bool((word >> bit) & 1 != 0);
            }
        }
        values.extend(extra);
    }
    RowMajorMatrix::new(values, WIDTH)
}
