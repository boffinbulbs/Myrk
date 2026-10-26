use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::Statement;

pub const HEIGHT: usize = 1024;
pub(crate) const SELECTORS: usize = NUM_KECCAK_COLS;
pub(crate) const MESSAGE: usize = SELECTORS + 29;
pub(crate) const OUTPUT: usize = MESSAGE + 576;
pub(crate) const AMOUNTS: usize = OUTPUT + 576;
pub(crate) const SUM: usize = AMOUNTS + 256;
pub(crate) const INPUT_CARRY: usize = SUM + 64;
pub(crate) const OUTPUT_CARRY: usize = INPUT_CARRY + 64;
pub const WIDTH: usize = OUTPUT_CARRY + 64;
pub const PUBLIC_VALUES: usize = 64 + 32 + 16 + 32 + 256 + 64;

#[derive(Clone, Copy)]
enum Source {
    Fixed(u8),
    Public(usize),
    Private,
    Amount(usize),
}

fn frame(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

pub fn opening_bytes(amount: u64, note: usize, statement: &Statement) -> [u8; 418] {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"thorum.relation-lab.note-opening.v2");
    frame(&mut bytes, &2u16.to_be_bytes());
    frame(&mut bytes, &statement.chain);
    frame(&mut bytes, &statement.creation_versions[note].to_be_bytes());
    frame(&mut bytes, &statement.asset);
    frame(&mut bytes, &amount.to_be_bytes());
    frame(&mut bytes, &[11 + note as u8; 64]);
    frame(&mut bytes, &[21 + note as u8; 64]);
    frame(&mut bytes, &[31 + note as u8; 64]);
    frame(&mut bytes, &[41 + note as u8; 32]);
    frame(&mut bytes, &[51 + note as u8; 32]);
    frame(&mut bytes, &[0]);
    bytes.try_into().unwrap()
}

pub fn padded(opening: &[u8; 418]) -> [u8; 504] {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"thorum.relation-lab.note-commitment.v2");
    frame(&mut bytes, opening);
    assert_eq!(bytes.len(), 464);
    bytes.resize(504, 0);
    bytes[464] = 6;
    bytes[503] = 128;
    bytes.try_into().unwrap()
}

fn layout(note: usize) -> [Source; 504] {
    let statement = Statement {
        fee: 0,
        chain: [0; 32],
        creation_versions: [0; 4],
        asset: [0; 32],
        commitments: [[0; 64]; 4],
        context: [0; 64],
    };
    let mut result = padded(&opening_bytes(0, note, &statement)).map(Source::Fixed);
    for (start, end) in [(187, 251), (255, 319), (323, 387), (391, 423), (427, 459)] {
        result[start..end].fill(Source::Private);
    }
    for i in 0..32 {
        result[95 + i] = Source::Public(64 + i);
    }
    for i in 0..4 {
        result[131 + i] = Source::Public(96 + note * 4 + i);
    }
    for i in 0..32 {
        result[139 + i] = Source::Public(112 + i);
    }
    for i in 0..8 {
        result[175 + i] = Source::Amount(note * 64 + (7 - i) * 8);
    }
    result
}

pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    let mut result: Vec<_> = (0..64)
        .map(|i| BabyBear::from_u8(((statement.fee >> i) & 1) as u8))
        .collect();
    result.extend(statement.chain.map(BabyBear::from_u8));
    for version in statement.creation_versions {
        result.extend(version.to_be_bytes().map(BabyBear::from_u8));
    }
    result.extend(statement.asset.map(BabyBear::from_u8));
    for digest in statement.commitments {
        result.extend(digest.map(BabyBear::from_u8));
    }
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
        self.0.assert_zero(value);
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }
}

pub struct NoteConservationAir;
impl<F> BaseAir<F> for NoteConservationAir {
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
impl<AB: AirBuilder> Air<AB> for NoteConservationAir {
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

        // A fixed schedule identifies all 28 real permutations and padding.
        let mut selector_sum = AB::Expr::ZERO;
        for i in 0..29 {
            let selector = local[SELECTORS + i];
            selector_sum += selector.into();
            builder.assert_bool(selector);
            builder
                .when_first_row()
                .assert_eq(selector, AB::F::from_bool(i == 0));
            let advance: AB::Expr = if i == 0 {
                AB::Expr::ZERO
            } else if i == 28 {
                local[SELECTORS + 27].into() + local[SELECTORS + 28]
            } else {
                local[SELECTORS + i - 1].into()
            };
            builder.when_transition().assert_eq(
                next[SELECTORS + i],
                selector.into() + final_round * (advance - selector),
            );
        }
        builder.assert_one(selector_sum);

        // Private integers and carries are shared by every note hash in this proof.
        for column in AMOUNTS..WIDTH {
            builder
                .when_transition()
                .assert_eq(local[column], next[column]);
        }
        for value in &local[AMOUNTS..INPUT_CARRY + 64] {
            builder.assert_bool(*value);
        }
        for bit in 0..64 {
            let carry_a: AB::Expr = if bit == 0 {
                AB::Expr::ZERO
            } else {
                local[INPUT_CARRY + bit - 1].into()
            };
            let carry_b: AB::Expr = if bit == 0 {
                AB::Expr::ZERO
            } else {
                local[OUTPUT_CARRY + bit - 1].into()
            };
            let out = local[OUTPUT_CARRY + bit];
            let out_expr: AB::Expr = out.into();
            builder.assert_zero(
                out_expr.clone() * (out_expr.clone() - AB::Expr::ONE) * (out_expr - AB::Expr::TWO),
            );
            builder.assert_eq(
                local[AMOUNTS + bit] + local[AMOUNTS + 64 + bit] + carry_a,
                local[SUM + bit] + local[INPUT_CARRY + bit] * AB::F::TWO,
            );
            builder.assert_eq(
                local[AMOUNTS + 128 + bit]
                    + local[AMOUNTS + 192 + bit]
                    + public[bit].into()
                    + carry_b,
                local[SUM + bit] + out * AB::F::TWO,
            );
        }
        builder.assert_zero(local[INPUT_CARRY + 63]);
        builder.assert_zero(local[OUTPUT_CARRY + 63]);

        // Each message block is constant for all rounds of its permutation.
        for bit in 0..576 {
            builder.assert_bool(local[MESSAGE + bit]);
            builder
                .when(builder.is_transition() * (AB::Expr::ONE - final_round))
                .assert_eq(local[MESSAGE + bit], next[MESSAGE + bit]);
            builder.assert_bool(local[OUTPUT + bit]);
        }
        for note in 0..4 {
            let sources = layout(note);
            for block in 0..7 {
                let selector = local[SELECTORS + note * 7 + block];
                for byte in 0..72 {
                    let bits = &local[MESSAGE + byte * 8..MESSAGE + byte * 8 + 8];
                    match sources[block * 72 + byte] {
                        Source::Private => {}
                        Source::Amount(offset) => {
                            for bit in 0..8 {
                                builder
                                    .when(selector)
                                    .assert_eq(bits[bit], local[AMOUNTS + offset + bit]);
                            }
                        }
                        source => {
                            let value: AB::Expr = match source {
                                Source::Fixed(value) => AB::F::from_u8(value).into(),
                                Source::Public(index) => public[index].into(),
                                _ => unreachable!(),
                            };
                            let packed = (0..8)
                                .rev()
                                .fold(AB::Expr::ZERO, |acc, bit| acc.double() + bits[bit]);
                            builder.when(selector).assert_eq(packed, value);
                        }
                    }
                }
            }
            let first_selector = local[SELECTORS + note * 7];
            let first = first_round * first_selector;
            for limb in 0..100 {
                let expected = if limb < 36 {
                    (0..16).rev().fold(AB::Expr::ZERO, |acc, bit| {
                        acc.double() + local[MESSAGE + limb * 16 + bit]
                    })
                } else {
                    AB::Expr::ZERO
                };
                builder.when(first.clone()).assert_eq(
                    keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4],
                    expected,
                );
            }
            let last = final_round * local[SELECTORS + note * 7 + 6];
            for limb in 0..32 {
                let expected = public[144 + note * 64 + limb * 2].into()
                    + public[144 + note * 64 + limb * 2 + 1].into() * AB::F::from_u16(256);
                builder.when(last.clone()).assert_eq(
                    keccak.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
                    expected,
                );
            }
        }
        // All rate output bits are tied to the actual permutation, not host hashing.
        for limb in 0..36 {
            let packed = (0..16).rev().fold(AB::Expr::ZERO, |acc, bit| {
                acc.double() + local[OUTPUT + limb * 16 + bit]
            });
            builder.when(final_round).assert_eq(
                packed,
                keccak.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
            );
        }
        let continuation: AB::Expr = (0..28)
            .filter(|i| i % 7 != 6)
            .map(|i| local[SELECTORS + i].into())
            .sum();
        let boundary = builder.is_transition() * final_round * continuation;
        for limb in 0..100 {
            let expected = if limb < 36 {
                (0..16).rev().fold(AB::Expr::ZERO, |acc, bit| {
                    let output: AB::Expr = local[OUTPUT + limb * 16 + bit].into();
                    let message: AB::Expr = next[MESSAGE + limb * 16 + bit].into();
                    acc.double() + output.xor(&message)
                })
            } else {
                keccak
                    .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                    .into()
            };
            builder.when(boundary.clone()).assert_eq(
                next_keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4],
                expected,
            );
        }
    }
}

pub fn trace(openings: &[[u8; 418]; 4], statement: &Statement) -> RowMajorMatrix<BabyBear> {
    let messages = openings.map(|opening| padded(&opening));
    trace_with_messages(openings, statement, &messages, &[])
}

pub(crate) fn trace_with_messages(
    openings: &[[u8; 418]; 4],
    statement: &Statement,
    messages: &[[u8; 504]; 4],
    overrides: &[(usize, usize, u64)],
) -> RowMajorMatrix<BabyBear> {
    let mut inputs = Vec::new();
    for message in messages {
        let mut state = [0u64; 25];
        for block in message.chunks_exact(72) {
            for (lane, bytes) in block.chunks_exact(8).enumerate() {
                state[lane] ^= u64::from_le_bytes(bytes.try_into().unwrap());
            }
            for &(permutation, lane, mask) in overrides {
                if inputs.len() == permutation {
                    state[lane] ^= mask;
                }
            }
            inputs.push(state);
            let subtrace = generate_trace_rows::<BabyBear>(vec![state], 0);
            let row = subtrace.row_slice(23).unwrap();
            let row: &KeccakCols<BabyBear> = (*row).borrow();
            for (lane, word) in state.iter_mut().enumerate() {
                *word = (0..4)
                    .map(|limb| {
                        (row.a_prime_prime_prime(lane / 5, lane % 5, limb)
                            .as_canonical_u32() as u64)
                            << (limb * 16)
                    })
                    .sum();
            }
        }
    }
    let keccak = generate_trace_rows::<BabyBear>(inputs, 0);
    assert_eq!(keccak.height(), HEIGHT);
    let amounts = openings.map(|opening| u64::from_be_bytes(opening[129..137].try_into().unwrap()));
    let mut global = [BabyBear::ZERO; WIDTH - AMOUNTS];
    for note in 0..4 {
        for bit in 0..64 {
            global[note * 64 + bit] = BabyBear::from_bool(((amounts[note] >> bit) & 1) != 0);
        }
    }
    let mut carry_a = 0;
    let mut carry_b = 0;
    for bit in 0..64 {
        let a = ((amounts[0] >> bit) & 1) + ((amounts[1] >> bit) & 1) + carry_a;
        let b = ((amounts[2] >> bit) & 1)
            + ((amounts[3] >> bit) & 1)
            + ((statement.fee >> bit) & 1)
            + carry_b;
        global[SUM - AMOUNTS + bit] = BabyBear::from_u8((a & 1) as u8);
        carry_a = a >> 1;
        carry_b = b >> 1;
        global[INPUT_CARRY - AMOUNTS + bit] = BabyBear::from_u8(carry_a as u8);
        global[OUTPUT_CARRY - AMOUNTS + bit] = BabyBear::from_u8(carry_b as u8);
    }
    let mut values = Vec::with_capacity(WIDTH * HEIGHT);
    for row_index in 0..HEIGHT {
        let keccak_row = keccak.row_slice(row_index).unwrap();
        values.extend_from_slice(&keccak_row);
        let mut extras = vec![BabyBear::ZERO; AMOUNTS - NUM_KECCAK_COLS];
        let permutation = (row_index / 24).min(28);
        extras[permutation] = BabyBear::ONE;
        if permutation < 28 {
            let block =
                &messages[permutation / 7][(permutation % 7) * 72..(permutation % 7 + 1) * 72];
            for bit in 0..576 {
                extras[MESSAGE - NUM_KECCAK_COLS + bit] =
                    BabyBear::from_bool((block[bit / 8] >> (bit % 8)) & 1 != 0);
            }
        }
        let typed: &KeccakCols<BabyBear> = (*keccak_row).borrow();
        for limb in 0..36 {
            let word = typed
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .as_canonical_u32();
            for bit in 0..16 {
                extras[OUTPUT - NUM_KECCAK_COLS + limb * 16 + bit] =
                    BabyBear::from_bool((word >> bit) & 1 != 0);
            }
        }
        values.extend(extras);
        values.extend(global);
    }
    RowMajorMatrix::new(values, WIDTH)
}
