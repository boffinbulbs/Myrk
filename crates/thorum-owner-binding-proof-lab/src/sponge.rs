use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use sha3::{Digest, Sha3_512};

use crate::{Statement, Witness};

pub const DEPTH: usize = 32;
pub const HEIGHT: usize = 8192;
pub const PERMUTATIONS: usize = 308;
pub(crate) const SELECTORS: usize = NUM_KECCAK_COLS;
pub(crate) const MESSAGE: usize = SELECTORS + PERMUTATIONS + 1;
pub(crate) const OUTPUT: usize = MESSAGE + 576;
pub(crate) const AMOUNTS: usize = OUTPUT + 576;
pub(crate) const SUM: usize = AMOUNTS + 256;
pub(crate) const INPUT_CARRY: usize = SUM + 64;
pub(crate) const OUTPUT_CARRY: usize = INPUT_CARRY + 64;
pub(crate) const COMMITMENTS: usize = OUTPUT_CARRY + 64;
pub(crate) const DISTINCT_INVERSE: usize = COMMITMENTS + 64;
pub(crate) const INPUT_VERSIONS: usize = DISTINCT_INVERSE + 32;
pub(crate) const SECRETS: usize = INPUT_VERSIONS + 8;
pub(crate) const BINDINGS: usize = SECRETS + 64;
pub(crate) const OWNERS: usize = BINDINGS + 128;
pub(crate) const CM_SPLIT: usize = OWNERS + 128;
pub(crate) const ROLLING: usize = CM_SPLIT + 4;
pub(crate) const DIRECTION: usize = ROLLING + 32;
pub const WIDTH: usize = DIRECTION + 1;
pub const PUBLIC_VALUES: usize = 64 + 32 + 8 + 32 + 64 + 128 + 128 + 64;
const PUBLIC_ASSET: usize = 104;
const PUBLIC_ROOT: usize = 136;
const PUBLIC_OUTPUTS: usize = 200;
const PUBLIC_NULLIFIERS: usize = 328;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Note(usize),
    Owner(usize),
    Binding(usize),
    Nullifier(usize),
    Leaf(usize),
    Parent(usize, usize),
}
#[derive(Clone, Copy)]
pub(crate) struct Permutation {
    pub kind: Kind,
    pub block: usize,
    pub last: bool,
}
pub(crate) fn schedule() -> Vec<Permutation> {
    let mut result = Vec::new();
    let mut add = |kind, blocks| {
        for block in 0..blocks {
            result.push(Permutation {
                kind,
                block,
                last: block + 1 == blocks,
            });
        }
    };
    for note in 0..4 {
        add(Kind::Note(note), 7);
    }
    for input in 0..2 {
        add(Kind::Owner(input), 37);
        add(Kind::Binding(input), 2);
        add(Kind::Nullifier(input), 3);
        add(Kind::Leaf(input), 2);
        for level in 0..DEPTH {
            add(Kind::Parent(input, level), 3);
        }
    }
    assert_eq!(result.len(), PERMUTATIONS);
    result
}

#[derive(Clone, Copy)]
enum Source {
    Fixed(u8),
    Public(usize),
    Private,
    Amount(usize),
    Version(usize),
    Binding(usize),
    Owner(usize),
}
pub(crate) fn frame(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}
pub(crate) fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> [u8; 64] {
    let mut bytes = Vec::new();
    frame(&mut bytes, domain);
    for field in fields {
        frame(&mut bytes, field);
    }
    Sha3_512::digest(&bytes).into()
}
pub(crate) fn pad(mut bytes: Vec<u8>) -> Vec<u8> {
    let len = bytes.len();
    bytes.resize((len / 72 + 1) * 72, 0);
    bytes[len] = 6;
    *bytes.last_mut().unwrap() |= 128;
    bytes
}
pub(crate) fn owner_message(public_key: &[u8; 2592]) -> Vec<u8> {
    pad(public_key.to_vec())
}
pub(crate) fn note_message(opening: &[u8; 418]) -> Vec<u8> {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"thorum.relation-lab.note-commitment.v2");
    frame(&mut bytes, opening);
    assert_eq!(bytes.len(), 464);
    pad(bytes)
}
pub(crate) fn leaf_message(chain: &[u8; 32], commitment: &[u8; 64]) -> Vec<u8> {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"thorum.relation-lab.merkle-leaf.v1");
    frame(&mut bytes, chain);
    frame(&mut bytes, commitment);
    assert_eq!(bytes.len(), 142);
    pad(bytes)
}
pub(crate) fn parent_message(chain: &[u8; 32], left: &[u8; 64], right: &[u8; 64]) -> Vec<u8> {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"thorum.relation-lab.merkle-node.v1");
    frame(&mut bytes, chain);
    frame(&mut bytes, left);
    frame(&mut bytes, right);
    assert_eq!(bytes.len(), 210);
    pad(bytes)
}
pub(crate) fn binding_message(chain: &[u8; 32], secret: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    frame(
        &mut bytes,
        b"thorum.relation-lab.nullifier-secret-binding.v2",
    );
    frame(&mut bytes, chain);
    frame(&mut bytes, secret);
    assert_eq!(bytes.len(), 123);
    pad(bytes)
}
pub(crate) fn nullifier_message(
    chain: &[u8; 32],
    secret: &[u8; 32],
    commitment: &[u8; 64],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"thorum.relation-lab.note-nullifier.v2");
    frame(&mut bytes, chain);
    frame(&mut bytes, secret);
    frame(&mut bytes, commitment);
    assert_eq!(bytes.len(), 181);
    pad(bytes)
}
fn note_layout(note: usize) -> Vec<Source> {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"thorum.relation-lab.note-opening.v2");
    frame(&mut bytes, &2u16.to_be_bytes());
    frame(&mut bytes, &[0; 32]);
    frame(&mut bytes, &[0; 4]);
    frame(&mut bytes, &[0; 32]);
    frame(&mut bytes, &[0; 8]);
    for _ in 0..3 {
        frame(&mut bytes, &[0; 64]);
    }
    for _ in 0..2 {
        frame(&mut bytes, &[0; 32]);
    }
    frame(&mut bytes, &[0]);
    let opening: [u8; 418] = bytes.try_into().unwrap();
    let mut result: Vec<_> = note_message(&opening)
        .into_iter()
        .map(Source::Fixed)
        .collect();
    for (start, end) in [(187, 251), (255, 319), (323, 387), (391, 423), (427, 459)] {
        result[start..end].fill(Source::Private);
    }
    if note < 2 {
        for i in 0..64 {
            result[255 + i] = Source::Binding(note * 64 + i);
            result[187 + i] = Source::Owner(note * 64 + i);
        }
    }
    for i in 0..32 {
        result[95 + i] = Source::Public(64 + i);
        result[139 + i] = Source::Public(PUBLIC_ASSET + i);
    }
    for i in 0..4 {
        result[131 + i] = if note < 2 {
            Source::Version(note * 4 + i)
        } else {
            Source::Public(96 + (note - 2) * 4 + i)
        };
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
    for version in statement.output_creation_versions {
        result.extend(version.to_be_bytes().map(BabyBear::from_u8));
    }
    result.extend(statement.asset.map(BabyBear::from_u8));
    result.extend(statement.root.map(BabyBear::from_u8));
    for digest in statement.output_commitments {
        result.extend(digest.map(BabyBear::from_u8));
    }
    for digest in statement.nullifiers {
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
        self.0.assert_zero(value)
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        self.0.public_values()
    }
}
pub struct OwnerBindingAir;
impl<F> BaseAir<F> for OwnerBindingAir {
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
impl<AB: AirBuilder> Air<AB> for OwnerBindingAir {
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
        let stages = schedule();
        let mut selector_sum = AB::Expr::ZERO;
        for i in 0..=PERMUTATIONS {
            let selector = local[SELECTORS + i];
            selector_sum += selector.into();
            builder.assert_bool(selector);
            builder
                .when_first_row()
                .assert_eq(selector, AB::F::from_bool(i == 0));
            let advance: AB::Expr = if i == 0 {
                AB::Expr::ZERO
            } else if i == PERMUTATIONS {
                local[SELECTORS + i - 1].into() + local[SELECTORS + i]
            } else {
                local[SELECTORS + i - 1].into()
            };
            builder.when_transition().assert_eq(
                next[SELECTORS + i],
                selector.into() + final_round * (advance - selector),
            );
        }
        builder.assert_one(selector_sum);
        // These values are shared by all note commitments and both paths.
        for column in AMOUNTS..ROLLING {
            builder
                .when_transition()
                .assert_eq(local[column], next[column]);
        }
        for value in &local[AMOUNTS..INPUT_CARRY + 64] {
            builder.assert_bool(*value);
        }
        for bit in 0..64 {
            let ca: AB::Expr = if bit == 0 {
                AB::Expr::ZERO
            } else {
                local[INPUT_CARRY + bit - 1].into()
            };
            let cb: AB::Expr = if bit == 0 {
                AB::Expr::ZERO
            } else {
                local[OUTPUT_CARRY + bit - 1].into()
            };
            let out = local[OUTPUT_CARRY + bit];
            let oe: AB::Expr = out.into();
            builder.assert_zero(oe.clone() * (oe.clone() - AB::Expr::ONE) * (oe - AB::Expr::TWO));
            builder.assert_eq(
                local[AMOUNTS + bit] + local[AMOUNTS + 64 + bit] + ca,
                local[SUM + bit] + local[INPUT_CARRY + bit] * AB::F::TWO,
            );
            builder.assert_eq(
                local[AMOUNTS + 128 + bit] + local[AMOUNTS + 192 + bit] + public[bit].into() + cb,
                local[SUM + bit] + out * AB::F::TWO,
            );
        }
        builder.assert_zero(local[INPUT_CARRY + 63]);
        builder.assert_zero(local[OUTPUT_CARRY + 63]);
        let distinct: AB::Expr = (0..32)
            .map(|i| {
                (local[COMMITMENTS + i].into() - local[COMMITMENTS + 32 + i])
                    * local[DISTINCT_INVERSE + i]
            })
            .sum();
        builder.assert_one(distinct);
        for bit in 0..576 {
            builder.assert_bool(local[MESSAGE + bit]);
            builder.assert_bool(local[OUTPUT + bit]);
            builder
                .when(builder.is_transition() * (AB::Expr::ONE - final_round))
                .assert_eq(local[MESSAGE + bit], next[MESSAGE + bit]);
        }
        builder.assert_bool(local[DIRECTION]);
        let hash_end: AB::Expr = stages
            .iter()
            .enumerate()
            .filter(|(_, s)| s.last)
            .map(|(i, _)| local[SELECTORS + i].into())
            .sum();
        builder
            .when(builder.is_transition() * (AB::Expr::ONE - final_round * hash_end.clone()))
            .assert_eq(local[DIRECTION], next[DIRECTION]);
        let digest_end: AB::Expr = stages
            .iter()
            .enumerate()
            .filter(|(_, s)| s.last && matches!(s.kind, Kind::Leaf(_) | Kind::Parent(_, _)))
            .map(|(i, _)| local[SELECTORS + i].into())
            .sum();
        for limb in 0..32 {
            let out: AB::Expr = keccak
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .into();
            builder.when_transition().assert_eq(
                next[ROLLING + limb],
                local[ROLLING + limb].into()
                    + final_round * digest_end.clone() * (out - local[ROLLING + limb]),
            );
        }
        // Four exact note encodings share the same constrained integer witness.
        for note in 0..4 {
            let sources = note_layout(note);
            for block in 0..7 {
                let selector = local[SELECTORS + note * 7 + block];
                for byte in 0..72 {
                    let start = MESSAGE + byte * 8;
                    match sources[block * 72 + byte] {
                        Source::Private => {}
                        Source::Amount(offset) => {
                            for bit in 0..8 {
                                builder
                                    .when(selector)
                                    .assert_eq(local[start + bit], local[AMOUNTS + offset + bit]);
                            }
                        }
                        source => {
                            let value: AB::Expr = match source {
                                Source::Fixed(x) => AB::F::from_u8(x).into(),
                                Source::Public(i) => public[i].into(),
                                Source::Version(i) => local[INPUT_VERSIONS + i].into(),
                                Source::Binding(i) => local[BINDINGS + i].into(),
                                Source::Owner(i) => local[OWNERS + i].into(),
                                _ => unreachable!(),
                            };
                            builder
                                .when(selector)
                                .assert_eq(packed::<AB>(local, start, 8), value);
                        }
                    }
                }
            }
            let last = final_round * local[SELECTORS + note * 7 + 6];
            for limb in 0..32 {
                let expected: AB::Expr = if note < 2 {
                    local[COMMITMENTS + note * 32 + limb].into()
                } else {
                    public[PUBLIC_OUTPUTS + (note - 2) * 64 + limb * 2].into()
                        + public[PUBLIC_OUTPUTS + (note - 2) * 64 + limb * 2 + 1].into()
                            * AB::F::from_u16(256)
                };
                builder.when(last.clone()).assert_eq(
                    keccak.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
                    expected,
                );
            }
        }
        // Encoded verification keys are hashed without framing. Exactly 2592
        // data bytes occupy 36 rate blocks. A separate 37th block contains padding.
        for input in 0..2 {
            let final_selector: AB::Expr = stages
                .iter()
                .enumerate()
                .filter(|(_, s)| s.kind == Kind::Owner(input) && s.last)
                .map(|(i, _)| local[SELECTORS + i].into())
                .sum();
            for byte in 0..72 {
                let expected = if byte == 0 {
                    6
                } else if byte == 71 {
                    128
                } else {
                    0
                };
                builder.when(final_selector.clone()).assert_eq(
                    packed::<AB>(local, MESSAGE + byte * 8, 8),
                    AB::F::from_u8(expected),
                );
            }
            for limb in 0..32 {
                let start = OWNERS + input * 64 + limb * 2;
                let expected: AB::Expr =
                    local[start].into() + local[start + 1] * AB::F::from_u16(256);
                builder
                    .when(final_round * final_selector.clone())
                    .assert_eq(
                        keccak.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
                        expected,
                    );
            }
        }
        // Both message families share the retained key and the exact committed
        // binding bytes. CM limb13 crosses the nullifier sponge rate boundary.
        for input in 0..2 {
            builder.assert_eq(
                local[COMMITMENTS + input * 32 + 13],
                local[CM_SPLIT + input * 2].into()
                    + local[CM_SPLIT + input * 2 + 1] * AB::F::from_u16(256),
            );
            for kind in [Kind::Binding(input), Kind::Nullifier(input)] {
                let is_binding = matches!(kind, Kind::Binding(_));
                let template = if is_binding {
                    binding_message(&[0; 32], &[0; 32])
                } else {
                    nullifier_message(&[0; 32], &[0; 32], &[0; 64])
                };
                let (chain_start, secret_start) = if is_binding { (55, 91) } else { (45, 81) };
                for block in 0..template.len() / 72 {
                    let selector: AB::Expr = stages
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| s.kind == kind && s.block == block)
                        .map(|(i, _)| local[SELECTORS + i].into())
                        .sum();
                    for byte in 0..72 {
                        let absolute = block * 72 + byte;
                        let expected: AB::Expr =
                            if (chain_start..chain_start + 32).contains(&absolute) {
                                public[64 + absolute - chain_start].into()
                            } else if (secret_start..secret_start + 32).contains(&absolute) {
                                local[SECRETS + input * 32 + absolute - secret_start].into()
                            } else if !is_binding && (117..181).contains(&absolute) {
                                if absolute == 143 || absolute == 144 {
                                    local[CM_SPLIT + input * 2 + absolute - 143].into()
                                } else {
                                    continue;
                                }
                            } else {
                                AB::F::from_u8(template[absolute]).into()
                            };
                        builder
                            .when(selector.clone())
                            .assert_eq(packed::<AB>(local, MESSAGE + byte * 8, 8), expected);
                    }
                    if !is_binding {
                        for limb in 0..32 {
                            if limb == 13 {
                                continue;
                            }
                            let absolute = 117 + limb * 2;
                            if absolute / 72 != block {
                                continue;
                            }
                            builder.when(selector.clone()).assert_eq(
                                packed::<AB>(local, MESSAGE + (absolute % 72) * 8, 16),
                                local[COMMITMENTS + input * 32 + limb],
                            );
                        }
                    }
                }
                let last: AB::Expr = stages
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.kind == kind && s.last)
                    .map(|(i, _)| local[SELECTORS + i].into())
                    .sum();
                for limb in 0..32 {
                    let start = if is_binding {
                        BINDINGS + input * 64 + limb * 2
                    } else {
                        PUBLIC_NULLIFIERS + input * 64 + limb * 2
                    };
                    let expected: AB::Expr = if is_binding {
                        local[start].into() + local[start + 1] * AB::F::from_u16(256)
                    } else {
                        public[start].into() + public[start + 1].into() * AB::F::from_u16(256)
                    };
                    builder.when(final_round * last.clone()).assert_eq(
                        keccak.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
                        expected,
                    );
                }
            }
        }
        // Each leaf has its own hidden commitment. All node hashes share the
        // same exact encoding and privately choose the side of the rolling child.
        for input in 0..2 {
            let zero = [0; 64];
            let template = leaf_message(&[0; 32], &zero);
            for block in 0..2 {
                let selector: AB::Expr = stages
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.kind == Kind::Leaf(input) && s.block == block)
                    .map(|(i, _)| local[SELECTORS + i].into())
                    .sum();
                for byte in 0..72 {
                    let absolute = block * 72 + byte;
                    if (78..142).contains(&absolute) {
                        continue;
                    }
                    let expected: AB::Expr = if (42..74).contains(&absolute) {
                        public[64 + absolute - 42].into()
                    } else {
                        AB::F::from_u8(template[absolute]).into()
                    };
                    builder
                        .when(selector.clone())
                        .assert_eq(packed::<AB>(local, MESSAGE + byte * 8, 8), expected);
                }
                for limb in 0..32 {
                    let absolute = 78 + limb * 2;
                    if absolute / 72 != block {
                        continue;
                    }
                    builder.when(selector.clone()).assert_eq(
                        packed::<AB>(local, MESSAGE + (absolute % 72) * 8, 16),
                        local[COMMITMENTS + input * 32 + limb],
                    );
                }
            }
        }
        let template = parent_message(&[0; 32], &[0; 64], &[0; 64]);
        for block in 0..3 {
            let selector: AB::Expr = stages
                .iter()
                .enumerate()
                .filter(|(_, s)| matches!(s.kind, Kind::Parent(_, _)) && s.block == block)
                .map(|(i, _)| local[SELECTORS + i].into())
                .sum();
            for byte in 0..72 {
                let absolute = block * 72 + byte;
                if (78..142).contains(&absolute) || (146..210).contains(&absolute) {
                    continue;
                }
                let expected: AB::Expr = if (42..74).contains(&absolute) {
                    public[64 + absolute - 42].into()
                } else {
                    AB::F::from_u8(template[absolute]).into()
                };
                builder
                    .when(selector.clone())
                    .assert_eq(packed::<AB>(local, MESSAGE + byte * 8, 8), expected);
            }
            for limb in 0..32 {
                for (start, right) in [(78, false), (146, true)] {
                    let absolute = start + limb * 2;
                    if absolute / 72 != block {
                        continue;
                    }
                    let side: AB::Expr = if right {
                        local[DIRECTION].into()
                    } else {
                        AB::Expr::ONE - local[DIRECTION]
                    };
                    builder.when(selector.clone() * side).assert_eq(
                        packed::<AB>(local, MESSAGE + (absolute % 72) * 8, 16),
                        local[ROLLING + limb],
                    );
                }
            }
        }
        // Every hash starts from an all zero SHA3 capacity. Interior sponge
        // blocks absorb all rate bits and preserve every capacity limb.
        let first_hash: AB::Expr = stages
            .iter()
            .enumerate()
            .filter(|(_, s)| s.block == 0)
            .map(|(i, _)| local[SELECTORS + i].into())
            .sum();
        for limb in 0..100 {
            let expected = if limb < 36 {
                packed::<AB>(local, MESSAGE + limb * 16, 16)
            } else {
                AB::Expr::ZERO
            };
            builder.when(first_round * first_hash.clone()).assert_eq(
                keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4],
                expected,
            );
        }
        for limb in 0..36 {
            builder.when(final_round).assert_eq(
                packed::<AB>(local, OUTPUT + limb * 16, 16),
                keccak.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
            );
        }
        let continuation: AB::Expr = stages
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.last)
            .map(|(i, _)| local[SELECTORS + i].into())
            .sum();
        let boundary = builder.is_transition() * final_round * continuation;
        for limb in 0..100 {
            let expected = if limb < 36 {
                (0..16).rev().fold(AB::Expr::ZERO, |acc, bit| {
                    let a: AB::Expr = local[OUTPUT + limb * 16 + bit].into();
                    let b: AB::Expr = next[MESSAGE + limb * 16 + bit].into();
                    acc.double() + a.xor(&b)
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
        let path_end: AB::Expr = stages
            .iter()
            .enumerate()
            .filter(|(_, s)| s.last && matches!(s.kind, Kind::Parent(_, 31)))
            .map(|(i, _)| local[SELECTORS + i].into())
            .sum();
        for limb in 0..32 {
            let expected: AB::Expr = public[PUBLIC_ROOT + limb * 2].into()
                + public[PUBLIC_ROOT + limb * 2 + 1].into() * AB::F::from_u16(256);
            builder.when(final_round * path_end.clone()).assert_eq(
                keccak.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
                expected,
            );
        }
    }
}

pub(crate) fn messages(witness: &Witness, statement: &Statement) -> Vec<Vec<u8>> {
    let mut result: Vec<_> = witness.openings.iter().map(note_message).collect();
    for input in 0..2 {
        let cm: [u8; 64] = Sha3_512::digest(&result[input][..464]).into();
        result.push(owner_message(&witness.public_keys[input]));
        result.push(binding_message(&statement.chain, &witness.secrets[input]));
        result.push(nullifier_message(
            &statement.chain,
            &witness.secrets[input],
            &cm,
        ));
        result.push(leaf_message(&statement.chain, &cm));
        let mut current = hash_fields(
            b"thorum.relation-lab.merkle-leaf.v1",
            &[&statement.chain, &cm],
        );
        for level in 0..DEPTH {
            let sibling = &witness.siblings[input][level];
            let (left, right) = if (witness.indices[input] >> level) & 1 == 0 {
                (&current, sibling)
            } else {
                (sibling, &current)
            };
            let message = parent_message(&statement.chain, left, right);
            current = Sha3_512::digest(&message[..210]).into();
            result.push(message);
        }
    }
    result
}
pub fn trace(witness: &Witness, statement: &Statement) -> RowMajorMatrix<BabyBear> {
    trace_with_messages(witness, statement, &messages(witness, statement), &[])
}
pub(crate) fn trace_with_messages(
    witness: &Witness,
    statement: &Statement,
    messages: &[Vec<u8>],
    overrides: &[(usize, usize, u64)],
) -> RowMajorMatrix<BabyBear> {
    let mut inputs = Vec::new();
    let mut blocks = Vec::new();
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
            blocks.push(block);
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
    assert_eq!(inputs.len(), PERMUTATIONS);
    let keccak = generate_trace_rows::<BabyBear>(inputs, 0);
    assert_eq!(keccak.height(), HEIGHT);
    let amounts = witness
        .openings
        .map(|o| u64::from_be_bytes(o[129..137].try_into().unwrap()));
    let mut global = vec![BabyBear::ZERO; ROLLING - AMOUNTS];
    for note in 0..4 {
        for bit in 0..64 {
            global[note * 64 + bit] = BabyBear::from_bool((amounts[note] >> bit) & 1 != 0);
        }
    }
    let (mut ca, mut cb) = (0, 0);
    for bit in 0..64 {
        let a = ((amounts[0] >> bit) & 1) + ((amounts[1] >> bit) & 1) + ca;
        let b = ((amounts[2] >> bit) & 1)
            + ((amounts[3] >> bit) & 1)
            + ((statement.fee >> bit) & 1)
            + cb;
        global[SUM - AMOUNTS + bit] = BabyBear::from_u8((a & 1) as u8);
        ca = a >> 1;
        cb = b >> 1;
        global[INPUT_CARRY - AMOUNTS + bit] = BabyBear::from_u8(ca as u8);
        global[OUTPUT_CARRY - AMOUNTS + bit] = BabyBear::from_u8(cb as u8);
    }
    for input in 0..2 {
        let cm: [u8; 64] = Sha3_512::digest(&note_message(&witness.openings[input])[..464]).into();
        for limb in 0..32 {
            global[COMMITMENTS - AMOUNTS + input * 32 + limb] =
                BabyBear::from_u16(u16::from_le_bytes([cm[limb * 2], cm[limb * 2 + 1]]));
        }
        for i in 0..32 {
            global[SECRETS - AMOUNTS + input * 32 + i] =
                BabyBear::from_u8(witness.secrets[input][i]);
        }
        for i in 0..64 {
            global[BINDINGS - AMOUNTS + input * 64 + i] =
                BabyBear::from_u8(witness.openings[input][209 + i]);
            global[OWNERS - AMOUNTS + input * 64 + i] =
                BabyBear::from_u8(witness.openings[input][141 + i]);
        }
        for i in 0..2 {
            global[CM_SPLIT - AMOUNTS + input * 2 + i] = BabyBear::from_u8(cm[26 + i]);
        }
        for i in 0..4 {
            global[INPUT_VERSIONS - AMOUNTS + input * 4 + i] =
                BabyBear::from_u8(witness.openings[input][85 + i]);
        }
    }
    for limb in 0..32 {
        let delta =
            global[COMMITMENTS - AMOUNTS + limb] - global[COMMITMENTS - AMOUNTS + 32 + limb];
        if delta != BabyBear::ZERO {
            global[DISTINCT_INVERSE - AMOUNTS + limb] = delta.inverse();
            break;
        }
    }
    let stages = schedule();
    let mut rolling = [BabyBear::ZERO; 32];
    let mut values = Vec::with_capacity(WIDTH * HEIGHT);
    for row_index in 0..HEIGHT {
        let kr = keccak.row_slice(row_index).unwrap();
        values.extend_from_slice(&kr);
        let typed: &KeccakCols<BabyBear> = (*kr).borrow();
        let permutation = (row_index / 24).min(PERMUTATIONS);
        let mut extras = vec![BabyBear::ZERO; AMOUNTS - NUM_KECCAK_COLS];
        extras[permutation] = BabyBear::ONE;
        if permutation < PERMUTATIONS {
            for bit in 0..576 {
                extras[MESSAGE - NUM_KECCAK_COLS + bit] =
                    BabyBear::from_bool((blocks[permutation][bit / 8] >> (bit % 8)) & 1 != 0);
            }
        }
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
        values.extend_from_slice(&global);
        values.extend_from_slice(&rolling);
        let direction = if permutation < PERMUTATIONS {
            match stages[permutation].kind {
                Kind::Parent(input, level) => (witness.indices[input] >> level) & 1 != 0,
                _ => false,
            }
        } else {
            false
        };
        // Direction may change only after a complete hash. Leaf/note hashes use
        // the following parent's direction, keeping each full hash constant.
        values.push(BabyBear::from_bool(direction));
        if permutation < PERMUTATIONS
            && row_index % 24 == 23
            && stages[permutation].last
            && matches!(stages[permutation].kind, Kind::Leaf(_) | Kind::Parent(_, _))
        {
            for (limb, value) in rolling.iter_mut().enumerate() {
                *value = typed.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4);
            }
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}
