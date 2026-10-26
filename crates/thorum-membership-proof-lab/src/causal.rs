use super::*;
use p3_field::{Field, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::Matrix;
use serde_json::Value;
use sha3::{Digest, Sha3_512};
use std::borrow::Borrow;

fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    let text = value.as_str().unwrap();
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

fn fixture() -> (Witness, Statement) {
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/membership-proofs/membership_vectors.json"
    ))
    .unwrap();
    let case = &data["cases"][0];
    let p = &case["public"];
    let w = &case["witness"];
    let mut statement = Statement {
        fee: p["fee"].as_u64().unwrap(),
        chain: bytes(&p["chain_hex"]),
        output_creation_versions: core::array::from_fn(|i| {
            p["output_creation_versions"][i].as_u64().unwrap() as u32
        }),
        asset: bytes(&p["asset_hex"]),
        root: [0; 64],
        output_commitments: core::array::from_fn(|i| bytes(&p["output_commitments_hex"][i])),
        context: bytes(&p["context_hex"]),
    };
    let openings = core::array::from_fn(|i| bytes(&w["openings_hex"][i]));
    let commitments: [[u8; 64]; 2] = core::array::from_fn(|i| {
        Sha3_512::digest(&sponge::note_message(&openings[i])[..464]).into()
    });
    let leaves = commitments.map(|cm| leaf(&statement.chain, &cm));
    let mut siblings = [[[0; 64]; 32]; 2];
    siblings[0][0] = leaves[1];
    siblings[1][0] = leaves[0];
    for input in &mut siblings {
        for (level, sibling) in input.iter_mut().enumerate().skip(1) {
            *sibling = [0x80 + level as u8; 64];
        }
    }
    let witness = Witness::from_openings_and_paths(openings, [0, 1], siblings);
    let mut root = parent(&statement.chain, &leaves[0], &leaves[1]);
    for sibling in witness.siblings[0].iter().skip(1) {
        root = parent(&statement.chain, &root, sibling);
    }
    statement.root = root;
    (witness, statement)
}

fn leaf(chain: &[u8; 32], cm: &[u8; 64]) -> [u8; 64] {
    sponge::hash_fields(b"thorum.relation-lab.merkle-leaf.v1", &[chain, cm])
}

fn parent(chain: &[u8; 32], left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
    sponge::hash_fields(b"thorum.relation-lab.merkle-node.v1", &[chain, left, right])
}

fn message_index(input: usize, level: Option<usize>) -> usize {
    4 + input * 33 + level.map_or(0, |level| level + 1)
}

fn permutation_index(input: usize, level: Option<usize>, block: usize) -> usize {
    28 + input * 98 + level.map_or(0, |level| 2 + level * 3) + block
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Attack {
    CommitmentToLeaf,
    LeafToParent,
    InteriorRollingChild,
    ReversedChildren,
    GlobalCommitmentConstancy,
    DirectionConstancy,
    NonbooleanDirection,
}

pub(crate) const ATTACKS: [Attack; 7] = [
    Attack::CommitmentToLeaf,
    Attack::LeafToParent,
    Attack::InteriorRollingChild,
    Attack::ReversedChildren,
    Attack::GlobalCommitmentConstancy,
    Attack::DirectionConstancy,
    Attack::NonbooleanDirection,
];

pub(crate) fn attack_trace(attack: Attack) -> (RowMajorMatrix<BabyBear>, Statement) {
    let (witness, mut statement) = fixture();
    let mut messages = sponge::messages(&witness, &statement);
    let cms: [[u8; 64]; 2] =
        core::array::from_fn(|input| Sha3_512::digest(&messages[input][..464]).into());
    let original_leaves = cms.map(|cm| leaf(&statement.chain, &cm));
    let mut leaves = original_leaves;
    let mut alternative_cm = cms[0];
    alternative_cm[17] ^= 1;
    if matches!(
        attack,
        Attack::CommitmentToLeaf | Attack::GlobalCommitmentConstancy
    ) {
        messages[message_index(0, None)] = sponge::leaf_message(&statement.chain, &alternative_cm);
        leaves[0] = leaf(&statement.chain, &alternative_cm);
    }
    if matches!(attack, Attack::LeafToParent) {
        leaves[0] = [0x3c; 64];
    }
    let mut roots = [[0; 64]; 2];
    for input in 0..2 {
        let mut current = leaves[input];
        for level in 0..32 {
            if matches!(attack, Attack::InteriorRollingChild) && level == 7 {
                current = [0x5a; 64];
            }
            let sibling = if level == 0 {
                leaves[1 - input]
            } else if matches!(
                attack,
                Attack::DirectionConstancy | Attack::NonbooleanDirection
            ) && level == 1
            {
                current
            } else {
                witness.siblings[input][level]
            };
            let reverse = matches!(attack, Attack::ReversedChildren) && level == 0;
            let direction = ((witness.indices[input] >> level) & 1 != 0) ^ reverse;
            let (left, right) = if direction {
                (sibling, current)
            } else {
                (current, sibling)
            };
            messages[message_index(input, Some(level))] =
                sponge::parent_message(&statement.chain, &left, &right);
            current = parent(&statement.chain, &left, &right);
        }
        roots[input] = current;
    }
    assert_eq!(
        roots[0], roots[1],
        "attack must retain one common public root"
    );
    statement.root = roots[0];
    let mut trace = sponge::trace_with_messages(&witness, &statement, &messages, &[]);
    if matches!(attack, Attack::GlobalCommitmentConstancy) {
        let replacement: [BabyBear; 32] = core::array::from_fn(|limb| {
            BabyBear::from_u16(u16::from_le_bytes([
                alternative_cm[limb * 2],
                alternative_cm[limb * 2 + 1],
            ]))
        });
        let other: [BabyBear; 32] = core::array::from_fn(|limb| {
            BabyBear::from_u16(u16::from_le_bytes([cms[1][limb * 2], cms[1][limb * 2 + 1]]))
        });
        let mut inverse = [BabyBear::ZERO; 32];
        let index = (0..32).find(|&i| replacement[i] != other[i]).unwrap();
        inverse[index] = (replacement[index] - other[index]).inverse();
        for row in 28 * 24..sponge::HEIGHT {
            let start = row * sponge::WIDTH;
            trace.values[start + sponge::COMMITMENTS..start + sponge::COMMITMENTS + 32]
                .copy_from_slice(&replacement);
            trace.values[start + sponge::DISTINCT_INVERSE..start + sponge::DISTINCT_INVERSE + 32]
                .copy_from_slice(&inverse);
        }
    }
    if matches!(
        attack,
        Attack::DirectionConstancy | Attack::NonbooleanDirection
    ) {
        for input in 0..2 {
            let blocks = if matches!(attack, Attack::DirectionConstancy) {
                2..3
            } else {
                0..3
            };
            let value = if matches!(attack, Attack::DirectionConstancy) {
                1
            } else {
                2
            };
            for block in blocks {
                let permutation = permutation_index(input, Some(1), block);
                for row in permutation * 24..(permutation + 1) * 24 {
                    trace.values[row * sponge::WIDTH + sponge::DIRECTION] =
                        BabyBear::from_u8(value);
                }
            }
        }
    }
    (trace, statement)
}

fn keccak_only_is_valid(trace: &RowMajorMatrix<BabyBear>) -> bool {
    let values = trace
        .values
        .chunks_exact(sponge::WIDTH)
        .flat_map(|row| row[..NUM_KECCAK_COLS].iter().copied())
        .collect();
    check_all_constraints(
        &p3_keccak_air::KeccakAir {},
        &RowMajorMatrix::new(values, NUM_KECCAK_COLS),
        &[],
        Some(1),
    )
    .is_ok()
}

fn final_digest(trace: &RowMajorMatrix<BabyBear>, input: usize) -> [u8; 64] {
    let row = trace
        .row_slice((permutation_index(input, Some(31), 2) + 1) * 24 - 1)
        .unwrap();
    let keccak: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
    let mut result = [0; 64];
    for limb in 0..32 {
        result[limb * 2..limb * 2 + 2].copy_from_slice(
            &(keccak
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .as_canonical_u32() as u16)
                .to_le_bytes(),
        );
    }
    result
}

#[test]
fn honest_rebuilt_paths_pass() {
    let (witness, statement) = fixture();
    assert!(trace_is_valid(&trace(&witness, &statement), &statement));
}

#[test]
fn valid_hash_attacks_with_matching_roots_fail_the_complete_air() {
    for attack in ATTACKS {
        let (trace, statement) = attack_trace(attack);
        assert!(
            keccak_only_is_valid(&trace),
            "{attack:?}: genuine permutation traces"
        );
        for input in 0..2 {
            assert_eq!(
                final_digest(&trace, input),
                statement.root,
                "{attack:?}: public root"
            );
        }
        assert!(!trace_is_valid(&trace, &statement), "{attack:?}");
        eprintln!("rejected {attack:?} with valid hashes and matching roots");
    }
}
