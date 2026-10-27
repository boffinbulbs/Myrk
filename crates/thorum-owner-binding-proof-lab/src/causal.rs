use super::*;
use p3_field::PrimeField32;
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS, generate_trace_rows};
use p3_matrix::Matrix;
use serde_json::Value;
use sha3::{Digest, Sha3_512};
use std::borrow::Borrow;

fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    let text = value.as_str().unwrap();
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}
fn digest(message: &[u8], length: usize) -> [u8; 64] {
    Sha3_512::digest(&message[..length]).into()
}
fn fixture() -> (Witness, Statement) {
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/owner-bindings/owner_binding_vectors.json"
    ))
    .unwrap();
    let case = &data["cases"][64];
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
        nullifiers: [[0; 64]; 2],
        context: bytes(&p["context_hex"]),
    };
    let mut witness = Witness::from_openings_keys_secrets_and_paths(
        core::array::from_fn(|i| bytes(&w["openings_hex"][i])),
        core::array::from_fn(|i| bytes(&w["owner_public_keys_hex"][i])),
        core::array::from_fn(|i| bytes(&w["nullifier_secrets_hex"][i])),
        [0, 1],
        [[[0; 64]; 32]; 2],
    );
    rebuild_membership(&mut witness, &mut statement);
    (witness, statement)
}
fn rebuild_membership(witness: &mut Witness, statement: &mut Statement) {
    let cms: [[u8; 64]; 2] =
        core::array::from_fn(|i| digest(&sponge::note_message(&witness.openings[i]), 464));
    let leaves = cms.map(|cm| digest(&sponge::leaf_message(&statement.chain, &cm), 142));
    witness.siblings[0][0] = leaves[1];
    witness.siblings[1][0] = leaves[0];
    for input in 0..2 {
        let mut current = leaves[input];
        for level in 0..32 {
            if level > 0 {
                witness.siblings[input][level] = [0x90 + level as u8; 64];
            }
            let sibling = witness.siblings[input][level];
            let (left, right) = if (witness.indices[input] >> level) & 1 == 0 {
                (&current, &sibling)
            } else {
                (&sibling, &current)
            };
            current = digest(&sponge::parent_message(&statement.chain, left, right), 210);
        }
        if input == 0 {
            statement.root = current;
        } else {
            assert_eq!(statement.root, current);
        }
        statement.nullifiers[input] = digest(
            &sponge::nullifier_message(&statement.chain, &witness.secrets[input], &cms[input]),
            181,
        );
    }
}
fn owner_start(input: usize) -> usize {
    28 + input * 140
}
fn owner_message_index(input: usize) -> usize {
    4 + input * 36
}
fn owner_digest(message: &[u8], overrides: &[(usize, usize, u64)]) -> [u8; 64] {
    let mut state = [0u64; 25];
    for (block_index, block) in message.chunks_exact(72).enumerate() {
        for (lane, bytes) in block.chunks_exact(8).enumerate() {
            state[lane] ^= u64::from_le_bytes(bytes.try_into().unwrap());
        }
        for &(at, lane, mask) in overrides {
            if at == block_index {
                state[lane] ^= mask;
            }
        }
        let trace = generate_trace_rows::<BabyBear>(vec![state], 0);
        let row = trace.row_slice(23).unwrap();
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
    let mut result = [0; 64];
    for (lane, word) in state.iter().take(8).enumerate() {
        result[lane * 8..lane * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    result
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Attack {
    OpeningLow,
    OpeningHigh,
    WrongKey,
    GlobalOwnerConstancy,
    ByteRangeAlias,
    WrongSuffix,
    NonzeroPadding,
    MissingTerminalBit,
    InitialCapacity,
    RateContinuation,
    CapacityContinuation,
    RollingPollution,
    SwappedKeys,
}

pub(crate) fn attack_trace(input: usize, attack: Attack) -> (RowMajorMatrix<BabyBear>, Statement) {
    let (mut witness, mut statement) = fixture();
    let mut modified_owner = None;
    let mut local_overrides = Vec::new();
    if matches!(attack, Attack::OpeningLow | Attack::OpeningHigh) {
        let byte = if matches!(attack, Attack::OpeningLow) {
            28
        } else {
            29
        };
        witness.openings[input][141 + byte] ^= 1;
        rebuild_membership(&mut witness, &mut statement);
    }
    if matches!(attack, Attack::WrongKey | Attack::GlobalOwnerConstancy) {
        witness.public_keys[input][11] ^= 1;
    }
    if matches!(attack, Attack::SwappedKeys) {
        witness.public_keys.swap(0, 1);
    }
    if matches!(
        attack,
        Attack::WrongSuffix
            | Attack::NonzeroPadding
            | Attack::MissingTerminalBit
            | Attack::InitialCapacity
            | Attack::RateContinuation
            | Attack::CapacityContinuation
    ) {
        let mut owner = sponge::owner_message(&witness.public_keys[input]);
        match attack {
            Attack::WrongSuffix => owner[2592] = 31,
            Attack::NonzeroPadding => owner[2627] = 1,
            Attack::MissingTerminalBit => owner[2663] = 0,
            Attack::InitialCapacity => local_overrides.push((0, 24, 1)),
            Attack::RateContinuation => local_overrides.push((17, 8, 1u64 << 63)),
            Attack::CapacityContinuation => local_overrides.push((17, 24, 1)),
            _ => unreachable!(),
        }
        let actual = owner_digest(&owner, &local_overrides);
        witness.openings[input][141..205].copy_from_slice(&actual);
        rebuild_membership(&mut witness, &mut statement);
        modified_owner = Some(owner);
    }
    let mut messages = sponge::messages(&witness, &statement);
    if let Some(owner) = modified_owner {
        messages[owner_message_index(input)] = owner;
    }
    let overrides: Vec<_> = local_overrides
        .iter()
        .map(|&(block, lane, mask)| (owner_start(input) + block, lane, mask))
        .collect();
    let mut trace = sponge::trace_with_messages(&witness, &statement, &messages, &overrides);
    let actual_owner: [u8; 64] = Sha3_512::digest(witness.public_keys[input]).into();
    if matches!(
        attack,
        Attack::OpeningLow | Attack::OpeningHigh | Attack::GlobalOwnerConstancy
    ) {
        let first_row = if matches!(attack, Attack::GlobalOwnerConstancy) {
            owner_start(input) * 24
        } else {
            0
        };
        for row in first_row..sponge::HEIGHT {
            for (byte, value) in actual_owner.iter().enumerate() {
                trace.values[row * sponge::WIDTH + sponge::OWNERS + input * 64 + byte] =
                    BabyBear::from_u8(*value);
            }
        }
    }
    if matches!(attack, Attack::ByteRangeAlias) {
        for row in 0..sponge::HEIGHT {
            let start = row * sponge::WIDTH + sponge::OWNERS + input * 64 + 28;
            trace.values[start] += BabyBear::from_u16(256);
            trace.values[start + 1] -= BabyBear::ONE;
        }
    }
    if matches!(attack, Attack::RollingPollution) {
        for row in (owner_start(input) + 37) * 24..(owner_start(input) + 44) * 24 {
            for limb in 0..32 {
                trace.values[row * sponge::WIDTH + sponge::ROLLING + limb] =
                    BabyBear::from_u16(u16::from_le_bytes([
                        actual_owner[limb * 2],
                        actual_owner[limb * 2 + 1],
                    ]));
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
fn final_digest(trace: &RowMajorMatrix<BabyBear>, kind: sponge::Kind) -> [u8; 64] {
    let permutation = sponge::schedule()
        .iter()
        .position(|s| s.kind == kind && s.last)
        .unwrap();
    let row = trace.row_slice((permutation + 1) * 24 - 1).unwrap();
    let typed: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
    let mut result = [0; 64];
    for limb in 0..32 {
        result[limb * 2..limb * 2 + 2].copy_from_slice(
            &(typed
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .as_canonical_u32() as u16)
                .to_le_bytes(),
        );
    }
    result
}

fn owner_terminal_matches_registers(trace: &RowMajorMatrix<BabyBear>, input: usize) -> bool {
    let row = (owner_start(input) + 37) * 24 - 1;
    let digest = final_digest(trace, sponge::Kind::Owner(input));
    (0..32).all(|limb| {
        let offset = row * sponge::WIDTH + sponge::OWNERS + input * 64 + limb * 2;
        trace.values[offset] + trace.values[offset + 1] * BabyBear::from_u16(256)
            == BabyBear::from_u16(u16::from_le_bytes([digest[limb * 2], digest[limb * 2 + 1]]))
    })
}

#[test]
fn honest_distinct_keys_and_rebuilt_private_paths_pass() {
    let (witness, statement) = fixture();
    assert_ne!(witness.public_keys[0], witness.public_keys[1]);
    assert!(trace_is_valid(&trace(&witness, &statement), &statement));
}
#[test]
fn valid_hashes_matching_nullifiers_and_roots_do_not_allow_detached_owner_bindings() {
    for input in 0..2 {
        for attack in [
            Attack::OpeningLow,
            Attack::OpeningHigh,
            Attack::WrongKey,
            Attack::GlobalOwnerConstancy,
            Attack::ByteRangeAlias,
            Attack::WrongSuffix,
            Attack::NonzeroPadding,
            Attack::MissingTerminalBit,
            Attack::InitialCapacity,
            Attack::RateContinuation,
            Attack::CapacityContinuation,
            Attack::RollingPollution,
        ] {
            let (trace, statement) = attack_trace(input, attack);
            assert!(
                keccak_only_is_valid(&trace),
                "{input} {attack:?}: genuine permutations"
            );
            for source in 0..2 {
                assert_eq!(
                    final_digest(&trace, sponge::Kind::Parent(source, 31)),
                    statement.root
                );
                assert_eq!(
                    final_digest(&trace, sponge::Kind::Nullifier(source)),
                    statement.nullifiers[source]
                );
            }
            if !matches!(attack, Attack::WrongKey) {
                assert!(
                    owner_terminal_matches_registers(&trace, input),
                    "{input} {attack:?}: terminal owner digest matches"
                );
            }
            assert!(!trace_is_valid(&trace, &statement), "{input} {attack:?}");
        }
    }
    let (trace, statement) = attack_trace(0, Attack::SwappedKeys);
    assert!(keccak_only_is_valid(&trace));
    for input in 0..2 {
        assert_eq!(
            final_digest(&trace, sponge::Kind::Parent(input, 31)),
            statement.root
        );
        assert_eq!(
            final_digest(&trace, sponge::Kind::Nullifier(input)),
            statement.nullifiers[input]
        );
    }
    assert!(!trace_is_valid(&trace, &statement));
}
