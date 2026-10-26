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

fn digest(message: &[u8], len: usize) -> [u8; 64] {
    Sha3_512::digest(&message[..len]).into()
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
        nullifiers: [[0; 64]; 2],
        context: bytes(&p["context_hex"]),
    };
    let mut witness = Witness::from_openings_secrets_and_paths(
        core::array::from_fn(|i| bytes(&w["openings_hex"][i])),
        [[0x5b; 32]; 2],
        [0, 1],
        [[[0; 64]; 32]; 2],
    );
    rebuild_membership(&mut witness, &mut statement);
    (witness, statement)
}

fn rebuild_membership(witness: &mut Witness, statement: &mut Statement) {
    let cms: [[u8; 64]; 2] =
        core::array::from_fn(|input| digest(&sponge::note_message(&witness.openings[input]), 464));
    let leaves = cms.map(|cm| digest(&sponge::leaf_message(&statement.chain, &cm), 142));
    witness.siblings[0][0] = leaves[1];
    witness.siblings[1][0] = leaves[0];
    for input in 0..2 {
        let mut current = leaves[input];
        for level in 0..32 {
            if level > 0 {
                witness.siblings[input][level] = [0x80 + level as u8; 64];
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
            assert_eq!(current, statement.root);
        }
        statement.nullifiers[input] = digest(
            &sponge::nullifier_message(&statement.chain, &witness.secrets[input], &cms[input]),
            181,
        );
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Attack {
    BindingToOpeningLow,
    BindingToOpeningHigh,
    BindingDigestLow,
    BindingDigestHigh,
    NullifierCommitmentLow,
    NullifierCommitmentHigh,
    NullifierCommitmentOther,
    NullifierKey,
    GlobalSecretConstancy,
    GlobalCommitmentConstancy,
    SplitBridgeAlias,
    RollingPollution,
}

pub(crate) const ATTACKS: [Attack; 12] = [
    Attack::BindingToOpeningLow,
    Attack::BindingToOpeningHigh,
    Attack::BindingDigestLow,
    Attack::BindingDigestHigh,
    Attack::NullifierCommitmentLow,
    Attack::NullifierCommitmentHigh,
    Attack::NullifierCommitmentOther,
    Attack::NullifierKey,
    Attack::GlobalSecretConstancy,
    Attack::GlobalCommitmentConstancy,
    Attack::SplitBridgeAlias,
    Attack::RollingPollution,
];

pub(crate) fn attack_trace(attack: Attack) -> (RowMajorMatrix<BabyBear>, Statement) {
    let (mut witness, mut statement) = fixture();
    let binding = digest(
        &sponge::binding_message(&statement.chain, &witness.secrets[0]),
        123,
    );
    if matches!(
        attack,
        Attack::BindingToOpeningLow
            | Attack::BindingToOpeningHigh
            | Attack::BindingDigestLow
            | Attack::BindingDigestHigh
    ) {
        let byte = if matches!(
            attack,
            Attack::BindingToOpeningLow | Attack::BindingDigestLow
        ) {
            32
        } else {
            33
        };
        witness.openings[0][209 + byte] ^= 1;
        rebuild_membership(&mut witness, &mut statement);
    }
    let mut messages = sponge::messages(&witness, &statement);
    let cms: [[u8; 64]; 2] =
        core::array::from_fn(|input| digest(&sponge::note_message(&witness.openings[input]), 464));
    let mut alternative_cm = cms[0];
    let mut alternative_secret = witness.secrets[0];
    alternative_secret[13] ^= 1;
    if matches!(
        attack,
        Attack::NullifierCommitmentLow
            | Attack::NullifierCommitmentHigh
            | Attack::NullifierCommitmentOther
            | Attack::GlobalCommitmentConstancy
    ) {
        let byte = match attack {
            Attack::NullifierCommitmentLow => 26,
            Attack::NullifierCommitmentHigh => 27,
            _ => 17,
        };
        alternative_cm[byte] ^= 1;
        messages[5] =
            sponge::nullifier_message(&statement.chain, &witness.secrets[0], &alternative_cm);
        statement.nullifiers[0] = digest(&messages[5], 181);
    }
    if matches!(attack, Attack::NullifierKey | Attack::GlobalSecretConstancy) {
        messages[5] = sponge::nullifier_message(&statement.chain, &alternative_secret, &cms[0]);
        statement.nullifiers[0] = digest(&messages[5], 181);
    }
    let mut trace = sponge::trace_with_messages(&witness, &statement, &messages, &[]);
    if matches!(
        attack,
        Attack::BindingToOpeningLow | Attack::BindingToOpeningHigh
    ) {
        // The binding hash is correct. Only the canonical opening uses a
        // different byte, including both sides of its absorption boundary.
        for row in 0..sponge::HEIGHT {
            for (byte, value) in binding.iter().copied().enumerate() {
                trace.values[row * sponge::WIDTH + sponge::BINDINGS + byte] =
                    BabyBear::from_u8(value);
            }
        }
    }
    if matches!(attack, Attack::GlobalSecretConstancy) {
        // Both standalone message computations use exactly the expected
        // key at their own rows. The retained key changes only between them.
        for row in 30 * 24..sponge::HEIGHT {
            for (byte, value) in alternative_secret.iter().copied().enumerate() {
                trace.values[row * sponge::WIDTH + sponge::SECRETS + byte] =
                    BabyBear::from_u8(value);
            }
        }
    }
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
        for row in 30 * 24..33 * 24 {
            let start = row * sponge::WIDTH;
            trace.values[start + sponge::COMMITMENTS..start + sponge::COMMITMENTS + 32]
                .copy_from_slice(&replacement);
            trace.values[start + sponge::DISTINCT_INVERSE..start + sponge::DISTINCT_INVERSE + 32]
                .copy_from_slice(&inverse);
            for byte in 0..2 {
                trace.values[start + sponge::CM_SPLIT + byte] =
                    BabyBear::from_u8(alternative_cm[26 + byte]);
            }
        }
    }
    if matches!(attack, Attack::SplitBridgeAlias) {
        // Preserve the u16 reconstruction while leaving the unique byte
        // representation. Both Boolean message byte links must reject it.
        for row in 0..sponge::HEIGHT {
            let start = row * sponge::WIDTH + sponge::CM_SPLIT;
            trace.values[start] += BabyBear::from_u16(256);
            trace.values[start + 1] -= BabyBear::ONE;
        }
    }
    if matches!(attack, Attack::RollingPollution) {
        // Binding and nullifier stages have no authority to replace a
        // membership child, even if a later leaf would overwrite the value.
        for row in 30 * 24..35 * 24 {
            for limb in 0..32 {
                trace.values[row * sponge::WIDTH + sponge::ROLLING + limb] =
                    BabyBear::from_u16(u16::from_le_bytes([
                        binding[limb * 2],
                        binding[limb * 2 + 1],
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
fn honest_rebuilt_paths_and_nullifiers_pass() {
    let (witness, statement) = fixture();
    assert!(trace_is_valid(&trace(&witness, &statement), &statement));
}

#[test]
fn causal_valid_hashes_and_matching_membership_fail_the_complete_air() {
    for attack in ATTACKS {
        let (trace, statement) = attack_trace(attack);
        assert!(
            keccak_only_is_valid(&trace),
            "{attack:?}: genuine permutation traces"
        );
        for input in 0..2 {
            assert_eq!(
                final_digest(&trace, sponge::Kind::Parent(input, 31)),
                statement.root,
                "{attack:?}: actual membership reaches the public root"
            );
            assert_eq!(
                final_digest(&trace, sponge::Kind::Nullifier(input)),
                statement.nullifiers[input],
                "{attack:?}: standalone nullifier matches the public digest"
            );
        }
        assert!(!trace_is_valid(&trace, &statement), "{attack:?}");
        eprintln!(
            "rejected {attack:?} with valid hashes, common membership root and matching public nullifiers"
        );
    }
}
