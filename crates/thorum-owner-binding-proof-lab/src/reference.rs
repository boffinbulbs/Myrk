//! Independent canonical framing, full sponge states and hash adapter fixtures.

use super::{hash, sponge, tests, trace_is_valid};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_symmetric::CryptographicHasher;
use serde_json::Value;
use sha3::{Digest, Sha3_512};
use std::{borrow::Borrow, collections::BTreeMap};

const PREIMAGES: &str = include_str!("../../../research/owner-bindings/hash_preimages.json");
const BLOCKS: &str = include_str!("../../../research/owner-bindings/sponge_blocks.csv");
const ROUNDS: &str = include_str!("../../../research/owner-bindings/keccak_rounds.csv");
const HASHES: &str = include_str!("../../../research/owner-bindings/hash_vectors.csv");
const CASES: &str = include_str!("../../../research/owner-bindings/owner_binding_vectors.json");
const OLD_CASES: &str = include_str!("../../../research/nullifier-proofs/nullifier_vectors.json");
const RETAINED: &str = include_str!("../../../research/owner-bindings/retained_v2_identities.json");

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn state_bytes(trace: &RowMajorMatrix<BabyBear>, row: usize, preimage: bool) -> Vec<u8> {
    let row = trace.row_slice(row).unwrap();
    let columns: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
    (0..100)
        .flat_map(|limb| {
            let value = if preimage {
                columns.preimage[limb / 20][(limb / 4) % 5][limb % 4]
            } else {
                columns.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            };
            u16::try_from(value.as_canonical_u32())
                .unwrap()
                .to_le_bytes()
        })
        .collect()
}

fn message_bytes(trace: &RowMajorMatrix<BabyBear>, permutation: usize) -> Vec<u8> {
    let row = trace.row_slice(permutation * 24).unwrap();
    (0..72)
        .map(|byte| {
            (0..8).fold(0u8, |value, bit| {
                let bit_value = row[sponge::MESSAGE + byte * 8 + bit].as_canonical_u32();
                assert!(bit_value < 2);
                value | ((bit_value as u8) << bit)
            })
        })
        .collect()
}

#[test]
fn independent_canonical_messages_and_full_sponge_states_match_the_actual_trace() {
    let (witness, statement, _) = tests::fixture(0);
    let messages = sponge::messages(&witness, &statement);
    let trace = sponge::trace(&witness, &statement);
    assert!(trace_is_valid(&trace, &statement));
    let document: Value = serde_json::from_str(PREIMAGES).unwrap();
    let hashes = document["hashes"].as_array().unwrap();
    assert_eq!(hashes.len(), 76);
    assert_eq!(messages.len(), 76);
    let mut positions = BTreeMap::new();
    let mut permutation = 0usize;
    for (index, (hash, message)) in hashes.iter().zip(&messages).enumerate() {
        let name = hash["name"].as_str().unwrap();
        let preimage = unhex(hash["preimage_hex"].as_str().unwrap());
        let padded = unhex(hash["padded_preimage_hex"].as_str().unwrap());
        let digest = unhex(hash["digest_hex"].as_str().unwrap());
        let blocks = usize::try_from(hash["absorb_blocks"].as_u64().unwrap()).unwrap();
        assert_eq!(
            preimage.len() as u64,
            hash["preimage_length"].as_u64().unwrap()
        );
        assert_eq!(padded.len() as u64, hash["padded_length"].as_u64().unwrap());
        assert_eq!(blocks * 72, padded.len());
        assert_eq!(message, &padded, "canonical hash {name}");
        assert_eq!(&message[..preimage.len()], preimage, "preimage {name}");
        assert_eq!(Sha3_512::digest(&preimage).as_slice(), digest);
        assert_eq!(
            &state_bytes(&trace, (permutation + blocks) * 24 - 1, false)[..64],
            digest,
            "final digest {name}"
        );
        assert!(
            positions
                .insert(name, (index, permutation, blocks))
                .is_none()
        );
        permutation += blocks;
    }
    assert_eq!(permutation, 308);

    let mut count = 0;
    for line in BLOCKS.lines().skip(1) {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 6);
        let &(hash_index, start, blocks) = positions.get(fields[0]).unwrap();
        let block = fields[1].parse::<usize>().unwrap();
        assert!(block < blocks);
        let index = start + block;
        let input = unhex(fields[2]);
        assert_eq!(input, message_bytes(&trace, index), "message {index}");
        assert_eq!(input, messages[hash_index][block * 72..(block + 1) * 72]);
        let before = if block == 0 {
            vec![0; 200]
        } else {
            state_bytes(&trace, index * 24 - 1, false)
        };
        assert_eq!(before, unhex(fields[3]), "before {index}");
        let absorbed = state_bytes(&trace, index * 24, true);
        assert_eq!(absorbed, unhex(fields[4]), "absorbed {index}");
        let mut expected_absorbed = before;
        for (byte, value) in input.into_iter().enumerate() {
            expected_absorbed[byte] ^= value;
        }
        assert_eq!(absorbed, expected_absorbed, "full state absorption {index}");
        assert_eq!(
            state_bytes(&trace, index * 24 + 23, false),
            unhex(fields[5]),
            "after {index}"
        );
        count += 1;
    }
    assert_eq!(count, 308);

    count = 0;
    for line in ROUNDS.lines().skip(1) {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 4);
        let &(_, start, blocks) = positions.get(fields[0]).unwrap();
        let block = fields[1].parse::<usize>().unwrap();
        let round = fields[2].parse::<usize>().unwrap();
        assert!(block < blocks && round < 24);
        let row = (start + block) * 24 + round;
        assert_eq!(
            state_bytes(&trace, row, false),
            unhex(fields[3]),
            "round {row}"
        );
        count += 1;
    }
    assert_eq!(count, 2184);
}

#[test]
fn independent_adapter_hash_goldens_match_full_digests_and_word_encodings() {
    let mut count = 0;
    for line in HASHES.lines().skip(1) {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 4);
        let expected_words: Vec<u64> = fields[3]
            .split(':')
            .map(|word| word.parse().unwrap())
            .collect();
        let words = match fields[0] {
            "leaf.v1" => {
                hash::LeafHash.hash_iter([0, 1, 2_013_265_920, 0x1234_5678].map(BabyBear::from_u32))
            }
            "node.v1" => hash::NodeHash.hash_iter([0, 1, u64::MAX].into_iter().chain(0..13)),
            "transcript.v1" => {
                let bytes = hash::TranscriptHash.hash_iter(0u8..64);
                core::array::from_fn(|i| {
                    u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap())
                })
            }
            other => panic!("unknown fixture {other}"),
        };
        assert_eq!(words.as_slice(), expected_words);
        let digest: Vec<_> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        assert_eq!(digest, unhex(fields[2]));
        assert_eq!(Sha3_512::digest(unhex(fields[1])).as_slice(), digest);
        count += 1;
    }
    assert_eq!(count, 3);
}

#[test]
fn independent_public_vectors_and_retained_v2_identities_match() {
    let document: Value = serde_json::from_str(CASES).unwrap();
    let old: Value = serde_json::from_str(OLD_CASES).unwrap();
    let retained: Value = serde_json::from_str(RETAINED).unwrap();
    let cases = document["cases"].as_array().unwrap();
    let old_cases = old["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 85);
    assert_eq!(old_cases.len(), 64);
    for (index, case) in cases.iter().enumerate() {
        let (_, statement, _) = tests::fixture(index);
        let actual: Vec<u32> = sponge::public_values(&statement)
            .into_iter()
            .map(|value| value.as_canonical_u32())
            .collect();
        let expected: Vec<u32> = case["public_values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| u32::try_from(value.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(actual.len(), 520);
        assert_eq!(actual, expected, "{}", case["name"]);
        if index < old_cases.len() {
            let previous = &old_cases[index];
            assert_eq!(case["name"], previous["name"]);
            assert_eq!(case["public"], previous["public"]);
            assert_eq!(case["public_values"], previous["public_values"]);
            for field in ["openings_hex", "nullifier_secrets_hex", "inputs"] {
                assert_eq!(
                    case["witness"][field], previous["witness"][field],
                    "{} {field}",
                    case["name"]
                );
            }
            for (field, value) in previous["expected"].as_object().unwrap() {
                assert_eq!(&case["expected"][field], value, "{} {field}", case["name"]);
            }
            assert_eq!(
                case["expected"]["base_nullifier_component_valid"],
                previous["expected"]["valid_component"]
            );
        }
    }
    assert_eq!(retained["source_format"], old["format"]);
    assert_eq!(
        retained["unchanged_baseline_openings_hex"],
        cases[0]["witness"]["openings_hex"]
    );
    assert_eq!(
        retained["unchanged_baseline_public_statement"],
        cases[0]["public"]
    );
    assert_eq!(
        retained["unchanged_baseline_public_values"],
        cases[0]["public_values"]
    );
    let (witness, statement, _) = tests::fixture(0);
    let messages = sponge::messages(&witness, &statement);
    for (index, message) in messages.iter().take(4).enumerate() {
        assert_eq!(
            Sha3_512::digest(&message[..464]).as_slice(),
            unhex(
                retained["unchanged_baseline_commitments_hex"][index]
                    .as_str()
                    .unwrap()
            )
        );
    }
    let expected_owner = unhex(retained["owner_hash_hex"].as_str().unwrap());
    for input in 0..2 {
        assert_eq!(
            Sha3_512::digest(witness.public_keys[input]).as_slice(),
            expected_owner
        );
        assert_eq!(&witness.openings[input][141..205], expected_owner);
    }
}
