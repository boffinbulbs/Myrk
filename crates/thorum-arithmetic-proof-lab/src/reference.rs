//! Independent canonical rows, exact division witnesses and adapter encodings.

use super::{Statement, Witness, air, hash, trace_is_valid};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use p3_symmetric::CryptographicHasher;
use serde_json::Value;
use sha3::{Digest, Sha3_512};

const CASES: &str = include_str!("../../../research/arithmetic-proofs/multiplication_vectors.json");
const HASHES: &str = include_str!("../../../research/arithmetic-proofs/hash_vectors.csv");

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn independently_generated_exact_products_match_the_honest_witness_and_every_row() {
    let document: Value = serde_json::from_str(CASES).unwrap();
    let cases = document["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 206);
    let mut accepted = 0;
    for case in cases {
        if !case["expected"]["valid_component"].as_bool().unwrap() {
            continue;
        }
        let public = &case["public"];
        let statement = Statement::new(
            u32::try_from(public["x"].as_u64().unwrap()).unwrap(),
            u32::try_from(public["y"].as_u64().unwrap()).unwrap(),
            u32::try_from(public["z"].as_u64().unwrap()).unwrap(),
            unhex(public["context_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let witness = Witness::for_operands(statement.x(), statement.y()).unwrap();
        let trace = air::trace(&witness, &statement);
        assert!(trace_is_valid(&trace, &statement), "{}", case["name"]);
        let expected: Vec<u32> = case["witness"]["raw_bits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| u32::try_from(value.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(expected.len(), 211);
        for row in 0..trace.height() {
            let actual: Vec<u32> = trace
                .row_slice(row)
                .unwrap()
                .iter()
                .map(|value| value.as_canonical_u32())
                .collect();
            assert_eq!(actual, expected, "{} row {row}", case["name"]);
        }
        let actual: Vec<u32> = air::public_values(&statement)
            .iter()
            .map(|value| value.as_canonical_u32())
            .collect();
        let expected: Vec<u32> = case["public_values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| u32::try_from(value.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 76);
        accepted += 1;
    }
    assert_eq!(accepted, 166);
}

#[test]
fn independent_adapter_hash_goldens_match_full_digests_and_words() {
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
                core::array::from_fn(|index| {
                    u64::from_le_bytes(bytes[8 * index..8 * index + 8].try_into().unwrap())
                })
            }
            other => panic!("unknown adapter {other}"),
        };
        assert_eq!(words.as_slice(), expected_words);
        let digest: Vec<u8> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        assert_eq!(digest, unhex(fields[2]));
        assert_eq!(Sha3_512::digest(unhex(fields[1])).as_slice(), digest);
        count += 1;
    }
    assert_eq!(count, 3);
}
