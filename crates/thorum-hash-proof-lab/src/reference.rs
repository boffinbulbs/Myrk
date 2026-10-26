//! Independent full sponge transitions, output blocks and adapter encodings.

use super::{Mode, Statement, Witness, hash, sponge, tests, trace_is_valid};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_symmetric::CryptographicHasher;
use serde_json::Value;
use sha3::{Digest, Sha3_512};
use std::borrow::Borrow;

const PREIMAGES: &str = include_str!("../../../research/hash-proofs/hash_preimages.json");
const STAGES: &str = include_str!("../../../research/hash-proofs/sponge_stages.csv");
const ROUNDS: &str = include_str!("../../../research/hash-proofs/keccak_rounds.csv");
const HASHES: &str = include_str!("../../../research/hash-proofs/hash_vectors.csv");

fn state_bytes(trace: &RowMajorMatrix<BabyBear>, row: usize, before: bool) -> Vec<u8> {
    let row = trace.row_slice(row).unwrap();
    let columns: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
    (0..100)
        .flat_map(|limb| {
            let value = if before {
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

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn independent_authorization_hashes_match_complete_states_and_output_projection() {
    let document: Value = serde_json::from_str(PREIMAGES).unwrap();
    let cases = document["hashes"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    let mut stage_count = 0;
    let mut round_count = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mode = match case["mode"].as_u64().unwrap() {
            1 => Mode::Sha3_512,
            2 => Mode::Shake128,
            3 => Mode::Shake256,
            other => panic!("unknown primitive {other}"),
        };
        let input = tests::bytes(&case["input_hex"]);
        let output = tests::bytes(&case["output_hex"]);
        let statement = Statement::new(mode, input.len(), &output, [0; 64]).unwrap();
        let witness = Witness::from_bytes(&input).unwrap();
        let air = sponge::HashAir::new(&statement);
        let rate = mode.rate();
        assert_eq!(rate as u64, case["rate"].as_u64().unwrap());
        assert_eq!(mode.suffix() as u64, case["suffix"].as_u64().unwrap());
        assert_eq!(input.len() as u64, case["input_length"].as_u64().unwrap());
        assert_eq!(output.len() as u64, case["output_length"].as_u64().unwrap());
        assert_eq!(
            air.absorbs() as u64,
            case["absorb_permutations"].as_u64().unwrap()
        );
        assert_eq!(
            air.permutations() as u64,
            case["total_permutations"].as_u64().unwrap()
        );
        let blocks = sponge::blocks(&witness, &statement);
        let padded: Vec<u8> = blocks[..air.absorbs()]
            .iter()
            .flat_map(|block| block[..rate].iter().copied())
            .collect();
        assert_eq!(padded, tests::bytes(&case["padded_input_hex"]));
        for block in &blocks[air.absorbs()..] {
            assert!(block.iter().all(|byte| *byte == 0));
        }
        let trace = sponge::trace(&witness, &statement);
        assert!(trace_is_valid(&trace, &statement), "{name}");
        let mut projected = Vec::new();
        for stage in air.absorbs() - 1..air.permutations() {
            projected.extend_from_slice(&state_bytes(&trace, stage * 24 + 23, false)[..rate]);
        }
        projected.truncate(output.len());
        assert_eq!(projected, output, "rate output projection {name}");
        let mut count = 0;
        for line in STAGES.lines().skip(1) {
            let fields: Vec<_> = line.split(',').collect();
            assert_eq!(fields.len(), 8);
            if fields[0] != name {
                continue;
            }
            let stage = fields[1].parse::<usize>().unwrap();
            assert!(stage < air.permutations());
            assert_eq!(fields[3].parse::<usize>().unwrap(), rate);
            assert_eq!(
                fields[2],
                if stage < air.absorbs() {
                    "absorb"
                } else {
                    "squeeze"
                }
            );
            let block = unhex(fields[4]);
            assert_eq!(block, blocks[stage][..rate]);
            let before = if stage == 0 {
                vec![0; 200]
            } else {
                state_bytes(&trace, stage * 24 - 1, false)
            };
            assert_eq!(before, unhex(fields[5]), "before {name} {stage}");
            let mut expected = before;
            if stage < air.absorbs() {
                for (byte, value) in block.iter().enumerate() {
                    expected[byte] ^= value;
                }
            }
            let absorbed = state_bytes(&trace, stage * 24, true);
            assert_eq!(absorbed, expected, "full state transition {name} {stage}");
            assert_eq!(absorbed, unhex(fields[6]));
            assert_eq!(
                state_bytes(&trace, stage * 24 + 23, false),
                unhex(fields[7])
            );
            count += 1;
        }
        assert_eq!(count, air.permutations());
        stage_count += count;
        for line in ROUNDS.lines().skip(1) {
            let fields: Vec<_> = line.split(',').collect();
            assert_eq!(fields.len(), 5);
            if fields[0] != name {
                continue;
            }
            let stage = fields[1].parse::<usize>().unwrap();
            let round = fields[3].parse::<usize>().unwrap();
            assert!(stage < air.permutations() && round < 24);
            assert_eq!(
                state_bytes(&trace, stage * 24 + round, false),
                unhex(fields[4]),
                "round {name} {stage} {round}"
            );
            round_count += 1;
        }
    }
    assert_eq!(stage_count, 158);
    assert_eq!(round_count, 1080);
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
