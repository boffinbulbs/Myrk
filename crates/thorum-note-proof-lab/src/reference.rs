//! Canonical framing, permutation and integer fixtures are generated independently.

use super::{Statement, hash, sponge, trace_is_valid};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::Matrix;
use p3_symmetric::CryptographicHasher;
use serde_json::Value;
use sha3::{Digest, Sha3_512};
use std::borrow::Borrow;

const CASES: &str = include_str!("../../../research/note-proofs/combined_vectors.json");
const OPENINGS: &str = include_str!("../../../research/note-proofs/commitment_vectors.csv");
const BLOCKS: &str = include_str!("../../../research/note-proofs/sponge_blocks.csv");
const ROUNDS: &str = include_str!("../../../research/note-proofs/keccak_rounds.csv");
const HASHES: &str = include_str!("../../../research/note-proofs/hash_vectors.csv");

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn fixed<const N: usize>(value: &Value) -> [u8; N] {
    unhex(value.as_str().unwrap()).try_into().unwrap()
}

#[test]
fn independent_four_note_cases_match_actual_constraints() {
    let document: Value = serde_json::from_str(CASES).unwrap();
    let cases = document["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    for case in cases {
        let public = &case["public"];
        let openings = core::array::from_fn(|i| fixed::<418>(&case["openings_hex"][i]));
        let statement = Statement {
            fee: public["fee"].as_u64().unwrap(),
            chain: fixed(&public["chain_hex"]),
            creation_versions: core::array::from_fn(|i| {
                u32::try_from(public["creation_versions"][i].as_u64().unwrap()).unwrap()
            }),
            asset: fixed(&public["asset_hex"]),
            commitments: core::array::from_fn(|i| fixed(&public["commitments_hex"][i])),
            context: fixed(&public["context_hex"]),
        };
        for (i, opening) in openings.iter().enumerate() {
            assert_eq!(
                u64::from_be_bytes(opening[129..137].try_into().unwrap()),
                case["amounts"][i].as_u64().unwrap()
            );
            let digest: [u8; 64] = Sha3_512::digest(&sponge::padded(opening)[..464]).into();
            assert_eq!(digest, statement.commitments[i]);
        }
        let trace = sponge::trace(&openings, &statement);
        assert_eq!(
            trace_is_valid(&trace, &statement),
            case["valid_integer"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

fn permutation_bytes(columns: &KeccakCols<BabyBear>, preimage: bool) -> Vec<u8> {
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

#[test]
fn independent_full_sponge_states_and_canonical_openings_match() {
    let mut base = [0; 418];
    let mut count = 0;
    for line in OPENINGS.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        let opening: [u8; 418] = unhex(fields[2]).try_into().unwrap();
        let preimage = unhex(fields[3]);
        assert_eq!(&sponge::padded(&opening)[..464], preimage);
        assert_eq!(Sha3_512::digest(&preimage).as_slice(), unhex(fields[4]));
        assert_eq!(
            u64::from_be_bytes(opening[129..137].try_into().unwrap()),
            fields[1].parse::<u64>().unwrap()
        );
        if fields[0] == "recipient_payment" {
            base = opening;
        }
        count += 1;
    }
    assert_eq!(count, 4);
    let amount = u64::from_be_bytes(base[129..137].try_into().unwrap());
    assert_ne!(amount, 0);
    let amounts = [amount, 0, amount - 1, 0];
    let mut openings = [base; 4];
    for (i, opening) in openings.iter_mut().enumerate() {
        opening[129..137].copy_from_slice(&amounts[i].to_be_bytes());
    }
    let statement = Statement {
        fee: 1,
        chain: core::array::from_fn(|i| i as u8),
        creation_versions: [1; 4],
        asset: [0xa7; 32],
        commitments: openings
            .map(|opening| Sha3_512::digest(&sponge::padded(&opening)[..464]).into()),
        context: [0; 64],
    };
    let trace = sponge::trace(&openings, &statement);
    assert!(trace_is_valid(&trace, &statement));
    count = 0;
    for line in ROUNDS.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        let index = fields[0].parse::<usize>().unwrap() * 24 + fields[1].parse::<usize>().unwrap();
        let row = trace.row_slice(index).unwrap();
        let columns: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
        assert_eq!(
            permutation_bytes(columns, false),
            unhex(fields[2]),
            "round {index}"
        );
        count += 1;
    }
    assert_eq!(count, 168);
    count = 0;
    for line in BLOCKS.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        let index = fields[0].parse::<usize>().unwrap();
        let row = trace.row_slice(index * 24).unwrap();
        let columns: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
        assert_eq!(
            permutation_bytes(columns, true),
            unhex(fields[3]),
            "block {index}"
        );
        let row = trace.row_slice(index * 24 + 23).unwrap();
        let columns: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
        assert_eq!(permutation_bytes(columns, false), unhex(fields[4]));
        count += 1;
    }
    assert_eq!(count, 7);
}

#[test]
fn independent_application_hash_domains_match_full_digest_goldens() {
    let mut count = 0;
    for line in HASHES.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
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
        let digest: Vec<u8> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        assert_eq!(digest, unhex(fields[2]));
        assert_eq!(Sha3_512::digest(unhex(fields[1])).as_slice(), digest);
        count += 1;
    }
    assert_eq!(count, 3);
}
