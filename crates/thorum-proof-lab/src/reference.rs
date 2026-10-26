//! Independent fixtures use unbounded Python integer arithmetic and hashlib.

use super::{Statement, air, hash, trace_is_valid};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use p3_symmetric::CryptographicHasher;

const CASES: &str = include_str!("../../../research/proofs/conservation_vectors.csv");
const TRACE: &str = include_str!("../../../research/proofs/trace_vector.csv");
const PUBLIC: &str = include_str!("../../../research/proofs/public_values.csv");
const HASHES: &str = include_str!("../../../research/proofs/hash_vectors.csv");

fn numbers(line: &str) -> Vec<u64> {
    line.split(',').map(|part| part.parse().unwrap()).collect()
}

fn busy_case() -> ([u64; 4], u64) {
    let row = CASES
        .lines()
        .find(|line| line.starts_with("busy,"))
        .unwrap();
    let values = numbers(row.split_once(',').unwrap().1);
    (values[..4].try_into().unwrap(), values[4])
}

#[test]
fn independent_integer_cases() {
    let mut count = 0;
    for line in CASES.lines().skip(1) {
        let (id, rest) = line.split_once(',').unwrap();
        let values = numbers(rest);
        let statement = Statement {
            fee: values[4],
            context: [0; 64],
        };
        let trace = air::trace(values[..4].try_into().unwrap(), statement.fee);
        assert_eq!(trace_is_valid(&trace, &statement), values[5] == 1, "{id}");
        count += 1;
    }
    assert_eq!(count, 13);
}

#[test]
fn independent_trace_and_public_values() {
    let (amounts, fee) = busy_case();
    let trace = air::trace(amounts, fee);
    let context = core::array::from_fn(|i| i as u8);
    let public = air::public_values(fee, &context);
    let mut count = 0;
    for line in TRACE.lines().skip(1) {
        let v = numbers(line);
        let row_index = usize::try_from(v[0]).unwrap();
        let bit = usize::try_from(v[1]).unwrap();
        let phase = usize::try_from(v[2]).unwrap();
        let row: Vec<u32> = trace
            .row(row_index)
            .unwrap()
            .into_iter()
            .map(|value| value.as_canonical_u32())
            .collect();
        assert_eq!(row.len(), air::WIDTH);
        for (i, value) in row[..4].iter().enumerate() {
            assert_eq!(*value, u32::from(i == phase));
        }
        for (i, value) in row[air::SELECTOR..air::A0].iter().enumerate() {
            assert_eq!(*value, u32::from(i == bit));
        }
        let private: Vec<u32> = v[3..12]
            .iter()
            .map(|x| u32::try_from(*x).unwrap())
            .collect();
        assert_eq!(&row[air::A0..], private);
        assert_eq!(public[bit].as_canonical_u32(), v[12] as u32);
        count += 1;
    }
    assert_eq!(count, air::HEIGHT);
    let expected: Vec<BabyBear> = PUBLIC
        .lines()
        .skip(1)
        .enumerate()
        .map(|(i, line)| {
            let values = numbers(line);
            assert_eq!(values[0], i as u64);
            BabyBear::from_u64(values[1])
        })
        .collect();
    assert_eq!(public, expected);
    assert_eq!(public.len(), air::PUBLIC_VALUES);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn independent_hash_encodings() {
    let mut count = 0;
    for line in HASHES.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
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
        assert_eq!(words.as_slice(), expected_words, "{}", fields[0]);
        let digest: Vec<u8> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        assert_eq!(hex(&digest), fields[2], "{}", fields[0]);
        count += 1;
    }
    assert_eq!(count, 3);
}
