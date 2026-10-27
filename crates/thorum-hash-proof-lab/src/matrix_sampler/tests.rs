use super::*;
use air::*;
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, check_all_constraints};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::KeccakCols;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use serde_json::Value;

pub(crate) fn data() -> Value {
    serde_json::from_str(include_str!(
        "../../../../research/matrix-sampling/vectors.json"
    ))
    .unwrap()
}
fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}
pub(crate) fn fixture(case: &Value) -> (Witness, Statement) {
    (
        Witness::from_rho(bytes(case["rho_hex"].as_str().unwrap())),
        Statement::new(
            case["row"].as_u64().unwrap() as u8,
            case["column"].as_u64().unwrap() as u8,
            core::array::from_fn(|i| case["coefficients"][i].as_u64().unwrap() as u32),
            [0x6b; 64],
        )
        .unwrap(),
    )
}
fn check(trace: &RowMajorMatrix<BabyBear>, s: &Statement) -> bool {
    check_all_constraints(&MatrixSamplerAir, trace, &public_values(s), Some(16)).is_ok()
}

#[test]
fn exact_offsets_and_derived_symbolic_degree() {
    assert_eq!(
        [
            HASH_PC,
            MESSAGE,
            OUTPUT,
            RHO,
            XOF,
            COEFFICIENTS,
            PROGRAM,
            COUNT,
            CANDIDATE,
            SLACK,
            TAKE,
            CURSOR,
            WIDTH
        ],
        [
            2633, 2640, 3984, 5328, 5360, 6368, 6624, 6961, 7218, 7242, 7265, 7266, 7276
        ]
    );
    let layout = p3_air::symbolic::AirLayout {
        main_width: WIDTH,
        num_public_values: PUBLIC_VALUES,
        ..Default::default()
    };
    let degree = p3_air::symbolic::get_max_constraint_degree::<BabyBear, _>(
        &MatrixSamplerAir,
        layout,
        HEIGHT,
    );
    println!("actual degree {degree}");
    assert_eq!(degree, 3);
}

#[test]
fn one_complete_genuine_relation_passes_actual_air() {
    let data = data();
    let (w, s) = fixture(&data["genuine"][0]);
    let trace = trace(&w, &s).unwrap();
    let report = check_all_constraints(&MatrixSamplerAir, &trace, &public_values(&s), Some(16));
    assert!(report.is_ok(), "{report:?}");
}

#[test]
fn all_224_genuine_expansions_match_every_full_sponge_and_coefficient() {
    let data = data();
    assert_eq!(data["genuine"].as_array().unwrap().len(), 224);
    for case in data["genuine"].as_array().unwrap() {
        let (w, s) = fixture(case);
        let (inputs, output) = expansion(&w, &s);
        assert_eq!(
            output,
            bytes::<CAPACITY>(case["stream_hex"].as_str().unwrap())
        );
        for (block, input) in inputs.iter().enumerate() {
            let before: [u8; 200] =
                bytes(case["sponge_blocks"][block]["before_hex"].as_str().unwrap());
            let after: [u8; 200] =
                bytes(case["sponge_blocks"][block]["after_hex"].as_str().unwrap());
            for lane in 0..25 {
                assert_eq!(
                    input[lane],
                    u64::from_le_bytes(before[lane * 8..lane * 8 + 8].try_into().unwrap())
                );
            }
            let result = state_after(*input);
            for lane in 0..25 {
                assert_eq!(
                    result[lane],
                    u64::from_le_bytes(after[lane * 8..lane * 8 + 8].try_into().unwrap())
                );
            }
        }
        let selected: Vec<u32> = output
            .chunks_exact(3)
            .map(|b| u32::from(b[0]) + (u32::from(b[1]) << 8) + (u32::from(b[2] & 127) << 16))
            .filter(|v| *v < MODULUS)
            .take(256)
            .collect();
        assert_eq!(selected, s.coefficients);
    }
}

#[test]
fn every_genuine_case_passes_the_complete_connected_air() {
    let data = data();
    for index in 0..224 {
        let (w, s) = fixture(&data["genuine"][index]);
        assert!(check(&trace(&w, &s).unwrap(), &s), "genuine case {index}");
    }
}

fn fields_mutated(
    trace: &RowMajorMatrix<BabyBear>,
    column: usize,
    delta: BabyBear,
    start: usize,
) -> RowMajorMatrix<BabyBear> {
    let mut result = trace.clone();
    for at in start..HEIGHT {
        result.values[at * WIDTH + column] += delta;
    }
    result
}

#[test]
fn complete_bank_holds_and_bytewise_unused_output_links_are_required() {
    let data = data();
    let (w, s) = fixture(&data["genuine"][0]);
    let original = trace(&w, &s).unwrap();
    for (column, start) in [(RHO, 144), (XOF + 990, 144), (COEFFICIENTS + 3, 400)] {
        assert!(!check(
            &fields_mutated(&original, column, BabyBear::ONE, start),
            &s
        ));
    }
    let mut alias = fields_mutated(&original, XOF + 990, BabyBear::from_u32(256), 0);
    for at in 0..HEIGHT {
        alias.values[at * WIDTH + XOF + 991] -= BabyBear::ONE;
    }
    assert!(!check(&alias, &s));
    let mut shifted = original.clone();
    for at in 0..HEIGHT {
        for byte in 0..RATE {
            shifted.values[at * WIDTH + XOF + 840 + byte] =
                original.values[at * WIDTH + XOF + 672 + byte];
        }
    }
    assert!(!check(&shifted, &s));
}

#[test]
fn genuine_wrong_seed_with_matching_outputs_cannot_replace_the_rho_bank() {
    let data = data();
    let (original, s0) = fixture(&data["genuine"][0]);
    let (wrong, s) = fixture(&data["genuine"][56]);
    assert_eq!((s.row, s.column), (s0.row, s0.column));
    let mut changed = trace(&wrong, &s).unwrap();
    assert!(check(&changed, &s));
    for at in 0..HEIGHT {
        for byte in 0..32 {
            changed.values[at * WIDTH + RHO + byte] = BabyBear::from_u8(original.rho[byte]);
        }
    }
    assert!(!check(&changed, &s));
}

#[test]
fn byte_distinct_expected_coefficients_cannot_use_a_field_prime_alias() {
    let data = data();
    let (w, s) = fixture(&data["genuine"][0]);
    let trace = trace(&w, &s).unwrap();
    for index in [0, 127, 255] {
        let mut public = public_values(&s);
        for (byte, value) in (s.coefficients[index] + 2_013_265_921)
            .to_le_bytes()
            .into_iter()
            .enumerate()
        {
            public[2 + index * 4 + byte] = BabyBear::from_u8(value);
        }
        assert!(!check_all_constraints(&MatrixSamplerAir, &trace, &public, Some(16)).is_ok());
    }
}

#[test]
fn generated_keccak_rows_match_independent_full_rate_states() {
    let data = data();
    let (w, s) = fixture(&data["genuine"][0]);
    let trace = trace(&w, &s).unwrap();
    for block in 0..BLOCKS {
        let row = trace.row_slice(block * 24 + 23).unwrap();
        let typed: &KeccakCols<BabyBear> = row[..2633].borrow();
        let expected: [u8; 200] = bytes(
            data["genuine"][0]["sponge_blocks"][block]["after_hex"]
                .as_str()
                .unwrap(),
        );
        for limb in 0..100 {
            assert_eq!(
                typed
                    .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                    .as_canonical_u32(),
                u32::from(u16::from_le_bytes(
                    expected[limb * 2..limb * 2 + 2].try_into().unwrap()
                ))
            );
        }
    }
}

struct SamplerOnly;
impl<F> BaseAir<F> for SamplerOnly {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

#[test]
fn all_selected_independent_round_states_match_actual_keccak_rows() {
    let data = data();
    let mut count = 0;
    for case in data["genuine"].as_array().unwrap() {
        let Some(rounds) = case.get("round_states") else {
            continue;
        };
        let (w, s) = fixture(case);
        let trace = trace(&w, &s).unwrap();
        for state in rounds.as_array().unwrap() {
            let at = state["stage"].as_u64().unwrap() as usize * 24
                + state["round"].as_u64().unwrap() as usize;
            let row = trace.row_slice(at).unwrap();
            let typed: &KeccakCols<BabyBear> = row[..2633].borrow();
            let expected: [u8; 200] = bytes(state["state_hex"].as_str().unwrap());
            for limb in 0..100 {
                assert_eq!(
                    typed
                        .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32(),
                    u32::from(u16::from_le_bytes(
                        expected[limb * 2..limb * 2 + 2].try_into().unwrap()
                    ))
                );
            }
            count += 1;
        }
    }
    assert_eq!(count, 288);
}

#[test]
fn proof_namespace_goldens_match_all_digest_words() {
    use super::hash::{LeafHash, NodeHash, TranscriptHash};
    use p3_symmetric::CryptographicHasher;
    for line in include_str!("../../../../research/matrix-sampling/hash_vectors.csv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = line.split(',').collect();
        let expected: Vec<u64> = fields[3]
            .split(':')
            .map(|word| word.parse().unwrap())
            .collect();
        let actual = match fields[0] {
            "leaf" => LeafHash.hash_iter([0, 1, 2013265920, 0x12345678].map(BabyBear::from_u32)),
            "node" => NodeHash.hash_iter([0, 1, u64::MAX].into_iter().chain(0..13)),
            "transcript" => {
                let digest = TranscriptHash.hash_iter(0u8..64);
                core::array::from_fn(|i| {
                    u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().unwrap())
                })
            }
            _ => unreachable!(),
        };
        assert_eq!(actual.as_slice(), expected);
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for SamplerOnly {
    fn eval(&self, builder: &mut AB) {
        eval_sampler(builder);
    }
}

#[test]
fn injected_streams_exercise_only_sampler_control_without_a_seed_claim() {
    let data = data();
    let (w, base) = fixture(&data["genuine"][0]);
    let (inputs, _) = expansion(&w, &base);
    for case in data["injected"].as_array().unwrap() {
        assert_eq!(case["seed_claim"], false);
        let output = bytes::<CAPACITY>(case["stream_hex"].as_str().unwrap());
        let result = trace_with_expansion(&w, &base, inputs.clone(), output);
        if !case["supported_complete"].as_bool().unwrap() {
            assert!(matches!(result, Err(Error::UnsupportedCapacity)));
            let incomplete = raw_trace_with_expansion(&w, &base, inputs.clone(), output).unwrap();
            assert!(
                !check_all_constraints(&SamplerOnly, &incomplete, &public_values(&base), Some(16))
                    .is_ok()
            );
            let mut forged = incomplete.clone();
            let before = case["coefficients"].as_array().unwrap().len();
            for at in EVENTS + 1..HEIGHT {
                forged.values[at * WIDTH + COUNT + before] = BabyBear::ZERO;
                forged.values[at * WIDTH + COUNT + 256] = BabyBear::ONE;
            }
            assert!(
                !check_all_constraints(&SamplerOnly, &forged, &public_values(&base), Some(16))
                    .is_ok()
            );
            continue;
        }
        let s = Statement::new(
            0,
            0,
            core::array::from_fn(|i| case["coefficients"][i].as_u64().unwrap() as u32),
            base.context,
        )
        .unwrap();
        let trace = result.unwrap();
        assert!(
            check_all_constraints(&SamplerOnly, &trace, &public_values(&s), Some(16)).is_ok(),
            "{}",
            case["name"]
        );
        assert!(!check(&trace, &s));
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Fault {
    SeedSplice,
    CoordinatesSplice,
    RateContinuation,
    CapacityContinuation,
    RepeatedPadding,
    SixthBlockSplice,
    UnusedByteAlias,
    SeedHoldReset,
    OutputBankHoldReset,
    CounterSkip,
    CursorReset,
    PaddingTake,
    PublicIntegerAlias,
}
pub(crate) const FAULTS: [Fault; 13] = [
    Fault::SeedSplice,
    Fault::CoordinatesSplice,
    Fault::RateContinuation,
    Fault::CapacityContinuation,
    Fault::RepeatedPadding,
    Fault::SixthBlockSplice,
    Fault::UnusedByteAlias,
    Fault::SeedHoldReset,
    Fault::OutputBankHoldReset,
    Fault::CounterSkip,
    Fault::CursorReset,
    Fault::PaddingTake,
    Fault::PublicIntegerAlias,
];

pub(crate) fn attack(fault: Fault) -> (RowMajorMatrix<BabyBear>, Statement) {
    let data = data();
    let (w, mut s) = fixture(&data["genuine"][0]);
    let mut result = match fault {
        Fault::SeedSplice => {
            let (other, other_s) = fixture(&data["genuine"][56]);
            s = other_s;
            let mut result = trace(&other, &s).unwrap();
            for at in 0..HEIGHT {
                for byte in 0..32 {
                    result.values[at * WIDTH + RHO + byte] = BabyBear::from_u8(w.rho[byte]);
                }
            }
            result
        }
        Fault::CoordinatesSplice => {
            let (other, other_s) = fixture(&data["genuine"][7]);
            let result = trace(&other, &other_s).unwrap();
            s = other_s;
            s.row = 0;
            result
        }
        Fault::RateContinuation | Fault::CapacityContinuation | Fault::RepeatedPadding => {
            let (mut inputs, _) = expansion(&w, &s);
            let mut output = [0u8; CAPACITY];
            for block in 0..BLOCKS {
                if block > 0 {
                    inputs[block] = state_after(inputs[block - 1]);
                }
                if block == 1 {
                    match fault {
                        Fault::RateContinuation => inputs[block][0] ^= 1,
                        Fault::CapacityContinuation => inputs[block][21] ^= 1,
                        Fault::RepeatedPadding => inputs[block][4] ^= 31u64 << 16,
                        _ => unreachable!(),
                    }
                }
                let after = state_after(inputs[block]);
                for lane in 0..RATE / 8 {
                    output[block * RATE + lane * 8..block * RATE + lane * 8 + 8]
                        .copy_from_slice(&after[lane].to_le_bytes());
                }
            }
            let coefficients: Vec<u32> = output
                .chunks_exact(3)
                .map(|b| u32::from(b[0]) + (u32::from(b[1]) << 8) + (u32::from(b[2] & 127) << 16))
                .filter(|v| *v < MODULUS)
                .take(256)
                .collect();
            s.coefficients.copy_from_slice(&coefficients);
            trace_with_expansion(&w, &s, inputs, output).unwrap()
        }
        _ => trace(&w, &s).unwrap(),
    };
    match fault {
        Fault::SixthBlockSplice => {
            for at in 0..HEIGHT {
                for byte in 0..RATE {
                    result.values[at * WIDTH + XOF + 840 + byte] =
                        result.values[at * WIDTH + XOF + 672 + byte];
                }
            }
        }
        Fault::UnusedByteAlias => {
            for at in 0..HEIGHT {
                result.values[at * WIDTH + XOF + 990] += BabyBear::from_u32(256);
                result.values[at * WIDTH + XOF + 991] -= BabyBear::ONE;
            }
        }
        Fault::SeedHoldReset => result = fields_mutated(&result, RHO, BabyBear::ONE, 144),
        Fault::OutputBankHoldReset => {
            result = fields_mutated(&result, COEFFICIENTS + 3, BabyBear::ONE, 400)
        }
        Fault::CounterSkip => {
            result.values[10 * WIDTH + COUNT + 10] = BabyBear::ZERO;
            result.values[10 * WIDTH + COUNT + 11] = BabyBear::ONE;
        }
        Fault::CursorReset => {
            result.values[100 * WIDTH + CURSOR..100 * WIDTH + WIDTH].fill(BabyBear::ZERO)
        }
        Fault::PaddingTake => result.values[400 * WIDTH + TAKE] = BabyBear::ONE,
        Fault::PublicIntegerAlias => s.coefficients[0] += 2_013_265_921,
        _ => {}
    }
    (result, s)
}

#[test]
fn genuine_hashes_with_wrong_source_continuation_or_control_fail_actual_air() {
    for fault in FAULTS {
        let (trace, statement) = attack(fault);
        assert!(!check(&trace, &statement), "{fault:?}");
    }
}
