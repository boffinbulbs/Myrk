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
        "../../../../research/challenge-sampling/vectors.json"
    ))
    .unwrap()
}
fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}
pub(crate) fn fixture(case: &Value) -> (Witness, Statement) {
    (
        Witness::from_challenge_seed(bytes(case["seed_hex"].as_str().unwrap())),
        Statement::new(
            core::array::from_fn(|i| case["normal"][i].as_u64().unwrap() as u32),
            [0x73; 64],
        )
        .unwrap(),
    )
}
fn check(trace: &RowMajorMatrix<BabyBear>, s: &Statement) -> bool {
    check_all_constraints(&ChallengeSamplerAir, trace, &public_values(s), Some(16)).is_ok()
}

#[test]
fn exact_layout_and_actual_symbolic_degree() {
    assert_eq!(
        [
            HASH_PC, MESSAGE, OUTPUT, SEED, XOF, SIGN_BITS, PLUS, MINUS, FINAL, PROGRAM, COUNT,
            CANDIDATE, LOWER, UPPER, INDEX, TAKE, OLD_PLUS, OLD_MINUS, CURSOR, WIDTH
        ],
        [
            2633, 2636, 3724, 4812, 4876, 5148, 5212, 5468, 5724, 5980, 6245, 6306, 6314, 6322,
            6330, 6586, 6587, 6588, 6589, 6598
        ]
    );
    let layout = p3_air::symbolic::AirLayout {
        main_width: WIDTH,
        num_public_values: PUBLIC_VALUES,
        ..Default::default()
    };
    let degree = p3_air::symbolic::get_max_constraint_degree::<BabyBear, _>(
        &ChallengeSamplerAir,
        layout,
        HEIGHT,
    );
    println!("actual challenge degree {degree}");
    assert_eq!(degree, 3);
}

#[test]
fn all_genuine_challenges_pass_the_complete_connected_air() {
    let data = data();
    assert_eq!(data["genuine"].as_array().unwrap().len(), 6);
    for case in data["genuine"].as_array().unwrap() {
        let (w, s) = fixture(case);
        let trace = trace(&w, &s).unwrap();
        let report =
            check_all_constraints(&ChallengeSamplerAir, &trace, &public_values(&s), Some(16));
        assert!(report.is_ok(), "{} {report:?}", case["name"]);
    }
}

#[test]
fn full_states_rounds_output_bytes_and_header_match_independent_reference() {
    let data = data();
    let mut count = 0;
    for case in data["genuine"].as_array().unwrap() {
        let (w, s) = fixture(case);
        let (inputs, output) = expansion(&w);
        assert_eq!(
            output,
            bytes::<CAPACITY>(case["stream_hex"].as_str().unwrap())
        );
        for block in 0..BLOCKS {
            let expected: [u8; 200] = bytes(case["sponges"][block]["before_hex"].as_str().unwrap());
            for lane in 0..25 {
                assert_eq!(
                    inputs[block][lane],
                    u64::from_le_bytes(expected[lane * 8..lane * 8 + 8].try_into().unwrap())
                );
            }
        }
        let trace = trace(&w, &s).unwrap();
        for state in case["rounds"].as_array().unwrap() {
            let at = state["stage"].as_u64().unwrap() as usize * 24
                + state["round"].as_u64().unwrap() as usize;
            let row = trace.row_slice(at).unwrap();
            let k: &KeccakCols<BabyBear> = row[..2633].borrow();
            let expected: [u8; 200] = bytes(state["state_hex"].as_str().unwrap());
            for limb in 0..100 {
                assert_eq!(
                    k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32(),
                    u32::from(u16::from_le_bytes(
                        expected[2 * limb..2 * limb + 2].try_into().unwrap()
                    ))
                );
            }
            count += 1;
        }
    }
    assert_eq!(count, 288);
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
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for SamplerOnly {
    fn eval(&self, builder: &mut AB) {
        eval_sampler(builder);
    }
}

#[test]
fn every_final_index_repeated_index_sign_and_capacity_case_passes_its_expected_boundary() {
    let data = data();
    let (w, base) = fixture(&data["genuine"][0]);
    let (inputs, _) = expansion(&w);
    assert_eq!(data["injected"].as_array().unwrap().len(), 267);
    for case in data["injected"].as_array().unwrap() {
        assert_eq!(case["seed_claim"], false);
        let output = bytes::<CAPACITY>(case["stream_hex"].as_str().unwrap());
        let result = trace_with_expansion(&w, inputs.clone(), output, false);
        if !case["supported_complete"].as_bool().unwrap() {
            assert!(matches!(result, Err(Error::UnsupportedCapacity)));
            let raw = trace_with_expansion(&w, inputs.clone(), output, true).unwrap();
            assert!(
                !check_all_constraints(&SamplerOnly, &raw, &public_values(&base), Some(16)).is_ok()
            );
            continue;
        }
        let statement = Statement::new(
            core::array::from_fn(|i| case["normal"][i].as_u64().unwrap() as u32),
            base.context,
        )
        .unwrap();
        let trace = result.unwrap();
        assert!(
            check_all_constraints(&SamplerOnly, &trace, &public_values(&statement), Some(16))
                .is_ok(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn seed_hold_unused_squeeze_bytes_and_public_integer_aliases_reject() {
    let data = data();
    let (w, s) = fixture(&data["genuine"][0]);
    let original = trace(&w, &s).unwrap();
    for (column, start) in [
        (SEED, 48),
        (XOF + 260, 48),
        (SIGN_BITS, 100),
        (FINAL + 3, 400),
    ] {
        let mut changed = original.clone();
        for row in start..HEIGHT {
            changed.values[row * WIDTH + column] += BabyBear::ONE;
        }
        assert!(!check(&changed, &s));
    }
    let mut alias = original.clone();
    for row in 0..HEIGHT {
        alias.values[row * WIDTH + XOF + 260] += BabyBear::from_u32(256);
        alias.values[row * WIDTH + XOF + 261] -= BabyBear::ONE;
    }
    assert!(!check(&alias, &s));
    for index in [0, 196, 255] {
        let mut public = public_values(&s);
        for (byte, value) in (s.coefficients[index] + 2_013_265_921)
            .to_le_bytes()
            .into_iter()
            .enumerate()
        {
            public[index * 4 + byte] = BabyBear::from_u8(value);
        }
        assert!(!check_all_constraints(&ChallengeSamplerAir, &original, &public, Some(16)).is_ok());
    }
}

fn sampler_check(trace: &RowMajorMatrix<BabyBear>, statement: &Statement) -> bool {
    check_all_constraints(&SamplerOnly, trace, &public_values(statement), Some(16)).is_ok()
}

fn statement_from_stream(output: &[u8; CAPACITY], context: [u8; 64]) -> Statement {
    let signs = u64::from_le_bytes(output[..8].try_into().unwrap());
    let mut signed = [0i8; 256];
    let mut accepted = 0;
    for candidate in &output[8..] {
        let index = usize::from(*candidate);
        let destination = 196 + accepted;
        if index <= destination {
            signed[destination] = signed[index];
            signed[index] = 1 - 2 * ((signs >> accepted) & 1) as i8;
            accepted += 1;
            if accepted == 60 {
                break;
            }
        }
    }
    assert_eq!(accepted, 60);
    Statement::new(
        signed.map(|value| {
            if value == -1 {
                MODULUS - 1
            } else {
                value as u32
            }
        }),
        context,
    )
    .unwrap()
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum HashFault {
    SeedSplice,
    RateContinuation,
    CapacityContinuation,
    RepeatedPadding,
    SecondBlockSplice,
}
pub(crate) const HASH_FAULTS: [HashFault; 5] = [
    HashFault::SeedSplice,
    HashFault::RateContinuation,
    HashFault::CapacityContinuation,
    HashFault::RepeatedPadding,
    HashFault::SecondBlockSplice,
];

pub(crate) fn hash_attack(fault: HashFault) -> (RowMajorMatrix<BabyBear>, Statement) {
    let data = data();
    let (w, original) = fixture(&data["genuine"][0]);
    if let HashFault::SeedSplice = fault {
        let (other, statement) = fixture(&data["genuine"][1]);
        let mut changed = trace(&other, &statement).unwrap();
        assert!(check(&changed, &statement));
        for at in 0..HEIGHT {
            for byte in 0..64 {
                changed.values[at * WIDTH + SEED + byte] = BabyBear::from_u8(w.seed[byte]);
            }
        }
        return (changed, statement);
    }
    let (mut inputs, _) = expansion(&w);
    match fault {
        HashFault::RateContinuation => inputs[1][0] ^= 1,
        // The capacity begins at byte 136, lane 17.
        HashFault::CapacityContinuation => inputs[1][17] ^= 1,
        HashFault::RepeatedPadding => {
            inputs[1][8] ^= 31;
            inputs[1][16] ^= 128u64 << 56;
        }
        HashFault::SecondBlockSplice => {
            let (other, _) = fixture(&data["genuine"][1]);
            inputs[1] = expansion(&other).0[1];
        }
        HashFault::SeedSplice => unreachable!(),
    }
    let mut output = [0u8; CAPACITY];
    for block in 0..BLOCKS {
        let after = state_after(inputs[block]);
        for lane in 0..RATE / 8 {
            output[block * RATE + lane * 8..block * RATE + lane * 8 + 8]
                .copy_from_slice(&after[lane].to_le_bytes());
        }
    }
    let statement = statement_from_stream(&output, original.context);
    let changed = trace_with_expansion(&w, inputs, output, false).unwrap();
    assert!(sampler_check(&changed, &statement));
    (changed, statement)
}

#[test]
fn matching_valid_keccak_and_sampler_rows_cannot_replace_private_source_or_continuation() {
    for fault in HASH_FAULTS {
        let (changed, statement) = hash_attack(fault);
        assert!(sampler_check(&changed, &statement), "{fault:?}");
        assert!(!check(&changed, &statement), "{fault:?}");
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum StateFault {
    OldReadAfterOverwrite,
    RelocationDestination,
    SignConsumedOnRejection,
    UntouchedCell,
}
pub(crate) const STATE_FAULTS: [StateFault; 4] = [
    StateFault::OldReadAfterOverwrite,
    StateFault::RelocationDestination,
    StateFault::SignConsumedOnRejection,
    StateFault::UntouchedCell,
];

pub(crate) fn state_attack(fault: StateFault) -> (RowMajorMatrix<BabyBear>, Statement) {
    let data = data();
    let (w, original) = fixture(&data["genuine"][0]);
    let (_, output) = expansion(&w);
    let signs = u64::from_le_bytes(output[..8].try_into().unwrap());
    let mut changed = trace(&w, &original).unwrap();
    let mut state = [0i8; 256];
    let mut accepted = 0usize;
    let mut triggered = false;
    for at in 0..HEIGHT {
        let row = &mut changed.values[at * WIDTH..(at + 1) * WIDTH];
        for index in 0..256 {
            row[PLUS + index] = BabyBear::from_bool(state[index] == 1);
            row[MINUS + index] = BabyBear::from_bool(state[index] == -1);
        }
        assert_eq!(state.iter().filter(|v| **v != 0).count(), accepted);
        if accepted == 60 || at >= EVENTS {
            continue;
        }
        let destination = 196 + accepted;
        let index = usize::from(output[8 + at]);
        if index > destination {
            continue;
        }
        let mut old = state[index];
        let mut sign = 1 - 2 * ((signs >> accepted) & 1) as i8;
        let mut destination_override = None;
        if matches!(fault, StateFault::OldReadAfterOverwrite) && !triggered && old == -sign {
            // Preserve weight and Boolean encodings while substituting the new
            // value for the required read before replacement.
            old = sign;
            triggered = true;
        }
        if matches!(fault, StateFault::RelocationDestination) && !triggered && old != 0 {
            destination_override = (0..196).find(|k| *k != index && state[*k] == 0);
            assert!(destination_override.is_some());
            triggered = true;
        }
        if matches!(fault, StateFault::SignConsumedOnRejection) {
            let wrong = 1 - 2 * ((signs >> (at % 64)) & 1) as i8;
            triggered |= wrong != sign;
            sign = wrong;
        }
        row[OLD_PLUS] = BabyBear::from_bool(old == 1);
        row[OLD_MINUS] = BabyBear::from_bool(old == -1);
        state[destination_override.unwrap_or(destination)] = old;
        state[index] = sign;
        if matches!(fault, StateFault::UntouchedCell) && !triggered && accepted >= 5 {
            let other = (0..256)
                .find(|k| *k != index && *k != destination && state[*k] != 0)
                .unwrap();
            state[other] = -state[other];
            triggered = true;
        }
        accepted += 1;
    }
    assert!(triggered, "{fault:?}");
    assert_eq!(accepted, 60);
    let coefficients = state.map(|v| if v == -1 { MODULUS - 1 } else { v as u32 });
    assert_ne!(coefficients, original.coefficients);
    for row in changed.values.chunks_exact_mut(WIDTH) {
        for index in 0..256 {
            row[FINAL + index] = BabyBear::from_u32(coefficients[index]);
        }
    }
    let statement = Statement::new(coefficients, original.context).unwrap();
    (changed, statement)
}

#[test]
fn locally_boolean_weight_preserving_wrong_state_updates_reject_matching_final_polynomials() {
    for fault in STATE_FAULTS {
        let (changed, statement) = state_attack(fault);
        assert!(!sampler_check(&changed, &statement), "{fault:?}");
        assert!(!check(&changed, &statement), "{fault:?}");
    }
}

#[test]
fn counters_program_cursor_and_padding_cannot_skip_or_resume_work() {
    let data = data();
    let (w, statement) = fixture(&data["genuine"][0]);
    let original = trace(&w, &statement).unwrap();
    for (column, row) in [
        (PROGRAM + 10, 10),
        (COUNT + 10, 10),
        (CURSOR + 3, 10),
        (TAKE, 400),
        (INDEX + 8, 400),
        (CANDIDATE, 400),
        (PLUS + 3, 400),
    ] {
        let mut changed = original.clone();
        changed.values[row * WIDTH + column] += BabyBear::ONE;
        assert!(!sampler_check(&changed, &statement));
    }
    let mut jump = original.clone();
    jump.values[10 * WIDTH + PROGRAM + 10] = BabyBear::ZERO;
    jump.values[10 * WIDTH + PROGRAM + 11] = BabyBear::ONE;
    assert!(!sampler_check(&jump, &statement));
    let mut count = original.clone();
    count.values[10 * WIDTH + COUNT..10 * WIDTH + CANDIDATE].fill(BabyBear::ZERO);
    count.values[10 * WIDTH + COUNT + 11] = BabyBear::ONE;
    assert!(!sampler_check(&count, &statement));
}

#[test]
fn proof_namespace_goldens_match_all_digest_words() {
    use super::hash::{LeafHash, NodeHash, TranscriptHash};
    use p3_symmetric::CryptographicHasher;
    for line in include_str!("../../../../research/challenge-sampling/hash_vectors.csv")
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
