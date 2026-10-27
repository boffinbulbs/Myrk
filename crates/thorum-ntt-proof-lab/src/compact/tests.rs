use super::*;
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use serde_json::Value;

fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../research/ntt-proofs/ntt_vectors.json"
    ))
    .unwrap()
}

fn reference_case(case: &Value) -> (Witness, Statement) {
    let public = &case["public"];
    let mode = match public["mode"].as_u64().unwrap() {
        1 => Mode::Forward,
        2 => Mode::Inverse,
        _ => panic!("mode"),
    };
    let input = core::array::from_fn(|i| public["input"][i].as_u64().unwrap() as u32);
    let output = core::array::from_fn(|i| public["output"][i].as_u64().unwrap() as u32);
    let text = public["context_hex"].as_str().unwrap();
    let context =
        core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap());
    (
        Witness::from_input(input).unwrap(),
        Statement::new(mode, input, output, context).unwrap(),
    )
}

fn packed_bits(bits: &[BabyBear]) -> u32 {
    bits.iter()
        .rev()
        .fold(0, |sum, bit| 2 * sum + bit.as_canonical_u32())
}

fn power(mut value: u64, mut exponent: u64) -> u32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * value % u64::from(mul::MODULUS);
        }
        value = value * value % u64::from(mul::MODULUS);
        exponent >>= 1;
    }
    result as u32
}

fn direct_transform(input: &[u32; 256], mode: Mode) -> [u32; 256] {
    let q = u64::from(mul::MODULUS);
    match mode {
        Mode::Forward => core::array::from_fn(|i| {
            let root = power(1753, 2 * u64::from((i as u8).reverse_bits()) + 1);
            input.iter().rev().fold(0, |sum, value| {
                (sum * u64::from(root) + u64::from(*value)) % q
            }) as u32
        }),
        Mode::Inverse => core::array::from_fn(|coefficient| {
            let sum = input.iter().enumerate().fold(0, |sum, (i, value)| {
                let exponent = (512
                    - ((2 * u64::from((i as u8).reverse_bits()) + 1) * coefficient as u64) % 512)
                    % 512;
                (sum + u64::from(*value) * u64::from(power(1753, exponent))) % q
            });
            (sum * u64::from(ntt::INVERSE_256) % q) as u32
        }),
    }
}

#[test]
fn fixed_schedule_dimensions_and_actual_symbolic_degree() {
    assert_eq!(air::WIDTH, 2921);
    assert_eq!(air::HEIGHT, 256);
    for mode in [Mode::Forward, Mode::Inverse] {
        let program = air::program(mode);
        assert_eq!(program.len(), if mode == Mode::Forward { 192 } else { 224 });
        for instruction in &program {
            let destinations: Vec<_> = instruction.destinations.iter().flatten().copied().collect();
            let mut unique = destinations.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(destinations.len(), unique.len());
        }
        let statement = Statement::new(mode, [0; 256], [0; 256], [0; 64]).unwrap();
        let trace = trace(&Witness::from_input([0; 256]).unwrap(), &statement);
        assert_eq!(trace.width(), 2921);
        assert_eq!(trace.height(), 256);
        let degree = p3_air::symbolic::get_max_constraint_degree_extension::<BabyBear, Challenge, _>(
            &NttAir::new(&statement),
            p3_air::symbolic::AirLayout {
                main_width: air::WIDTH,
                num_public_values: air::PUBLIC_VALUES,
                ..Default::default()
            },
            air::HEIGHT,
        );
        assert_eq!(degree, 2);
    }
}

#[test]
fn exact_same_47_reference_cases_and_all_public_values() {
    let cases = corpus();
    assert_eq!(cases["cases"].as_array().unwrap().len(), 47);
    let mut accepting = 0;
    for case in cases["cases"].as_array().unwrap() {
        let (witness, statement) = reference_case(case);
        let values: Vec<_> = public_values(&statement)
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect();
        let expected: Vec<_> = case["public_values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(values, expected, "{}", case["name"]);
        let expected = case["expected"]["valid_component"].as_bool().unwrap();
        assert_eq!(
            trace_is_valid(&trace(&witness, &statement), &statement),
            expected,
            "{}",
            case["name"]
        );
        if expected {
            assert_eq!(
                statement.output,
                direct_transform(&statement.input, statement.mode)
            );
            accepting += 1;
        }
    }
    assert_eq!(accepting, 31);
}

#[test]
fn every_valid_independent_stage_and_auxiliary_record_matches() {
    let cases = corpus();
    let stages: Value = serde_json::from_str(include_str!(
        "../../../../research/ntt-proofs/stage_vectors.json"
    ))
    .unwrap();
    let mut traces = std::collections::BTreeMap::new();
    let mut states_checked = 0;
    for case in cases["cases"].as_array().unwrap() {
        if case["expected"]["valid_component"] != true {
            continue;
        }
        let (witness, statement) = reference_case(case);
        let trace = trace(&witness, &statement);
        let name = case["name"].as_str().unwrap();
        let expected = stages["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == name)
            .unwrap();
        for (stage, polynomial) in expected["states"].as_array().unwrap().iter().enumerate() {
            let row = if stage <= 8 {
                32 + 16 * stage
            } else {
                160 + (stage - 8) * 16
            };
            for i in 0..256 {
                assert_eq!(
                    trace.values[row * air::WIDTH + air::BANK + i].as_canonical_u32(),
                    polynomial[i].as_u64().unwrap() as u32,
                    "{name} stage{stage} coefficient{i}"
                );
            }
            states_checked += 1;
        }
        traces.insert(name.to_owned(), trace);
    }
    assert_eq!(states_checked, 309);
    let mut products_checked = 0;
    for line in include_str!("../../../../research/ntt-proofs/butterfly_operations.csv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = line.split(',').collect();
        let Some(trace) = traces.get(fields[0]) else {
            continue;
        };
        let stage: usize = fields[1].parse().unwrap();
        let old_slot: usize = fields[3].parse().unwrap();
        let row_index = if stage < 8 {
            32 + stage * 16 + old_slot / 8
        } else {
            160 + (stage - 8) * 16 + old_slot / 8
        };
        let slot = old_slot % 8;
        let row = &trace.values[row_index * air::WIDTH..(row_index + 1) * air::WIDTH];
        let offset = air::PRODUCTS + slot * mul::WIDTH;
        for (index, expected) in fields[12..16].iter().enumerate() {
            assert_eq!(
                packed_bits(&row[offset + index * 23..offset + (index + 1) * 23]),
                expected.parse::<u32>().unwrap(),
                "{} stage{stage} slot{old_slot}",
                fields[0]
            );
        }
        assert_eq!(
            packed_bits(&row[offset + mul::CARRY0..offset + mul::CARRY1]) as i32 - 2,
            fields[16].parse::<i32>().unwrap()
        );
        assert_eq!(
            packed_bits(&row[offset + mul::CARRY1..offset + mul::WIDTH]) as i32 - 4096,
            fields[17].parse::<i32>().unwrap()
        );
        assert_eq!(
            row[air::FLAGS + slot * 2].as_canonical_u32(),
            fields[18].parse::<u32>().unwrap()
        );
        assert_eq!(
            row[air::FLAGS + slot * 2 + 1].as_canonical_u32(),
            fields[19].parse::<u32>().unwrap()
        );
        if stage < 8 {
            let left: usize = fields[6].parse().unwrap();
            let right: usize = fields[7].parse().unwrap();
            assert_eq!(
                row[air::BANK + left].as_canonical_u32(),
                fields[10].parse::<u32>().unwrap()
            );
            assert_eq!(
                row[air::BANK + right].as_canonical_u32(),
                fields[11].parse::<u32>().unwrap()
            );
            for member in 0..2 {
                let at = air::WRITES + (slot * 2 + member) * 46;
                assert_eq!(
                    packed_bits(&row[at..at + 23]),
                    fields[20 + member].parse::<u32>().unwrap()
                );
            }
        }
        products_checked += 1;
    }
    assert_eq!(products_checked, 35_584);
}

#[test]
fn initialization_holds_program_flags_and_padding_faults_reject() {
    let case = &corpus()["cases"][20];
    let (witness, statement) = reference_case(case);
    let original = trace(&witness, &statement);
    assert!(trace_is_valid(&original, &statement));
    let faults = [
        (0, air::BANK + 255),
        (33, air::BANK + 255),
        (200, air::BANK + 10),
        (10, air::FLAGS),
        (192, air::WRITES),
        (32, 33),
        (223, air::PAD),
    ];
    for (row, column) in faults {
        let mut changed = original.clone();
        changed.values[row * air::WIDTH + column] += BabyBear::ONE;
        assert!(
            !trace_is_valid(&changed, &statement),
            "row{row} column{column}"
        );
    }
    let mut changed = original.clone();
    let offset = 200 * air::WIDTH + air::PRODUCTS;
    air::encode_product(
        &ntt::product(1, 1),
        &mut changed.values[offset..offset + mul::WIDTH],
    );
    assert!(!trace_is_valid(&changed, &statement));
}

#[test]
fn bytewise_public_field_aliases_and_output_byte_faults_reject() {
    let case = &corpus()["cases"][20];
    let (witness, statement) = reference_case(case);
    let trace = trace(&witness, &statement);
    for output in [false, true] {
        for index in [0, 7, 8, 127, 128, 255] {
            let value = if output {
                statement.output[index]
            } else {
                statement.input[index]
            };
            let alias = value + 2013265921;
            let mut public = public_values(&statement);
            let start = (if output { 1025 } else { 1 }) + index * 4;
            for (byte, encoded) in alias.to_le_bytes().into_iter().enumerate() {
                public[start + byte] = BabyBear::from_u8(encoded);
            }
            assert!(
                !check_all_constraints(&NttAir::new(&statement), &trace, &public, Some(1)).is_ok()
            );
        }
    }
}

#[test]
fn invalid_statement_is_rejected_before_any_proof_decoding() {
    for mode in [Mode::Forward, Mode::Inverse] {
        let mut statement = Statement::new(mode, [0; 256], [0; 256], [0; 64]).unwrap();
        statement.input[255] = mul::MODULUS;
        assert_eq!(
            verify_compact_ntt(&[], &statement),
            Err(Error::InvalidStatement)
        );
        assert!(
            Statement::new(mode, statement.input, statement.output, statement.context).is_err()
        );
        assert!(Witness::from_input(statement.input).is_err());
    }
}

#[test]
fn causal_valid_products_cannot_replace_authorized_dataflow() {
    use causal::Attack;
    for (mode, attack) in [
        (Mode::Forward, Attack::WrongTwiddle),
        (Mode::Inverse, Attack::WrongTwiddle),
        (Mode::Forward, Attack::DetachedMultiplicand),
        (Mode::Forward, Attack::UnauthorizedBankWrite),
        (Mode::Inverse, Attack::UnauthorizedBankWrite),
        (Mode::Inverse, Attack::MissingNormalization),
        (Mode::Forward, Attack::DetachedOutputRead),
        (Mode::Inverse, Attack::DetachedOutputRead),
        (Mode::Forward, Attack::ChangedFirstOutputBank),
        (Mode::Inverse, Attack::ChangedFirstOutputBank),
        (Mode::Forward, Attack::ChangedPaddingBank),
        (Mode::Inverse, Attack::ChangedPaddingBank),
        (Mode::Forward, Attack::UninitializedBank),
        (Mode::Inverse, Attack::UninitializedBank),
    ] {
        let (trace, statement) = causal::attack_trace(mode, attack);
        assert!(!trace_is_valid(&trace, &statement), "{mode:?} {attack:?}");
    }
}

#[test]
fn distinct_hash_adapter_goldens_match_every_digest_word() {
    use p3_symmetric::CryptographicHasher;
    let leaf = LeafHash.hash_iter([0, 1, 0x7800_0000, 0x1234_5678].map(BabyBear::from_u32));
    let node = NodeHash.hash_iter([0, 1, u64::MAX].into_iter().chain(0..13));
    let transcript = TranscriptHash.hash_iter(0..64);
    let transcript_words: [u64; 8] = core::array::from_fn(|i| {
        u64::from_le_bytes(transcript[i * 8..i * 8 + 8].try_into().unwrap())
    });
    for (actual, line) in [leaf, node, transcript_words].iter().zip(
        include_str!("../../../../research/compact-ntt/hash_vectors.csv")
            .lines()
            .skip(1),
    ) {
        let expected: Vec<u64> = line
            .split(',')
            .nth(3)
            .unwrap()
            .split(':')
            .map(|word| word.parse().unwrap())
            .collect();
        assert_eq!(actual.as_slice(), expected);
    }
}
