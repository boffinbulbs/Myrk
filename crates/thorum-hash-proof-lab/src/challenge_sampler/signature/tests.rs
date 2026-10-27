use super::*;
use air::*;
use p3_air::{
    check_all_constraints,
    symbolic::{AirLayout, get_max_constraint_degree},
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use serde_json::Value;

pub(crate) fn data() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../research/signature-challenge/vectors.json"
    ))
    .unwrap()
}
pub(crate) fn fixture(case: &Value) -> (Witness, Statement) {
    let text = case["signature_hex"].as_str().unwrap();
    let signature =
        core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap());
    let c = core::array::from_fn(|i| case["challenge_normal"][i].as_u64().unwrap() as u32);
    (
        Witness::from_signature(signature),
        Statement::new(c, [0x79; 64]).unwrap(),
    )
}
fn check(trace: &RowMajorMatrix<BabyBear>, statement: &Statement) -> bool {
    check_all_constraints(
        &SignatureChallengeAir,
        trace,
        &public_values(statement),
        Some(1),
    )
    .is_ok()
}

#[test]
fn exact_dimensions_degree_and_complete_source_coverage() {
    assert_eq!((HEIGHT, WIDTH, PUBLIC_VALUES), (512, 16650, 1088));
    let degree = get_max_constraint_degree::<BabyBear, _>(
        &SignatureChallengeAir,
        AirLayout {
            main_width: WIDTH,
            num_public_values: PUBLIC_VALUES,
            ..Default::default()
        },
        HEIGHT,
    );
    println!("actual same signature degree {degree}");
    assert_eq!(degree, 3);
    let mut reads = [0u8; 4627];
    for count in &mut reads[..64] {
        *count += 1;
    }
    for event in 0..448 {
        for byte in 0..10 {
            reads[64 + event * 10 + byte] += 1;
        }
    }
    for position in 0..75 {
        reads[4544 + position] += 1;
    }
    for cut in 0..8 {
        reads[4619 + cut] += 1;
    }
    assert!(reads.iter().all(|n| *n == 1));
}

#[test]
fn independent_canonical_classification_and_final_private_values_match_every_signature() {
    let data = data();
    assert_eq!(data["cases"].as_array().unwrap().len(), 124);
    for case in data["cases"].as_array().unwrap() {
        let (w, s) = fixture(case);
        let trace = trace(&w, &s).unwrap();
        let actual = check(&trace, &s);
        let expected = case["canonical"].as_bool().unwrap();
        assert_eq!(actual, expected, "{}", case["name"]);
        if expected {
            let row = trace.row_slice(HEIGHT - 1).unwrap();
            for index in 0..1792 {
                assert_eq!(
                    row[Z_VALUES + index].as_canonical_u32(),
                    case["z_q"][index / 256][index % 256].as_u64().unwrap() as u32
                );
            }
            for index in 0..2048 {
                assert_eq!(
                    row[HINTS + index].as_canonical_u32(),
                    u32::from(case["hints"][index / 256][index % 256].as_u64().unwrap() != 0)
                );
            }
        }
    }
}

#[test]
fn canonical_joined_byte_string_is_not_mistaken_for_complete_signature_authorization() {
    let data = data();
    let case = data["cases"].as_array().unwrap().last().unwrap();
    assert_eq!(case["name"], "represented_prefix_a_with_canonical_tail_b");
    let (w, s) = fixture(case);
    assert!(check(&trace(&w, &s).unwrap(), &s));
}

#[test]
fn correct_decoder_for_other_bytes_cannot_replace_the_held_signature_tail() {
    let data = data();
    let (original, s) = fixture(&data["cases"][0]);
    let (joined, joined_s) = fixture(data["cases"].as_array().unwrap().last().unwrap());
    assert_eq!(s.coefficients, joined_s.coefficients);
    let mut changed = trace(&joined, &joined_s).unwrap();
    assert!(check(&changed, &joined_s));
    for row in changed.values.chunks_exact_mut(WIDTH) {
        for byte in 0..4563 {
            row[SIGNATURE_TAIL + byte] = BabyBear::from_u8(original.signature_tail[byte]);
        }
    }
    assert!(!check(&changed, &s));
}

#[test]
fn tail_banks_decoded_registers_and_hint_padding_cannot_reset() {
    let data = data();
    let (w, s) = fixture(&data["cases"][0]);
    let original = trace(&w, &s).unwrap();
    for (column, start) in [(SIGNATURE_TAIL + 5, 400), (Z_VALUES, 1), (HINTS + 5, 400)] {
        let mut changed = original.clone();
        for row in start..HEIGHT {
            changed.values[row * WIDTH + column] += BabyBear::ONE;
        }
        assert!(!check(&changed, &s));
    }
    let mut omitted = original.clone();
    let hints = &data["cases"][0]["hints"];
    let index = (0..2048)
        .find(|i| hints[i / 256][i % 256].as_u64() == Some(1))
        .unwrap();
    for row in 75..HEIGHT {
        omitted.values[row * WIDTH + HINTS + index] = BabyBear::ZERO;
    }
    assert!(!check(&omitted, &s));
}

#[test]
fn honest_expansion_from_another_prefix_cannot_replace_the_private_seed_bank() {
    let data = data();
    let (original, _) = fixture(&data["cases"][0]);
    let (other, s) = fixture(&data["cases"][1]);
    let mut changed = trace(&other, &s).unwrap();
    assert!(check(&changed, &s));
    for row in changed.values.chunks_exact_mut(WIDTH) {
        for byte in 0..64 {
            row[challenge::SEED + byte] = BabyBear::from_u8(original.seed[byte]);
        }
    }
    assert!(!check(&changed, &s));
}

#[test]
fn fixed_programs_last_writes_and_zero_padding_are_required() {
    let data = data();
    let (w, s) = fixture(&data["cases"][0]);
    let original = trace(&w, &s).unwrap();
    for (column, at) in [
        (Z_PROGRAM + 20, 20),
        (HINT_START + 20, 20),
        (Z_AUX, 500),
        (GROUP, 500),
        (ONE_HOT, 500),
    ] {
        let mut changed = original.clone();
        changed.values[at * WIDTH + column] += BabyBear::ONE;
        assert!(!check(&changed, &s));
    }
    let mut wrong_last = original.clone();
    for at in 448..HEIGHT {
        wrong_last.values[at * WIDTH + Z_VALUES + 1791] += BabyBear::ONE;
    }
    assert!(!check(&wrong_last, &s));
    let mut byte_alias = original.clone();
    for row in byte_alias.values.chunks_exact_mut(WIDTH) {
        row[SIGNATURE_TAIL + 5] += BabyBear::from_u32(256);
        row[SIGNATURE_TAIL + 6] -= BabyBear::ONE;
    }
    assert!(!check(&byte_alias, &s));
}

fn set_bits(row: &mut [BabyBear], start: usize, value: i64, width: usize) {
    for bit in 0..width {
        row[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
    }
}

#[test]
fn rebuilt_hint_order_segment_and_final_update_attacks_reject() {
    let data = data();
    let (base, s) = fixture(&data["cases"][0]);
    let mut descending = Witness {
        seed: base.seed,
        signature_tail: base.signature_tail,
    };
    descending.signature_tail.swap(4480, 4481);
    let mut seen_reset = trace(&descending, &s).unwrap();
    assert!(!check(&seen_reset, &s));
    seen_reset.values[WIDTH + SEEN] = BabyBear::ZERO;
    seen_reset.values[WIDTH + ORDER..WIDTH + ORDER + 8].fill(BabyBear::ZERO);
    assert!(!check(&seen_reset, &s));

    let mut descending = Witness {
        seed: base.seed,
        signature_tail: base.signature_tail,
    };
    descending.signature_tail.swap(4481, 4482);
    let mut last_reset = trace(&descending, &s).unwrap();
    let index = i64::from(descending.signature_tail[4482]);
    assert!(index > 0);
    let row = &mut last_reset.values[2 * WIDTH..3 * WIDTH];
    set_bits(row, LAST, index - 1, 8);
    row[ORDER..ORDER + 8].fill(BabyBear::ZERO);
    assert!(!check(&last_reset, &s));

    let mut routed = trace(&base, &s).unwrap();
    let cuts: [i64; 8] = core::array::from_fn(|i| i64::from(base.signature_tail[4555 + i]));
    let mut hints = [[false; 256]; 8];
    let mut last = [0i64; 8];
    let mut seen = [false; 8];
    for (at, row) in routed.values.chunks_exact_mut(WIDTH).enumerate() {
        row[GROUP..WIDTH].fill(BabyBear::ZERO);
        for i in 0..8 {
            set_bits(row, LAST + i * 8, last[i], 8);
            row[SEEN + i] = BabyBear::from_bool(seen[i]);
            for k in 0..256 {
                row[HINTS + i * 256 + k] = BabyBear::from_bool(hints[i][k]);
            }
        }
        if at < 75 && (at as i64) < cuts[7] {
            let j = at as i64;
            let correct = (0..8)
                .find(|i| {
                    let previous = if *i == 0 { 0 } else { cuts[*i - 1] };
                    previous <= j && j < cuts[*i]
                })
                .unwrap();
            let group = if at == 0 {
                assert_eq!(correct, 0);
                1
            } else {
                correct
            };
            let index = usize::from(base.signature_tail[4480 + at]);
            row[GROUP + group] = BabyBear::ONE;
            row[ONE_HOT + index] = BabyBear::ONE;
            let previous = if group == 0 { 0 } else { cuts[group - 1] };
            set_bits(row, SEGMENT_LOWER + group * 7, j - previous, 7);
            set_bits(row, SEGMENT_UPPER + group * 7, cuts[group] - j - 1, 7);
            if seen[group] {
                set_bits(row, ORDER + group * 8, index as i64 - last[group] - 1, 8);
            }
            assert!(!hints[group][index]);
            last[group] = index as i64;
            seen[group] = true;
            hints[group][index] = true;
        }
    }
    assert_eq!(
        hints.iter().flatten().filter(|v| **v).count(),
        cuts[7] as usize
    );
    assert!(!check(&routed, &s));

    let maximum = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "hint_maximum_weight_75")
        .unwrap();
    let (w, statement) = fixture(maximum);
    assert_eq!(w.signature_tail[4562], 75);
    let mut omitted = trace(&w, &statement).unwrap();
    assert!(check(&omitted, &statement));
    let group = (0..8)
        .find(|i| {
            let previous = if *i == 0 {
                0
            } else {
                w.signature_tail[4555 + *i - 1]
            };
            previous <= 74 && 74 < w.signature_tail[4555 + *i]
        })
        .unwrap();
    let index = usize::from(w.signature_tail[4480 + 74]);
    assert_eq!(
        omitted.values[74 * WIDTH + HINTS + group * 256 + index],
        BabyBear::ZERO
    );
    assert_eq!(
        omitted.values[75 * WIDTH + HINTS + group * 256 + index],
        BabyBear::ONE
    );
    for row in 75..HEIGHT {
        omitted.values[row * WIDTH + HINTS + group * 256 + index] = BabyBear::ZERO;
    }
    assert!(!check(&omitted, &statement));
}

#[test]
fn exact_rebuilt_norm_endpoints_fail_with_canonical_normal_residues() {
    let data = data();
    let (base, s) = fixture(&data["cases"][0]);
    for d in [120u32, 1048456] {
        let mut w = Witness {
            seed: base.seed,
            signature_tail: base.signature_tail,
        };
        w.signature_tail[0] = d as u8;
        w.signature_tail[1] = (d >> 8) as u8;
        w.signature_tail[2] = (w.signature_tail[2] & 0xf0) | ((d >> 16) as u8 & 15);
        let rebuilt = trace(&w, &s).unwrap();
        let expected = (524288i64 - i64::from(d)).rem_euclid(i64::from(MODULUS)) as u32;
        assert_eq!(
            rebuilt.values[WIDTH + Z_VALUES].as_canonical_u32(),
            expected
        );
        assert!(expected < MODULUS);
        assert!(!check(&rebuilt, &s));
    }
}
