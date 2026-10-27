use super::super::super::air::*;
use super::super::super::tests::{data, fixture};
use super::super::*;
use serde_json::json;

fn set_bits(row: &mut [BabyBear], start: usize, value: i64, width: usize) {
    for bit in 0..width {
        row[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
    }
}

fn route_to_wrong_group(w: &Witness, s: &Statement) -> RowMajorMatrix<BabyBear> {
    let mut result = trace(w, s).unwrap();
    let cuts: [i64; 8] = core::array::from_fn(|i| i64::from(w.signature_tail[4555 + i]));
    let mut hints = [[false; 256]; 8];
    let mut last = [0i64; 8];
    let mut seen = [false; 8];
    for (at, row) in result.values.chunks_exact_mut(WIDTH).enumerate() {
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
            let index = usize::from(w.signature_tail[4480 + at]);
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
    result
}

#[test]
fn fifteen_raw_false_proofs_reject_at_the_backend() {
    let data = data();
    let (w, s) = fixture(&data["cases"][0]);
    let original = trace(&w, &s).unwrap();
    let mut attacks = Vec::new();
    let (other, other_s) = fixture(&data["cases"][1]);
    let mut seed_splice = trace(&other, &other_s).unwrap();
    for row in seed_splice.values.chunks_exact_mut(WIDTH) {
        for byte in 0..64 {
            row[super::super::super::challenge::SEED + byte] = BabyBear::from_u8(w.seed[byte]);
        }
    }
    attacks.push(("SeedSourceSplice", seed_splice, other_s));
    let (joined, joined_s) = fixture(data["cases"].as_array().unwrap().last().unwrap());
    let mut tail_splice = trace(&joined, &joined_s).unwrap();
    for row in tail_splice.values.chunks_exact_mut(WIDTH) {
        for byte in 0..4563 {
            row[SIGNATURE_TAIL + byte] = BabyBear::from_u8(w.signature_tail[byte]);
        }
    }
    attacks.push(("TailSourceSplice", tail_splice, joined_s));
    for (name, column, start) in [
        ("TailHold", SIGNATURE_TAIL + 5, 400),
        ("FirstZWrite", Z_VALUES, 1),
        ("LastZWrite", Z_VALUES + 1791, 448),
    ] {
        let mut changed = original.clone();
        for at in start..HEIGHT {
            changed.values[at * WIDTH + column] += BabyBear::ONE;
        }
        attacks.push((name, changed, s));
    }
    let mut alias = original.clone();
    for row in alias.values.chunks_exact_mut(WIDTH) {
        row[SIGNATURE_TAIL + 5] += BabyBear::from_u32(256);
        row[SIGNATURE_TAIL + 6] -= BabyBear::ONE;
    }
    attacks.push(("ByteAlias", alias, s));
    for (name, program) in [("ZProgramSkip", Z_PROGRAM), ("HintProgramSkip", HINT_START)] {
        let mut changed = original.clone();
        changed.values[20 * WIDTH + program + 20] = BabyBear::ZERO;
        changed.values[20 * WIDTH + program + 21] = BabyBear::ONE;
        attacks.push((name, changed, s));
    }
    let mut descending = Witness {
        seed: w.seed,
        signature_tail: w.signature_tail,
    };
    descending.signature_tail.swap(4480, 4481);
    let mut seen_reset = trace(&descending, &s).unwrap();
    seen_reset.values[WIDTH + SEEN] = BabyBear::ZERO;
    seen_reset.values[WIDTH + ORDER..WIDTH + ORDER + 8].fill(BabyBear::ZERO);
    attacks.push(("DescendingSeenReset", seen_reset, s));
    let mut descending = Witness {
        seed: w.seed,
        signature_tail: w.signature_tail,
    };
    descending.signature_tail.swap(4481, 4482);
    let mut last_reset = trace(&descending, &s).unwrap();
    let row = &mut last_reset.values[2 * WIDTH..3 * WIDTH];
    set_bits(row, LAST, i64::from(descending.signature_tail[4482]) - 1, 8);
    row[ORDER..ORDER + 8].fill(BabyBear::ZERO);
    attacks.push(("DescendingLastReset", last_reset, s));
    attacks.push(("WrongHintSegment", route_to_wrong_group(&w, &s), s));
    let maximum = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "hint_maximum_weight_75")
        .unwrap();
    let (max_w, max_s) = fixture(maximum);
    assert_eq!(max_w.signature_tail[4562], 75);
    let mut omitted = trace(&max_w, &max_s).unwrap();
    let group = (0..8)
        .find(|i| {
            let previous = if *i == 0 {
                0
            } else {
                max_w.signature_tail[4555 + *i - 1]
            };
            previous <= 74 && 74 < max_w.signature_tail[4555 + *i]
        })
        .unwrap();
    let index = usize::from(max_w.signature_tail[4554]);
    for at in 75..HEIGHT {
        omitted.values[at * WIDTH + HINTS + group * 256 + index] = BabyBear::ZERO;
    }
    attacks.push(("Omitted75thHintWrite", omitted, max_s));
    for (name, d) in [("StrictLowerNorm", 120u32), ("StrictUpperNorm", 1048456)] {
        let mut bad = Witness {
            seed: w.seed,
            signature_tail: w.signature_tail,
        };
        bad.signature_tail[0] = d as u8;
        bad.signature_tail[1] = (d >> 8) as u8;
        bad.signature_tail[2] = (bad.signature_tail[2] & 0xf0) | ((d >> 16) as u8 & 15);
        attacks.push((name, trace(&bad, &s).unwrap(), s));
    }
    let mut padding = original;
    padding.values[500 * WIDTH + Z_AUX] = BabyBear::ONE;
    attacks.push(("PaddingAuxiliary", padding, s));
    assert_eq!(attacks.len(), 15);
    let mut results = Vec::new();
    for (name, trace, statement) in attacks {
        let public = public_values(&statement);
        assert!(
            !check_all_constraints(&SignatureChallengeAir, &trace, &public, Some(1)).is_ok(),
            "{name}"
        );
        let proof = prove(
            &prover_config().unwrap(),
            &SignatureChallengeAir,
            trace,
            &public,
        )
        .expect("raw backend bypasses witness checks");
        validate_shape(&proof).unwrap();
        let error = verify(&verifier_config(), &SignatureChallengeAir, &proof, &public)
            .expect_err("false backend proof rejected");
        let bytes = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_signature_challenge(&bytes, &statement),
            Err(Error::InvalidProof),
            "{name}"
        );
        results.push(
            json!({"fault":name,"encoded_bytes":bytes.len(),"backend_error":format!("{error:?}")}),
        );
    }

    println!(
        "15 raw false proofs bypassed witness checks and rejected at direct backend verification"
    );
}
