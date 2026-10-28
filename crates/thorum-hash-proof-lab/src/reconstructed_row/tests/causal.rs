use super::reference::{WithoutHash, bytes, count, data, fixture, from_input, value};
use super::*;
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use serde_json::Value;

fn hostile() -> &'static Value {
    static DATA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../research/reconstructed-row/hostile_cases.json"
            ))
            .unwrap(),
        )
        .unwrap()
    })
}
fn compare_sponge(t: &RowMajorMatrix<BabyBear>, column: usize, record: &Value) {
    for block in 0..6 {
        let before = bytes::<200>(
            record["sponges"][block]["state_absorbed_hex"]
                .as_str()
                .unwrap(),
        );
        let after = bytes::<200>(
            record["sponges"][block]["state_after_hex"]
                .as_str()
                .unwrap(),
        );
        let row = t.row_slice(column * 42 + block * 6 + 5).unwrap();
        let k: &KeccakCols<BabyBear> = row[3 * NUM_KECCAK_COLS..4 * NUM_KECCAK_COLS].borrow();
        for limb in 0..100 {
            let get = |state: &[u8; 200]| {
                u32::from(u16::from_le_bytes([state[limb * 2], state[limb * 2 + 1]]))
            };
            assert_eq!(
                k.preimage[limb / 20][(limb / 4) % 5][limb % 4].as_canonical_u32(),
                get(&before)
            );
            assert_eq!(
                k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                    .as_canonical_u32(),
                get(&after)
            );
        }
    }
    if let Some(rounds) = record["round_states"].as_array() {
        assert_eq!(rounds.len(), 144);
        for (logical, r) in rounds.iter().enumerate() {
            let stage = logical / 24;
            let preimage = bytes::<200>(
                record["sponges"][stage]["state_absorbed_hex"]
                    .as_str()
                    .unwrap(),
            );
            let before = if logical % 24 == 0 {
                preimage
            } else {
                bytes(rounds[logical - 1]["state_hex"].as_str().unwrap())
            };
            let after = bytes::<200>(r["state_hex"].as_str().unwrap());
            let row = t.row_slice(column * 42 + logical / 4).unwrap();
            let k: &KeccakCols<BabyBear> =
                row[(logical % 4) * NUM_KECCAK_COLS..(logical % 4 + 1) * NUM_KECCAK_COLS].borrow();
            for limb in 0..100 {
                let get = |state: &[u8; 200]| {
                    u32::from(u16::from_le_bytes([state[limb * 2], state[limb * 2 + 1]]))
                };
                assert_eq!(
                    k.preimage[limb / 20][(limb / 4) % 5][limb % 4].as_canonical_u32(),
                    get(&preimage)
                );
                assert_eq!(
                    k.a[limb / 20][(limb / 4) % 5][limb % 4].as_canonical_u32(),
                    get(&before)
                );
                assert_eq!(
                    k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32(),
                    get(&after)
                );
            }
        }
    }
}
#[test]
fn all_deduplicated_full_sponges_and_selected_packed_rounds_match_independent_oracle() {
    let mut sponges = 0;
    let mut rounds = 0;
    for case in data()["cases"].as_array().unwrap().iter().take(4) {
        let (w, s) = fixture(case);
        let t = trace(&w, &s).unwrap();
        for column in 0..7 {
            let id = case["input"]["matrix_ids"][column].as_str().unwrap();
            let record = &data()["matrix_records"][id];
            compare_sponge(&t, column, record);
            sponges += 6;
            rounds += record["round_states"].as_array().map_or(0, Vec::len);
            let expected = bytes::<1008>(record["stream_hex"].as_str().unwrap());
            for at in [column * 42, column * 42 + 35, column * 42 + 41] {
                let row = t.row_slice(at).unwrap();
                for (byte, v) in expected.iter().enumerate() {
                    assert_eq!(row[XOF + byte], BabyBear::from_u8(*v));
                }
            }
        }
    }
    assert_eq!((sponges, rounds), (168, 288));
}

struct GadgetsOnly;
impl<F> BaseAir<F> for GadgetsOnly {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for GadgetsOnly {
    fn eval(&self, b: &mut AB) {
        use p3_air::WindowAccess;
        let main = b.main();
        let row = main.current_slice();
        for lane in 0..8 {
            mul::eval_mul(
                b,
                &row[PRODUCTS + lane * mul::WIDTH..PRODUCTS + (lane + 1) * mul::WIDTH],
            );
            hints::eval_use_hint(
                b,
                &row[USE_HINT + lane * hints::WIDTH..USE_HINT + (lane + 1) * hints::WIDTH],
            );
        }
        for bit in &row[WRITES..T1_BITS] {
            b.assert_bool(*bit);
        }
        for slot in 0..16 {
            b.assert_eq(
                air::packed::<AB>(&row[WRITES + slot * 46..WRITES + slot * 46 + 23])
                    + air::packed::<AB>(&row[WRITES + slot * 46 + 23..WRITES + (slot + 1) * 46]),
                BabyBear::from_u32(MODULUS - 1),
            );
        }
    }
}
#[test]
fn valid_whole_private_operands_pass_but_restored_source_banks_reject_real_downstream_math() {
    let original = &data()["cases"][0];
    let (w, s) = fixture(original);
    for alternative in hostile()["valid_alternatives"].as_array().unwrap() {
        let changed = from_input(&alternative["input"]);
        let mut t = trace(&changed, &s).unwrap();
        assert!(check(&t, &s));
        let expected = bytes::<128>(alternative["packed_w1_hex"].as_str().unwrap());
        let final_row = t.row_slice(1023).unwrap();
        for (i, b) in expected.iter().enumerate() {
            assert_eq!(final_row[W1 + i], BabyBear::from_u8(*b));
        }
        drop(final_row);
        let (start, values): (usize, Vec<u32>) = match alternative["name"].as_str().unwrap() {
            "whole_zhat_column_change" => (ZHAT + 4 * 256, w.zhat[4].to_vec()),
            "whole_chat_change" => (CHAT, w.chat.to_vec()),
            "whole_hint_change" => (HINTS, w.hints.iter().map(|v| u32::from(*v)).collect()),
            _ => unreachable!(),
        };
        for at in 0..HEIGHT {
            for (i, v) in values.iter().enumerate() {
                t.values[at * WIDTH + start + i] = BabyBear::from_u32(*v);
            }
        }
        assert!(check_all_constraints(&GadgetsOnly, &t, &public_values(&s), Some(1)).is_ok());
        assert!(!check(&t, &s), "{}", alternative["name"]);
    }
}
#[test]
fn genuine_wrong_row_column_or_rho_windows_keep_real_rounds_and_arithmetic_but_reject_binding() {
    let original = &data()["cases"][0];
    let (w, s) = fixture(original);
    for fault in hostile()["faults"].as_array().unwrap().iter().take(3) {
        let mut inputs = Vec::new();
        let mut streams = [[0u8; 1008]; 7];
        for column in 0..7 {
            let id = fault["matrix_columns"][column]["selected_matrix_id"]
                .as_str()
                .unwrap();
            let m = &data()["matrix_records"][id];
            streams[column] = bytes(m["stream_hex"].as_str().unwrap());
            inputs.push(
                m["sponges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|sp| {
                        let state = bytes::<200>(sp["state_absorbed_hex"].as_str().unwrap());
                        core::array::from_fn(|lane| {
                            u64::from_le_bytes(state[lane * 8..lane * 8 + 8].try_into().unwrap())
                        })
                    })
                    .collect(),
            );
        }
        let t = build::trace_with_columns(&w, &s, inputs, streams, false).unwrap();
        assert!(check_all_constraints(&WithoutHash, &t, &public_values(&s), Some(1)).is_ok());
        assert!(check_all_constraints(&GadgetsOnly, &t, &public_values(&s), Some(1)).is_ok());
        assert!(!check(&t, &s));
        let expected = bytes::<128>(fault["packed_w1_hex"].as_str().unwrap());
        let last = t.row_slice(1023).unwrap();
        for (i, b) in expected.iter().enumerate() {
            assert_eq!(last[W1 + i], BabyBear::from_u8(*b));
        }
    }
}
#[test]
fn unused_sixth_block_capacity_fault_keeps_every_row_result_but_rejects_full_join() {
    let h: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../research/reconstructed-row/continuation_faults.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let fault = h["hash_continuation_faults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "unused_sixth_output_block_capacity_change")
        .unwrap();
    let (mut w, _) = fixture(&data()["cases"][0]);
    w.rho = bytes(fault["rho_hex"].as_str().unwrap());
    let s = Statement::new(fault["row"].as_u64().unwrap() as u8, [0x71; 64]).unwrap();
    let honest = trace(&w, &s).unwrap();
    assert!(check(&honest, &s));
    let column = fault["column"].as_u64().unwrap() as usize;
    let expansions: Vec<_> = (0..7).map(|c| build::expansion(&w, &s, c)).collect();
    let mut inputs: Vec<_> = expansions.iter().map(|v| v.0.clone()).collect();
    let mut streams = core::array::from_fn(|c| expansions[c].1);
    inputs[column] = fault["sponge_blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sp| {
            let raw = bytes::<200>(sp["state_absorbed_hex"].as_str().unwrap());
            core::array::from_fn(|lane| {
                u64::from_le_bytes(raw[lane * 8..lane * 8 + 8].try_into().unwrap())
            })
        })
        .collect();
    streams[column] = bytes(fault["stream_hex"].as_str().unwrap());
    assert_eq!(&streams[column][..840], &expansions[column].1[..840]);
    let t = build::trace_with_columns(&w, &s, inputs, streams, false).unwrap();
    let last = t.row_slice(column * 42 + 41).unwrap();
    assert_eq!(count(&last, 8), 256);
    assert!(value(&last, CURSOR + 80, 10) <= 840);
    drop(last);
    for at in 0..HEIGHT {
        let good = honest.row_slice(at).unwrap();
        let bad = t.row_slice(at).unwrap();
        assert_eq!(&good[ACCUMULATOR..COUNT], &bad[ACCUMULATOR..COUNT]);
    }
    assert!(check_all_constraints(&WithoutHash, &t, &public_values(&s), Some(1)).is_ok());
    assert!(check_all_constraints(&GadgetsOnly, &t, &public_values(&s), Some(1)).is_ok());
    assert!(!check(&t, &s));
}

#[test]
fn real_downstream_phase_math_does_not_replace_actual_input_and_transition_bindings() {
    let baseline = &data()["cases"][0];
    let (w, s) = fixture(baseline);
    let expansions: Vec<_> = (0..7).map(|c| build::expansion(&w, &s, c)).collect();
    for model in hostile()["faults"]
        .as_array()
        .unwrap()
        .iter()
        .skip(3)
        .take(9)
    {
        let t = build::replay::raw_trace(
            &w,
            &s,
            expansions.iter().map(|v| v.0.clone()).collect(),
            core::array::from_fn(|c| expansions[c].1),
            false,
            model,
            (false, false),
        )
        .unwrap();
        assert!(
            check_all_constraints(&GadgetsOnly, &t, &public_values(&s), Some(1)).is_ok(),
            "real local operations {}",
            model["name"]
        );
        for (at, start, expected) in [
            (422, WORK, &model["t1_forward"]["output"]),
            (582, ACCUMULATOR, &model["inverse"]["raw_butterfly_output"]),
            (614, ACCUMULATOR, &model["inverse"]["output"]),
        ] {
            let row = t.row_slice(at).unwrap();
            for index in 0..256 {
                assert_eq!(
                    row[start + index].as_canonical_u32(),
                    expected[index].as_u64().unwrap() as u32,
                    "actual downstream bank row{at} cell{index} {}",
                    model["name"]
                );
            }
        }
        let expected = bytes::<128>(model["packed_w1_hex"].as_str().unwrap());
        let last = t.row_slice(1023).unwrap();
        for (i, b) in expected.iter().enumerate() {
            assert_eq!(
                last[W1 + i],
                BabyBear::from_u8(*b),
                "independent downstream bytes {}",
                model["name"]
            );
        }
        assert!(
            !check(&t, &s),
            "actual phase and private source {}",
            model["name"]
        );
    }
    for (wrong_twiddle, skip_normalize) in [(true, false), (false, true)] {
        let t = build::replay::raw_trace(
            &w,
            &s,
            expansions.iter().map(|v| v.0.clone()).collect(),
            core::array::from_fn(|c| expansions[c].1),
            false,
            baseline,
            (wrong_twiddle, skip_normalize),
        )
        .unwrap();
        assert!(check_all_constraints(&GadgetsOnly, &t, &public_values(&s), Some(1)).is_ok());
        assert!(
            !check(&t, &s),
            "fixed twiddle and inverse normalization operands"
        );
    }
}

#[test]
fn canonical_wrong_butterfly_route_and_reversed_nibble_packing_reject() {
    let baseline = &data()["cases"][0];
    let (w, s) = fixture(baseline);
    let original = trace(&w, &s).unwrap();
    let mut wrong = original.clone();
    let at = 294;
    let start = at * WIDTH + WRITES;
    let left = wrong.values[start..start + 46].to_vec();
    let right = wrong.values[start + 46..start + 92].to_vec();
    wrong.values[start..start + 46].copy_from_slice(&right);
    wrong.values[start + 46..start + 92].copy_from_slice(&left);
    let destinations = program::instructions()[at].butterflies[0];
    wrong.values[(at + 1) * WIDTH + WORK + destinations.0] =
        original.values[(at + 1) * WIDTH + WORK + destinations.1];
    wrong.values[(at + 1) * WIDTH + WORK + destinations.1] =
        original.values[(at + 1) * WIDTH + WORK + destinations.0];
    assert!(check_all_constraints(&GadgetsOnly, &wrong, &public_values(&s), Some(1)).is_ok());
    assert!(!check(&wrong, &s));
    let model = hostile()["faults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "packing_adjacent_nibbles_reversed")
        .unwrap();
    let reversed = bytes::<128>(model["supplied_packed_hex"].as_str().unwrap());
    let mut wrong = original.clone();
    for (byte, v) in reversed.iter().enumerate() {
        for at in 615 + byte / 4..HEIGHT {
            wrong.values[at * WIDTH + W1 + byte] = BabyBear::from_u8(*v);
        }
    }
    assert!(check_all_constraints(&GadgetsOnly, &wrong, &public_values(&s), Some(1)).is_ok());
    assert!(!check(&wrong, &s));
}

#[test]
fn public_row_is_bound_but_opaque_context_is_not_an_authorization_message() {
    let (w, s) = fixture(&data()["cases"][0]);
    let t = trace(&w, &s).unwrap();
    let mut pv = public_values(&s);
    for value in &mut pv[1..] {
        *value += BabyBear::ONE;
    }
    assert!(check_all_constraints(&ReconstructedRowAir::default(), &t, &pv, Some(1)).is_ok());
    pv[0] = BabyBear::from_u8(8);
    assert!(!check_all_constraints(&ReconstructedRowAir::default(), &t, &pv, Some(1)).is_ok());
}
