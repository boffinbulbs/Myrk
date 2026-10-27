use super::*;
use air::*;
use p3_air::{
    check_all_constraints,
    symbolic::{AirLayout, get_max_constraint_degree},
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

fn synthetic() -> Witness {
    Witness::from_keys(core::array::from_fn(|slot| {
        core::array::from_fn(|i| ((i * 17 + slot * 43 + 7) % 256) as u8)
    }))
}
fn check(t: &RowMajorMatrix<BabyBear>) -> bool {
    check_all_constraints(
        &KeySlotsAir,
        t,
        &public_values(&Statement::new([0x61; 64])),
        Some(1),
    )
    .is_ok()
}
#[test]
fn actual_layout_degree_and_complete_key_window_coverage() {
    assert_eq!((HEIGHT, WIDTH, PUBLIC_VALUES), (1024, 20168, 64));
    assert_eq!(
        [
            HASH_PC, KEY, MESSAGE, OUTPUT, RHO, OWNER, TR, T1, T1_PC, T1_MESSAGE
        ],
        [
            10532, 10647, 13239, 14327, 15415, 15479, 15607, 15735, 19831, 20088
        ]
    );
    let degree = get_max_constraint_degree::<BabyBear, _>(
        &KeySlotsAir,
        AirLayout {
            main_width: WIDTH,
            num_public_values: PUBLIC_VALUES,
            ..Default::default()
        },
        HEIGHT,
    );
    println!("actual four-round key segment degree {degree}");
    assert_eq!(degree, 4);
    for slot in 0..2 {
        let mut owner_reads = [0u8; KEY_BYTES];
        let mut tr_reads = [0u8; KEY_BYTES];
        for stage in slot * 57..slot * 57 + 57 {
            for byte in 0..136 {
                if let Some(at) = source_byte(stage, byte) {
                    if stage % 57 < 37 {
                        owner_reads[at] += 1;
                    } else {
                        tr_reads[at] += 1;
                    }
                }
            }
        }
        assert!(owner_reads.iter().chain(&tr_reads).all(|n| *n == 1));
    }
}
#[test]
fn both_private_sources_hashes_decoding_and_reuse_pass_the_actual_air() {
    let w = synthetic();
    let t = trace(&w);
    let report = check_all_constraints(
        &KeySlotsAir,
        &t,
        &public_values(&Statement::new([0x61; 64])),
        Some(8),
    );
    assert!(report.is_ok(), "{report:?}");
    let first = t.row_slice(0).unwrap();
    assert!(first[RHO..T1_PC].iter().all(|x| *x == BabyBear::ZERO));
    for slot in 0..2 {
        let start = slot * 342;
        let snapshot = t.row_slice(start + 1).unwrap();
        for byte in 0..32 {
            assert_eq!(
                snapshot[RHO + slot * 32 + byte],
                BabyBear::from_u8(w.keys[slot][byte])
            );
        }
        let complete = t.row_slice(start + 256).unwrap();
        for i in 0..2048 {
            assert!(complete[T1 + slot * 2048 + i].as_canonical_u32() <= 1023);
        }
    }
}
#[test]
fn partial_source_splices_early_late_reload_and_retained_output_resets_reject() {
    let w = synthetic();
    let original = trace(&w);
    assert!(check(&original));
    for (at, column) in [
        (222, KEY),
        (341, KEY),
        (343, KEY),
        (342, RHO),
        (684, TR),
        (598, T1 + 2048 + 2047),
    ] {
        let mut changed = original.clone();
        for row in at..HEIGHT {
            changed.values[row * WIDTH + column] += BabyBear::ONE;
        }
        assert!(!check(&changed), "{at}/{column}");
    }
    for (at, pc) in [(341, T1_PC + 256), (342, T1_PC), (683, HASH_PC + 113)] {
        let mut changed = original.clone();
        changed.values[at * WIDTH + pc] += BabyBear::ONE;
        assert!(!check(&changed));
    }
}

fn independent() -> &'static serde_json::Value {
    static DATA: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../research/key-source/vectors.json"
        )))
        .unwrap()
    })
}
fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}
fn fixture(case: &serde_json::Value) -> Witness {
    Witness::from_keys(core::array::from_fn(|slot| {
        bytes(case["keys_hex"][slot].as_str().unwrap())
    }))
}
fn assert_outputs(row: &[BabyBear], case: &serde_json::Value, slot: usize) {
    for (bank, field, size) in [
        (RHO, "rho_hex", 32),
        (OWNER, "owner_hex", 64),
        (TR, "tr_hex", 64),
    ] {
        let text = case[field][slot].as_str().unwrap();
        for byte in 0..size {
            let expected = u8::from_str_radix(&text[byte * 2..byte * 2 + 2], 16).unwrap();
            assert_eq!(row[bank + slot * size + byte], BabyBear::from_u8(expected));
        }
    }
    for i in 0..2048 {
        assert_eq!(
            row[T1 + slot * 2048 + i].as_canonical_u32(),
            case["t1"][slot][i / 256][i % 256].as_u64().unwrap() as u32
        );
    }
}
#[test]
fn every_independent_pair_and_every_private_output_matches_full_hash_and_decode_oracles() {
    let d = independent();
    assert_eq!(d["cases"].as_array().unwrap().len(), 14);
    for case in d["cases"].as_array().unwrap() {
        assert_eq!(case["valid_key_encoding_relation"], true);
        assert_eq!(case["full_authorization_claim"], false);
        let w = fixture(case);
        let t = trace(&w);
        assert!(check(&t), "{}", case["name"]);
        let final_row = t.row_slice(HEIGHT - 1).unwrap();
        for slot in 0..2 {
            assert_outputs(&final_row, case, slot);
            let available = t.row_slice(slot * 342 + 342).unwrap();
            assert_outputs(&available, case, slot);
            let before = t.row_slice(slot * 342).unwrap();
            assert!(
                before[RHO + slot * 32..RHO + (slot + 1) * 32]
                    .iter()
                    .all(|x| *x == BabyBear::ZERO)
            );
            let owner_before = t.row_slice(slot * 342 + 221).unwrap();
            assert!(
                owner_before[OWNER + slot * 64..OWNER + (slot + 1) * 64]
                    .iter()
                    .all(|x| *x == BabyBear::ZERO)
            );
            let tr_before = t.row_slice(slot * 342 + 341).unwrap();
            assert!(
                tr_before[TR + slot * 64..TR + (slot + 1) * 64]
                    .iter()
                    .all(|x| *x == BabyBear::ZERO)
            );
            let decoded = t.row_slice(slot * 342 + 256).unwrap();
            assert_eq!(
                &decoded[T1 + slot * 2048..T1 + (slot + 1) * 2048],
                &final_row[T1 + slot * 2048..T1 + (slot + 1) * 2048]
            );
        }
    }
}

#[test]
fn independent_full_round_states_all_rates_padding_and_four_slot_locations_match() {
    use core::borrow::Borrow;
    use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
    let d = independent();
    let dummy: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../research/key-source/dummy_rounds.json"
    )))
    .unwrap();
    let zeros_before: Vec<[u8; 200]> = dummy["rounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| bytes(r["round_before_hex"].as_str().unwrap()))
        .collect();
    let zeros_after: Vec<[u8; 200]> = dummy["rounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| bytes(r["state_hex"].as_str().unwrap()))
        .collect();
    let mut meaningful = 0usize;
    let mut padding = 0usize;
    for case in d["cases"].as_array().unwrap() {
        let w = fixture(case);
        let t = trace(&w);
        let recs: [&serde_json::Value; 2] =
            core::array::from_fn(|slot| &d["key_records"][case["key_ids"][slot].as_str().unwrap()]);
        let records: Vec<([u8; 200], [u8; 200], [u8; 200])> = (0..2736)
            .map(|logical| {
                let r = &recs[logical / 1368]["rounds"][logical % 1368];
                assert_eq!(r["logical_round_in_key"], logical % 1368);
                assert_eq!(r["physical_row_in_key"], (logical % 1368) / 4);
                assert_eq!(r["slot"], logical % 4);
                (
                    bytes(r["preimage_hex"].as_str().unwrap()),
                    bytes(r["round_before_hex"].as_str().unwrap()),
                    bytes(r["state_hex"].as_str().unwrap()),
                )
            })
            .collect();
        for logical in 0..LOGICAL_HEIGHT {
            let row = t.row_slice(logical / 4).unwrap();
            let start = (logical % 4) * NUM_KECCAK_COLS;
            let k: &KeccakCols<BabyBear> = row[start..start + NUM_KECCAK_COLS].borrow();
            let (pre, before, after) = if logical < 2736 {
                meaningful += 1;
                records[logical]
            } else {
                padding += 1;
                (
                    [0u8; 200],
                    zeros_before[logical % 24],
                    zeros_after[logical % 24],
                )
            };
            for limb in 0..100 {
                let y = limb / 20;
                let x = (limb / 4) % 5;
                let l = limb % 4;
                let get =
                    |s: &[u8; 200]| u32::from(u16::from_le_bytes([s[2 * limb], s[2 * limb + 1]]));
                assert_eq!(k.preimage[y][x][l].as_canonical_u32(), get(&pre));
                assert_eq!(k.a[y][x][l].as_canonical_u32(), get(&before));
                assert_eq!(
                    k.a_prime_prime_prime(y, x, l).as_canonical_u32(),
                    get(&after)
                );
            }
            for flag in 0..24 {
                assert_eq!(
                    k.step_flags[flag],
                    BabyBear::from_bool(flag == logical % 24)
                );
            }
        }
        for stage in 0..114 {
            let record = &recs[stage / 57]["sponges"][stage % 57];
            let source = record["input_hex"].as_str().unwrap();
            let rate = record["rate"].as_u64().unwrap() as usize;
            assert_eq!(source.len(), rate * 2);
            for at in [stage * 6, stage * 6 + 5] {
                let row = t.row_slice(at).unwrap();
                for byte in 0..136 {
                    let actual = (0..8)
                        .map(|bit| row[MESSAGE + byte * 8 + bit].as_canonical_u32() << bit)
                        .sum::<u32>();
                    let expected = if byte < rate {
                        u32::from(u8::from_str_radix(&source[byte * 2..byte * 2 + 2], 16).unwrap())
                    } else {
                        0
                    };
                    assert_eq!(actual, expected);
                }
            }
        }
    }
    assert_eq!((meaningful, padding), (14 * 2736, 14 * (4096 - 2736)));
}

#[test]
fn locally_rebuilt_wrong_key_hashes_and_canonical_cross_boundary_decodes_reject() {
    let case = &independent()["cases"][0];
    let w = fixture(case);
    let original = trace(&w);
    let swapped = Witness::from_keys([w.keys[1], w.keys[0]]);
    assert!(
        check(&trace(&swapped)),
        "complete private witness permutation stays valid"
    );
    let good_inputs = inputs(&w);
    let wrong_inputs = inputs(&swapped);
    for (start, end) in [(0, 37), (37, 57)] {
        let mut injected = good_inputs.clone();
        injected[start..end].copy_from_slice(&wrong_inputs[start..end]);
        let changed = trace_with_inputs(&w, injected);
        assert!(!check(&changed), "honest alternate hash source {start}");
    }
    let mut wrong_window = original.clone();
    let event = 255;
    let source = &w.keys[1][32 + event * 10..32 + event * 10 + 10];
    assert_ne!(source, &w.keys[0][2582..]);
    for (byte, value) in source.iter().enumerate() {
        for bit in 0..8 {
            wrong_window.values[event * WIDTH + T1_MESSAGE + byte * 8 + bit] =
                BabyBear::from_bool((value >> bit) & 1 != 0);
        }
    }
    let values: [u32; 8] = core::array::from_fn(|i| {
        let mut block = [0u8; 8];
        block[..5].copy_from_slice(&source[(i / 4) * 5..(i / 4) * 5 + 5]);
        ((u64::from_le_bytes(block) >> ((i % 4) * 10)) & 1023) as u32
    });
    for at in event + 1..HEIGHT {
        for (i, value) in values.iter().enumerate() {
            wrong_window.values[at * WIDTH + T1 + event * 8 + i] = BabyBear::from_u32(*value);
        }
    }
    assert!(
        !check(&wrong_window),
        "canonical last window straddles tr block18/19 but must use original source"
    );
    let mut redirected = original.clone();
    for at in 222..HEIGHT {
        for byte in 0..64 {
            redirected.values[at * WIDTH + OWNER + byte] = BabyBear::ZERO;
            if at < 564 {
                redirected.values[at * WIDTH + OWNER + 64 + byte] =
                    original.values[at * WIDTH + OWNER + byte];
            }
        }
    }
    assert!(
        !check(&redirected),
        "producer cannot write another retained slot"
    );
}

struct KeccakOnly;
impl<F> p3_air::BaseAir<F> for KeccakOnly {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: p3_air::AirBuilder<F = BabyBear>> p3_air::Air<AB> for KeccakOnly {
    fn eval(&self, builder: &mut AB) {
        crate::key_source::keccak::eval(builder);
    }
}
#[test]
fn fully_recomputed_independent_hash_faults_keep_real_rounds_and_digest_but_reject_source_or_absorption()
 {
    let h: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../research/key-source/hostile_cases.json"
    )))
    .unwrap();
    let d = independent();
    let case = d["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == h["baseline_pair"])
        .unwrap();
    let w = fixture(case);
    let good_inputs = inputs(&w);
    assert_eq!(h["hash_faults"].as_array().unwrap().len(), 8);
    for fault in h["hash_faults"].as_array().unwrap() {
        let slot = case["key_ids"]
            .as_array()
            .unwrap()
            .iter()
            .position(|id| id == &fault["key_id"])
            .unwrap();
        let owner = fault["kind"] == "owner";
        let start = slot * 57 + if owner { 0 } else { 37 };
        let states = fault["sponges"].as_array().unwrap();
        assert_eq!(states.len(), if owner { 37 } else { 20 });
        let mut injected = good_inputs.clone();
        for (block, state) in states.iter().enumerate() {
            let raw = bytes::<200>(state["state_absorbed_hex"].as_str().unwrap());
            injected[start + block] = core::array::from_fn(|lane| {
                u64::from_le_bytes(raw[lane * 8..lane * 8 + 8].try_into().unwrap())
            });
        }
        let t = trace_with_inputs(&w, injected);
        let expected = bytes::<64>(fault["supplied_digest_hex"].as_str().unwrap());
        let final_row = t.row_slice(HEIGHT - 1).unwrap();
        let bank = if owner { OWNER } else { TR };
        for byte in 0..64 {
            assert_eq!(
                final_row[bank + slot * 64 + byte],
                BabyBear::from_u8(expected[byte])
            );
        }
        assert!(
            check_all_constraints(
                &KeccakOnly,
                &t,
                &public_values(&Statement::new([0x61; 64])),
                Some(1)
            )
            .is_ok(),
            "locally real permutations {}",
            fault["name"]
        );
        assert!(
            !check(&t),
            "full held source and XOR absorption {}",
            fault["name"]
        );
    }
}

#[test]
fn per_byte_sources_reject_carry_aliases_and_noncanonical_t1_outputs() {
    let w = synthetic();
    let original = trace(&w);
    let mut alias = original.clone();
    for at in 0..342 {
        alias.values[at * WIDTH + KEY] += BabyBear::from_u32(256);
        alias.values[at * WIDTH + KEY + 1] -= BabyBear::ONE;
    }
    let public = public_values(&Statement::new([0x61; 64]));
    assert!(check_all_constraints(&KeccakOnly, &alias, &public, Some(1)).is_ok());
    assert!(
        !check(&alias),
        "a carry alias cannot replace two exact byte bindings"
    );

    let mut noncanonical = original.clone();
    for at in 1..HEIGHT {
        noncanonical.values[at * WIDTH + T1] = BabyBear::from_u32(1024);
    }
    assert!(check_all_constraints(&KeccakOnly, &noncanonical, &public, Some(1)).is_ok());
    assert!(
        !check(&noncanonical),
        "a retained t1 coefficient must be its ten-bit decode"
    );
}
