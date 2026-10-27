use super::*;
use crate::key_source::air::*;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

struct KeccakOnly;
impl<F> BaseAir<F> for KeccakOnly {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for KeccakOnly {
    fn eval(&self, builder: &mut AB) {
        crate::key_source::keccak::eval(builder);
    }
}

fn reject_raw(t: RowMajorMatrix<BabyBear>, statement: &Statement, name: &str) {
    assert!(!trace_is_valid(&t, statement), "false trace {name}");
    let proof = prove(
        &prover_config().unwrap(),
        &KeySlotsAir,
        t,
        &public_values(statement),
    )
    .unwrap();
    assert!(
        verify(
            &verifier_config(),
            &KeySlotsAir,
            &proof,
            &public_values(statement)
        )
        .is_err(),
        "backend {name}"
    );
    let encoded = serde_json::to_vec(&proof).unwrap();
    json_preflight(&encoded).unwrap();
    validate_shape(&proof).unwrap();
    assert_eq!(
        verify_key_slots(&encoded, statement),
        Err(Error::InvalidProof),
        "wrapper {name}"
    );
    println!("raw false proof rejected by backend and wrapper: {name}");
}

#[test]
fn fifteen_raw_key_source_proofs_reject() {
    let w = fixture();
    let statement = Statement::new([0x61; 64]);
    let good_inputs = inputs(&w);
    let h: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../research/key-source/hostile_cases.json"
    )))
    .unwrap();
    let mut rejected = Vec::new();
    for fault in h["hash_faults"].as_array().unwrap() {
        let slot = match fault["key_id"].as_str().unwrap() {
            "retained_a" => 0,
            "retained_b" => 1,
            _ => unreachable!(),
        };
        let owner = fault["kind"] == "owner";
        let start = slot * 57 + if owner { 0 } else { 37 };
        let mut injected = good_inputs.clone();
        let states = fault["sponges"].as_array().unwrap();
        assert_eq!(states.len(), if owner { 37 } else { 20 });
        for (offset, state) in states.iter().enumerate() {
            let raw = bytes::<200>(state["state_absorbed_hex"].as_str().unwrap());
            injected[start + offset] = core::array::from_fn(|i| {
                u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap())
            });
        }
        let t = trace_with_inputs(&w, injected);
        assert!(
            check_all_constraints(&KeccakOnly, &t, &public_values(&statement), Some(1)).is_ok()
        );
        let bank = if owner { OWNER } else { TR };
        let digest = bytes::<64>(fault["supplied_digest_hex"].as_str().unwrap());
        let last = t.row_slice(HEIGHT - 1).unwrap();
        for i in 0..64 {
            assert_eq!(last[bank + slot * 64 + i], BabyBear::from_u8(digest[i]));
        }
        drop(last);
        let name = fault["name"].as_str().unwrap();
        reject_raw(t, &statement, name);
        rejected.push(name.to_owned());
    }
    let swapped = Witness::from_keys([w.keys[1], w.keys[0]]);
    let wrong_inputs = inputs(&swapped);
    for (name, start, end) in [
        ("alternate_real_owner_source", 0, 37),
        ("alternate_real_tr_source", 37, 57),
    ] {
        let mut injected = good_inputs.clone();
        injected[start..end].copy_from_slice(&wrong_inputs[start..end]);
        let t = trace_with_inputs(&w, injected);
        assert!(
            check_all_constraints(&KeccakOnly, &t, &public_values(&statement), Some(1)).is_ok()
        );
        reject_raw(t, &statement, name);
        rejected.push(name.to_owned());
    }
    for variant in 0..5 {
        let mut t = trace(&w);
        let name = match variant {
            0 => {
                let source = &w.keys[1][2582..];
                let event = 255;
                for (i, v) in source.iter().enumerate() {
                    for bit in 0..8 {
                        t.values[event * WIDTH + T1_MESSAGE + i * 8 + bit] =
                            BabyBear::from_bool((v >> bit) & 1 != 0);
                    }
                }
                for i in 0..8 {
                    let mut raw = [0u8; 8];
                    raw[..5].copy_from_slice(&source[i / 4 * 5..i / 4 * 5 + 5]);
                    let value = ((u64::from_le_bytes(raw) >> (i % 4 * 10)) & 1023) as u32;
                    for at in 256..HEIGHT {
                        t.values[at * WIDTH + T1 + 2040 + i] = BabyBear::from_u32(value);
                    }
                }
                "canonical_t1_window_from_other_key"
            }
            1 => {
                for at in 1..HEIGHT {
                    t.values[at * WIDTH + RHO] = BabyBear::from_u8(w.keys[1][0]);
                }
                "retained_rho_from_other_key"
            }
            2 => {
                for at in 222..HEIGHT {
                    t.values[at * WIDTH + OWNER] += BabyBear::ONE;
                }
                "retained_owner_changed_after_producer"
            }
            3 => {
                for at in 0..342 {
                    t.values[at * WIDTH + KEY] += BabyBear::from_u16(256);
                    t.values[at * WIDTH + KEY + 1] -= BabyBear::ONE;
                }
                "per_byte_carry_alias_in_key_bank"
            }
            4 => {
                for at in 1..HEIGHT {
                    t.values[at * WIDTH + T1] = BabyBear::from_u16(1024);
                }
                "noncanonical_t1_output_1024"
            }
            _ => unreachable!(),
        };
        reject_raw(t, &statement, name);
        rejected.push(name.to_owned());
    }
    assert_eq!(rejected.len(), 15);
}
