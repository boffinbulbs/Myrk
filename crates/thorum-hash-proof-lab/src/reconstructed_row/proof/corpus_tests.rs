// Conditional row proof controls with independent data and local math checks.
// Raw phase witnesses use the same constrained products and coefficient rules.
use super::*;
use crate::reconstructed_row::air::*;
use crate::reconstructed_row::{arithmetic, build, control, hints, keccak, mul, program, row_hash};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, check_all_constraints};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use p3_uni_stark::StarkGenericConfig;
use serde_json::Value;

fn data() -> &'static Value {
    static DATA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| read_json("vectors.json"))
}
fn hostile() -> &'static Value {
    static DATA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| read_json("hostile_cases.json"))
}
fn read_json(relative: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/reconstructed-row")
        .join(relative);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn from_input(input: &Value) -> Witness {
    Witness::from_inputs(
        bytes(input["rho_hex"].as_str().unwrap()),
        core::array::from_fn(|c| {
            core::array::from_fn(|i| input["zhat"][c][i].as_u64().unwrap() as u32)
        }),
        core::array::from_fn(|i| input["t1"][i].as_u64().unwrap() as u16),
        core::array::from_fn(|i| input["chat"][i].as_u64().unwrap() as u32),
        core::array::from_fn(|i| input["hint"][i].as_u64().unwrap() as u8),
    )
}
fn states(sponges: &Value) -> Vec<[u64; 25]> {
    sponges
        .as_array()
        .unwrap()
        .iter()
        .map(|sp| {
            let raw = bytes::<200>(sp["state_absorbed_hex"].as_str().unwrap());
            core::array::from_fn(|i| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap()))
        })
        .collect()
}

// These are local mathematical positive controls, never verifier alternatives.
#[derive(Clone, Copy)]
enum Diagnostic {
    WithoutSpongeBinding,
    WithoutSpongeBindingOrXofLifetime,
    LocalGadgetsStateAndCanonicalCounts,
    LocalGadgets,
}
impl<F> BaseAir<F> for Diagnostic {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
fn local_gadgets<AB: AirBuilder<F = BabyBear>>(b: &mut AB) {
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
            BabyBear::from_u32(crate::reconstructed_row::MODULUS - 1),
        );
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for Diagnostic {
    fn eval(&self, b: &mut AB) {
        match self {
            Self::WithoutSpongeBinding | Self::WithoutSpongeBindingOrXofLifetime => {
                keccak::eval(b);
                air::eval_state(b);
                if matches!(self, Self::WithoutSpongeBinding) {
                    row_hash::eval_lifetime(b);
                }
                control::eval(b);
                arithmetic::eval(&ReconstructedRowAir::default(), b);
            }
            Self::LocalGadgetsStateAndCanonicalCounts => {
                keccak::eval(b);
                air::eval_state(b);
                local_gadgets(b);
                let main = b.main();
                let row = main.current_slice();
                for lane in 0..9 {
                    let mut sum = AB::Expr::ZERO;
                    for bit in &row[COUNT + lane * 257..COUNT + (lane + 1) * 257] {
                        b.assert_bool(*bit);
                        sum += (*bit).into();
                    }
                    b.assert_one(sum);
                }
            }
            Self::LocalGadgets => local_gadgets(b),
        }
    }
}
fn positive(t: &RowMajorMatrix<BabyBear>, s: &Statement, diagnostic: Diagnostic) {
    assert!(check_all_constraints(&diagnostic, t, &public_values(s), Some(1)).is_ok());
}
fn bank(t: &RowMajorMatrix<BabyBear>, at: usize, start: usize, expected: &Value) {
    let row = t.row_slice(at).unwrap();
    assert_eq!(expected.as_array().unwrap().len(), 256);
    for i in 0..256 {
        assert!(
            row[start + i].as_canonical_u32() == expected[i].as_u64().unwrap() as u32,
            "Independent bank mismatch at row{at} cell{i}"
        );
    }
}
fn output(t: &RowMajorMatrix<BabyBear>, model: &Value) {
    let expected = bytes::<128>(model["packed_w1_hex"].as_str().unwrap());
    let last = t.row_slice(HEIGHT - 1).unwrap();
    for (i, v) in expected.iter().enumerate() {
        assert!(
            last[W1 + i] == BabyBear::from_u8(*v),
            "Independent packed output mismatch at byte{i}"
        );
    }
}
fn phase_banks(t: &RowMajorMatrix<BabyBear>, model: &Value) {
    bank(t, 422, WORK, &model["t1_forward"]["output"]);
    bank(
        t,
        582,
        ACCUMULATOR,
        &model["inverse"]["raw_butterfly_output"],
    );
    bank(t, 614, ACCUMULATOR, &model["inverse"]["output"]);
    output(t, model);
}

const RAW_NAMES: [&str; 16] = [
    "R01_wrong_public_row_hash_window",
    "R02_other_rho_hash_window",
    "R03_unused_sixth_block_capacity",
    "R04_early_xof_reload",
    "R05_canonical_false_c8_completion",
    "R06_zhat_consumer_source",
    "R07_chat_consumer_source",
    "R08_hint_consumer_source",
    "R09_unshifted_t1_input",
    "R10_bit_reversed_t1hat_read",
    "R11_other_inverse_input",
    "R12_hint_before_normalization",
    "R13_skipped_inverse_normalization",
    "R14_canonical_butterfly_output_permutation",
    "R15_reversed_private_nibble_packing",
    "R16_late_private_output_hold",
];
const POSITIVE_SCOPES: [&str; 16] = [
    "Real Keccak, state, XOF lifetime, control and arithmetic; independent final bytes",
    "Real Keccak, state, XOF lifetime, control and arithmetic; independent final bytes",
    "Real Keccak and complete nonhash relation; every semantic bank matches honest trace",
    "Keccak/state/control/arithmetic only; sponge binding AND XOF lifetime are omitted",
    "Keccak/state/local gadgets and canonical counts only; both count recurrence and completion are false",
    "Whole private alternative first accepted; actual gadgets remain valid after source restoration",
    "Whole private alternative first accepted; actual gadgets remain valid after source restoration",
    "Whole private alternative first accepted; actual gadgets remain valid after source restoration",
    "Real local gadgets and independent forward/raw inverse/normalized inverse/output banks",
    "Real local gadgets and independent forward/raw inverse/normalized inverse/output banks",
    "Real local gadgets and independent forward/raw inverse/normalized inverse/output banks",
    "Real local gadgets and independent forward/raw inverse/normalized inverse/output banks",
    "Real local products with factor one; later hint source can also be false",
    "Real local gadgets and canonical outputs; multiple output/routing joins can be false",
    "Real local gadgets, canonical reversed packed bytes; producer binding is false",
    "Complete nonhash relation except output holds is not asserted; local gadgets unchanged",
];

// Construct one wide trace at a time and establish its real positive subrelation.
// A fully changed conditional witness is never a negative by itself.
fn raw_case(index: usize) -> (RowMajorMatrix<BabyBear>, Statement) {
    let baseline = &data()["cases"][0];
    let (w, s) = fixture();
    let mut t = match index {
        0 | 1 => {
            let model = &hostile()["faults"][if index == 0 { 0 } else { 2 }];
            let records: Vec<_> = (0..7)
                .map(|c| {
                    let id = model["matrix_columns"][c]["selected_matrix_id"]
                        .as_str()
                        .unwrap();
                    &data()["matrix_records"][id]
                })
                .collect();
            let inputs = records.iter().map(|m| states(&m["sponges"])).collect();
            let streams =
                core::array::from_fn(|c| bytes(records[c]["stream_hex"].as_str().unwrap()));
            let t = build::trace_with_columns(&w, &s, inputs, streams, false).unwrap();
            positive(&t, &s, Diagnostic::WithoutSpongeBinding);
            output(&t, model);
            t
        }
        2 => {
            let h = read_json("continuation_faults.json");
            let fault = h["hash_continuation_faults"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["name"] == "unused_sixth_output_block_capacity_change")
                .unwrap();
            let mut w = from_input(&baseline["input"]);
            w.rho = bytes(fault["rho_hex"].as_str().unwrap());
            assert_eq!(fault["row"], 0);
            assert_eq!(fault["column"], 0);
            let expansions: Vec<_> = (0..7).map(|c| build::expansion(&w, &s, c)).collect();
            let mut inputs: Vec<_> = expansions.iter().map(|v| v.0.clone()).collect();
            let mut streams = core::array::from_fn(|c| expansions[c].1);
            inputs[0] = states(&fault["sponge_blocks"]);
            streams[0] = bytes(fault["stream_hex"].as_str().unwrap());
            assert!(
                streams[0][..840] == expansions[0].1[..840],
                "R03 consumed stream prefix differs"
            );
            let t = build::trace_with_columns(&w, &s, inputs, streams, false).unwrap();
            {
                let honest = crate::reconstructed_row::trace(&w, &s).unwrap();
                assert!(trace_is_valid(&honest, &s));
                for at in 0..HEIGHT {
                    let a = honest.row_slice(at).unwrap();
                    let b = t.row_slice(at).unwrap();
                    assert!(
                        a[ACCUMULATOR..COUNT] == b[ACCUMULATOR..COUNT],
                        "R03 semantic banks differ at row{at}"
                    );
                }
            }
            positive(&t, &s, Diagnostic::WithoutSpongeBinding);
            t
        }
        5..=7 => {
            let model = &hostile()["valid_alternatives"][index - 5];
            assert_eq!(
                model["name"],
                [
                    "whole_zhat_column_change",
                    "whole_chat_change",
                    "whole_hint_change"
                ][index - 5]
            );
            let changed = from_input(&model["input"]);
            let mut t = crate::reconstructed_row::trace(&changed, &s).unwrap();
            assert!(trace_is_valid(&t, &s));
            output(&t, model);
            let (start, values): (usize, Vec<u32>) = match index {
                5 => (ZHAT + 4 * 256, w.zhat[4].to_vec()),
                6 => (CHAT, w.chat.to_vec()),
                7 => (HINTS, w.hints.iter().map(|v| u32::from(*v)).collect()),
                _ => unreachable!(),
            };
            for at in 0..HEIGHT {
                for (i, v) in values.iter().enumerate() {
                    t.values[at * WIDTH + start + i] = BabyBear::from_u32(*v);
                }
            }
            t
        }
        8..=12 => {
            let name = match index {
                8 => "forward_t1_without_8192_shift",
                9 => "t1hat_consumer_bit_reversal",
                10 => "inverse_from_other_row_subtraction",
                11 => "hint_before_inverse_normalization",
                12 => "",
                _ => unreachable!(),
            };
            let model = if index == 12 {
                baseline
            } else {
                hostile()["faults"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|m| m["name"] == name)
                    .unwrap()
            };
            let expansions: Vec<_> = (0..7).map(|c| build::expansion(&w, &s, c)).collect();
            let t = build::replay::raw_trace(
                &w,
                &s,
                expansions.iter().map(|v| v.0.clone()).collect(),
                core::array::from_fn(|c| expansions[c].1),
                false,
                model,
                (false, index == 12),
            )
            .unwrap();
            if index == 12 {
                bank(&t, 422, WORK, &baseline["t1_forward"]["output"]);
                bank(
                    &t,
                    582,
                    ACCUMULATOR,
                    &baseline["inverse"]["raw_butterfly_output"],
                );
                bank(
                    &t,
                    614,
                    ACCUMULATOR,
                    &baseline["inverse"]["raw_butterfly_output"],
                );
            } else {
                phase_banks(&t, model);
            }
            t
        }
        _ => crate::reconstructed_row::trace(&w, &s).unwrap(),
    };
    match index {
        3 => {
            let next = build::expansion(&w, &s, 1).1;
            for (i, v) in next.iter().enumerate() {
                t.values[41 * WIDTH + XOF + i] = BabyBear::from_u8(*v);
            }
            assert_eq!(t.values[41 * WIDTH + COUNT + 256], BabyBear::ONE);
            positive(&t, &s, Diagnostic::WithoutSpongeBindingOrXofLifetime);
        }
        4 => {
            assert_eq!(t.values[41 * WIDTH + COUNT + 8 * 257 + 256], BabyBear::ONE);
            t.values[41 * WIDTH + COUNT + 8 * 257 + 256] = BabyBear::ZERO;
            t.values[41 * WIDTH + COUNT + 8 * 257 + 255] = BabyBear::ONE;
            positive(&t, &s, Diagnostic::LocalGadgetsStateAndCanonicalCounts);
        }
        13 => {
            for i in 0..46 {
                t.values
                    .swap(294 * WIDTH + WRITES + i, 294 * WIDTH + WRITES + 46 + i);
            }
            let (a, b, _) = program::instructions()[294].butterflies[0];
            t.values
                .swap(295 * WIDTH + WORK + a, 295 * WIDTH + WORK + b);
        }
        14 => {
            let model = hostile()["faults"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["name"] == "packing_adjacent_nibbles_reversed")
                .unwrap();
            let reversed = bytes::<128>(model["supplied_packed_hex"].as_str().unwrap());
            for (byte, v) in reversed.iter().enumerate() {
                for at in 615 + byte / 4..HEIGHT {
                    t.values[at * WIDTH + W1 + byte] = BabyBear::from_u8(*v);
                }
            }
        }
        15 => {
            let value = t.values[699 * WIDTH + W1 + 127].as_canonical_u32() ^ 1;
            assert!(value < 256);
            for at in 700..HEIGHT {
                t.values[at * WIDTH + W1 + 127] = BabyBear::from_u32(value);
            }
        }
        _ => {}
    }
    positive(&t, &s, Diagnostic::LocalGadgets);
    assert!(!trace_is_valid(&t, &s), "{}", RAW_NAMES[index]);
    (t, s)
}

#[test]
fn sixteen_raw_cases_pass_local_math_and_fail_actual_row_without_proving() {
    for (i, name) in RAW_NAMES.iter().enumerate() {
        let (t, _) = raw_case(i);
        assert_eq!((t.height(), t.width()), (HEIGHT, WIDTH));
        drop(t);
        println!("fast raw case checked: {name}; {}", POSITIVE_SCOPES[i]);
    }
}

fn canonical_corruption(p: &mut Proof<Config>, index: usize) {
    match index {
        0 => p.degree_bits = 10,
        1 => p.commitments.trace = MerkleCap::new(vec![[0u64; 8]; 2]),
        2 => {
            p.opened_values.trace_local.pop();
        }
        3 => p.opened_values.trace_next = None,
        4 => {
            p.opened_values.quotient_chunks.pop();
        }
        5 => p.opened_values.random = None,
        6 => {
            let extra = p.opening_proof.0[0][0].clone();
            p.opening_proof.0[0].push(extra);
        }
        7 => {
            p.opening_proof.1.commit_phase_commits.pop();
        }
        8 => {
            p.opening_proof.1.input_openings[1].opened_values[0][0].pop();
        }
        9 => {
            p.opening_proof.1.input_openings[0].opening_proof.0[0][0].pop();
        }
        10 => {
            p.opening_proof.1.input_openings[0]
                .opening_proof
                .1
                .sibling_hashes = vec![[0; 8]; 897]
        }
        11 => {
            let mut cap = p.commitments.trace.roots().to_vec();
            cap[0][0] ^= 1;
            p.commitments.trace = MerkleCap::new(cap);
        }
        12 => p.opening_proof.1.input_openings[1].opened_values[0][0][0] += BabyBear::ONE,
        13 => p.opening_proof.1.final_poly[0] += Challenge::ONE,
        14 => p.opening_proof.0[0][0][0][0] += Challenge::ONE,
        15 => {
            let mut cap = p.opening_proof.1.commit_phase_commits[0].roots().to_vec();
            cap[0][0] ^= 1;
            p.opening_proof.1.commit_phase_commits[0] = MerkleCap::new(cap);
        }
        _ => unreachable!(),
    }
}

#[test]
fn sixteen_typed_mutations_have_the_declared_canonical_shape_classification() {
    for i in 0..16 {
        let mut p = synthetic_maximum_shape();
        canonical_corruption(&mut p, i);
        assert_eq!(validate_shape(&p).is_ok(), i >= 11, "C{:02}", i + 1);
        let encoded = serde_json::to_vec(&p).unwrap();
        json_preflight(&encoded).unwrap();
        let decoded: Proof<Config> = serde_json::from_slice(&encoded).unwrap();
        assert!(
            serde_json::to_vec(&decoded).unwrap() == encoded,
            "Typed synthetic mutation did not retain canonical encoding"
        );
    }
}

// Actual proof corpus tests run serially through a release test executable.
fn require_release() {
    #[cfg(debug_assertions)]
    panic!("Actual proof corpus requires a release test executable");
}

#[test]
#[ignore = "Serial release corpus: three honest proofs, public and transport checks"]
fn three_fresh_private_rows_public_mutations_and_transport() {
    require_release();
    let (w, s) = fixture();
    let first = prove_reconstructed_row(&w, &s).unwrap();
    verify_reconstructed_row(&first, &s).unwrap();
    let first_commitments = {
        let p: Proof<Config> = serde_json::from_slice(&first).unwrap();
        serde_json::to_vec(&p.commitments).unwrap()
    };
    let mut lengths = vec![first.len()];
    {
        let second = prove_reconstructed_row(&w, &s).unwrap();
        verify_reconstructed_row(&second, &s).unwrap();
        assert!(
            first != second,
            "Repeated fresh row encodings unexpectedly match"
        );
        let p: Proof<Config> = serde_json::from_slice(&second).unwrap();
        assert_ne!(
            first_commitments,
            serde_json::to_vec(&p.commitments).unwrap()
        );
        lengths.push(second.len());
    }
    {
        let changed = from_input(&hostile()["valid_alternatives"][0]["input"]);
        let third = prove_reconstructed_row(&changed, &s).unwrap();
        verify_reconstructed_row(&third, &s).unwrap();
        let p: Proof<Config> = serde_json::from_slice(&third).unwrap();
        assert_ne!(
            first_commitments,
            serde_json::to_vec(&p.commitments).unwrap()
        );
        lengths.push(third.len());
    }
    let config = verifier_config();
    {
        let p: Proof<Config> = serde_json::from_slice(&first).unwrap();
        let expected = public_values(&s);
        for index in 0..PUBLIC_VALUES {
            let mut changed = Statement::new(s.row, s.context).unwrap();
            if index == 0 {
                changed.row = 1;
            } else {
                changed.context[index - 1] ^= 1;
            }
            let pv = public_values(&changed);
            assert_ne!(expected[index], pv[index]);
            assert!(
                verify(&config, &ReconstructedRowAir::default(), &p, &pv).is_err(),
                "public {index}"
            );
            assert_eq!(
                verify_reconstructed_row(&first, &changed),
                Err(Error::InvalidProof)
            );
        }
        let wrong = Config::new(
            config.pcs().clone(),
            Challenger::new(HashChallenger::new(
                b"thorum.reconstructed-row-proof-lab.wrong-profile.v1".to_vec(),
                TranscriptHash,
            )),
        );
        assert!(verify(&wrong, &ReconstructedRowAir::default(), &p, &expected).is_err());
    }
    let invalid = Statement {
        row: 8,
        context: s.context,
    };
    assert_eq!(
        verify_reconstructed_row(&first, &invalid),
        Err(Error::InvalidStatement)
    );
    for index in 0..16 {
        let mut p: Proof<Config> = serde_json::from_slice(&first).unwrap();
        canonical_corruption(&mut p, index);
        let encoded = serde_json::to_vec(&p).unwrap();
        json_preflight(&encoded).unwrap();
        let typed: Proof<Config> = serde_json::from_slice(&encoded).unwrap();
        assert!(
            serde_json::to_vec(&typed).unwrap() == encoded,
            "Typed actual mutation did not retain canonical encoding"
        );
        if index < 11 {
            assert!(validate_shape(&typed).is_err());
        } else {
            validate_shape(&typed).unwrap();
            assert!(
                verify(
                    &config,
                    &ReconstructedRowAir::default(),
                    &typed,
                    &public_values(&s)
                )
                .is_err()
            );
        }
        assert_eq!(
            verify_reconstructed_row(&encoded, &s),
            Err(Error::InvalidProof),
            "C{:02}",
            index + 1
        );
    }
    for end in [0, 1, 10, first.len() / 2, first.len() - 1] {
        assert_eq!(
            verify_reconstructed_row(&first[..end], &s),
            Err(Error::InvalidEncoding)
        );
    }
    for variant in 0..3 {
        let mut changed = first.clone();
        match variant {
            0 => changed.push(b' '),
            1 => {
                changed.pop();
                changed.extend_from_slice(b",\"ignored\":0}");
            }
            2 => {
                changed.pop();
                changed.extend_from_slice(b",\"degree_bits\":11}");
            }
            _ => unreachable!(),
        }
        assert_eq!(
            verify_reconstructed_row(&changed, &s),
            Err(Error::InvalidEncoding)
        );
    }
    println!(
        "Three fresh conditional row proofs verified. All 65 public positions, wrong profile, 16 canonical corruptions and 8 encoding cases rejected. Encoded sizes: {lengths:?}"
    );
}

#[test]
#[ignore = "Serial release corpus: sixteen raw false proofs bypassing local precheck"]
fn sixteen_raw_false_row_proofs_reject_backend_and_wrapper() {
    require_release();
    let mut records = Vec::new();
    for (index, name) in RAW_NAMES.iter().enumerate() {
        let (t, s) = raw_case(index);
        // raw_case already establishes real local math and full AIR rejection.
        // The wrapper's witness precheck is intentionally NOT the proving route.
        let p = prove(
            &prover_config().unwrap(),
            &ReconstructedRowAir::default(),
            t,
            &public_values(&s),
        )
        .unwrap();
        let encoded = serde_json::to_vec(&p).unwrap();
        json_preflight(&encoded).unwrap();
        validate_shape(&p).unwrap();
        {
            let typed: Proof<Config> = serde_json::from_slice(&encoded).unwrap();
            assert!(
                serde_json::to_vec(&typed).unwrap() == encoded,
                "Raw false proof did not retain canonical encoding"
            );
        }
        assert!(
            verify(
                &verifier_config(),
                &ReconstructedRowAir::default(),
                &p,
                &public_values(&s)
            )
            .is_err(),
            "backend {name}"
        );
        assert_eq!(
            verify_reconstructed_row(&encoded, &s),
            Err(Error::InvalidProof),
            "wrapper {name}"
        );
        records.push(*name);
        println!(
            "raw false row proof constructed and rejected: {name}, {} encoded bytes",
            encoded.len()
        );
    }
    assert_eq!(records.len(), RAW_NAMES.len());
}
