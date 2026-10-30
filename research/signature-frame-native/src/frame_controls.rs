//! Actual retained constraints on finite genuine frames, not a payment verifier.
use crate::{
    build::{decoder_state::DecodeError, port_source::PortSource},
    clock,
    layout::*,
    packed, BoundInputs, PackedSignatureOwnerAir, Witness,
};
use p3_air::{BaseAir, DebugConstraintBuilder};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrixView, stack::ViewPair};
use serde_json::{json, Value};
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use thorum_core::Amount;
use thorum_crypto_lab::{SealedNote, KEM_CIPHERTEXT_BYTES};
use thorum_relation_lab::{PaymentOutput, PaymentStatement};
fn record(v: Value) {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&d).unwrap();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(d.join("observations.jsonl"))
        .unwrap();
    serde_json::to_writer(&mut f, &v).unwrap();
    f.write_all(b"\n").unwrap();
    f.sync_all().unwrap();
}
fn bytes<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}
fn tx() -> PaymentStatement {
    PaymentStatement {
        chain_id: core::array::from_fn(|i| i as u8),
        protocol_version: 7,
        validation_tag: [0x33; 32],
        anchor: [0x44; 64],
        input_nullifiers: vec![[0x50; 64], [0x51; 64]],
        outputs: (0..2)
            .map(|i| PaymentOutput {
                commitment: [0x60 + i; 64],
                envelope: SealedNote {
                    kem_ciphertext: vec![0x70 + i; KEM_CIPHERTEXT_BYTES],
                    nonce: [0x80 + i; 12],
                    ciphertext: vec![0x90 + i; 32],
                },
            })
            .collect(),
        native_fee: Amount::from_atomic(5),
    }
}
fn bound() -> BoundInputs {
    let f: Value = serde_json::from_str(include_str!(
        "../../signature-matrix-source/fixtures-matrix.json"
    ))
    .unwrap();
    let w = Witness::from_sources(
        bytes(f["key_hex"].as_str().unwrap()),
        bytes(f["signature_hex"].as_str().unwrap()),
        bytes(f["note_hex"].as_str().unwrap()),
    );
    let tx = tx();
    let c = tx.canonical_bytes().unwrap();
    let t = f["transaction"]["canonical_T_hex"].as_str().unwrap();
    assert_eq!(c.len() * 2, t.len());
    assert!(c
        .iter()
        .enumerate()
        .all(|(i, b)| *b == u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap()));
    let b = BoundInputs::bind(w, tx).unwrap();
    let a = bytes::<196>(f["transaction"]["A196_hex"].as_str().unwrap());
    let p = b.public_values();
    assert_eq!(p.len(), 196);
    assert!(p
        .iter()
        .zip(a)
        .all(|(x, y)| x.as_canonical_u32() == u32::from(y)));
    b
}
fn source(b: &BoundInputs) -> PortSource<'_> {
    match PortSource::new(b) {
        Ok(s) => s,
        Err(DecodeError::Encoding(e)) => panic!("synthetic encoding: {e:?}"),
        Err(_) => panic!("unexpected initialization"),
    }
}
const BASELINES: [usize; 12] = [0, 63, 74, 233, 255, 413, 447, 5315, 5368, 5369, 8190, 8191];
// Indices derive from retained clock/packed assertion order and frozen tail-port annotations.
const FAILURE_BOUND: usize = 6502;
struct Evaluation {
    failures: usize,
    indices: Vec<usize>,
}
fn evaluate(
    local: &[BabyBear],
    next: &[BabyBear],
    public: &[BabyBear],
    at: usize,
    phase: &str,
    case: &str,
) -> Evaluation {
    assert_eq!(local.len(), WIDTH);
    assert_eq!(next.len(), WIDTH);
    assert_eq!(public.len(), PUBLIC_VALUES);
    assert!(at < HEIGHT);
    let main = ViewPair::new(
        RowMajorMatrixView::new_row(local),
        RowMajorMatrixView::new_row(next),
    );
    let pre = ViewPair::new(
        RowMajorMatrixView::new(&[], 0),
        RowMajorMatrixView::new(&[], 0),
    );
    let mut builder = DebugConstraintBuilder::<BabyBear>::new(
        at,
        main,
        pre,
        public,
        BabyBear::from_bool(at == 0),
        BabyBear::from_bool(at == HEIGHT - 1),
        BabyBear::from_bool(at != HEIGHT - 1),
        &[],
    );
    clock::eval(&mut builder, local, next, CLOCK, CLOCK_LOW, CLOCK_HIGH);
    packed::eval(&mut builder); // Unconditional even after a failed clock constraint.
    let failures = builder.failures();
    let count = failures.len();
    let indices = failures
        .iter()
        .take(8)
        .map(|f| f.constraint)
        .collect::<Vec<_>>();
    record(
        json!({"kind":"frame_evaluation","row":at,"next_row":(at+1)%HEIGHT,"phase":phase,"case":case,"first":at==0,"last":at==HEIGHT-1,"transition":at!=HEIGHT-1,"failure_count":count,"first_indices":indices,"failure_rows_match":failures.iter().all(|f|f.row==at),"clock_called":true,"packed_called":true}),
    );
    assert!(count <= FAILURE_BOUND);
    assert!(failures.iter().all(|f| f.row == at));
    Evaluation {
        failures: count,
        indices,
    }
}
#[derive(Clone, Copy)]
enum Side {
    Local,
    Next,
}
fn negative(
    local: &mut [BabyBear],
    next: &mut [BabyBear],
    public: &[BabyBear],
    at: usize,
    case: &str,
    changes: &[(Side, usize, BabyBear)],
    expected: &[usize],
) {
    let mut saved = Vec::with_capacity(changes.len());
    for &(side, column, value) in changes {
        let row = match side {
            Side::Local => &mut *local,
            Side::Next => &mut *next,
        };
        saved.push((side, column, row[column]));
        row[column] = value;
    }
    let result = evaluate(local, next, public, at, "negative", case);
    if case == "current_clock" {
        assert!(result.failures >= expected.len());
        assert!(expected.iter().all(|index| result.indices.contains(index)));
    } else {
        assert_eq!(result.failures, expected.len());
        assert_eq!(result.indices, expected);
    }
    for (side, column, value) in saved {
        let row = match side {
            Side::Local => &mut *local,
            Side::Next => &mut *next,
        };
        row[column] = value;
    }
    let restored = evaluate(local, next, public, at, "restored", case);
    assert_eq!(restored.failures, 0);
}
fn frame(local: &mut [BabyBear], next: &mut [BabyBear], public: &[BabyBear], at: usize) -> usize {
    assert!(BASELINES.contains(&at));
    let base = evaluate(local, next, public, at, "baseline", "genuine");
    assert_eq!(base.failures, 0);
    match at {
        0 => {
            assert_eq!(local[CLOCK], BabyBear::ONE);
            negative(
                local,
                next,
                public,
                at,
                "current_clock",
                &[(Side::Local, CLOCK, BabyBear::TWO)],
                &[0, 1, 5, 576],
            );
            1
        }
        63 => {
            assert_eq!(next[CLOCK + CLOCK_LOW], BabyBear::ZERO);
            assert_eq!(next[CLOCK + CLOCK_LOW + 1], BabyBear::ONE);
            negative(
                local,
                next,
                public,
                at,
                "high_carry",
                &[
                    (Side::Next, CLOCK + CLOCK_LOW, BabyBear::ONE),
                    (Side::Next, CLOCK + CLOCK_LOW + 1, BabyBear::ZERO),
                ],
                &[194, 197],
            );
            1
        }
        5315 => {
            assert!(!packed::word_ids_at(at).contains(&0));
            let value = next[KEY] + BabyBear::ONE;
            negative(
                local,
                next,
                public,
                at,
                "held_next",
                &[(Side::Next, KEY, value)],
                &[580],
            );
            1
        }
        5369 => {
            assert_eq!(packed::port_at(at, packed::Bank::Signature, 63), (21, 0));
            let column = SOURCE_PORTS + 24 * 21;
            let value = BabyBear::ONE - local[column];
            negative(
                local,
                next,
                public,
                at,
                "selected_byte",
                &[(Side::Local, column, value)],
                &[6158],
            );
            1
        }
        8190 => {
            assert!(packed::word_ids_at(at).len() < 125);
            let unused = SOURCE_PORTS + 24 * 124;
            assert_eq!(local[unused], BabyBear::ZERO);
            assert_eq!(local[unused + 1], BabyBear::ZERO);
            negative(
                local,
                next,
                public,
                at,
                "compensated_non_boolean",
                &[
                    (Side::Local, unused, BabyBear::TWO),
                    (Side::Local, unused + 1, -BabyBear::ONE),
                ],
                &[6103, 6104],
            );
            negative(
                local,
                next,
                public,
                at,
                "unused_port",
                &[(Side::Local, unused, BabyBear::ONE)],
                &[6315],
            );
            assert_eq!(packed::port_at(at, packed::Bank::Signature, 4626), (3, 0));
            let word = SIGNATURE + 1542;
            let virtual_bit = SOURCE_PORTS + 24 * 3 + 8;
            assert_eq!(local[virtual_bit], BabyBear::ZERO);
            let delta = BabyBear::from_u32(256);
            let lv = local[word] + delta;
            let nv = next[word] + delta;
            negative(
                local,
                next,
                public,
                at,
                "local_virtual_tail",
                &[
                    (Side::Local, word, lv),
                    (Side::Next, word, nv),
                    (Side::Local, virtual_bit, BabyBear::ONE),
                ],
                &[6131],
            );
            3
        }
        _ => 0,
    }
}
/// Fixed synthetic frames are never an authorization API for caller transactions.
pub fn fixed_frame_controls() -> Value {
    let b = bound();
    let mut candidate = source(&b);
    let public = b.public_values();
    let air = PackedSignatureOwnerAir;
    assert_eq!(
        <PackedSignatureOwnerAir as BaseAir<BabyBear>>::width(&air),
        WIDTH
    );
    assert_eq!(
        <PackedSignatureOwnerAir as BaseAir<BabyBear>>::num_public_values(&air),
        PUBLIC_VALUES
    );
    assert_eq!(
        <PackedSignatureOwnerAir as BaseAir<BabyBear>>::preprocessed_width(&air),
        0
    );
    assert!(<PackedSignatureOwnerAir as BaseAir<BabyBear>>::preprocessed_trace(&air).is_none());
    assert_eq!(
        <PackedSignatureOwnerAir as BaseAir<BabyBear>>::num_periodic_columns(&air),
        0
    );
    assert!(<PackedSignatureOwnerAir as BaseAir<BabyBear>>::periodic_columns(&air).is_empty());
    assert!(<PackedSignatureOwnerAir as BaseAir<BabyBear>>::public_boundary_io(&air).is_empty());
    record(
        json!({"kind":"source_start","height":HEIGHT,"width":WIDTH,"public_values":public.len(),"preprocessed_columns":0,"periodic_columns":0,"boundary_io":0}),
    );
    let marker = BabyBear::from_u32(17);
    let mut previous = vec![marker; WIDTH];
    let mut current = vec![marker; WIDTH];
    let mut first = vec![marker; WIDTH];
    let (mut baseline_count, mut negative_count) = (0usize, 0usize);
    for at in 0..HEIGHT {
        current.fill(marker);
        assert_eq!(candidate.emit_next(&mut current).unwrap(), at);
        if at == 0 {
            first.copy_from_slice(&current);
        }
        if at > 0 && BASELINES.contains(&(at - 1)) {
            negative_count += frame(&mut previous, &mut current, &public, at - 1);
            baseline_count += 1;
        }
        core::mem::swap(&mut previous, &mut current);
    }
    negative_count += frame(&mut previous, &mut first, &public, HEIGHT - 1);
    baseline_count += 1;
    let complete = candidate.finish();
    record(
        json!({"kind":"source_complete","result":format!("{complete:?}"),"position":candidate.position()}),
    );
    assert!(complete.is_ok());
    let a = candidate.initial_generation();
    let m = candidate.matrix_generation();
    let f = candidate.final_generation();
    let evaluations = baseline_count + 2 * negative_count;
    let result = json!({"kind":"frame_summary","source_rows":HEIGHT,"baseline_pairs":baseline_count,"negative_evaluations":negative_count,"restored_evaluations":negative_count,"positive_evaluations":baseline_count+negative_count,"combined_frame_evaluations":evaluations,"clock_evaluations":evaluations,"packed_evaluations":evaluations,"source_inferred_failure_bound_per_evaluation":FAILURE_BOUND,"clean_constraint_count_measured":false,"initial_generation":[a.attempted,a.completed,a.maximum_live],"matrix_generation":[m.attempted,m.completed,m.maximum_live],"final_generation":[f.attempted,f.completed,f.maximum_live],"candidate_trace_generator_calls":a.attempted+m.attempted+f.attempted,"reference_trace_generator_calls":0,"preserved_comparisons":candidate.preserved(),"prefix_preserved":candidate.prefix_preserved(),"complete_streamed_row_walks":1,"complete_wide_trace_allocations":0,"whole_air_evaluations":0,"packed_port_air_signature_equality_executed":false,"backend_proofs":0,"old_controls_reexecuted":false});
    record(result.clone());
    assert_eq!((baseline_count, negative_count, evaluations), (12, 7, 26));
    result
}
