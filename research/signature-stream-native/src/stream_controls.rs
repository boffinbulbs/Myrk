//! Complete actual native AIR on fixed synthetic streamed rows. No proof verifier.
use crate::{
    build::{decoder_state::DecodeError, port_source::PortSource},
    layout::*,
    packed, BoundInputs, PackedSignatureOwnerAir, Witness,
};
use p3_air::{Air, BaseAir, DebugConstraintBuilder};
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
const FAILURE_BOUND: usize = 69242;
const PROGRESS: [usize; 26] = [
    0, 233, 234, 413, 447, 511, 1023, 1535, 2047, 2559, 3071, 3583, 4095, 4607, 5119, 5315, 5316,
    5369, 5370, 5631, 6143, 6655, 7167, 7679, 8190, 8191,
];
struct Evaluation {
    count: usize,
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
    PackedSignatureOwnerAir.eval(&mut builder);
    let failures = builder.failures();
    let count = failures.len();
    let indices = failures
        .iter()
        .take(8)
        .map(|f| f.constraint)
        .collect::<Vec<_>>();
    let row_match = failures.iter().all(|f| f.row == at);
    // Logging selection never changes the actual AIR or suppresses a bad baseline.
    if phase != "baseline" || count != 0 || PROGRESS.contains(&at) {
        record(
            json!({"kind":"whole_air_evaluation","row":at,"next_row":(at+1)%HEIGHT,"phase":phase,"case":case,"first":at==0,"last":at==HEIGHT-1,"transition":at!=HEIGHT-1,"failure_count":count,"first_indices":indices,"failure_rows_match":row_match,"actual_full_air_called":true}),
        );
    }
    assert!(count <= FAILURE_BOUND);
    assert!(row_match);
    Evaluation { count, indices }
}
fn control(
    local: &mut [BabyBear],
    next: &mut [BabyBear],
    public: &[BabyBear],
    at: usize,
    specification: (&str, packed::Bank, usize, usize),
) {
    let (case, bank, byte, expected) = specification;
    let (word_start, word_base) = match bank {
        packed::Bank::Key => (KEY, 0),
        packed::Bank::Signature => (SIGNATURE, 864),
        packed::Bank::Note => (NOTE, 2407),
    };
    let word = word_start + byte / 3;
    let (port, offset) = packed::port_at(at, bank, byte);
    assert_eq!(offset, byte % 3);
    assert_eq!(
        usize::from(packed::word_ids_at(at)[port]),
        word_base + byte / 3
    );
    let column = SOURCE_PORTS + 24 * port + 8 * offset;
    let bit = local[column];
    assert!(bit == BabyBear::ZERO || bit == BabyBear::ONE);
    let saved = [local[word], next[word], local[column]];
    assert_eq!(saved[0], saved[1]);
    let delta = (BabyBear::ONE - bit.double()) * BabyBear::from_u32(1 << (8 * offset));
    local[word] += delta;
    next[word] += delta;
    local[column] = BabyBear::ONE - bit;
    assert!(local[word].as_canonical_u32() < 1 << 24 && next[word].as_canonical_u32() < 1 << 24);
    let result = evaluate(local, next, public, at, "negative", case);
    assert_eq!(result.count, 1);
    assert_eq!(result.indices, [expected]);
    local[word] = saved[0];
    next[word] = saved[1];
    local[column] = saved[2];
    let restored = evaluate(local, next, public, at, "restored", case);
    assert_eq!(restored.count, 0);
}
fn frame(local: &mut [BabyBear], next: &mut [BabyBear], public: &[BabyBear], at: usize) -> usize {
    let base = evaluate(local, next, public, at, "baseline", "genuine");
    assert_eq!(base.count, 0, "complete AIR failed at genuine row {at}");
    match at {
        234 => {
            control(
                local,
                next,
                public,
                at,
                ("same_note_owner", packed::Bank::Note, 141, 25052),
            );
            1
        }
        5369 => {
            control(
                local,
                next,
                public,
                at,
                ("final_signature", packed::Bank::Signature, 0, 23836),
            );
            1
        }
        8190 => {
            control(
                local,
                next,
                public,
                at,
                ("transaction_context", packed::Bank::Note, 49, 24958),
            );
            1
        }
        _ => 0,
    }
}
/// Only the fixed synthetic private owner is evaluated. No caller supplies a verdict.
pub fn fixed_stream_controls() -> Value {
    let b = bound();
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
    let mut candidate = source(&b);
    record(
        json!({"kind":"source_start","height":HEIGHT,"width":WIDTH,"public_values":public.len(),"preprocessed_columns":0,"periodic_columns":0,"boundary_io":0,"source_inferred_failure_bound":FAILURE_BOUND}),
    );
    let marker = BabyBear::from_u32(17);
    let mut previous = vec![marker; WIDTH];
    let mut current = vec![marker; WIDTH];
    let mut first = vec![marker; WIDTH];
    let (mut baseline_count, mut negatives) = (0usize, 0usize);
    for at in 0..HEIGHT {
        current.fill(marker);
        assert_eq!(candidate.emit_next(&mut current).unwrap(), at);
        if at == 0 {
            first.copy_from_slice(&current);
        }
        if at > 0 {
            negatives += frame(&mut previous, &mut current, &public, at - 1);
            baseline_count += 1;
        }
        core::mem::swap(&mut previous, &mut current);
    }
    negatives += frame(&mut previous, &mut first, &public, HEIGHT - 1);
    baseline_count += 1;
    let complete = candidate.finish();
    record(
        json!({"kind":"source_complete","result":format!("{complete:?}"),"position":candidate.position()}),
    );
    assert!(complete.is_ok());
    let a = candidate.initial_generation();
    let m = candidate.matrix_generation();
    let f = candidate.final_generation();
    let result = json!({"kind":"stream_summary","source_rows":HEIGHT,"complete_baseline_frames":baseline_count,"negative_evaluations":negatives,"restored_evaluations":negatives,"positive_evaluations":baseline_count+negatives,"whole_air_evaluations":baseline_count+2*negatives,"baseline_progress_records":PROGRESS.len(),"source_inferred_failure_bound_per_evaluation":FAILURE_BOUND,"clean_constraint_count_measured":false,"initial_generation":[a.attempted,a.completed,a.maximum_live],"matrix_generation":[m.attempted,m.completed,m.maximum_live],"final_generation":[f.attempted,f.completed,f.maximum_live],"candidate_trace_generator_calls":a.attempted+m.attempted+f.attempted,"reference_trace_generator_calls":0,"preserved_comparisons":candidate.preserved(),"prefix_preserved":candidate.prefix_preserved(),"complete_streamed_row_walks":1,"complete_wide_trace_allocations":0,"actual_final_signature_equality_executed":true,"backend_proofs":0,"old_controls_reexecuted":false});
    record(result.clone());
    assert_eq!((baseline_count, negatives), (8192, 3));
    result
}
