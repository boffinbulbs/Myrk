//! Complete native overlay relation on one owned synthetic source walk.
use crate::{
    build::{decoder_state::DecodeError, port_source::PortSource},
    hints,
    layout::*,
    ntt, packed, BoundInputs, PackedSignatureOwnerAir, Witness,
};
use p3_air::{Air, DebugConstraintBuilder};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrixView, stack::ViewPair};
use serde_json::{json, Value};
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use thorum_core::Amount;
use thorum_crypto_lab::{SealedNote, KEM_CIPHERTEXT_BYTES};
use thorum_relation_lab::{PaymentOutput, PaymentStatement};

const FAILURE_BOUND: usize = 71623;
const PROGRESS: [usize; 15] = [
    0, 234, 482, 1535, 3071, 3522, 3554, 3714, 4095, 5119, 5314, 5369, 6143, 8190, 8191,
];

struct Journal {
    output: std::fs::File,
    bytes: usize,
    records: usize,
}
impl Journal {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
        std::fs::create_dir_all(&directory).unwrap();
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("observations.jsonl"))
            .unwrap();
        Self {
            output,
            bytes: 0,
            records: 0,
        }
    }
    fn record(&mut self, value: Value) {
        let encoded = serde_json::to_vec(&value).unwrap();
        assert!(encoded.len() <= 16384);
        assert!(self.bytes + encoded.len() < 65536);
        self.output.write_all(&encoded).unwrap();
        self.output.write_all(b"\n").unwrap();
        self.output.sync_all().unwrap();
        self.bytes += encoded.len() + 1;
        self.records += 1;
    }
}
fn bytes<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}
fn bound() -> BoundInputs {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../signature-matrix-source/fixtures-matrix.json"
    ))
    .unwrap();
    let witness = Witness::from_sources(
        bytes(fixture["key_hex"].as_str().unwrap()),
        bytes(fixture["signature_hex"].as_str().unwrap()),
        bytes(fixture["note_hex"].as_str().unwrap()),
    );
    let transaction = PaymentStatement {
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
    };
    let canonical = transaction.canonical_bytes().unwrap();
    let literal = fixture["transaction"]["canonical_T_hex"].as_str().unwrap();
    assert_eq!(2 * canonical.len(), literal.len());
    assert!(canonical
        .iter()
        .enumerate()
        .all(|(i, b)| *b == u8::from_str_radix(&literal[2 * i..2 * i + 2], 16).unwrap()));
    let inputs = BoundInputs::bind(witness, transaction).unwrap();
    let expected = bytes::<196>(fixture["transaction"]["A196_hex"].as_str().unwrap());
    assert!(inputs
        .public_values()
        .iter()
        .zip(expected)
        .all(|(actual, value)| actual.as_canonical_u32() == u32::from(value)));
    inputs
}
fn read_bits(row: &[BabyBear], start: usize, count: usize) -> i64 {
    row[start..start + count]
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let bit = value.as_canonical_u32();
            assert!(bit <= 1);
            i64::from(bit) << i
        })
        .sum()
}
struct References {
    forward: Value,
    inverse: Value,
    hint: Value,
    comparisons: [usize; 4],
}
impl References {
    fn new() -> Self {
        Self {
            forward: serde_json::from_str(include_str!(
                "../../signature-accumulator-source/fixtures-accumulator.json"
            ))
            .unwrap(),
            inverse: serde_json::from_str(include_str!(
                "../../signature-inverse-source/fixtures-inverse.json"
            ))
            .unwrap(),
            hint: serde_json::from_str(include_str!(
                "../../signature-hint-source/fixtures-hint.json"
            ))
            .unwrap(),
            comparisons: [0; 4],
        }
    }
    fn observe(&mut self, row: &[BabyBear], at: usize) {
        if (642..=3522).contains(&at) && (at - 450).is_multiple_of(192) {
            let t = (at - 450) / 192 - 1;
            let output = match t {
                0..=6 => &self.forward["forward_outputs"]["zhat"][t],
                7 => &self.forward["forward_outputs"]["chat"],
                _ => &self.forward["forward_outputs"]["t1hat"][t - 8],
            };
            assert_eq!(output.as_array().unwrap().len(), 256);
            for k in 0..256 {
                assert_eq!(
                    u64::from(row[output_column(t, k)].as_canonical_u32()),
                    output[k].as_u64().unwrap(),
                    "forward endpoint {t}, coefficient {k}"
                );
                self.comparisons[0] += 1;
            }
        }
        if let Some((i, ntt::InverseOp::Output(g))) = ntt::inverse_operation(at) {
            let inverse = &self.inverse["inverses"][i];
            let state = inverse["output_state_index"].as_u64().unwrap() as usize;
            for s in 0..8 {
                let k = 8 * g + s;
                assert_eq!(
                    u64::from(row[NTT_SCRATCH + k].as_canonical_u32()),
                    inverse["states"][state][k].as_u64().unwrap(),
                    "inverse endpoint {i}, coefficient {k}"
                );
                self.comparisons[1] += 1;
                let start = USE_HINT + s * hints::WIDTH;
                let u = read_bits(row, start + hints::U, 19);
                let edge = i64::from(row[start + hints::EDGE].as_canonical_u32());
                for (name, value) in [
                    ("high", read_bits(row, start + hints::HIGH, 4)),
                    ("low", u - i64::from(hints::GAMMA2) + 1 - edge),
                    (
                        "positive",
                        i64::from(row[start + hints::POSITIVE].as_canonical_u32()),
                    ),
                    ("output", read_bits(row, start + hints::OUTPUT, 4)),
                    ("n", read_bits(row, start + hints::N, 5)),
                    ("u", u),
                    ("edge", edge),
                    ("sign_slack", read_bits(row, start + hints::SIGN_SLACK, 18)),
                    (
                        "borrow",
                        i64::from(row[start + hints::BORROW].as_canonical_u32()),
                    ),
                    (
                        "overflow",
                        i64::from(row[start + hints::OVERFLOW].as_canonical_u32()),
                    ),
                ] {
                    assert_eq!(
                        value,
                        self.hint["rows"][i]["hint_step_columns"][name][k]
                            .as_i64()
                            .unwrap(),
                        "hint field {name}, row {i}, coefficient {k}"
                    );
                    self.comparisons[2] += 1;
                }
            }
        }
        if at == 5314 {
            let expected = bytes::<1024>(self.hint["packed_w1_hex"].as_str().unwrap());
            for (i, value) in expected.into_iter().enumerate() {
                assert_eq!(row[W1 + i].as_canonical_u32(), u32::from(value));
                self.comparisons[3] += 1;
            }
        }
    }
}
struct Evaluation {
    count: usize,
    expected_seen: bool,
}
fn evaluate(
    journal: &mut Journal,
    local: &[BabyBear],
    next: &[BabyBear],
    public: &[BabyBear],
    at: usize,
    label: (&str, &str),
    expected: &[usize],
) -> Evaluation {
    assert_eq!(
        (local.len(), next.len(), public.len()),
        (WIDTH, WIDTH, PUBLIC_VALUES)
    );
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
    let indices: Vec<_> = failures
        .iter()
        .take(8)
        .map(|failure| failure.constraint)
        .collect();
    let expected_seen = expected
        .iter()
        .all(|wanted| failures.iter().any(|failure| failure.constraint == *wanted));
    let rows_match = failures.iter().all(|failure| failure.row == at);
    if label.0 != "baseline" || count != 0 || PROGRESS.contains(&at) {
        journal.record(json!({"kind":"complete_air","row":at,"next":(at+1)%HEIGHT,"phase":label.0,"case":label.1,
            "failures":count,"first_indices":indices,"expected_indices":expected,"expected_seen":expected_seen,"rows_match":rows_match}));
    }
    assert!(count <= FAILURE_BOUND && rows_match);
    Evaluation {
        count,
        expected_seen,
    }
}
fn cell_control(
    journal: &mut Journal,
    row: &mut [BabyBear],
    next: &[BabyBear],
    public: &[BabyBear],
    at: usize,
    specification: (&str, usize, &[usize]),
) {
    let (case, column, expected) = specification;
    let saved = row[column];
    assert!(saved == BabyBear::ZERO || saved == BabyBear::ONE);
    row[column] = BabyBear::ONE - saved;
    let negative = evaluate(journal, row, next, public, at, ("negative", case), expected);
    assert!(negative.count > 0 && negative.expected_seen);
    row[column] = saved;
    assert_eq!(
        evaluate(journal, row, next, public, at, ("restored", case), &[]).count,
        0
    );
}
fn owner_control(
    journal: &mut Journal,
    row: &mut [BabyBear],
    next: &mut [BabyBear],
    public: &[BabyBear],
    at: usize,
    specification: (&str, packed::Bank, usize, usize),
) {
    let (case, bank, byte, expected) = specification;
    let first = match bank {
        packed::Bank::Key => KEY,
        packed::Bank::Signature => SIGNATURE,
        packed::Bank::Note => NOTE,
    };
    let word = first + byte / 3;
    let (port, offset) = packed::port_at(at, bank, byte);
    assert_eq!(offset, byte % 3);
    let column = SOURCE_PORTS + 24 * port + 8 * offset;
    let saved = [row[word], next[word], row[column]];
    assert_eq!(saved[0], saved[1]);
    assert!(saved[2] == BabyBear::ZERO || saved[2] == BabyBear::ONE);
    let delta = (BabyBear::ONE - saved[2].double()) * BabyBear::from_u32(1 << (8 * offset));
    row[word] += delta;
    next[word] += delta;
    row[column] = BabyBear::ONE - saved[2];
    assert!(row[word].as_canonical_u32() < 1 << 24 && next[word].as_canonical_u32() < 1 << 24);
    let negative = evaluate(
        journal,
        row,
        next,
        public,
        at,
        ("negative", case),
        &[expected],
    );
    assert!(negative.expected_seen);
    assert_eq!(negative.count, 1);
    row[word] = saved[0];
    next[word] = saved[1];
    row[column] = saved[2];
    assert_eq!(
        evaluate(journal, row, next, public, at, ("restored", case), &[]).count,
        0
    );
}
fn frame(
    journal: &mut Journal,
    row: &mut [BabyBear],
    next: &mut [BabyBear],
    public: &[BabyBear],
    at: usize,
) -> usize {
    assert_eq!(
        evaluate(journal, row, next, public, at, ("baseline", "genuine"), &[]).count,
        0,
        "complete overlay row {at}"
    );
    // Clock emits580 roots, then5mode bindings,1688idle and688suffix roots.
    match at {
        0 => cell_control(
            journal,
            row,
            next,
            public,
            at,
            ("idle_bank", USE_HINT, &[585]),
        ),
        234 => owner_control(
            journal,
            row,
            next,
            public,
            at,
            ("same_note_owner", packed::Bank::Note, 141, 27433),
        ),
        482 => {
            cell_control(
                journal,
                row,
                next,
                public,
                at,
                ("product_mode", PRODUCT_MODE, &[582]),
            );
            cell_control(
                journal,
                row,
                next,
                public,
                at,
                ("simultaneous_modes", HINT_MODE, &[583, 584]),
            );
            cell_control(
                journal,
                row,
                next,
                public,
                at,
                ("product_result_bit", USE_HINT + 69, &[]),
            );
            return 3;
        }
        3554 => cell_control(
            journal,
            row,
            next,
            public,
            at,
            ("inverse_result_bit", USE_HINT + 69, &[]),
        ),
        3714 => {
            cell_control(
                journal,
                row,
                next,
                public,
                at,
                ("hint_mode", HINT_MODE, &[583]),
            );
            cell_control(
                journal,
                row,
                next,
                public,
                at,
                ("hint_input_bit", USE_HINT + hints::R, &[]),
            );
            cell_control(
                journal,
                row,
                next,
                public,
                at,
                ("hint_suffix", USE_HINT + 1000, &[2273]),
            );
            return 3;
        }
        5369 => owner_control(
            journal,
            row,
            next,
            public,
            at,
            ("final_signature", packed::Bank::Signature, 0, 26217),
        ),
        8190 => owner_control(
            journal,
            row,
            next,
            public,
            at,
            ("transaction_context", packed::Bank::Note, 49, 27339),
        ),
        8191 => cell_control(
            journal,
            row,
            next,
            public,
            at,
            ("last_clock", CLOCK + CLOCK_LOW + CLOCK_HIGH - 1, &[579]),
        ),
        _ => return 0,
    }
    1
}
pub fn fixed_overlay_stream() -> Value {
    let mut journal = Journal::new();
    journal.record(json!({"kind":"start","height":HEIGHT,"width":WIDTH,"public_values":PUBLIC_VALUES,"failure_bound":FAILURE_BOUND}));
    let inputs = bound();
    let public = inputs.public_values();
    let mut references = References::new();
    let mut candidate = match PortSource::new(&inputs) {
        Ok(source) => source,
        Err(DecodeError::Encoding(error)) => panic!("synthetic encoding: {error:?}"),
        Err(_) => panic!("source initialization failed"),
    };
    let marker = BabyBear::from_u32(17);
    let (mut previous, mut current, mut first) = (
        vec![marker; WIDTH],
        vec![marker; WIDTH],
        vec![marker; WIDTH],
    );
    let (mut baselines, mut controls) = (0, 0);
    let mut modes = [0usize; 3];
    for at in 0..HEIGHT {
        current.fill(marker);
        let emitted = candidate.emit_next(&mut current);
        if emitted.is_err() {
            journal
                .record(json!({"kind":"source_failure","row":at,"error":format!("{emitted:?}")}));
        }
        assert_eq!(emitted.unwrap(), at);
        references.observe(&current, at);
        match (
            current[PRODUCT_MODE].as_canonical_u32(),
            current[HINT_MODE].as_canonical_u32(),
        ) {
            (1, 0) => modes[0] += 1,
            (0, 1) => modes[1] += 1,
            (0, 0) => modes[2] += 1,
            _ => panic!("invalid emitted modes"),
        }
        if at == 0 {
            first.copy_from_slice(&current);
        }
        if at > 0 {
            controls += frame(&mut journal, &mut previous, &mut current, &public, at - 1);
            baselines += 1;
        }
        core::mem::swap(&mut previous, &mut current);
    }
    controls += frame(&mut journal, &mut previous, &mut first, &public, HEIGHT - 1);
    baselines += 1;
    let finished = candidate.finish();
    journal.record(json!({"kind":"source_complete","result":format!("{finished:?}"),"position":candidate.position()}));
    assert!(finished.is_ok());
    let a = candidate.initial_generation();
    let m = candidate.matrix_generation();
    let f = candidate.final_generation();
    let summary = json!({"kind":"summary","height":HEIGHT,"width":WIDTH,"public_values":PUBLIC_VALUES,
        "source_walks":1,"baseline_frames":baselines,"negative_frames":controls,"restored_frames":controls,
        "complete_air_calls":baselines+2*controls,"mode_rows":modes,"reference_comparisons":references.comparisons,
        "initial_generation":[a.attempted,a.completed,a.maximum_live],"matrix_generation":[m.attempted,m.completed,m.maximum_live],
        "final_generation":[f.attempted,f.completed,f.maximum_live],"trace_generator_calls":a.attempted+m.attempted+f.attempted,
        "preserved":candidate.preserved(),"prefix_preserved":candidate.prefix_preserved(),
        "whole_trace_allocations":0,"symbolic_collections":0,"backend_proofs":0,"new_reference_generations":0,
        "journal_records_before_summary":journal.records});
    journal.record(summary.clone());
    assert_eq!((baselines, controls), (8192, 12));
    assert_eq!(modes, [3328, 256, 4608]);
    assert_eq!(references.comparisons, [4096, 2048, 20480, 1024]);
    assert_eq!((a.attempted, m.attempted, f.attempted), (70, 336, 9));
    summary
}
