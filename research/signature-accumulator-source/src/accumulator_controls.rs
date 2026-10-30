//! Fixed synthetic accumulation controls and an explicit source-row fault.
use crate::{
    build::{
        accumulator_reference::{AccumulatorReference, Inputs, ReferenceError},
        accumulator_source::{AccumulatorSource, SourceError},
        accumulator_state::MatrixAccumulatorError,
        decoder_state::DecodeError,
        hash_source::Generation,
        matrix_overlay::MatrixGeneration,
    },
    full_program as fp,
    layout::*,
    mul, BoundInputs, Witness,
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
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
fn vector(v: &Value) -> [u32; 256] {
    let a = v.as_array().unwrap();
    assert_eq!(a.len(), 256);
    core::array::from_fn(|i| {
        let x = a[i].as_u64().unwrap();
        assert!(x < 8_380_417);
        x as u32
    })
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
fn source(b: &BoundInputs) -> AccumulatorSource<'_> {
    match AccumulatorSource::new(b) {
        Ok(s) => s,
        Err(DecodeError::Encoding(e)) => panic!("synthetic encoding: {e:?}"),
        Err(_) => panic!("unexpected initialization"),
    }
}
fn initial(g: Generation) -> [usize; 3] {
    [g.attempted, g.completed, g.maximum_live]
}
fn matrix(g: MatrixGeneration) -> [usize; 3] {
    [g.attempted, g.completed, g.maximum_live]
}
fn bits(row: &[BabyBear], at: usize, n: usize) -> u32 {
    (0..n).map(|i| row[at + i].as_canonical_u32() << i).sum()
}
fn count(row: &[BabyBear], slot: usize) -> usize {
    let a = &row[MATRIX_COUNT + 257 * slot..MATRIX_COUNT + 257 * (slot + 1)];
    assert_eq!(a.iter().filter(|x| **x == BabyBear::ONE).count(), 1);
    a.iter().position(|x| *x == BabyBear::ONE).unwrap()
}
fn product(row: &[BabyBear], slot: usize, operand: usize) -> u32 {
    bits(
        row,
        EXTRA_PRODUCTS + slot * mul::WIDTH + mul::VALUES + 23 * operand,
        23,
    )
}
fn mismatch(row: &[BabyBear], expected: &[BabyBear]) -> Option<usize> {
    row[MATRIX_COUNT..USE_HINT]
        .iter()
        .zip(&expected[MATRIX_COUNT..USE_HINT])
        .position(|(a, b)| a != b)
        .map(|i| MATRIX_COUNT + i)
        .or_else(|| {
            row[ACTIVE_MATRIX..ACTIVE_MATRIX + 8]
                .iter()
                .zip(&expected[ACTIVE_MATRIX..ACTIVE_MATRIX + 8])
                .position(|(a, b)| a != b)
                .map(|i| ACTIVE_MATRIX + i)
        })
}
fn equal(row: &[BabyBear], expected: &[BabyBear], at: usize) {
    if let Some(column) = mismatch(row, expected) {
        record(json!({"kind":"accumulator_mismatch","row":at,"first_column":column}));
        panic!("accumulator mismatch at row {at}, column {column}");
    }
}
fn golden(actual: u32, expected: u32, at: usize, column: usize) {
    if actual != expected {
        record(json!({"kind":"independent_mismatch","row":at,"first_column":column}));
        panic!("accumulator golden at row {at}, column {column}");
    }
}
struct Column {
    coeff: [u32; 256],
    products: [u32; 256],
    after: [u32; 256],
    cursor: u32,
    rejected: Vec<u32>,
}
struct Goldens {
    columns: Vec<Column>,
    zhat: [[u32; 256]; 7],
    chat: [u32; 256],
    t1hat: [[u32; 256]; 8],
    point_products: [[u32; 256]; 8],
    point_after: [[u32; 256]; 8],
    streams: [[u8; 1008]; 56],
}
impl Goldens {
    fn new() -> Self {
        let f: Value = serde_json::from_str(include_str!("../fixtures-accumulator.json")).unwrap();
        let shared: Value = serde_json::from_str(include_str!(
            "../../signature-matrix-source/fixtures-matrix.json"
        ))
        .unwrap();
        let columns = f["matrix_columns"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(s, c)| {
                assert_eq!(c["chronological_index"], json!(s));
                assert_eq!(c["row"], json!(s % 8));
                assert_eq!(c["column"], json!(s / 8));
                Column {
                    coeff: vector(&c["coefficients"]),
                    products: vector(&c["products"]),
                    after: vector(&c["after"]),
                    cursor: c["cursor"]["bytes_consumed"].as_u64().unwrap() as u32,
                    rejected: c["cursor"]["rejected_candidate_indices"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_u64().unwrap() as u32)
                        .collect(),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(columns.len(), 56);
        Self {
            columns,
            zhat: core::array::from_fn(|i| vector(&f["forward_outputs"]["zhat"][i])),
            chat: vector(&f["forward_outputs"]["chat"]),
            t1hat: core::array::from_fn(|i| vector(&f["forward_outputs"]["t1hat"][i])),
            point_products: core::array::from_fn(|i| {
                vector(&f["point_rows"][i]["challenge_products"])
            }),
            point_after: core::array::from_fn(|i| vector(&f["point_rows"][i]["inverse_input"])),
            streams: core::array::from_fn(|s| {
                bytes(
                    shared["streams"][s]["six_block_stream_hex"]
                        .as_str()
                        .unwrap(),
                )
            }),
        }
    }
    fn reference_inputs(&self) -> Inputs {
        Inputs {
            streams: self.streams,
            zhat: self.zhat,
            chat: self.chat,
            t1hat: self.t1hat,
        }
    }
}
fn main_walk() -> Value {
    let b = bound();
    let mut candidate = source(&b);
    let g = Goldens::new();
    let early = candidate.finish();
    record(json!({"kind":"incomplete","result":format!("{early:?}")}));
    assert!(matches!(early, Err(SourceError::Incomplete)));
    let mut reference = AccumulatorReference::new(g.reference_inputs());
    for requested in [1, 6] {
        let r = reference.prepare(requested);
        let unchanged = reference.pristine();
        record(
            json!({"kind":"reference_sequence","requested":requested,"result":format!("{r:?}"),"unchanged":unchanged}),
        );
        assert!(matches!(r, Err(ReferenceError::Sequence)));
        assert!(unchanged);
    }
    let marker = BabyBear::from_u32(17);
    let mut row = vec![marker; WIDTH];
    let mut short = vec![marker; WIDTH - 1];
    let mut accepted = 0;
    let mut rejected = 0;
    let mut point_values = 0;
    let mut borrows = 0;
    let mut carries = 0;
    let mut stream_events = Vec::new();
    let mut first_rejection = None;
    let mut first_borrow = None;
    let mut complete_slots = 0;
    let mut controls = 0;
    for at in 0..HEIGHT {
        if at < 2 {
            let before = (
                initial(candidate.initial_generation()),
                matrix(candidate.matrix_generation()),
                candidate.position(),
            );
            let result = candidate.emit_next(&mut short);
            let after = (
                initial(candidate.initial_generation()),
                matrix(candidate.matrix_generation()),
                candidate.position(),
            );
            let unchanged = short.iter().all(|x| *x == marker);
            record(
                json!({"kind":"shape_refusal","row":at,"result":format!("{result:?}"),"before":before,"after":after,"unchanged":unchanged}),
            );
            assert!(matches!(result, Err(SourceError::RowShape)));
            assert_eq!(before, after);
            assert!(unchanged);
        }
        reference.prepare(at).unwrap();
        let expected = reference.row(at);
        row.fill(marker);
        assert_eq!(candidate.emit_next(&mut row).unwrap(), at);
        equal(&row, expected, at);
        if let Some((i, j, local)) = fp::matrix(at) {
            let stream = 8 * j + i;
            let c = &g.columns[stream];
            for slot in 0..8 {
                if row[ACTIVE_MATRIX + slot] == BabyBear::ONE {
                    let k = count(&row, slot);
                    let cur = bits(&row, MATRIX_CURSOR + 10 * slot, 10);
                    let take = row[MATRIX_TAKE + slot] == BabyBear::ONE;
                    let prior = if j == 0 {
                        0
                    } else {
                        g.columns[8 * (j - 1) + i].after[k]
                    };
                    golden(
                        row[output_column(j, k)].as_canonical_u32(),
                        g.zhat[j][k],
                        at,
                        output_column(j, k),
                    );
                    golden(
                        bits(&row, EXTRA_WRITES + 46 * (2 * slot), 23),
                        prior,
                        at,
                        EXTRA_WRITES + 46 * (2 * slot),
                    );
                    if take {
                        golden(
                            bits(&row, MATRIX_CANDIDATE + 24 * slot, 23),
                            c.coeff[k],
                            at,
                            MATRIX_CANDIDATE + 24 * slot,
                        );
                        golden(
                            product(&row, slot, 3),
                            c.products[k],
                            at,
                            EXTRA_PRODUCTS + slot * mul::WIDTH + 69,
                        );
                        golden(
                            bits(&row, EXTRA_WRITES + 46 * (2 * slot + 1), 23),
                            c.after[k],
                            at,
                            EXTRA_WRITES + 46 * (2 * slot + 1),
                        );
                        let carry = prior + c.products[k] >= mul::MODULUS;
                        golden(
                            row[EXTRA_FLAGS + 2 * slot].as_canonical_u32(),
                            u32::from(carry),
                            at,
                            EXTRA_FLAGS + 2 * slot,
                        );
                        carries += usize::from(carry);
                        accepted += 1;
                        if count(&row, slot + 1) == 256 {
                            complete_slots += 1;
                        }
                    } else {
                        golden(
                            product(&row, slot, 3),
                            0,
                            at,
                            EXTRA_PRODUCTS + slot * mul::WIDTH + 69,
                        );
                        golden(
                            bits(&row, EXTRA_WRITES + 46 * (2 * slot + 1), 23),
                            prior,
                            at,
                            EXTRA_WRITES + 46 * (2 * slot + 1),
                        );
                        assert!(stream_events.len() < 80);
                        stream_events.push(cur / 3);
                        rejected += 1;
                        if first_rejection.is_none() {
                            first_rejection = Some((at, slot));
                        }
                    }
                }
            }
            if local == 47 {
                let cursor = bits(&row, MATRIX_CURSOR + 80, 10);
                let last = count(&row, 8);
                record(
                    json!({"kind":"stream_complete","row":at,"stream":stream,"accepted":last,"cursor":cursor,"rejected_indices":stream_events}),
                );
                assert_eq!(last, 256);
                assert_eq!(cursor, c.cursor);
                assert_eq!(stream_events, c.rejected);
                stream_events.clear();
            }
        }
        if (fp::MATRIX_START + 48..=fp::MATRIX_END).contains(&at)
            && (at - fp::MATRIX_START).is_multiple_of(48)
        {
            let stream = (at - fp::MATRIX_START) / 48 - 1;
            let i = stream % 8;
            for k in 0..256 {
                golden(
                    row[ACCUMULATOR + 256 * i + k].as_canonical_u32(),
                    g.columns[stream].after[k],
                    at,
                    ACCUMULATOR + 256 * i + k,
                );
            }
            record(json!({"kind":"column_after","row":at,"stream":stream,"coefficients":256}));
        }
        if let Some((i, tile)) = fp::point(at) {
            let prior = &g.columns[48 + i].after;
            for slot in 0..8 {
                let k = 8 * tile + slot;
                golden(
                    row[output_column(7, k)].as_canonical_u32(),
                    g.chat[k],
                    at,
                    output_column(7, k),
                );
                golden(
                    row[output_column(8 + i, k)].as_canonical_u32(),
                    g.t1hat[i][k],
                    at,
                    output_column(8 + i, k),
                );
                golden(
                    product(&row, slot, 3),
                    g.point_products[i][k],
                    at,
                    EXTRA_PRODUCTS + slot * mul::WIDTH + 69,
                );
                golden(
                    bits(&row, EXTRA_WRITES + 46 * (2 * slot), 23),
                    prior[k],
                    at,
                    EXTRA_WRITES + 46 * (2 * slot),
                );
                golden(
                    bits(&row, EXTRA_WRITES + 46 * (2 * slot + 1), 23),
                    g.point_after[i][k],
                    at,
                    EXTRA_WRITES + 46 * (2 * slot + 1),
                );
                let borrow = prior[k] < g.point_products[i][k];
                golden(
                    row[EXTRA_FLAGS + 2 * slot].as_canonical_u32(),
                    u32::from(borrow),
                    at,
                    EXTRA_FLAGS + 2 * slot,
                );
                borrows += usize::from(borrow);
                point_values += 1;
                if borrow && first_borrow.is_none() {
                    first_borrow = Some((at, slot));
                }
            }
        }
        if (fp::POINT_START + 32..=fp::POINT_END).contains(&at)
            && (at - fp::POINT_START).is_multiple_of(32)
        {
            let i = (at - fp::POINT_START) / 32 - 1;
            for k in 0..256 {
                golden(
                    row[ACCUMULATOR + 256 * i + k].as_canonical_u32(),
                    g.point_after[i][k],
                    at,
                    ACCUMULATOR + 256 * i + k,
                );
            }
            record(json!({"kind":"point_after","row":at,"point_row":i,"coefficients":256}));
        }
        if at == HEIGHT - 1 {
            for i in 0..8 {
                for k in 0..256 {
                    golden(
                        row[ACCUMULATOR + 256 * i + k].as_canonical_u32(),
                        g.point_after[i][k],
                        at,
                        ACCUMULATOR + 256 * i + k,
                    );
                }
            }
            record(json!({"kind":"terminal_accumulator","row":at,"coefficients":2048}));
        }
        if [
            0, 647, 648, 689, 690, 3329, 3330, 3521, 3522, 3554, 3586, 8191,
        ]
        .contains(&at)
        {
            record(
                json!({"kind":"microstate_boundary","row":at,"count0":count(&row,0),"count8":count(&row,8),"cursor0":bits(&row,MATRIX_CURSOR,10),"cursor8":bits(&row,MATRIX_CURSOR+80,10),"active_slots":row[ACTIVE_MATRIX..ACTIVE_MATRIX+8].iter().filter(|x|**x==BabyBear::ONE).count()}),
            );
        }
        let corrupt = match at {
            0 => Some(EXTRA_PRODUCTS + mul::COMPLEMENTS),
            648 => Some(MATRIX_COUNT),
            649 => Some(MATRIX_CURSOR),
            689 => Some(ACTIVE_MATRIX),
            690 => Some(MATRIX_ENABLE),
            3330 => Some(EXTRA_FLAGS),
            3522 => Some(ACCUMULATOR),
            8191 => Some(MATRIX_COUNT + 256),
            _ => None,
        };
        if let Some(column) = corrupt {
            let v = row[column];
            row[column] += BabyBear::ONE;
            let detected = mismatch(&row, expected) == Some(column);
            record(
                json!({"kind":"comparator_corruption","row":at,"column":column,"detected":detected}),
            );
            assert!(detected);
            row[column] = v;
            equal(&row, expected, at);
            controls += 1;
        }
    }
    let finish = candidate.finish();
    record(json!({"kind":"complete","result":format!("{finish:?}")}));
    assert!(finish.is_ok());
    let before = (
        initial(candidate.initial_generation()),
        matrix(candidate.matrix_generation()),
        candidate.position(),
    );
    row.fill(marker);
    let result = candidate.emit_next(&mut row);
    let after = (
        initial(candidate.initial_generation()),
        matrix(candidate.matrix_generation()),
        candidate.position(),
    );
    let unchanged = row.iter().all(|x| *x == marker);
    record(
        json!({"kind":"exhaustion","result":format!("{result:?}"),"before":before,"after":after,"unchanged":unchanged}),
    );
    assert!(matches!(result, Err(SourceError::Exhausted)));
    assert_eq!(before, after);
    assert!(unchanged);
    let last = reference.row(HEIGHT - 1)[MATRIX_COUNT..USE_HINT].to_vec();
    let result = reference.prepare(HEIGHT);
    let unchanged = reference.row(HEIGHT - 1)[MATRIX_COUNT..USE_HINT] == last;
    record(
        json!({"kind":"reference_exhaustion","result":format!("{result:?}"),"prepared":reference.prepared(),"unchanged":unchanged}),
    );
    assert!(matches!(result, Err(ReferenceError::Exhausted)));
    assert!(unchanged);
    let report = json!({"kind":"accumulator_summary","rows":HEIGHT,"reference_rows":reference.prepared(),"owned_comparisons":HEIGHT*(USE_HINT-MATRIX_COUNT+8),"preserved_comparisons":candidate.preserved(),"prefix_preserved":candidate.prefix_preserved(),
        "accepted":accepted,"rejected":rejected,"completion_slots":complete_slots,"point_values":point_values,"point_borrows":borrows,"matrix_carries":carries,"first_rejection":first_rejection,"first_borrow":first_borrow,
        "stream_completions":56,"column_checkpoints":56,"point_checkpoints":8,"terminal_coefficients":2048,"comparator_controls":controls,"restored_controls":controls,
        "initial_generation":initial(candidate.initial_generation()),"matrix_generation":matrix(candidate.matrix_generation()),"reference_hash_generations":0});
    record(report.clone());
    assert_eq!(accepted, 56 * 256);
    assert_eq!(point_values, 2048);
    report
}
fn shortage_walk() -> Value {
    let b = bound();
    let mut candidate = source(&b);
    let marker = BabyBear::from_u32(17);
    let mut row = vec![marker; WIDTH];
    record(
        json!({"kind":"fault_begin","scope":"Fixed source-row XOF shortage injection after real prefix. No genuine seed/hash or proof rejection claim."}),
    );
    let mut failed_at = None;
    for at in 0..=689 {
        row.fill(marker);
        let result = candidate.emit_shortage_source_row(&mut row);
        if let Err(SourceError::UnsupportedMatrixClass {
            row: failed_row,
            accepted,
            cursor,
        }) = result
        {
            record(
                json!({"kind":"fault_capacity","row":failed_row,"accepted":accepted,"cursor":cursor,"position":candidate.position(),"initial_generation":initial(candidate.initial_generation()),"matrix_generation":matrix(candidate.matrix_generation())}),
            );
            assert_eq!((at, failed_row, accepted, cursor), (689, 689, 0, 1008));
            failed_at = Some(at);
            break;
        }
        assert_eq!(result.unwrap(), at);
    }
    assert_eq!(failed_at, Some(689));
    let before = (
        initial(candidate.initial_generation()),
        matrix(candidate.matrix_generation()),
        candidate.position(),
    );
    for operation in ["normal", "fault"] {
        row.fill(marker);
        let result = if operation == "normal" {
            candidate.emit_next(&mut row)
        } else {
            candidate.emit_shortage_source_row(&mut row)
        };
        let after = (
            initial(candidate.initial_generation()),
            matrix(candidate.matrix_generation()),
            candidate.position(),
        );
        let unchanged = row.iter().all(|x| *x == marker);
        record(
            json!({"kind":"fault_refusal","operation":operation,"result":format!("{result:?}"),"before":before,"after":after,"unchanged":unchanged}),
        );
        assert!(matches!(result, Err(SourceError::Failed)));
        assert_eq!(before, after);
        assert!(unchanged);
    }
    let result = candidate.finish();
    row.fill(marker);
    let (kernel_emit, kernel_finish) = candidate.probe_failed_kernel(&mut row);
    let unchanged = row.iter().all(|x| *x == marker);
    record(
        json!({"kind":"fault_finish","result":format!("{result:?}"),"kernel_emit":format!("{kernel_emit:?}"),"kernel_finish":format!("{kernel_finish:?}"),"unchanged":unchanged}),
    );
    assert!(matches!(result, Err(SourceError::Failed)));
    assert!(matches!(
        kernel_emit,
        Err(MatrixAccumulatorError::TerminalFailure)
    ));
    assert!(matches!(
        kernel_finish,
        Err(MatrixAccumulatorError::TerminalFailure)
    ));
    assert!(unchanged);
    let report = json!({"kind":"fault_summary","successful_rows":689,"upstream_rows":690,"failure_row":689,"class_accepted":0,"class_cursor":1008,"position":candidate.position(),"initial_generation":initial(candidate.initial_generation()),"matrix_generation":matrix(candidate.matrix_generation())});
    record(report.clone());
    report
}
/// Main construction and one serial fixed fault, with no caller supplied inputs.
pub fn fixed_accumulator_controls() -> Value {
    let main = main_walk();
    let fault = shortage_walk();
    let calls = main["initial_generation"][1].as_u64().unwrap()
        + main["matrix_generation"][1].as_u64().unwrap()
        + fault["initial_generation"][1].as_u64().unwrap()
        + fault["matrix_generation"][1].as_u64().unwrap();
    let report =
        json!({"kind":"combined_summary","main":main,"fault":fault,"trace_generator_calls":calls});
    record(report.clone());
    report
}
