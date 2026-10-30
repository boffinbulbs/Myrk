//! Fixed synthetic forward construction and independent saved state checks.
use crate::{
    build::{
        decoder_state::DecodeError,
        forward_reference::{ForwardReference, ReferenceError, WINDOW},
        forward_source::{ForwardSource, ForwardSourceError},
        hash_source::Generation,
        initial_source::InitialError,
        sample_state::SampleError,
    },
    layout::*,
    ntt::{self, Op},
    BoundInputs, Witness,
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde_json::{json, Value};
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use thorum_core::Amount;
use thorum_crypto_lab::{SealedNote, KEM_CIPHERTEXT_BYTES};
use thorum_relation_lab::{PaymentOutput, PaymentStatement};
fn record(value: Value) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&dir).unwrap();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("observations.jsonl"))
        .unwrap();
    serde_json::to_writer(&mut f, &value).unwrap();
    f.write_all(b"\n").unwrap();
    f.sync_all().unwrap();
}
fn bytes<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N);
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
fn generations(g: Generation) -> [usize; 3] {
    [g.attempted, g.completed, g.maximum_live]
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
fn mismatch(row: &[BabyBear], expected: &[BabyBear]) -> Option<usize> {
    row[NTT_OUTPUT..FORWARD_WIDTH]
        .iter()
        .zip(&expected[NTT_OUTPUT..FORWARD_WIDTH])
        .position(|(a, b)| a != b)
        .map(|i| NTT_OUTPUT + i)
}
fn equal(row: &[BabyBear], expected: &[BabyBear], at: usize) {
    if let Some(column) = mismatch(row, expected) {
        record(json!({"kind":"forward_mismatch","row":at,"first_column":column}));
        panic!("forward mismatch at row {at}, column {column}");
    }
}
fn golden(row: &[BabyBear], column: usize, expected: u32, at: usize) {
    if row[column].as_canonical_u32() != expected {
        record(json!({"kind":"independent_mismatch","row":at,"first_column":column}));
        panic!("forward golden mismatch at row {at}, column {column}");
    }
}
/// Fixed sources only. The saved reference inputs never enter the candidate.
pub fn fixed_forward_walk() -> Value {
    let f: Value = serde_json::from_str(include_str!(
        "../../signature-hash-source/fixtures-hash.json"
    ))
    .unwrap();
    let saved: Value = serde_json::from_str(include_str!("../fixtures-forward.json")).unwrap();
    let records = saved["forwards"].as_array().unwrap();
    assert_eq!(records.len(), 16);
    let inputs = core::array::from_fn(|t| {
        if t < 8 {
            vector(&records[t]["input"])
        } else {
            vector(&saved["unscaled_t1"][t - 8])
        }
    });
    let witness = Witness::from_sources(
        bytes(f["key_hex"].as_str().unwrap()),
        bytes(f["signature_hex"].as_str().unwrap()),
        bytes(f["note_hex"].as_str().unwrap()),
    );
    let tx = tx();
    let canonical = tx.canonical_bytes().unwrap();
    let t = f["transaction"]["canonical_T_hex"].as_str().unwrap();
    assert_eq!(canonical.len() * 2, t.len());
    assert!(canonical
        .iter()
        .enumerate()
        .all(|(i, b)| *b == u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap()));
    let bound = BoundInputs::bind(witness, tx).unwrap();
    let public = bound.public_values();
    let expected = bytes::<196>(f["transaction"]["A196_hex"].as_str().unwrap());
    assert_eq!(public.len(), 196);
    assert!(public
        .iter()
        .zip(expected)
        .all(|(a, e)| a.as_canonical_u32() == u32::from(e)));
    let mut candidate = match ForwardSource::new(&bound) {
        Ok(s) => s,
        Err(DecodeError::Encoding(e)) => panic!("synthetic encoding: {e:?}"),
        Err(_) => panic!("unexpected initialization"),
    };
    let early = candidate.finish();
    record(
        json!({"kind":"incomplete","result":format!("{early:?}"),"generation":generations(candidate.generation())}),
    );
    assert!(matches!(early, Err(ForwardSourceError::Incomplete)));
    let mut reference = ForwardReference::new(inputs);
    for at in [1, 32] {
        let refused = reference.prepare(at);
        let untouched = reference.pristine();
        record(
            json!({"kind":"reference_sequence","requested":at,"result":format!("{refused:?}"),"prepared":reference.prepared(),"unchanged":untouched}),
        );
        assert!(matches!(refused, Err(ReferenceError::Sequence)));
        assert!(untouched);
    }
    let marker = BabyBear::from_u32(17);
    let mut row = vec![marker; WIDTH];
    let mut short = vec![marker; WIDTH - 1];
    let mut stages = 0;
    let mut outputs = 0;
    let mut source_values = 0;
    let mut controls = 0;
    let mut windows = 0;
    for at in 0..HEIGHT {
        if at < 2 {
            let before = candidate.generation();
            let result = candidate.emit_next(&mut short);
            let after = candidate.generation();
            let unchanged = short.iter().all(|x| *x == marker);
            record(
                json!({"kind":"shape_refusal","row":at,"result":format!("{result:?}"),"before":generations(before),"after":generations(after),"unchanged":unchanged}),
            );
            assert!(matches!(result, Err(ForwardSourceError::RowShape)));
            assert_eq!(before, after);
            assert!(unchanged);
        }
        if at.is_multiple_of(WINDOW) {
            reference.prepare(at).unwrap();
            windows += 1;
        }
        row.fill(marker);
        assert_eq!(candidate.emit_next(&mut row).unwrap(), at);
        let expected = reference.row(at);
        equal(&row, expected, at);
        assert!(row[CLOCK..MESSAGE]
            .iter()
            .chain(&row[FORWARD_WIDTH..ACTIVE_CHALLENGE])
            .chain(&row[ACTIVE_CHALLENGE + 1..])
            .all(|x| *x == marker));
        if let Some((t, Op::Initialize(group))) = ntt::operation(at) {
            for slot in 0..8 {
                let index = group * 8 + slot;
                let (column, factor) = ntt::source(t, index);
                golden(&row, column, inputs[t][index], at);
                let canonical = records[t]["input"][index].as_u64().unwrap() as u32;
                assert_eq!(inputs[t][index] * factor, canonical);
                let write: u32 = (0..23)
                    .map(|b| row[NTT_WRITES + 46 * slot + b].as_canonical_u32() << b)
                    .sum();
                if write != canonical {
                    record(
                        json!({"kind":"input_write_mismatch","row":at,"first_column":NTT_WRITES+46*slot}),
                    );
                    panic!("forward source write at row {at}, slot {slot}");
                }
                source_values += 1;
            }
        }
        for (t, saved_transform) in records.iter().enumerate() {
            let start = ntt::START + ntt::ROWS_PER_TRANSFORM * t;
            for (stage, saved_state) in saved_transform["stages"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
            {
                if at == start + 32 + 16 * stage {
                    let values = vector(saved_state);
                    for (i, &v) in values.iter().enumerate() {
                        golden(&row, NTT_SCRATCH + i, v, at);
                    }
                    record(
                        json!({"kind":"stage_checkpoint","row":at,"transform":t,"stage":stage,"coefficients":256}),
                    );
                    stages += 1;
                }
            }
            if at == start + 192 {
                let values = vector(&saved_transform["output"]);
                for (i, &v) in values.iter().enumerate() {
                    golden(&row, output_column(t, i), v, at);
                }
                record(
                    json!({"kind":"output_checkpoint","row":at,"transform":t,"bank":OUTPUT_BANKS[t],"coefficients":256}),
                );
                outputs += 1;
            }
        }
        let corrupt = match at {
            0 => Some(NTT_PRODUCTS + crate::mul::COMPLEMENTS),
            450 => Some(NTT_WRITES + 8 * 46),
            482 => Some(NTT_PRODUCTS + crate::mul::CARRY0),
            610 => Some(NTT_SCRATCH + 1),
            642 => Some(output_column(0, 0)),
            8191 => Some(NTT_OUTPUT + 2303),
            _ => None,
        };
        if let Some(column) = corrupt {
            let original = row[column];
            row[column] += BabyBear::ONE;
            let detected = mismatch(&row, expected) == Some(column);
            record(
                json!({"kind":"comparator_corruption","row":at,"column":column,"detected":detected}),
            );
            assert!(detected);
            row[column] = original;
            equal(&row, expected, at);
            controls += 1;
        }
    }
    let finish = candidate.finish();
    record(json!({"kind":"complete","result":format!("{finish:?}")}));
    if let Err(ForwardSourceError::Initial(InitialError::Sample(reason))) = &finish {
        match reason {
            SampleError::Incomplete
            | SampleError::UnsupportedChallengeClass
            | SampleError::RowShape
            | SampleError::Exhausted => panic!("initial completion: {reason:?}"),
        }
    }
    assert!(finish.is_ok());
    let before = candidate.generation();
    row.fill(marker);
    let exhausted = candidate.emit_next(&mut row);
    let after = candidate.generation();
    let unchanged = row.iter().all(|x| *x == marker);
    record(
        json!({"kind":"exhaustion","result":format!("{exhausted:?}"),"before":generations(before),"after":generations(after),"unchanged":unchanged}),
    );
    assert!(matches!(exhausted, Err(ForwardSourceError::Exhausted)));
    assert_eq!(before, after);
    assert!(unchanged);
    let terminal = reference.row(HEIGHT - 1)[NTT_OUTPUT..FORWARD_WIDTH].to_vec();
    let refused = reference.prepare(HEIGHT);
    let unchanged = reference.row(HEIGHT - 1)[NTT_OUTPUT..FORWARD_WIDTH] == terminal;
    record(
        json!({"kind":"reference_exhaustion","result":format!("{refused:?}"),"prepared":reference.prepared(),"unchanged":unchanged}),
    );
    assert!(matches!(refused, Err(ReferenceError::Exhausted)));
    assert!(unchanged);
    let report = json!({"kind":"forward_summary","rows":HEIGHT,"reference_rows":reference.prepared(),"reference_windows":windows,
        "forward_comparisons":HEIGHT*(FORWARD_WIDTH-NTT_OUTPUT),"protected_source_comparisons":candidate.preservation_positions(),
        "initial_protected_comparisons":candidate.initial_preservation_positions(),"outside_comparisons":HEIGHT*(MESSAGE-CLOCK+WIDTH-FORWARD_WIDTH-1),
        "source_values":source_values,"stage_checkpoints":stages,"stage_coefficients":stages*256,"output_checkpoints":outputs,"output_coefficients":outputs*256,
        "comparator_controls":controls,"restored_controls":controls,"shape_refusals":2,"sequence_refusals":2,"incomplete_refusals":1,
        "exhaustion_refusals":1,"reference_exhaustion_refusals":1,"candidate_generation":generations(candidate.generation()),"reference_hash_generations":0});
    record(report.clone());
    report
}
