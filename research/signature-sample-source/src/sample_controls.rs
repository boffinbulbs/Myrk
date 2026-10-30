//! Fixed synthetic source composition diagnostics, without payment admission.
use crate::{
    build::{
        decoder_state::DecodeError,
        hash_source::Generation,
        initial_source::{InitialError, InitialSource},
        sample_reference::SampleReference,
        sample_state::SampleError,
    },
    layout::*,
    BoundInputs, Witness, MODULUS,
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde_json::{json, Value};
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use thorum_core::Amount;
use thorum_crypto_lab::{SealedNote, KEM_CIPHERTEXT_BYTES};
use thorum_relation_lab::{PaymentOutput, PaymentStatement};

const CHECKPOINTS: [usize; 11] = [0, 5, 6, 11, 12, 81, 82, 275, 276, 277, 8191];
fn record(value: Value) {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("observations.jsonl"))
        .unwrap();
    serde_json::to_writer(&mut output, &value).unwrap();
    output.write_all(b"\n").unwrap();
    output.sync_all().unwrap();
}
fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}
fn transaction() -> PaymentStatement {
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
fn integer(row: &[BabyBear], start: usize, bits: usize) -> u32 {
    (0..bits)
        .map(|i| row[start + i].as_canonical_u32() << i)
        .sum()
}
fn count(row: &[BabyBear]) -> usize {
    assert_eq!(
        row[COUNT..COUNT + 61]
            .iter()
            .filter(|x| **x == BabyBear::ONE)
            .count(),
        1
    );
    row[COUNT..COUNT + 61]
        .iter()
        .position(|x| *x == BabyBear::ONE)
        .unwrap()
}
fn mismatch(row: &[BabyBear], expected: &[BabyBear], active: BabyBear) -> Option<usize> {
    row[SIGN_BITS..INITIAL_WIDTH]
        .iter()
        .zip(expected)
        .position(|(a, b)| a != b)
        .map(|i| SIGN_BITS + i)
        .or_else(|| (row[ACTIVE_CHALLENGE] != active).then_some(ACTIVE_CHALLENGE))
}
fn assert_match(row: &[BabyBear], expected: &[BabyBear], active: BabyBear, at: usize) {
    if let Some(column) = mismatch(row, expected, active) {
        record(json!({"kind":"sampler_mismatch","row":at,"first_column":column}));
        panic!("sampler source mismatch at row {at}, column {column}");
    }
}

/// One fixed same-owner walk. No caller supplied witness, XOF or callback.
pub fn fixed_sample_walk() -> Value {
    let f: Value = serde_json::from_str(include_str!(
        "../../signature-hash-source/fixtures-hash.json"
    ))
    .unwrap();
    let saved: Value = serde_json::from_str(include_str!("../fixtures-sample.json")).unwrap();
    let witness = Witness::from_sources(
        bytes(f["key_hex"].as_str().unwrap()),
        bytes(f["signature_hex"].as_str().unwrap()),
        bytes(f["note_hex"].as_str().unwrap()),
    );
    let tx = transaction();
    let canonical = tx.canonical_bytes().unwrap();
    let t = f["transaction"]["canonical_T_hex"].as_str().unwrap();
    assert_eq!(canonical.len() * 2, t.len());
    assert!(canonical
        .iter()
        .enumerate()
        .all(|(i, b)| *b == u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap()));
    let inputs = BoundInputs::bind(witness, tx).unwrap();
    let public = inputs.public_values();
    let expected_public = bytes::<196>(f["transaction"]["A196_hex"].as_str().unwrap());
    assert_eq!(public.len(), 196);
    assert!(public
        .iter()
        .zip(expected_public)
        .all(|(a, e)| a.as_canonical_u32() == u32::from(e)));
    let mut source = match InitialSource::new(&inputs) {
        Ok(s) => s,
        Err(DecodeError::Encoding(e)) => panic!("synthetic encoding: {e:?}"),
        Err(_) => panic!("unexpected source initialization failure"),
    };
    let early = source.finish();
    record(
        json!({"kind":"incomplete","result":format!("{early:?}"),"generation":generations(source.generation())}),
    );
    assert!(matches!(
        early,
        Err(InitialError::Sample(SampleError::Incomplete))
    ));
    assert_eq!(generations(source.generation()), [0, 0, 0]);
    let xof = bytes::<272>(f["expected"]["challenge_xof272_hex"].as_str().unwrap());
    let mut oracle = SampleReference::new(&xof);
    let marker = BabyBear::from_u32(17);
    let mut row = vec![marker; WIDTH];
    let mut short = vec![marker; WIDTH - 1];
    let mut rejected = Vec::new();
    let mut alias_rows = Vec::new();
    let mut events = 0;
    let mut takes = 0;
    let mut terminal_checks = 0;
    let mut comparisons = 0;
    let mut outside = 0;
    let mut controls = 0;
    let mut first_terminal = None;
    for at in 0..HEIGHT {
        if at < 2 {
            let before = source.generation();
            let result = source.emit_next(&mut short);
            let after = source.generation();
            let unchanged = short.iter().all(|x| *x == marker);
            record(
                json!({"kind":"shape_refusal","row":at,"result":format!("{result:?}"),
                "before":generations(before),"after":generations(after),"unchanged":unchanged}),
            );
            assert!(matches!(result, Err(InitialError::RowShape)));
            assert_eq!(before, after);
            assert!(unchanged);
        }
        row.fill(marker);
        assert_eq!(source.emit_next(&mut row).unwrap(), at);
        let expected = oracle.band(at);
        let active = SampleReference::activity(expected, at);
        assert_match(&row, expected, active, at);
        comparisons += INITIAL_WIDTH - SIGN_BITS + 1;
        assert!(row[CLOCK..MESSAGE]
            .iter()
            .chain(&row[INITIAL_WIDTH..ACTIVE_CHALLENGE])
            .chain(&row[ACTIVE_CHALLENGE + 1..])
            .all(|x| *x == marker));
        outside +=
            MESSAGE - CLOCK + ACTIVE_CHALLENGE - INITIAL_WIDTH + WIDTH - ACTIVE_CHALLENGE - 1;
        for (i, &value) in xof.iter().enumerate() {
            let ready = if i < 136 { 6 } else { 12 };
            assert_eq!(
                row[CHALLENGE_XOF + i].as_canonical_u32(),
                u32::from(if at >= ready { value } else { 0 }),
                "source XOF at row {at}, column {}",
                CHALLENGE_XOF + i
            );
        }
        let accepted = count(&row);
        let cursor = integer(&row, CURSOR, 9);
        if accepted == 60 && first_terminal.is_none() {
            first_terminal = Some(at);
        }
        if active == BabyBear::ONE {
            events += 1;
            if row[TAKE] == BabyBear::ONE {
                takes += 1;
                if integer(&row, CANDIDATE, 8) as usize == 196 + accepted {
                    alias_rows.push(at);
                }
            } else {
                rejected.push(cursor);
            }
        }
        if [82, 276, 8191].contains(&at) {
            let signed = saved["challenge_signed"].as_array().unwrap();
            assert_eq!(signed.len(), 256);
            let mut weight = 0;
            for (i, coefficient) in signed.iter().enumerate() {
                let c = coefficient.as_i64().unwrap();
                assert!((-1..=1).contains(&c));
                let expected = if c < 0 { MODULUS - 1 } else { c as u32 };
                if row[CHALLENGE + i].as_canonical_u32() != expected {
                    record(json!({"kind":"terminal_mismatch","row":at,"first_column":CHALLENGE+i}));
                    panic!("terminal coefficient {i} at row {at}");
                }
                weight += usize::from(expected != 0);
            }
            if (accepted, cursor, weight) != (60, 78, 60) {
                record(
                    json!({"kind":"terminal_state_mismatch","row":at,"count":accepted,"cursor":cursor,"weight":weight}),
                );
                panic!("terminal sampler state at row {at}");
            }
            terminal_checks += 1;
        }
        if CHECKPOINTS.contains(&at) {
            record(
                json!({"kind":"sample_checkpoint","row":at,"count":accepted,"cursor":cursor,
                "active":active.as_canonical_u32(),"take":row[TAKE].as_canonical_u32(),
                "independent_terminal": ([82,276,8191].contains(&at))}),
            );
        }
        let corrupt = match at {
            6 => Some(SIGN_BITS),
            12 => Some(TAKE),
            82 => Some(ACTIVE_CHALLENGE),
            276 => Some(CANDIDATE),
            8191 => Some(CHALLENGE),
            _ => None,
        };
        if let Some(column) = corrupt {
            let original = row[column];
            row[column] += BabyBear::ONE;
            let detected = mismatch(&row, expected, active) == Some(column);
            record(
                json!({"kind":"comparator_corruption","row":at,"column":column,"detected":detected}),
            );
            assert!(detected);
            row[column] = original;
            assert_match(&row, expected, active, at);
            controls += 1;
        }
        if at >= 277 {
            assert!(!oracle.prefix_live());
        }
    }
    let finish = source.finish();
    record(json!({"kind":"complete","result":format!("{finish:?}")}));
    assert!(finish.is_ok());
    let before = source.generation();
    row.fill(marker);
    let exhausted = source.emit_next(&mut row);
    let after = source.generation();
    let unchanged = row.iter().all(|x| *x == marker);
    record(
        json!({"kind":"exhaustion","result":format!("{exhausted:?}"),"before":generations(before),
        "after":generations(after),"unchanged":unchanged}),
    );
    assert!(matches!(exhausted, Err(InitialError::Exhausted)));
    assert_eq!(before, after);
    assert!(unchanged);
    let expected_rejected: Vec<u32> = saved["challenge_cursor"]["rejected_byte_indices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect();
    let report = json!({"kind":"sample_summary","rows":HEIGHT,"original_prefix_rows":277,
        "original_fill_calls":1,"sampler_comparisons":comparisons,"outside_comparisons":outside,
        "protected_prefix_comparisons":source.preservation_positions(),"xof_byte_comparisons":HEIGHT*272,
        "checkpoints":CHECKPOINTS.len(),"terminal_checks":terminal_checks,"terminal_coefficients":terminal_checks*256,
        "events":events,"takes":takes,"rejects":rejected.len(),"rejected_byte_indices":rejected,
        "first_terminal_row":first_terminal,"observed_alias_rows":alias_rows,
        "comparator_controls":controls,"restored_controls":controls,"shape_refusals":2,
        "incomplete_refusals":1,"completion_checks":1,"exhaustion_refusals":1,
        "candidate_generation":generations(source.generation()),"reference_hash_generations":0,
        "prefix_released":!oracle.prefix_live()});
    record(report.clone());
    assert_eq!(rejected, expected_rejected);
    report
}
