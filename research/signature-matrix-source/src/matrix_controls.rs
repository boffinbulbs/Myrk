//! Fixed synthetic matrix hash and current squeeze bank construction controls.
use crate::{
    build::{
        decoder_state::DecodeError,
        hash_source::Generation,
        matrix_overlay::MatrixGeneration,
        matrix_reference::{MatrixReference, ReferenceError},
        matrix_source::{hash_row, MatrixSource, MatrixSourceError},
    },
    full_program as fp,
    layout::*,
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
fn initial(g: Generation) -> [usize; 3] {
    [g.attempted, g.completed, g.maximum_live]
}
fn matrix(g: MatrixGeneration) -> [usize; 3] {
    [g.attempted, g.completed, g.maximum_live]
}
fn mismatch(row: &[BabyBear], expected: &[BabyBear], at: usize) -> Option<usize> {
    if hash_row(at) {
        if let Some(i) = row[..CLOCK]
            .iter()
            .zip(&expected[..CLOCK])
            .position(|(a, b)| a != b)
        {
            return Some(i);
        }
        if let Some(i) = row[MESSAGE..RHO]
            .iter()
            .zip(&expected[MESSAGE..RHO])
            .position(|(a, b)| a != b)
        {
            return Some(MESSAGE + i);
        }
    }
    row[MATRIX_XOF..MATRIX_XOF + 1008]
        .iter()
        .zip(&expected[MATRIX_XOF..MATRIX_XOF + 1008])
        .position(|(a, b)| a != b)
        .map(|i| MATRIX_XOF + i)
}
fn equal(row: &[BabyBear], expected: &[BabyBear], at: usize) {
    if let Some(column) = mismatch(row, expected, at) {
        record(json!({"kind":"matrix_mismatch","row":at,"first_column":column}));
        panic!("matrix mismatch at row {at}, column {column}");
    }
}
fn golden(actual: u32, expected: u8, at: usize, column: usize) {
    if actual != u32::from(expected) {
        record(json!({"kind":"independent_mismatch","row":at,"first_column":column}));
        panic!("matrix golden at row {at}, column {column}");
    }
}
/// A fixed same-owner walk. Saved stream bytes are comparison values only.
pub fn fixed_matrix_walk() -> Value {
    let f: Value = serde_json::from_str(include_str!("../fixtures-matrix.json")).unwrap();
    let records = f["streams"].as_array().unwrap();
    assert_eq!(records.len(), 56);
    let streams: [[u8; 1008]; 56] = core::array::from_fn(|s| {
        assert_eq!(records[s]["chronological_index"], json!(s));
        assert_eq!(records[s]["row"], json!(s % 8));
        assert_eq!(records[s]["column"], json!(s / 8));
        bytes(records[s]["six_block_stream_hex"].as_str().unwrap())
    });
    let rho = bytes::<32>(f["rho_hex"].as_str().unwrap());
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
    let a = bytes::<196>(f["transaction"]["A196_hex"].as_str().unwrap());
    assert_eq!(public.len(), 196);
    assert!(public
        .iter()
        .zip(a)
        .all(|(x, v)| x.as_canonical_u32() == u32::from(v)));
    let mut candidate = match MatrixSource::new(&bound) {
        Ok(s) => s,
        Err(DecodeError::Encoding(e)) => panic!("synthetic encoding: {e:?}"),
        Err(_) => panic!("unexpected initialization"),
    };
    let early = candidate.finish();
    record(
        json!({"kind":"incomplete","result":format!("{early:?}"),"initial_generation":initial(candidate.initial_generation()),"matrix_generation":matrix(candidate.matrix_generation())}),
    );
    assert!(matches!(early, Err(MatrixSourceError::Incomplete)));
    let mut reference = MatrixReference::new(rho);
    for requested in [1, 6] {
        let result = reference.prepare(requested);
        let unchanged = reference.pristine();
        record(
            json!({"kind":"reference_sequence","requested":requested,"result":format!("{result:?}"),"prepared":reference.prepared(),"unchanged":unchanged}),
        );
        assert!(matches!(result, Err(ReferenceError::Sequence)));
        assert!(unchanged);
    }
    let marker = BabyBear::from_u32(17);
    let mut row = vec![marker; WIDTH];
    let mut short = vec![marker; WIDTH - 1];
    let mut hash_rows = 0;
    let mut hash_comparisons = 0;
    let mut windows = 0;
    let mut xof_comparisons = 0;
    let mut terminals = 0;
    let mut boundaries = 0;
    let mut controls = 0;
    let mut rho_checks = 0;
    for at in 0..HEIGHT {
        if at < 2 {
            let before_i = candidate.initial_generation();
            let before_m = candidate.matrix_generation();
            let result = candidate.emit_next(&mut short);
            let after_i = candidate.initial_generation();
            let after_m = candidate.matrix_generation();
            let unchanged = short.iter().all(|x| *x == marker);
            record(
                json!({"kind":"shape_refusal","row":at,"result":format!("{result:?}"),"initial_before":initial(before_i),"initial_after":initial(after_i),
                "matrix_before":matrix(before_m),"matrix_after":matrix(after_m),"unchanged":unchanged}),
            );
            assert!(matches!(result, Err(MatrixSourceError::RowShape)));
            assert_eq!(before_i, after_i);
            assert_eq!(before_m, after_m);
            assert!(unchanged);
        }
        if at.is_multiple_of(6) {
            reference.prepare(at).unwrap();
            windows += 1;
        }
        let expected = reference.row(at);
        row.fill(marker);
        assert_eq!(candidate.emit_next(&mut row).unwrap(), at);
        equal(&row, expected, at);
        if hash_row(at) {
            hash_rows += 1;
            hash_comparisons += CLOCK + RHO - MESSAGE;
        }
        let coordinate = fp::matrix(at);
        for byte in 0..1008 {
            let value = coordinate.map_or(0, |(i, j, local)| {
                if byte < 168 * (local / 6).min(6) {
                    streams[8 * j + i][byte]
                } else {
                    0
                }
            });
            golden(
                row[MATRIX_XOF + byte].as_canonical_u32(),
                value,
                at,
                MATRIX_XOF + byte,
            );
            xof_comparisons += 1;
        }
        if let Some((i, j, local)) = coordinate {
            if local < 36 && local.is_multiple_of(6) {
                for (k, &v) in rho.iter().enumerate() {
                    golden(row[RHO + k].as_canonical_u32(), v, at, RHO + k);
                    rho_checks += 1;
                }
            }
            if local < 36 && local % 6 == 5 {
                let block = local / 6;
                for byte in 0..168 {
                    let value: u32 = (0..8)
                        .map(|b| row[OUTPUT + 8 * byte + b].as_canonical_u32() << b)
                        .sum();
                    golden(
                        value,
                        streams[8 * j + i][168 * block + byte],
                        at,
                        OUTPUT + 8 * byte,
                    );
                }
                record(
                    json!({"kind":"squeeze_checkpoint","row":at,"stream":8*j+i,"block":block,"bytes":168}),
                );
                terminals += 1;
            }
        }
        if coordinate.is_some_and(|(_, _, local)| [0, 5, 6, 35, 36, 47].contains(&local))
            || [0, 641, 3330, 8191].contains(&at)
        {
            record(
                json!({"kind":"bank_checkpoint","row":at,"stream":coordinate.map(|(i,j,_)|8*j+i),"local":coordinate.map(|(_,_,l)|l),"ready_bytes":coordinate.map_or(0,|(_,_,l)|168*(l/6).min(6)),"bytes":1008}),
            );
            boundaries += 1;
        }
        let corrupt = match at {
            0 => Some(MATRIX_XOF),
            642 => Some(MESSAGE),
            647 => Some(OUTPUT),
            648 => Some(MATRIX_XOF),
            653 => Some(CLOCK - 1),
            3330 => Some(MATRIX_XOF),
            8191 => Some(MATRIX_XOF + 1007),
            _ => None,
        };
        if let Some(column) = corrupt {
            let value = row[column];
            row[column] += BabyBear::ONE;
            let detected = mismatch(&row, expected, at) == Some(column);
            record(
                json!({"kind":"comparator_corruption","row":at,"column":column,"detected":detected}),
            );
            assert!(detected);
            row[column] = value;
            equal(&row, expected, at);
            controls += 1;
        }
    }
    let finish = candidate.finish();
    record(json!({"kind":"complete","result":format!("{finish:?}")}));
    assert!(finish.is_ok());
    let before_i = candidate.initial_generation();
    let before_m = candidate.matrix_generation();
    row.fill(marker);
    let result = candidate.emit_next(&mut row);
    let after_i = candidate.initial_generation();
    let after_m = candidate.matrix_generation();
    let unchanged = row.iter().all(|x| *x == marker);
    record(
        json!({"kind":"exhaustion","result":format!("{result:?}"),"initial_before":initial(before_i),"initial_after":initial(after_i),"matrix_before":matrix(before_m),"matrix_after":matrix(after_m),"unchanged":unchanged}),
    );
    assert!(matches!(result, Err(MatrixSourceError::Exhausted)));
    assert_eq!(before_i, after_i);
    assert_eq!(before_m, after_m);
    assert!(unchanged);
    let terminal = reference.row(HEIGHT - 1)[MATRIX_XOF..MATRIX_XOF + 1008].to_vec();
    let before = reference.generation();
    let result = reference.prepare(HEIGHT);
    let unchanged = reference.row(HEIGHT - 1)[MATRIX_XOF..MATRIX_XOF + 1008] == terminal;
    let after = reference.generation();
    record(
        json!({"kind":"reference_exhaustion","result":format!("{result:?}"),"prepared":reference.prepared(),"before":matrix(before),"after":matrix(after),"unchanged":unchanged}),
    );
    assert!(matches!(result, Err(ReferenceError::Exhausted)));
    assert_eq!(before, after);
    assert!(unchanged);
    let report = json!({"kind":"matrix_summary","rows":HEIGHT,"reference_rows":reference.prepared(),"reference_windows":windows,"last_reference_rows":HEIGHT%6,
        "hash_rows":hash_rows,"hash_comparisons":hash_comparisons,"xof_comparisons":xof_comparisons,"preserved_comparisons":candidate.preserved(),
        "forward_preserved_comparisons":candidate.forward_preserved(),"initial_preserved_comparisons":candidate.initial_preserved(),
        "rho_bytes":rho_checks,"squeeze_checkpoints":terminals,"squeeze_bytes":terminals*168,"bank_checkpoints":boundaries,
        "comparator_controls":controls,"restored_controls":controls,"shape_refusals":2,"sequence_refusals":2,"incomplete_refusals":1,"exhaustion_refusals":1,"reference_exhaustion_refusals":1,
        "initial_generation":initial(candidate.initial_generation()),"matrix_generation":matrix(candidate.matrix_generation()),"reference_generation":matrix(reference.generation())});
    record(report.clone());
    report
}
