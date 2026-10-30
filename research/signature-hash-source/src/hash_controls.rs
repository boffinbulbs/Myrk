//! Fixed synthetic construction diagnostics, not witness or payment validation.
use crate::{
    build::{
        decoder_state::{DecodeError, DecodeState},
        hash_reference::ReferenceBlock,
        hash_source::{Generation, HashError, SourceHashState},
    },
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

const CHECKPOINTS: [usize; 15] = [
    0, 1, 5, 6, 11, 12, 233, 234, 353, 354, 371, 372, 413, 414, 8191,
];

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
fn mismatch(row: &[BabyBear], expected: &[BabyBear]) -> Option<usize> {
    row[..CLOCK]
        .iter()
        .zip(&expected[..CLOCK])
        .position(|(x, y)| x != y)
        .or_else(|| {
            row[MESSAGE..T1]
                .iter()
                .zip(&expected[MESSAGE..T1])
                .position(|(x, y)| x != y)
                .map(|offset| MESSAGE + offset)
        })
}
fn assert_matching(row: &[BabyBear], expected: &[BabyBear], at: usize, phase: &str) {
    if let Some(column) = mismatch(row, expected) {
        record(json!({"kind":"hash_mismatch","row":at,"phase":phase,"first_column":column}));
        panic!("hash source mismatch at row {at}, column {column}");
    }
}
fn generations(g: Generation) -> [usize; 3] {
    [g.attempted, g.completed, g.maximum_live]
}

struct Goldens {
    rho: [u8; 32],
    owner: [u8; 64],
    tr: [u8; 64],
    mu: [u8; 64],
    note: [u8; 64],
    xof: [u8; 272],
}
impl Goldens {
    fn from_fixture(f: &Value) -> Self {
        let e = &f["expected"];
        Self {
            rho: bytes(e["rho_hex"].as_str().unwrap()),
            owner: bytes(e["owner_hex"].as_str().unwrap()),
            tr: bytes(e["tr_hex"].as_str().unwrap()),
            mu: bytes(e["mu_hex"].as_str().unwrap()),
            note: bytes(e["note_commitment_hex"].as_str().unwrap()),
            xof: bytes(e["challenge_xof272_hex"].as_str().unwrap()),
        }
    }
    fn check(&self, row: &[BabyBear], at: usize) -> usize {
        let mut compared = 0;
        for (column, data, ready) in [
            (RHO, self.rho.as_slice(), 1),
            (OWNER, self.owner.as_slice(), 234),
            (TR, self.tr.as_slice(), 354),
            (MU, self.mu.as_slice(), 372),
            (NOTE_COMMITMENT, self.note.as_slice(), 414),
        ] {
            for (i, &value) in data.iter().enumerate() {
                let expected = if at >= ready { value } else { 0 };
                if row[column + i].as_canonical_u32() != u32::from(expected) {
                    record(json!({"kind":"golden_mismatch","row":at,"first_column":column+i}));
                    panic!("source bank mismatch at row {at}, column {}", column + i);
                }
                compared += 1;
            }
        }
        for (i, &value) in self.xof.iter().enumerate() {
            let ready = if i < 136 { 6 } else { 12 };
            let expected = if at >= ready { value } else { 0 };
            if row[CHALLENGE_XOF + i].as_canonical_u32() != u32::from(expected) {
                record(json!({"kind":"golden_mismatch","row":at,"first_column":CHALLENGE_XOF+i}));
                panic!(
                    "source XOF mismatch at row {at}, column {}",
                    CHALLENGE_XOF + i
                );
            }
            compared += 1;
        }
        compared
    }
}

#[derive(Debug)]
pub struct HashReport {
    pub hash_emissions: usize,
    pub decoder_emissions: usize,
    pub reference_rows: usize,
    pub reference_blocks: usize,
    pub owned_comparisons: usize,
    pub outside_comparisons: usize,
    pub composed_hash_comparisons: usize,
    pub composed_outside_comparisons: usize,
    pub independent_bank_bytes: usize,
    pub checkpoints: usize,
    pub corruption_controls: usize,
    pub restored_controls: usize,
    pub candidate_generation: [usize; 3],
    pub reference_generation: [usize; 3],
}

/// The fixed diagnostic composes both source cursors over the same sealed
/// witness and immutable transaction. No private row is returned to callers.
pub fn fixed_hash_walk() -> HashReport {
    let f: Value = serde_json::from_str(include_str!("../fixtures-hash.json")).unwrap();
    let witness = Witness::from_sources(
        bytes(f["key_hex"].as_str().unwrap()),
        bytes(f["signature_hex"].as_str().unwrap()),
        bytes(f["note_hex"].as_str().unwrap()),
    );
    let transaction = transaction();
    let canonical = transaction.canonical_bytes().unwrap();
    let expected_canonical = f["transaction"]["canonical_T_hex"].as_str().unwrap();
    assert_eq!(canonical.len() * 2, expected_canonical.len());
    assert!(
        canonical
            .iter()
            .enumerate()
            .all(|(i, b)| *b
                == u8::from_str_radix(&expected_canonical[2 * i..2 * i + 2], 16).unwrap())
    );
    let inputs = BoundInputs::bind(witness, transaction).unwrap();
    let public = inputs.public_values();
    let expected_public = bytes::<196>(f["transaction"]["A196_hex"].as_str().unwrap());
    assert_eq!(public.len(), 196);
    assert!(public
        .iter()
        .zip(expected_public)
        .all(|(actual, expected)| actual.as_canonical_u32() == u32::from(expected)));
    let mut decoder = match DecodeState::new(&inputs) {
        Ok(state) => state,
        Err(DecodeError::Encoding(error)) => panic!("synthetic decoding source: {error:?}"),
        Err(_) => panic!("unexpected decoding initialization failure"),
    };
    let mut source = SourceHashState::new(&inputs);
    let mut reference = ReferenceBlock::new(&inputs);
    let goldens = Goldens::from_fixture(&f);
    let marker = BabyBear::from_u32(17);
    let mut row = vec![marker; WIDTH];
    let mut short = vec![marker; WIDTH - 1];
    let mut report = HashReport {
        hash_emissions: 0,
        decoder_emissions: 0,
        reference_rows: 0,
        reference_blocks: 0,
        owned_comparisons: 0,
        outside_comparisons: 0,
        composed_hash_comparisons: 0,
        composed_outside_comparisons: 0,
        independent_bank_bytes: 0,
        checkpoints: 0,
        corruption_controls: 0,
        restored_controls: 0,
        candidate_generation: [0; 3],
        reference_generation: [0; 3],
    };
    for at in 0..HEIGHT {
        if at < 2 {
            let before = source.generation();
            let result = source.emit_next(&mut short);
            let after = source.generation();
            let untouched = short.iter().all(|x| *x == marker);
            record(
                json!({"kind":"shape_refusal","row":at,"result":format!("{result:?}"),
                "before":generations(before),"after":generations(after),"unchanged":untouched}),
            );
            assert!(matches!(result, Err(HashError::RowShape)));
            assert_eq!(before, after);
            assert!(untouched);
        }
        if at.is_multiple_of(6) {
            reference.prepare(at);
        }
        let expected = reference.row(at);
        row.fill(marker);
        assert_eq!(source.emit_next(&mut row).unwrap(), at);
        report.hash_emissions += 1;
        assert_matching(&row, expected, at, "initial");
        report.owned_comparisons += CLOCK + T1 - MESSAGE;
        assert!(row[CLOCK..MESSAGE]
            .iter()
            .chain(&row[T1..])
            .all(|x| *x == marker));
        report.outside_comparisons += MESSAGE - CLOCK + WIDTH - T1;
        if CHECKPOINTS.contains(&at) {
            let checked = goldens.check(&row, at);
            report.independent_bank_bytes += checked;
            report.checkpoints += 1;
            record(json!({"kind":"bank_checkpoint","row":at,"bytes_compared":checked}));
        }
        let corruption = match at {
            1 => Some(RHO),
            6 => Some(CHALLENGE_XOF),
            234 => Some(OWNER),
            414 => Some(MESSAGE),
            8191 => Some(CLOCK - 1),
            _ => None,
        };
        if let Some(column) = corruption {
            let original = row[column];
            row[column] += BabyBear::ONE;
            let detected = mismatch(&row, expected) == Some(column);
            record(
                json!({"kind":"comparator_corruption","row":at,"column":column,"detected":detected}),
            );
            assert!(detected);
            report.corruption_controls += 1;
            row[column] = original;
            assert_matching(&row, expected, at, "restored");
            report.restored_controls += 1;
        }
        assert_eq!(decoder.emit_next(&mut row).unwrap(), at);
        report.decoder_emissions += 1;
        assert_matching(&row, expected, at, "after_decoder");
        report.composed_hash_comparisons += CLOCK + T1 - MESSAGE;
        assert!(row[CLOCK..MESSAGE]
            .iter()
            .chain(&row[SIGN_BITS..])
            .all(|x| *x == marker));
        report.composed_outside_comparisons += MESSAGE - CLOCK + WIDTH - SIGN_BITS;
    }
    let before = source.generation();
    row.fill(marker);
    let exhausted = source.emit_next(&mut row);
    let after = source.generation();
    let untouched = row.iter().all(|x| *x == marker);
    record(
        json!({"kind":"exhaustion","result":format!("{exhausted:?}"),"before":generations(before),
        "after":generations(after),"unchanged":untouched}),
    );
    assert!(matches!(exhausted, Err(HashError::Exhausted)));
    assert_eq!(before, after);
    assert!(untouched);
    [report.reference_rows, report.reference_blocks] = reference.prepared();
    report.candidate_generation = generations(source.generation());
    report.reference_generation = generations(reference.generation());
    report
}
