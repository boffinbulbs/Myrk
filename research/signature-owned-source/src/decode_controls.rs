//! Fixed synthetic diagnostics for the partial decoding constructor.
//! These functions expose no private rows and establish no payment authority.
use crate::{
    layout::*,
    producer::{reference_prefix, DecodeError, DecodeState},
    BoundInputs, Witness,
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde_json::Value;
use thorum_core::Amount;
use thorum_crypto_lab::{SealedNote, KEM_CIPHERTEXT_BYTES};
use thorum_relation_lab::{PaymentOutput, PaymentStatement};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures-decode.json")).unwrap()
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
fn sources(f: &Value) -> ([u8; 2592], [u8; 4627], [u8; 418]) {
    (
        bytes(f["key_hex"].as_str().unwrap()),
        bytes(f["signature_hex"].as_str().unwrap()),
        bytes(f["note_hex"].as_str().unwrap()),
    )
}
fn bound(key: [u8; 2592], signature: [u8; 4627], note: [u8; 418]) -> BoundInputs {
    BoundInputs::bind(Witness::from_sources(key, signature, note), transaction()).unwrap()
}

#[derive(Debug)]
pub struct DecodeReport {
    pub case: &'static str,
    pub rows: usize,
    pub reference_rows: usize,
    pub owned_cells: usize,
    pub preserved_cells: usize,
    pub independent_terminal_values: usize,
    pub corruption_controls: usize,
    pub restored_controls: usize,
    pub public_values: usize,
    pub exhausted_without_writes: bool,
}

/// Compare the real extracted decoder with its unchanged retained loop and
/// independent terminal coefficients. Inputs are fixed public synthetic data.
pub enum DecodeCase {
    Baseline,
    ZEndpoints,
}

pub fn fixed_source_equivalence(case: DecodeCase) -> DecodeReport {
    source_walk(matches!(case, DecodeCase::ZEndpoints))
}

fn source_walk(endpoints: bool) -> DecodeReport {
    let f = fixture();
    let (key, mut signature, note) = sources(&f);
    let case = if endpoints { "z_endpoints" } else { "baseline" };
    if endpoints {
        let pair = 121u64 | (1_048_455u64 << 20);
        signature[64..69].copy_from_slice(&pair.to_le_bytes()[..5]);
    }
    let inputs = bound(key, signature, note);
    let canonical = transaction().canonical_bytes().unwrap();
    assert_eq!(
        canonical,
        bytes_vec(f["transaction"]["canonical_T_hex"].as_str().unwrap())
    );
    let public = inputs.public_values();
    let expected_public = bytes_vec(f["transaction"]["A196_hex"].as_str().unwrap());
    assert_eq!(
        public
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<_>>(),
        expected_public
            .iter()
            .copied()
            .map(u32::from)
            .collect::<Vec<_>>()
    );
    let mut state = DecodeState::new(&inputs).unwrap();
    let oracle = reference_prefix(&inputs);
    assert_eq!(oracle.len(), 449 * WIDTH);
    let marker = BabyBear::from_u32(17);
    let mut row = vec![marker; WIDTH];
    let mut owned_cells = 0;
    let mut preserved_cells = 0;
    let mut corruptions = 0;
    let mut restored = 0;
    for at in 0..HEIGHT {
        // A reused row must not carry any stale decoding auxiliaries.
        row[T1..SIGN_BITS].fill(marker);
        assert_eq!(state.emit_next(&mut row).unwrap(), at);
        let expected = &oracle[at.min(448) * WIDTH..(at.min(448) + 1) * WIDTH];
        if let Some(offset) = row[T1..SIGN_BITS]
            .iter()
            .zip(&expected[T1..SIGN_BITS])
            .position(|(actual, reference)| actual != reference)
        {
            mismatch_record(case, at, at.min(448), T1 + offset);
            panic!("decoding mismatch at row {at}, column {}", T1 + offset);
        }
        owned_cells += SIGN_BITS - T1;
        assert!(row[..T1]
            .iter()
            .chain(&row[SIGN_BITS..])
            .all(|x| *x == marker));
        preserved_cells += WIDTH - (SIGN_BITS - T1);
        let control = if at == 1 {
            Some(T1)
        } else if at == 448 {
            Some(Z_AUX)
        } else {
            None
        };
        if let Some(column) = control {
            let original = row[column];
            row[column] += BabyBear::ONE;
            assert!(row[T1..SIGN_BITS] != expected[T1..SIGN_BITS]);
            corruptions += 1;
            row[column] = original;
            assert!(row[T1..SIGN_BITS] == expected[T1..SIGN_BITS]);
            restored += 1;
        }
    }
    let terminal = &row;
    let mut coefficients = 0;
    for (i, group) in f["t1"].as_array().unwrap().iter().enumerate() {
        assert_eq!(group.as_array().unwrap().len(), 256);
        for (j, value) in group.as_array().unwrap().iter().enumerate() {
            assert_eq!(
                terminal[T1 + 256 * i + j].as_canonical_u32() as u64,
                value.as_u64().unwrap()
            );
            coefficients += 1;
        }
    }
    assert_eq!(f["t1"].as_array().unwrap().len(), 8);
    for (i, group) in f["z_signed"].as_array().unwrap().iter().enumerate() {
        assert_eq!(group.as_array().unwrap().len(), 256);
        for (j, value) in group.as_array().unwrap().iter().enumerate() {
            let normal = if endpoints && i == 0 && j < 2 {
                [524_167, 7_856_250][j]
            } else {
                value
                    .as_i64()
                    .unwrap()
                    .rem_euclid(i64::from(crate::MODULUS))
            };
            assert_eq!(
                terminal[Z_VALUES + 256 * i + j].as_canonical_u32(),
                normal as u32
            );
            coefficients += 1;
        }
    }
    assert_eq!(f["z_signed"].as_array().unwrap().len(), 7);
    assert_eq!(f["hints"].as_array().unwrap().len(), 8);
    for (i, group) in f["hints"].as_array().unwrap().iter().enumerate() {
        assert_eq!(group.as_array().unwrap().len(), 256);
        for (j, value) in group.as_array().unwrap().iter().enumerate() {
            assert_eq!(
                terminal[HINTS + 256 * i + j].as_canonical_u32() as u64,
                value.as_u64().unwrap()
            );
            coefficients += 1;
        }
    }
    row.fill(marker);
    let exhausted = state.emit_next(&mut row);
    let exhausted_without_writes = row.iter().all(|x| *x == marker);
    control_record(serde_json::json!({"kind":"exhaustion","case":case,
        "result":format!("{exhausted:?}"),"unchanged":exhausted_without_writes}));
    assert!(matches!(exhausted, Err(DecodeError::Exhausted)));
    assert!(exhausted_without_writes);
    DecodeReport {
        case,
        rows: HEIGHT,
        reference_rows: 449,
        owned_cells,
        preserved_cells,
        independent_terminal_values: coefficients,
        corruption_controls: corruptions,
        restored_controls: restored,
        public_values: public.len(),
        exhausted_without_writes,
    }
}

fn mismatch_record(case: &str, row: usize, reference_row: usize, column: usize) {
    control_record(serde_json::json!({"kind":"decode_mismatch",
        "case":case,"row":row,"reference_row":reference_row,"first_column":column}));
}

fn control_record(value: Value) {
    use std::{fs::OpenOptions, io::Write, path::PathBuf};
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

fn bytes_vec(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Encoding controls reach the actual retained preflight before creating state.
pub fn malformed_source_refusals() -> usize {
    let f = fixture();
    let mut rejected = 0;
    for case in 0..7 {
        let (key, mut signature, mut note) = sources(&f);
        match case {
            0 => note[417] = 1,
            1 => set_first_z(&mut signature, 120),
            2 => {
                set_first_z(&mut signature, 1_048_456);
            }
            3 => signature[4620] = 4,
            4 => signature[4626] = 76,
            5 => signature[4545] = signature[4544],
            6 => signature[4590] = 1,
            _ => unreachable!(),
        }
        let inputs = bound(key, signature, note);
        let result = DecodeState::new(&inputs);
        let names = [
            "fixed_note",
            "z_below_range",
            "z_above_range",
            "descending_cuts",
            "cut_above_limit",
            "duplicate_hint",
            "hint_padding",
        ];
        control_record(
            serde_json::json!({"kind":"encoding_refusal","case":names[case],
            "error":result.as_ref().err().map(|error|format!("{error:?}"))}),
        );
        assert!(matches!(
            result,
            Err(DecodeError::Encoding(crate::BuildError::InvalidEncoding))
        ));
        rejected += 1;
    }
    rejected
}

fn set_first_z(signature: &mut [u8; 4627], value: u64) {
    let mut encoded = [0; 8];
    encoded[..5].copy_from_slice(&signature[64..69]);
    let word = (u64::from_le_bytes(encoded) & !0xfffff) | value;
    signature[64..69].copy_from_slice(&word.to_le_bytes()[..5]);
}

/// A malformed destination cannot mutate either row storage or the cursor.
pub fn cursor_shape_guards() -> usize {
    let f = fixture();
    let (key, signature, note) = sources(&f);
    let inputs = bound(key, signature, note);
    let mut state = DecodeState::new(&inputs).unwrap();
    let marker = BabyBear::from_u32(17);
    let mut short = vec![marker; WIDTH - 1];
    let mut row = vec![marker; WIDTH];
    for expected in 0..2 {
        let result = state.emit_next(&mut short);
        let untouched = short.iter().all(|x| *x == marker);
        let next = state.emit_next(&mut row).unwrap();
        control_record(
            serde_json::json!({"kind":"shape_refusal","expected_next":expected,
            "error":format!("{result:?}"),"unchanged":untouched,"actual_next":next}),
        );
        assert!(matches!(result, Err(DecodeError::RowShape)));
        assert!(untouched);
        assert_eq!(next, expected);
    }
    2
}
