use kova_signature_packed::{
    build_full_private_signature_owner_sources, layout::*, PackedSignatureOwnerAir, Statement,
    Witness,
};
use p3_air::{check_all_constraints, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufReader, Read, Write},
    path::PathBuf,
};
use thorum_core::Amount;
use thorum_crypto_lab::{SealedNote, KEM_CIPHERTEXT_BYTES};
use thorum_relation_lab::{PaymentOutput, PaymentStatement};

#[derive(Clone, Copy)]
enum Expected {
    Accept,
    Owner,
    Context,
    FinalRange,
}
struct Case {
    id: &'static str,
    key: &'static str,
    signature: &'static str,
    transaction: &'static str,
    note: &'static str,
    expected: Expected,
}
const CASES: [Case; 9] = [
    Case {
        id: "A1",
        key: "A",
        signature: "A1",
        transaction: "T1",
        note: "N_A",
        expected: Expected::Accept,
    },
    Case {
        id: "B0",
        key: "B",
        signature: "B0",
        transaction: "T0",
        note: "N_B",
        expected: Expected::Accept,
    },
    Case {
        id: "B1",
        key: "B",
        signature: "B1",
        transaction: "T1",
        note: "N_B",
        expected: Expected::Accept,
    },
    Case {
        id: "A0_empty_context",
        key: "A",
        signature: "A0_empty_context",
        transaction: "T0",
        note: "N_A",
        expected: Expected::Context,
    },
    Case {
        id: "A0_wrong_context41",
        key: "A",
        signature: "A0_wrong_context41",
        transaction: "T0",
        note: "N_A",
        expected: Expected::Context,
    },
    Case {
        id: "A0_same_owner_alternate_note",
        key: "A",
        signature: "A0",
        transaction: "T0",
        note: "N_A_alt",
        expected: Expected::Accept,
    },
    Case {
        id: "A0_wrong_owner_note",
        key: "A",
        signature: "A0",
        transaction: "T0",
        note: "N_B",
        expected: Expected::Owner,
    },
    Case {
        id: "A0_wrong_verification_key",
        key: "B",
        signature: "A0",
        transaction: "T0",
        note: "N_B",
        expected: Expected::FinalRange,
    },
    Case {
        id: "A1_wrong_expected_transaction",
        key: "A",
        signature: "A1",
        transaction: "T0",
        note: "N_A",
        expected: Expected::FinalRange,
    },
];
#[derive(Deserialize)]
struct Raw {
    keys: Vec<Key>,
    signatures: Vec<Signature>,
}
#[derive(Deserialize)]
struct Key {
    id: String,
    public_key_hex: String,
}
#[derive(Deserialize)]
struct Signature {
    id: String,
    signature_hex: String,
}
#[derive(Deserialize)]
struct Reference {
    raw_sha256: String,
    notes: BTreeMap<String, Note>,
    transactions: Vec<Transaction>,
    signature_records: Vec<Record>,
    tuples: Vec<Tuple>,
}
#[derive(Deserialize)]
struct Note {
    opening_hex: String,
    commitment_hex: String,
}
#[derive(Deserialize)]
struct Transaction {
    id: String,
    fee_atoms: u64,
    #[serde(rename = "canonical_T_hex")]
    canonical_t_hex: String,
    #[serde(rename = "A196_hex")]
    authorization_hex: String,
}
#[derive(Deserialize)]
struct Tuple {
    id: String,
    signature_id: String,
    key_id: String,
    transaction_id: String,
    note_id: String,
    bounded_supported: bool,
    conditional_verdict: String,
}
#[derive(Deserialize)]
struct Record {
    id: String,
    key_id: String,
    transaction_id: String,
    fixed_target_stages: Stages,
}
#[derive(Deserialize)]
struct Stages {
    mu_hex: String,
    challenge_expected_hex: String,
}

fn read<T: DeserializeOwned>(name: &str) -> T {
    const LIMIT: u64 = 9 * 1024 * 1024;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../signature-ownership")
        .join(name);
    let file = File::open(path).unwrap();
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file() && metadata.len() <= LIMIT);
    serde_json::from_reader(BufReader::with_capacity(16 * 1024, file.take(LIMIT + 1))).unwrap()
}

fn bytes<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

fn transaction(fee: u64) -> PaymentStatement {
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
        native_fee: Amount::from_atomic(fee),
    }
}

fn record(output: &mut File, value: &Value) {
    serde_json::to_writer(&mut *output, value).unwrap();
    output.write_all(b"\n").unwrap();
    output.sync_all().unwrap();
}

fn compare_bytes(
    trace: &RowMajorMatrix<BabyBear>,
    row: usize,
    start: usize,
    expected: &[u8],
    bits: bool,
) {
    let row = &trace.values[row * WIDTH..(row + 1) * WIDTH];
    for (i, &expected) in expected.iter().enumerate() {
        let actual = if bits {
            (0..8)
                .map(|bit| row[start + 8 * i + bit].as_canonical_u32() << bit)
                .sum()
        } else {
            row[start + i].as_canonical_u32()
        };
        assert_eq!(
            actual,
            u32::from(expected),
            "independent byte comparison {i}"
        );
    }
}

#[test]
#[ignore = "Separate serial nine-tuple native corpus resource admission"]
fn remaining_nine_packed_native_tuples() {
    assert_eq!(
        std::env::var("KOVA_PACKED_CORPUS_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let mut observations = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("observations.jsonl"))
        .unwrap();
    let mut final_output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("corpus.json"))
        .unwrap();
    let raw: Raw = read("raw-fixture.json");
    let reference: Reference = read("reference-fixture.json");
    assert_eq!(
        reference.raw_sha256,
        "10426a9bbfd10707b2a339c63c787bd8d119ee2c76a78316aa03c1edab80c2f2"
    );
    assert_eq!(reference.tuples.len(), 10);
    let air = PackedSignatureOwnerAir;
    assert_eq!(
        <PackedSignatureOwnerAir as BaseAir<BabyBear>>::preprocessed_width(&air),
        0
    );
    assert!(<PackedSignatureOwnerAir as BaseAir<BabyBear>>::preprocessed_trace(&air).is_none());
    assert_eq!(
        <PackedSignatureOwnerAir as BaseAir<BabyBear>>::num_periodic_columns(&air),
        0
    );
    assert!(<PackedSignatureOwnerAir as BaseAir<BabyBear>>::public_boundary_io(&air).is_empty());
    let mut constructed = 0;
    let mut evaluated = 0;
    let mut accepted = 0;
    let mut rejected = 0;
    let mut live = 0;
    let mut maximum_live = 0;
    let mut byte_comparisons = 0;
    let mut independent_bytes = 0;
    let mut inferred_rows = 0;
    let mut ids = Vec::with_capacity(9);
    for case in &CASES {
        assert_eq!(live, 0);
        assert_ne!(case.id, "A0");
        let tuple = reference.tuples.iter().find(|t| t.id == case.id).unwrap();
        assert_eq!(
            (
                &*tuple.key_id,
                &*tuple.signature_id,
                &*tuple.transaction_id,
                &*tuple.note_id
            ),
            (case.key, case.signature, case.transaction, case.note)
        );
        assert!(tuple.bounded_supported);
        let expect_accept = matches!(case.expected, Expected::Accept);
        assert_eq!(
            tuple.conditional_verdict,
            if expect_accept {
                "AcceptConditional"
            } else {
                "Reject"
            }
        );
        let key = bytes::<2592>(
            &raw.keys
                .iter()
                .find(|k| k.id == case.key)
                .unwrap()
                .public_key_hex,
        );
        let signature = bytes::<4627>(
            &raw.signatures
                .iter()
                .find(|s| s.id == case.signature)
                .unwrap()
                .signature_hex,
        );
        let note = &reference.notes[case.note];
        let opening = bytes::<418>(&note.opening_hex);
        let tx = reference
            .transactions
            .iter()
            .find(|t| t.id == case.transaction)
            .unwrap();
        assert_eq!(
            tx.fee_atoms,
            match case.transaction {
                "T0" => 5,
                "T1" => 6,
                _ => panic!("unselected transaction"),
            }
        );
        let transaction = transaction(tx.fee_atoms);
        let canonical = transaction.canonical_bytes().unwrap();
        assert_eq!(canonical.len() * 2, tx.canonical_t_hex.len());
        for (i, byte) in canonical.iter().enumerate() {
            assert_eq!(
                *byte,
                u8::from_str_radix(&tx.canonical_t_hex[2 * i..2 * i + 2], 16).unwrap()
            );
        }
        let public = Statement::from_transaction(&transaction)
            .unwrap()
            .public_values();
        assert_eq!(
            public
                .iter()
                .map(|v| v.as_canonical_u32())
                .collect::<Vec<_>>(),
            bytes::<196>(&tx.authorization_hex).map(u32::from)
        );
        let witness = Witness::from_sources(key, signature, opening);
        // Construction refusal is a gate failure, never a native rejection.
        let trace = build_full_private_signature_owner_sources(&witness, &transaction).unwrap();
        constructed += 1;
        live += 1;
        maximum_live = maximum_live.max(live);
        record(
            &mut observations,
            &json!({"phase":"constructed","id":case.id,"construction":constructed,
            "height":trace.height(),"width":trace.width(),"raw_field_bytes":trace.values.len()*4,"live_traces":live}),
        );
        assert_eq!(
            (trace.height(), trace.width(), trace.values.len() * 4),
            (8192, 43176, 1414791168)
        );
        assert_eq!(live, 1);
        let owner_note = match case.key {
            "A" => "N_A",
            "B" => "N_B",
            _ => panic!("unselected key"),
        };
        let owner_opening = bytes::<418>(&reference.notes[owner_note].opening_hex);
        let mu_id = match (case.key, case.transaction) {
            ("A", "T0") => "A0",
            ("A", "T1") => "A1",
            ("B", "T0") => "B0",
            ("B", "T1") => "B1",
            _ => panic!("unselected key/transaction"),
        };
        let mu = reference
            .signature_records
            .iter()
            .find(|r| r.id == mu_id)
            .unwrap();
        assert_eq!(
            (&*mu.key_id, &*mu.transaction_id),
            (case.key, case.transaction)
        );
        compare_bytes(&trace, 1, RHO, &key[..32], false);
        compare_bytes(&trace, 234, OWNER, &owner_opening[141..205], false);
        compare_bytes(
            &trace,
            8191,
            MU,
            &bytes::<64>(&mu.fixed_target_stages.mu_hex),
            false,
        );
        compare_bytes(
            &trace,
            8191,
            NOTE_COMMITMENT,
            &bytes::<64>(&note.commitment_hex),
            false,
        );
        let signature_record = reference
            .signature_records
            .iter()
            .find(|r| r.id == case.signature)
            .unwrap();
        let final_golden = signature_record.key_id == case.key
            && signature_record.transaction_id == case.transaction;
        if final_golden {
            compare_bytes(
                &trace,
                5369,
                OUTPUT,
                &bytes::<64>(&signature_record.fixed_target_stages.challenge_expected_hex),
                true,
            );
        }
        let comparisons = 4 + usize::from(final_golden);
        let compared_bytes = 224 + 64 * usize::from(final_golden);
        byte_comparisons += comparisons;
        independent_bytes += compared_bytes;
        record(
            &mut observations,
            &json!({"phase":"independent_bytes","id":case.id,"comparisons":comparisons,
            "bytes":compared_bytes,"owner_reference":owner_note,"mu_reference":mu_id,"final_golden":final_golden,
            "canonical_transaction_match":true,"authorization_values_match":true}),
        );
        let report = check_all_constraints(&air, &trace, &public, Some(1));
        evaluated += 1;
        let passes = report.is_ok();
        if passes {
            accepted += 1;
        } else {
            rejected += 1;
        }
        let first = report.failures.first();
        let first_row = first.map(|f| f.row);
        let first_index = first.map(|f| f.constraint);
        let inferred = first_row.map_or(HEIGHT, |r| r + 1);
        inferred_rows += inferred;
        record(
            &mut observations,
            &json!({"phase":"evaluated","id":case.id,"evaluation":evaluated,
            "accepted":passes,"reported_trace_height":report.total_rows,"constraints_per_row":report.total_constraints_per_row,
            "all_rows_checked":passes,"rows_inferred_from_checker":inferred,"failures":report.failures.len(),
            "first_row":first_row,"first_index":first_index,"last_index":report.failures.last().map(|f|f.constraint),
            "first_indices":report.failures.iter().take(8).map(|f|f.constraint).collect::<Vec<_>>(),
            "same_failure_row":report.failures.iter().all(|f|Some(f.row)==first_row),
            "all_owner_range":report.failures.iter().all(|f|(25052..25116).contains(&f.constraint)),
            "all_final_range":report.failures.iter().all(|f|(23836..23900).contains(&f.constraint))}),
        );
        // Interpret the prediction only after preserving the actual verdict.
        assert_eq!(
            (report.total_rows, report.total_constraints_per_row),
            (8192, 69242)
        );
        assert_eq!(
            passes, expect_accept,
            "actual native verdict for {}",
            case.id
        );
        if !passes {
            let (row, range) = if matches!(case.expected, Expected::Owner) {
                (234, 25052..25116)
            } else {
                (5369, 23836..23900)
            };
            assert_eq!(first_row, Some(row));
            assert!(!report.failures.is_empty() && report.failures.len() <= 64);
            assert!(report
                .failures
                .iter()
                .all(|f| f.row == row && range.contains(&f.constraint)));
            if !matches!(case.expected, Expected::FinalRange) {
                assert_eq!(report.failures.len(), 64);
                for (i, failure) in report.failures.iter().enumerate() {
                    assert_eq!(failure.constraint, range.start + i);
                }
            }
        }
        drop(report);
        drop(trace);
        live -= 1;
        ids.push(case.id);
    }
    assert_eq!(
        (
            constructed,
            evaluated,
            accepted,
            rejected,
            maximum_live,
            live
        ),
        (9, 9, 4, 5, 1, 0)
    );
    assert_eq!(
        (byte_comparisons, independent_bytes, inferred_rows),
        (43, 2464, 54483)
    );
    serde_json::to_writer(&mut final_output,&json!({"case_ids":ids,"constructed_traces":constructed,
        "evaluations":evaluated,"accepted":accepted,"rejected":rejected,"maximum_live_traces":maximum_live,
        "live_traces_after":live,"independent_byte_comparisons":byte_comparisons,"independent_bytes":independent_bytes,
        "rows_inferred_from_checker":inferred_rows,"symbolic_collections":0,"borrowed_frame_checks":0,"backend_proofs":0})).unwrap();
    final_output.sync_all().unwrap();
}
