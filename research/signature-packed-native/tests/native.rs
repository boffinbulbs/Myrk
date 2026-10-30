use kova_signature_packed::{
    build_full_private_signature_owner_sources, layout::*, packed, PackedSignatureOwnerAir,
    Statement, Witness,
};
use p3_air::{check_all_constraints, Air, BaseAir, DebugConstraintBuilder};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::ViewPair,
    Matrix,
};
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

const ASSERTIONS: usize = 69242;
const CLOCK_ASSERTIONS: usize = 3 * (64 + 128) + 4;
const BOOL_START: usize = CLOCK_ASSERTIONS + 2547;
const PORT_START: usize = BOOL_START + 3000;
const SOURCE_END: usize = PORT_START + 125 + 66;

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

struct Frame {
    row: usize,
    failures: usize,
    first_indices: Vec<usize>,
    held_only: bool,
    bool_only: bool,
    source_port: bool,
    consumer: bool,
    exact_port: bool,
    exact_consumer: bool,
}

fn frames(
    trace: &RowMajorMatrix<BabyBear>,
    public: &[BabyBear],
    changed_row: usize,
    expected_port: Option<usize>,
    expected_consumer: Option<usize>,
) -> Vec<Frame> {
    let mut result = Vec::with_capacity(2);
    // These borrow the actual global trace, including the last-to-first wrap.
    for row in [(changed_row + HEIGHT - 1) % HEIGHT, changed_row] {
        let next = (row + 1) % HEIGHT;
        let local = &trace.values[row * WIDTH..(row + 1) * WIDTH];
        let next = &trace.values[next * WIDTH..(next + 1) * WIDTH];
        let main = ViewPair::new(
            RowMajorMatrixView::new_row(local),
            RowMajorMatrixView::new_row(next),
        );
        let empty: &[BabyBear] = &[];
        let preprocessed = ViewPair::new(
            RowMajorMatrixView::new(empty, 0),
            RowMajorMatrixView::new(empty, 0),
        );
        let periodic = <PackedSignatureOwnerAir as BaseAir<BabyBear>>::periodic_values(
            &PackedSignatureOwnerAir,
            row,
        );
        assert!(periodic.is_empty());
        let mut builder = DebugConstraintBuilder::new(
            row,
            main,
            preprocessed,
            public,
            BabyBear::from_bool(row == 0),
            BabyBear::from_bool(row == HEIGHT - 1),
            BabyBear::from_bool(row != HEIGHT - 1),
            &periodic,
        );
        PackedSignatureOwnerAir.eval(&mut builder);
        let failed = builder.failures();
        result.push(Frame {
            row,
            failures: failed.len(),
            first_indices: failed.iter().take(8).map(|f| f.constraint).collect(),
            held_only: failed.iter().all(|f| f.constraint == CLOCK_ASSERTIONS),
            bool_only: failed
                .iter()
                .all(|f| (BOOL_START..PORT_START).contains(&f.constraint)),
            source_port: failed
                .iter()
                .any(|f| (PORT_START..SOURCE_END).contains(&f.constraint)),
            consumer: failed.iter().any(|f| f.constraint >= SOURCE_END),
            exact_port: failed.iter().any(|f| Some(f.constraint) == expected_port),
            exact_consumer: failed
                .iter()
                .any(|f| Some(f.constraint) == expected_consumer),
        });
    }
    result
}

fn frame_record(name: &str, phase: &str, frames: &[Frame]) -> Value {
    json!({"name":name,"phase":phase,"frame_rows":frames.iter().map(|f|f.row).collect::<Vec<_>>(),
        "failures":frames.iter().map(|f|f.failures).collect::<Vec<_>>(),
        "first_indices":frames.iter().map(|f|&f.first_indices).collect::<Vec<_>>(),
        "all_held_only":frames.iter().all(|f|f.held_only),"all_boolean_only":frames.iter().all(|f|f.bool_only),
        "has_port_failure":frames.iter().any(|f|f.source_port),"has_consumer_failure":frames.iter().any(|f|f.consumer),
        "exact_port_match":frames.iter().map(|f|f.exact_port).collect::<Vec<_>>(),
        "exact_consumer_match":frames.iter().map(|f|f.exact_consumer).collect::<Vec<_>>()})
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
#[ignore = "Separate one-trace native construction and constraint admission"]
fn a0_complete_packed_native_and_source_controls() {
    assert_eq!(
        std::env::var("KOVA_PACKED_NATIVE_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("observations.jsonl"))
        .unwrap();
    let mut final_output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("native.json"))
        .unwrap();
    let raw: Raw = read("raw-fixture.json");
    let reference: Reference = read("reference-fixture.json");
    assert_eq!(
        reference.raw_sha256,
        "10426a9bbfd10707b2a339c63c787bd8d119ee2c76a78316aa03c1edab80c2f2"
    );
    let tuple = reference.tuples.iter().find(|t| t.id == "A0").unwrap();
    assert!(tuple.bounded_supported && tuple.conditional_verdict == "AcceptConditional");
    assert_eq!(
        (
            &*tuple.key_id,
            &*tuple.signature_id,
            &*tuple.transaction_id,
            &*tuple.note_id
        ),
        ("A", "A0", "T0", "N_A")
    );
    let key = bytes::<2592>(
        &raw.keys
            .iter()
            .find(|k| k.id == tuple.key_id)
            .unwrap()
            .public_key_hex,
    );
    let signature = bytes::<4627>(
        &raw.signatures
            .iter()
            .find(|s| s.id == tuple.signature_id)
            .unwrap()
            .signature_hex,
    );
    let note = &reference.notes[&tuple.note_id];
    let opening = bytes::<418>(&note.opening_hex);
    let tx = reference
        .transactions
        .iter()
        .find(|t| t.id == tuple.transaction_id)
        .unwrap();
    assert_eq!(tx.fee_atoms, 5);
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
    let mut trace = build_full_private_signature_owner_sources(&witness, &transaction).unwrap();
    record(
        &mut log,
        &json!({"phase":"constructed","height":trace.height(),"width":trace.width(),"raw_field_bytes":trace.values.len()*4}),
    );
    assert_eq!(
        (trace.height(), trace.width(), trace.values.len() * 4),
        (8192, 43176, 1414791168)
    );
    let stages = &reference
        .signature_records
        .iter()
        .find(|r| r.id == "A0")
        .unwrap()
        .fixed_target_stages;
    compare_bytes(&trace, 1, RHO, &key[..32], false);
    compare_bytes(&trace, 234, OWNER, &opening[141..205], false);
    compare_bytes(&trace, 8191, MU, &bytes::<64>(&stages.mu_hex), false);
    compare_bytes(
        &trace,
        8191,
        NOTE_COMMITMENT,
        &bytes::<64>(&note.commitment_hex),
        false,
    );
    compare_bytes(
        &trace,
        5369,
        OUTPUT,
        &bytes::<64>(&stages.challenge_expected_hex),
        true,
    );
    record(
        &mut log,
        &json!({"phase":"independent_bytes","comparisons":5,"bytes":288,"canonical_transaction_match":true,"authorization_values_match":true}),
    );
    let baseline = check_all_constraints(&air, &trace, &public, Some(1));
    record(
        &mut log,
        &json!({"phase":"baseline","accepted":baseline.is_ok(),"reported_trace_height":baseline.total_rows,
        "constraints_per_row":baseline.total_constraints_per_row,"all_rows_checked":baseline.is_ok(),
        "failures":baseline.failures.len(),"first_failures":baseline.failures.iter().take(8).map(|f|(f.row,f.constraint)).collect::<Vec<_>>() }),
    );
    assert!(
        baseline.is_ok(),
        "complete packed A0 witness must satisfy the actual relation"
    );
    assert_eq!(
        (baseline.total_rows, baseline.total_constraints_per_row),
        (8192, ASSERTIONS)
    );
    drop(baseline);
    use packed::Bank;
    let bit_column = |row, bank, index| {
        let (p, offset) = packed::port_at(row, bank, index);
        SOURCE_PORTS + 24 * p + 8 * offset
    };
    let pair = bit_column(0, Bank::Key, 30);
    assert!(!packed::word_ids_at(600).contains(&0));
    let cases = [
        ("unread_word_hold", 600, vec![(KEY, BabyBear::ONE)]),
        (
            "compensated_boolean_pair",
            0,
            vec![(pair, BabyBear::TWO), (pair + 1, BabyBear::NEG_ONE)],
        ),
        (
            "key_source_read",
            0,
            vec![(bit_column(0, Bank::Key, 30), BabyBear::ZERO)],
        ),
        (
            "signature_prefix_boundary",
            0,
            vec![(bit_column(0, Bank::Signature, 63), BabyBear::ZERO)],
        ),
        (
            "note_owner_read",
            234,
            vec![(bit_column(234, Bank::Note, 141), BabyBear::ZERO)],
        ),
        (
            "late_note_context",
            8191,
            vec![(bit_column(8191, Bank::Note, 49), BabyBear::ZERO)],
        ),
    ];
    let targets = [
        (None, None),
        (None, None),
        (Some(6141), Some(25047)),
        (Some(6182), Some(21797)),
        (Some(6280), Some(25052)),
        (Some(6157), Some(24958)),
    ];
    for (kind, (name, row, changes)) in cases.into_iter().enumerate() {
        let (expected_port, expected_consumer) = targets[kind];
        let old: Vec<_> = changes
            .iter()
            .map(|(col, _)| trace.values[row * WIDTH + col])
            .collect();
        for ((col, delta), &original) in changes.iter().zip(&old) {
            trace.values[row * WIDTH + col] = if kind < 2 {
                original + *delta
            } else {
                BabyBear::ONE - original
            };
        }
        let failed = frames(&trace, &public, row, expected_port, expected_consumer);
        let mut observation = frame_record(name, "mutated", &failed);
        observation["changed_columns"] =
            json!(changes.iter().map(|(column, _)| column).collect::<Vec<_>>());
        record(&mut log, &observation);
        assert!(failed.iter().all(|f| f.failures <= ASSERTIONS));
        assert!(
            failed.iter().any(|f| f.failures > 0),
            "real AIR must reject {name}"
        );
        if kind == 0 {
            assert!(failed.iter().all(|f| f.failures == 1 && f.held_only));
        } else if kind == 1 {
            assert!(failed.iter().all(|f| f.bool_only));
            assert_eq!(failed[0].failures, 0);
            assert_eq!(failed[1].first_indices, [3367, 3368]);
            assert_eq!(failed[1].failures, 2);
        } else {
            assert!(failed[1].exact_port && failed[1].exact_consumer);
            assert_eq!(failed[0].failures, 0);
            assert_eq!(failed[1].failures, 2);
            assert_eq!(
                failed[1].first_indices,
                [expected_port.unwrap(), expected_consumer.unwrap()]
            );
        }
        drop(failed);
        for ((col, _), &value) in changes.iter().zip(&old) {
            trace.values[row * WIDTH + col] = value;
        }
        let restored = frames(&trace, &public, row, expected_port, expected_consumer);
        record(&mut log, &frame_record(name, "restored", &restored));
        assert!(
            restored.iter().all(|f| f.failures == 0),
            "exact restoration {name}"
        );
    }
    drop(trace);
    let result = json!({"tuple":"A0","key":"A","signature":"A0","transaction":"T0","note":"N_A",
        "height":8192,"width":43176,"public_values":196,"constraints_per_row":ASSERTIONS,
        "constructed_traces":1,"maximum_live_traces":1,"full_positive_scans":1,"negative_borrowed_checks":6,
        "restored_positive_borrowed_checks":6,"borrowed_frame_evaluations":24,"independent_byte_comparisons":5,
        "independent_bytes":288,"canonical_transaction_match":true,"authorization_values_match":true,
        "symbolic_collections":0,"backend_proofs":0});
    serde_json::to_writer(&mut final_output, &result).unwrap();
    final_output.sync_all().unwrap();
}
