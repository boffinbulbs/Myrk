use kova_signature_packed::{
    build_full_private_signature_owner_sources, layout::*, packed::Bank, PackedSignatureOwnerAir,
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
mod ranks;

const ASSERTIONS: usize = 69242;
struct Case {
    name: &'static str,
    bank: Bank,
    word: usize,
    original: u32,
    offset: usize,
}
const CASES: [Case; 4] = [
    Case {
        name: "signature_offset1",
        bank: Bank::Signature,
        word: 13130,
        original: 46,
        offset: 1,
    },
    Case {
        name: "signature_offset2",
        bank: Bank::Signature,
        word: 13130,
        original: 46,
        offset: 2,
    },
    Case {
        name: "note_offset1",
        bank: Bank::Note,
        word: 13270,
        original: 0,
        offset: 1,
    },
    Case {
        name: "note_offset2",
        bank: Bank::Note,
        word: 13270,
        original: 0,
        offset: 2,
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

fn build_b0(log: &mut File) -> (RowMajorMatrix<BabyBear>, Vec<BabyBear>) {
    let raw: Raw = read("raw-fixture.json");
    let reference: Reference = read("reference-fixture.json");
    assert_eq!(
        reference.raw_sha256,
        "10426a9bbfd10707b2a339c63c787bd8d119ee2c76a78316aa03c1edab80c2f2"
    );
    let tuple = reference.tuples.iter().find(|t| t.id == "B0").unwrap();
    assert!(tuple.bounded_supported && tuple.conditional_verdict == "AcceptConditional");
    assert_eq!(
        (
            &*tuple.key_id,
            &*tuple.signature_id,
            &*tuple.transaction_id,
            &*tuple.note_id
        ),
        ("B", "B0", "T0", "N_B")
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
    assert_eq!(signature[4626], 46);
    assert_eq!(opening[417], 0);
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
    let trace = build_full_private_signature_owner_sources(&witness, &transaction).unwrap();
    record(
        log,
        &json!({"phase":"constructed","height":trace.height(),"width":trace.width(),"raw_field_bytes":trace.values.len()*4}),
    );
    assert_eq!(
        (trace.height(), trace.width(), trace.values.len() * 4),
        (8192, 43176, 1414791168)
    );
    let stages = &reference
        .signature_records
        .iter()
        .find(|r| r.id == "B0")
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
        log,
        &json!({"phase":"independent_bytes","comparisons":5,"bytes":288,"canonical_transaction_match":true,"authorization_values_match":true}),
    );
    (trace, public)
}

fn selected<'a>(case: &Case, ranks: &'a ranks::Ranks) -> &'a [u8] {
    match case.bank {
        Bank::Signature => &ranks.signature,
        Bank::Note => &ranks.note,
        Bank::Key => panic!("unselected bank"),
    }
}

fn alter(trace: &mut RowMajorMatrix<BabyBear>, case: &Case, ranks: &ranks::Ranks, restore: bool) {
    let delta = 1u32 << (8 * case.offset);
    let original = BabyBear::from_u32(case.original);
    let changed = BabyBear::from_u32(case.original + delta);
    for (row, &port) in selected(case, ranks).iter().enumerate() {
        let local = &mut trace.values[row * WIDTH..(row + 1) * WIDTH];
        let bit = SOURCE_PORTS + 24 * usize::from(port) + 8 * case.offset;
        let (before_word, after_word, before_bit, after_bit) = if restore {
            (changed, original, BabyBear::ONE, BabyBear::ZERO)
        } else {
            (original, changed, BabyBear::ZERO, BabyBear::ONE)
        };
        assert_eq!(local[case.word], before_word);
        assert_eq!(local[bit], before_bit);
        local[case.word] = after_word;
        local[bit] = after_bit;
        assert_eq!(local[case.word], after_word);
        assert_eq!(local[bit], after_bit);
    }
}

fn positive(trace: &RowMajorMatrix<BabyBear>, public: &[BabyBear], name: &str, log: &mut File) {
    let report = check_all_constraints(&PackedSignatureOwnerAir, trace, public, Some(1));
    record(
        log,
        &json!({"phase":"positive","name":name,"accepted":report.is_ok(),"reported_trace_height":report.total_rows,
        "constraints_per_row":report.total_constraints_per_row,"all_rows_checked":report.is_ok(),
        "failures":report.failures.len(),"first_failures":report.failures.iter().take(8).map(|f|(f.row,f.constraint)).collect::<Vec<_>>()}),
    );
    assert!(report.is_ok(), "full restored/baseline acceptance {name}");
    assert_eq!(
        (report.total_rows, report.total_constraints_per_row),
        (HEIGHT, ASSERTIONS)
    );
}

fn negative(
    trace: &RowMajorMatrix<BabyBear>,
    public: &[BabyBear],
    case: &Case,
    ranks: &ranks::Ranks,
    log: &mut File,
) -> usize {
    let mut rows = 0;
    let mut total_failures = 0;
    let mut histogram = [0usize; 125];
    let mut first_index = None;
    let mut last_index = None;
    for (row, &port) in selected(case, ranks).iter().enumerate() {
        let next = (row + 1) % HEIGHT;
        let main = ViewPair::new(
            RowMajorMatrixView::new_row(&trace.values[row * WIDTH..(row + 1) * WIDTH]),
            RowMajorMatrixView::new_row(&trace.values[next * WIDTH..(next + 1) * WIDTH]),
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
        rows += 1;
        let failed = builder.failures();
        let expected = ranks::expected_constraint(usize::from(port), case.offset);
        total_failures += failed.len();
        if failed.len() != 1 || failed[0].row != row || failed[0].constraint != expected {
            record(
                log,
                &json!({"phase":"negative_unexpected","name":case.name,"row":row,"rows_completed":rows,
                "pass_complete":false,"expected":expected,"failures":failed.len(),
                "first_failures":failed.iter().take(8).map(|f|(f.row,f.constraint)).collect::<Vec<_>>()}),
            );
            panic!("Unexpected complete AIR padding result at row {row}");
        }
        first_index.get_or_insert(failed[0].constraint);
        last_index = Some(failed[0].constraint);
        histogram[usize::from(port)] += 1;
        // The actual builder/failure vector drops before the next global frame.
        drop(builder);
    }
    record(
        log,
        &json!({"phase":"negative","name":case.name,"rows_evaluated":rows,"failures":total_failures,
        "unexpected_rows":0,"complete":true,"first_row":0,"last_row":rows-1,
        "first_index":first_index,"last_index":last_index,"port_histogram":histogram.as_slice()}),
    );
    assert_eq!((rows, total_failures), (HEIGHT, HEIGHT));
    assert_eq!(histogram.into_iter().sum::<usize>(), HEIGHT);
    rows
}

#[test]
#[ignore = "Separate consistent padding controls and all-frame resource admission"]
fn four_consistent_virtual_padding_controls() {
    assert_eq!(
        std::env::var("KOVA_PACKED_PADDING_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("observations.jsonl"))
        .unwrap();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("padding.json"))
        .unwrap();
    let ranks = ranks::projection();
    record(
        &mut log,
        &json!({"phase":"tail_ranks","projection_passes":1,"rows":HEIGHT,"actual_tail_ports_compared":2*HEIGHT}),
    );
    let (mut trace, public) = build_b0(&mut log);
    positive(&trace, &public, "baseline", &mut log);
    let mut positive_passes = 1;
    let mut negative_passes = 0;
    let mut negative_frames = 0;
    for case in &CASES {
        alter(&mut trace, case, &ranks, false);
        record(
            &mut log,
            &json!({"phase":"altered","name":case.name,"rows":HEIGHT,"changed_cells":2*HEIGHT,
            "held_column":case.word,"old_word":case.original,"new_word":case.original+(1u32<<(8*case.offset))}),
        );
        negative_frames += negative(&trace, &public, case, &ranks, &mut log);
        negative_passes += 1;
        alter(&mut trace, case, &ranks, true);
        positive(&trace, &public, case.name, &mut log);
        positive_passes += 1;
    }
    drop(trace);
    let result = json!({"fixture":"B0","constructed_traces":1,"maximum_live_traces":1,
        "positive_full_scans":positive_passes,"negative_all_frame_passes":negative_passes,"negative_frame_evaluations":negative_frames,
        "total_frame_evaluations":positive_passes*HEIGHT+negative_frames,"controls":4,"independent_byte_comparisons":5,
        "independent_bytes":288,"rank_projection_passes":1,"actual_tail_ports_compared":2*HEIGHT,"symbolic_collections":0,"backend_proofs":0});
    serde_json::to_writer(&mut output, &result).unwrap();
    output.sync_all().unwrap();
    assert_eq!(
        (positive_passes, negative_passes, negative_frames),
        (5, 4, 4 * HEIGHT)
    );
}
