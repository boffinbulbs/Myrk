//! Native constraint, reference and source-route tests for the bounded relation.
use super::*;
use full_program as fp;
use layout::*;
use p3_air::{
    check_all_constraints, Air, AirBuilder, BaseAir, DebugConstraintBuilder, WindowAccess,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::ViewPair,
    Matrix,
};
use serde::{de::DeserializeOwned, Deserialize};
use std::collections::BTreeMap;
use thorum_core::Amount;
use thorum_crypto_lab::{SealedNote, KEM_CIPHERTEXT_BYTES};
use thorum_relation_lab::PaymentOutput;

fn gate(name: &str) {
    assert_eq!(
        std::env::var(name).as_deref(),
        Ok("reviewed-external-resource-admission"),
        "Actual external resource limits and separate source review must precede test selection"
    );
}
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
    key_matrices: BTreeMap<String, Vec<MatrixReference>>,
    signature_records: Vec<Record>,
    tuples: Vec<Tuple>,
}
#[derive(Deserialize)]
struct Note {
    opening_hex: String,
}
#[derive(Deserialize)]
struct Transaction {
    id: String,
    fee_atoms: u64,
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
    zhat: Vec<Vec<u32>>,
    chat: Vec<u32>,
    rows: Vec<RowReference>,
    mu_hex: String,
    packed_w1_hex: String,
    challenge_expected_hex: String,
}
#[derive(Deserialize)]
struct RowReference {
    row: usize,
    columns: Vec<ColumnReference>,
    t1hat: Vec<u32>,
    challenge_products: Vec<u32>,
    inverse_input: Vec<u32>,
    inverse_output: Vec<u32>,
    hints: Vec<u8>,
    packed_w1_hex: String,
}
#[derive(Deserialize)]
struct ColumnReference {
    column: usize,
    after: Vec<u32>,
}
#[derive(Deserialize)]
struct MatrixReference {
    row: usize,
    column: usize,
    coefficients: Vec<u32>,
    cursor: Cursor,
    six_block_stream_hex: String,
}
#[derive(Deserialize)]
struct Cursor {
    bytes_consumed: usize,
}

// Unknown large diagnostic fields are skipped by serde instead of becoming a
// serde_json::Value tree. File bytes pass through one bounded16KiB reader.
fn read<T: DeserializeOwned>(name: &str) -> T {
    use std::io::Read;
    const LIMIT: u64 = 9 * 1024 * 1024;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../signature-ownership")
        .join(name);
    let file = std::fs::File::open(path).unwrap();
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file() && metadata.len() <= LIMIT);
    let reader = std::io::BufReader::with_capacity(16 * 1024, file.take(LIMIT + 1));
    serde_json::from_reader(reader).unwrap()
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
fn fixture(raw: &Raw, r: &Reference, t: &Tuple) -> (Witness, PaymentStatement) {
    let key = raw.keys.iter().find(|v| v.id == t.key_id).unwrap();
    let sig = raw
        .signatures
        .iter()
        .find(|v| v.id == t.signature_id)
        .unwrap();
    let note = &r.notes[&t.note_id];
    let tx = r
        .transactions
        .iter()
        .find(|v| v.id == t.transaction_id)
        .unwrap();
    (
        Witness::from_sources(
            bytes(&key.public_key_hex),
            bytes(&sig.signature_hex),
            bytes(&note.opening_hex),
        ),
        transaction(tx.fee_atoms),
    )
}
fn bits(row: &[BabyBear], at: usize, n: usize) -> u32 {
    (0..n).map(|i| row[at + i].as_canonical_u32() << i).sum()
}
fn valid(trace: &RowMajorMatrix<BabyBear>, public: &[BabyBear]) -> bool {
    check_all_constraints(&FullPrivateSignatureOwnerAir, trace, public, Some(1)).is_ok()
}
fn single_cell_affected_frames_valid(
    trace: &RowMajorMatrix<BabyBear>,
    public: &[BabyBear],
    mutation_row: usize,
) -> bool {
    assert_eq!(
        (trace.height(), trace.width(), public.len()),
        (HEIGHT, WIDTH, PUBLIC_VALUES)
    );
    assert!(mutation_row > 0 && mutation_row + 1 < HEIGHT);
    let air = FullPrivateSignatureOwnerAir;
    assert_eq!(
        <FullPrivateSignatureOwnerAir as BaseAir<BabyBear>>::preprocessed_width(&air),
        0
    );
    assert!(
        <FullPrivateSignatureOwnerAir as BaseAir<BabyBear>>::preprocessed_trace(&air).is_none()
    );
    assert_eq!(
        <FullPrivateSignatureOwnerAir as BaseAir<BabyBear>>::num_periodic_columns(&air),
        0
    );
    assert!(
        <FullPrivateSignatureOwnerAir as BaseAir<BabyBear>>::public_boundary_io(&air).is_empty()
    );

    // The AIR reads only the current and next main rows. With a known valid
    // complete trace and unchanged public values, metadata and selectors, a
    // single changed cell on interior row r can affect only frames r-1 and r.
    // Each case below changes exactly that cell and restores its exact value.
    // These are borrowed frames of the full trace, not a two-row mini trace.
    let mut frames_valid = true;
    for row_index in [mutation_row - 1, mutation_row] {
        let local = &trace.values[row_index * WIDTH..(row_index + 1) * WIDTH];
        let next = &trace.values[(row_index + 1) * WIDTH..(row_index + 2) * WIDTH];
        let main = ViewPair::new(
            RowMajorMatrixView::new_row(local),
            RowMajorMatrixView::new_row(next),
        );
        let empty: &[BabyBear] = &[];
        let preprocessed = ViewPair::new(
            RowMajorMatrixView::new(empty, 0),
            RowMajorMatrixView::new(empty, 0),
        );
        let periodic =
            <FullPrivateSignatureOwnerAir as BaseAir<BabyBear>>::periodic_values(&air, row_index);
        assert!(periodic.is_empty());
        let mut builder = DebugConstraintBuilder::new(
            row_index,
            main,
            preprocessed,
            public,
            BabyBear::from_bool(row_index == 0),
            BabyBear::from_bool(row_index == HEIGHT - 1),
            BabyBear::from_bool(row_index != HEIGHT - 1),
            &periodic,
        );
        air.eval(&mut builder);
        frames_valid &= !builder.has_failures();
    }
    frames_valid
}
fn assert_poly(row: &[BabyBear], at: usize, expected: &[u32]) {
    assert_eq!(expected.len(), 256);
    for (k, v) in expected.iter().enumerate() {
        assert!(
            row[at + k].as_canonical_u32() == *v,
            "private polynomial reference mismatch"
        );
    }
}
fn assert_bytes(row: &[BabyBear], at: usize, expected: &[u8]) {
    for (k, v) in expected.iter().enumerate() {
        assert!(
            row[at + k].as_canonical_u32() == u32::from(*v),
            "private byte reference mismatch"
        );
    }
}
fn compare_matrix(trace: &RowMajorMatrix<BabyBear>, r: &Reference, t: &Tuple) {
    let matrices = &r.key_matrices[&t.key_id];
    assert_eq!(matrices.len(), 56);
    for i in 0..8 {
        for j in 0..7 {
            let expected = &matrices[7 * i + j];
            assert_eq!((expected.row, expected.column), (i, j));
            let start = fp::matrix_start(i, j);
            let stream = bytes::<1008>(&expected.six_block_stream_hex);
            assert_bytes(&trace.row_slice(start + 36).unwrap(), MATRIX_XOF, &stream);
            for block in 0..6 {
                let row = trace.row_slice(start + 6 * (block + 1)).unwrap();
                assert_bytes(
                    &row,
                    MATRIX_XOF + 168 * block,
                    &stream[168 * block..168 * (block + 1)],
                );
            }
            let zero = trace.row_slice(start).unwrap();
            assert!(zero[MATRIX_XOF..MATRIX_XOF + 1008]
                .iter()
                .all(|v| *v == BabyBear::ZERO));
            let terminal = trace.row_slice(start + 47).unwrap();
            assert!(
                terminal[MATRIX_COUNT + 8 * 257 + 256] == BabyBear::ONE,
                "matrix completion sentinel mismatch"
            );
            assert!(
                bits(&terminal, MATRIX_CURSOR + 80, 10) as usize == expected.cursor.bytes_consumed,
                "private matrix cursor reference mismatch"
            );
            let mut accepted = 0;
            for u in 0..42 {
                let row = trace.row_slice(start + 6 + u).unwrap();
                for s in 0..8 {
                    if row[MATRIX_TAKE + s] == BabyBear::ONE {
                        assert!(
                            bits(&row, MATRIX_CANDIDATE + 24 * s, 23)
                                == expected.coefficients[accepted],
                            "private matrix coefficient reference mismatch"
                        );
                        accepted += 1;
                    }
                }
            }
            assert_eq!(accepted, 256);
        }
    }
}
fn compare_stages(trace: &RowMajorMatrix<BabyBear>, r: &Reference, t: &Tuple) {
    let record = r
        .signature_records
        .iter()
        .find(|v| v.id == t.signature_id)
        .unwrap();
    if record.key_id != t.key_id {
        return;
    }
    let stage = &record.fixed_target_stages;
    let last = trace.row_slice(HEIGHT - 1).unwrap();
    for j in 0..7 {
        assert_poly(&last, NTT_OUTPUT + 256 * j, &stage.zhat[j]);
    }
    assert_poly(&last, NTT_OUTPUT + 7 * 256, &stage.chat);
    for i in 0..8 {
        let row = &stage.rows[i];
        assert_eq!(row.row, i);
        assert_poly(&last, NTT_OUTPUT + 256 * (8 + i), &row.t1hat);
        for j in 0..7 {
            assert_eq!(row.columns[j].column, j);
            assert_poly(
                &trace.row_slice(fp::matrix_start(i, j) + 48).unwrap(),
                ACCUMULATOR + 256 * i,
                &row.columns[j].after,
            );
        }
        let point = fp::POINT_START + 32 * i;
        for g in 0..32 {
            let actual = trace.row_slice(point + g).unwrap();
            for s in 0..8 {
                assert!(
                    bits(&actual, EXTRA_PRODUCTS + s * mul::WIDTH + 3 * 23, 23)
                        == row.challenge_products[8 * g + s],
                    "private challenge product reference mismatch"
                );
            }
        }
        assert_poly(
            &trace.row_slice(point + 32).unwrap(),
            ACCUMULATOR + 256 * i,
            &row.inverse_input,
        );
        assert_poly(
            &trace.row_slice(fp::INVERSE_START + 224 * i + 192).unwrap(),
            NTT_SCRATCH,
            &row.inverse_output,
        );
        for k in 0..256 {
            assert!(
                last[HINTS + 256 * i + k].as_canonical_u32() == u32::from(row.hints[k]),
                "private hint reference mismatch"
            );
        }
        assert_bytes(&last, W1 + 128 * i, &bytes::<128>(&row.packed_w1_hex));
    }
    assert_bytes(&last, W1, &bytes::<1024>(&stage.packed_w1_hex));
    if record.transaction_id == t.transaction_id {
        assert_bytes(&last, MU, &bytes::<64>(&stage.mu_hex));
        let final_row = trace.row_slice(fp::FINAL_END - 1).unwrap();
        let expected = bytes::<64>(&stage.challenge_expected_hex);
        for (k, expected_byte) in expected.iter().enumerate() {
            assert!(
                bits(&final_row, OUTPUT + 8 * k, 8) == u32::from(*expected_byte),
                "private final digest reference mismatch"
            );
        }
    }
}

#[test]
#[ignore = "Requires explicit bounded source inventory admission, no wide trace"]
fn declared_shape_schedule_and_full_state_routes() {
    gate("THORUM_FULL_RELATION_STATIC_GATE");
    assert_eq!((HEIGHT, WIDTH, PUBLIC_VALUES), (8192, 55049, 196));
    assert_eq!(HEIGHT * WIDTH * 4, 1_803_845_632);
    assert_eq!(
        <FullPrivateSignatureOwnerAir as BaseAir<BabyBear>>::width(&FullPrivateSignatureOwnerAir),
        55049
    );
    assert_eq!(
        (
            fp::MATRIX_END,
            fp::POINT_END,
            fp::INVERSE_END,
            fp::FINAL_END
        ),
        (3330, 3586, 5314, 5370)
    );
    for i in 0..8 {
        for j in 0..7 {
            let start = fp::matrix_start(i, j);
            assert_eq!(
                fp::hash(start),
                fp::Hash::Matrix {
                    row: i,
                    column: j,
                    block: 0
                }
            );
            assert_eq!(
                fp::hash(start + 35),
                fp::Hash::Matrix {
                    row: i,
                    column: j,
                    block: 5
                }
            );
            assert_eq!(fp::hash(start + 36), fp::Hash::Dummy);
            assert!(
                matches!(fp::message(fp::hash(start),32),fp::Byte::Fixed(v) if usize::from(v)==j)
            );
            assert!(
                matches!(fp::message(fp::hash(start),33),fp::Byte::Fixed(v) if usize::from(v)==i)
            );
            for u in 0..42 {
                assert!(start + 6 + u >= start + 6 * ((24 * u + 23) / 168 + 1));
            }
        }
    }
    assert!(matches!(
        fp::message(fp::Hash::Final(8), 0),
        fp::Byte::Fixed(31)
    ));
    assert!(matches!(
        fp::message(fp::Hash::Final(8), 135),
        fp::Byte::Fixed(128)
    ));
    assert_eq!(
        ntt::inverse_operation(3522),
        Some((0, ntt::InverseOp::Initialize(0)))
    );
    assert_eq!(
        ntt::inverse_operation(5313),
        Some((7, ntt::InverseOp::Output(31)))
    );
}

#[test]
#[ignore = "Requires separately measured typed fixture reader admission, no wide trace"]
fn bounded_typed_reference_reader_without_json_value_tree() {
    gate("THORUM_FULL_RELATION_READER_GATE");
    let raw: Raw = read("raw-fixture.json");
    let reference: Reference = read("reference-fixture.json");
    assert_eq!(
        (raw.keys.len(), raw.signatures.len(), reference.tuples.len()),
        (2, 6, 10)
    );
    assert_eq!(
        reference.raw_sha256,
        "10426a9bbfd10707b2a339c63c787bd8d119ee2c76a78316aa03c1edab80c2f2"
    );
    assert_eq!(reference.key_matrices.len(), 2);
    println!("Typed reader retained six selected signature records and two key matrix sets. Peak remains externally measured.");
}

#[test]
#[ignore = "Requires separate construction-only2GiB resource admission, no AIR evaluation"]
fn single_a0_construction_without_air_evaluation() {
    gate("THORUM_FULL_RELATION_CONSTRUCTION_GATE");
    let raw: Raw = read("raw-fixture.json");
    let reference: Reference = read("reference-fixture.json");
    assert_eq!(
        (raw.keys.len(), raw.signatures.len(), reference.tuples.len()),
        (2, 6, 10)
    );
    let tuple = reference
        .tuples
        .iter()
        .find(|tuple| tuple.id == "A0")
        .unwrap();
    let (witness, transaction) = fixture(&raw, &reference, tuple);
    let trace = build_full_private_signature_owner_sources(&witness, &transaction).unwrap();
    assert_eq!((trace.height(), trace.width()), (8192, 55049));
    let _ = std::hint::black_box((&raw, &reference, &witness, &transaction, &trace));
    println!("FULL_RELATION_CONSTRUCTION_ONLY_NO_AIR_EVALUATION");
    drop(trace);
    drop(transaction);
    drop(reference);
    drop(raw);
}

#[test]
#[ignore = "Requires actual symbolic expression memory admission and no trace"]
fn actual_symbolic_full_shape_count_and_degree() {
    gate("THORUM_FULL_RELATION_SYMBOLIC_GATE");
    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    let air = FullPrivateSignatureOwnerAir;
    let shape = AirLayout::from_air::<BabyBear>(&air);
    assert_eq!(
        (
            shape.main_width,
            shape.num_public_values,
            shape.preprocessed_width,
            shape.num_periodic_columns
        ),
        (55049, 196, 0, 0)
    );
    let (count, degree) = {
        let constraints = get_symbolic_constraints::<BabyBear, _>(&air, shape);
        let count = constraints.len();
        let degree = constraints
            .iter()
            .map(|v| v.degree_multiple())
            .max()
            .unwrap_or(0);
        drop(constraints);
        (count, degree)
    };
    assert!(count > 0 && degree > 0);
    println!("Actual full constraints_per_row {count}, degree {degree}. No backend profile.");
}

#[test]
#[ignore = "Requires reviewed complete source, actual dimensions/degree, typed reader peak and separate2GiB native limits"]
fn ten_bounded_same_witness_relations_against_independent_integer_reference() {
    gate("THORUM_FULL_RELATION_NATIVE_GATE");
    let raw: Raw = read("raw-fixture.json");
    let reference: Reference = read("reference-fixture.json");
    assert_eq!(reference.tuples.len(), 10);
    let mut passed = 0;
    let mut failed = 0;
    for tuple in &reference.tuples {
        assert!(tuple.bounded_supported);
        let (w, tx) = fixture(&raw, &reference, tuple);
        let public = Statement::from_transaction(&tx).unwrap().public_values();
        let trace = build_full_private_signature_owner_sources(&w, &tx).unwrap_or_else(|error| {
            panic!(
                "Build preflight refusal for {} is not an AIR rejection: {error:?}",
                tuple.id
            )
        });
        assert_eq!((trace.height(), trace.width()), (8192, 55049));
        compare_matrix(&trace, &reference, tuple);
        compare_stages(&trace, &reference, tuple);
        let actual = valid(&trace, &public);
        assert!(
            actual == (tuple.conditional_verdict == "AcceptConditional"),
            "conditional tuple verdict mismatch"
        );
        if actual {
            passed += 1;
        } else {
            failed += 1;
        }
        drop(trace);
    }
    assert_eq!((passed, failed), (5, 5));
}

struct LocalPrimitives;
impl<F> BaseAir<F> for LocalPrimitives {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        196
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for LocalPrimitives {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let row = main.current_slice();
        for base in [NTT_PRODUCTS, EXTRA_PRODUCTS] {
            for s in 0..8 {
                mul::eval_mul(b, &row[base + s * mul::WIDTH..base + (s + 1) * mul::WIDTH]);
            }
        }
        for s in 0..8 {
            hints::eval_use_hint(
                b,
                &row[USE_HINT + s * hints::WIDTH..USE_HINT + (s + 1) * hints::WIDTH],
            );
        }
    }
}
struct KeccakOnly;
impl<F> BaseAir<F> for KeccakOnly {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        196
    }
}
impl<AB: AirBuilder> Air<AB> for KeccakOnly {
    fn eval(&self, b: &mut AB) {
        keccak::eval(b);
    }
}
fn rebuild_matrix_suffix(trace: &mut RowMajorMatrix<BabyBear>) {
    matrix::fill_xof(&mut trace.values);
    // A second test construction pass must erase earlier count/enable one hot
    // cells before writing its new complete prefixes. No trace clone is kept.
    for row in trace.values.chunks_exact_mut(WIDTH) {
        row[MATRIX_COUNT..EXTRA_PRODUCTS].fill(BabyBear::ZERO);
    }
    matrix::fill(&mut trace.values);
    ntt::fill_inverse(&mut trace.values);
    hint_rows::fill(&mut trace.values);
    sponge::fill_final(&mut trace.values);
}
fn wrong_first_matrix_nonce(trace: &mut RowMajorMatrix<BabyBear>) {
    use core::borrow::Borrow;
    use p3_keccak_air::KeccakCols;
    let start = fp::MATRIX_START;
    let mut message = [0u8; 168];
    for (byte, value) in message.iter_mut().take(32).enumerate() {
        *value = trace.values[start * WIDTH + RHO + byte].as_canonical_u32() as u8;
    }
    message[32] = 1;
    message[33] = 0;
    message[34] = 31;
    message[167] = 128;
    let mut state = [0u64; 25];
    for lane in 0..21 {
        state[lane] = u64::from_le_bytes(message[8 * lane..8 * (lane + 1)].try_into().unwrap());
    }
    for block in 0..6 {
        let logical = build::permutation(state);
        for local in 0..6 {
            let at = start + 6 * block + local;
            let row = &mut trace.values[at * WIDTH..(at + 1) * WIDTH];
            build::copy_rounds(row, &logical, 4 * local);
            for (byte, value) in message.iter().enumerate() {
                build::bits(
                    row,
                    MESSAGE + 8 * byte,
                    if block == 0 { u32::from(*value) } else { 0 },
                    8,
                );
            }
            let round = logical.row_slice(4 * local + 3).unwrap();
            let k: &KeccakCols<BabyBear> = (*round).borrow();
            for limb in 0..84 {
                build::bits(
                    row,
                    OUTPUT + 16 * limb,
                    k.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32(),
                    16,
                );
            }
        }
        state = build::state_after(&logical);
        drop(logical);
    }
}
#[test]
#[ignore = "Requires separate native hostile suffix admission, one wide trace only"]
fn locally_exact_detached_suffixes_and_source_boundary_mutations_reject() {
    gate("THORUM_FULL_RELATION_FALSE_GATE");
    let raw: Raw = read("raw-fixture.json");
    let reference: Reference = read("reference-fixture.json");
    let tuple = &reference.tuples[0];
    let (w, tx) = fixture(&raw, &reference, tuple);
    let public = Statement::from_transaction(&tx).unwrap().public_values();
    let mut trace = build_full_private_signature_owner_sources(&w, &tx).unwrap();
    assert!(valid(&trace, &public));
    // Slot(0,0) receives the genuine retained rho/nonce(1,0) stream. That
    // existing fixed stream is supported. All downstream arithmetic and final
    // hash are rebuilt, while the verifier fixed slot nonce remains(0,0).
    wrong_first_matrix_nonce(&mut trace);
    rebuild_matrix_suffix(&mut trace);
    assert!(check_all_constraints(&KeccakOnly, &trace, &public, Some(1)).is_ok());
    assert!(check_all_constraints(&LocalPrimitives, &trace, &public, Some(1)).is_ok());
    assert!(!valid(&trace, &public));
    sponge::fill_matrix(&mut trace.values);
    rebuild_matrix_suffix(&mut trace);
    assert!(valid(&trace, &public));
    // A changed actual corrected row drives a genuine downstream inverse,
    // UseHint and final sponge in the same trace, with exact local gadgets.
    let from = fp::POINT_START + 1;
    let col = ACCUMULATOR;
    let old = trace.values[from * WIDTH + col];
    let changed = BabyBear::from_u32((old.as_canonical_u32() + 1) % MODULUS);
    for at in from..HEIGHT {
        trace.values[at * WIDTH + col] = changed;
    }
    ntt::fill_inverse(&mut trace.values);
    hint_rows::fill(&mut trace.values);
    sponge::fill_final(&mut trace.values);
    assert!(check_all_constraints(&LocalPrimitives, &trace, &public, Some(1)).is_ok());
    assert!(!valid(&trace, &public));
    for at in from..HEIGHT {
        trace.values[at * WIDTH + col] = old;
    }
    ntt::fill_inverse(&mut trace.values);
    hint_rows::fill(&mut trace.values);
    sponge::fill_final(&mut trace.values);
    assert!(valid(&trace, &public));
    // An exact alternative extra multiplication cannot detach its operands.
    let at = (fp::MATRIX_START + 6) * WIDTH + EXTRA_PRODUCTS;
    let saved = trace.values[at..at + mul::WIDTH].to_vec();
    let x = bits(&saved, 0, 23);
    let y = bits(&saved, 23, 23);
    ntt::encode_product(
        ntt::product(x, (y + 1) % MODULUS),
        &mut trace.values[at..at + mul::WIDTH],
    );
    assert!(check_all_constraints(&LocalPrimitives, &trace, &public, Some(1)).is_ok());
    assert!(!valid(&trace, &public));
    trace.values[at..at + mul::WIDTH].copy_from_slice(&saved);
    for (row, col) in [
        (fp::MATRIX_START + 6, MATRIX_XOF),
        (fp::MATRIX_START + 47, MATRIX_COUNT + 8 * 257 + 256),
        (fp::MATRIX_START + 48, ACCUMULATOR),
        (3522, NTT_SCRATCH + 255),
        (3714, USE_HINT + hints::HINT),
        (5314, W1 + 1023),
        (HEIGHT - 1, W1),
        (HEIGHT - 1, NTT_OUTPUT + 4095),
        (HEIGHT - 1, MU),
    ] {
        let at = row * WIDTH + col;
        let old = trace.values[at];
        trace.values[at] += BabyBear::ONE;
        assert!(!valid(&trace, &public));
        trace.values[at] = old;
    }
    // Every final received seed byte remains part of the same immutable sigma.
    // These are route mutations, not isolation of one hash equality equation.
    let mutation_row = fp::FINAL_END - 1;
    for byte in 0..64 {
        assert!(single_cell_affected_frames_valid(
            &trace,
            &public,
            mutation_row
        ));
        let at = mutation_row * WIDTH + SIGNATURE + byte;
        let old = trace.values[at];
        trace.values[at] += BabyBear::ONE;
        assert!(!single_cell_affected_frames_valid(
            &trace,
            &public,
            mutation_row
        ));
        // The first and last routes also retain full trace negative checks.
        if byte == 0 || byte == 63 {
            assert!(!valid(&trace, &public));
        }
        trace.values[at] = old;
        assert!(single_cell_affected_frames_valid(
            &trace,
            &public,
            mutation_row
        ));
    }
    let at = (fp::POINT_START) * WIDTH + EXTRA_WRITES + 46;
    let saved_write = trace.values[at..at + 46].to_vec();
    build::bits(&mut trace.values[at..at + 46], 0, MODULUS, 23);
    build::bits(&mut trace.values[at..at + 46], 23, 0, 23);
    assert!(!valid(&trace, &public));
    trace.values[at..at + 46].copy_from_slice(&saved_write);
    assert!(valid(&trace, &public));
}
