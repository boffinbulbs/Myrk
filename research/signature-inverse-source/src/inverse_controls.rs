//! Fixed synthetic inverse construction and independent saved state checks.
use crate::{
    build::{
        decoder_state::DecodeError,
        hash_source::Generation,
        inverse_reference::{InverseReference, ReferenceError},
        inverse_source::{InverseSource, SourceError},
        inverse_state::InverseState,
        matrix_overlay::MatrixGeneration,
    },
    full_program as fp,
    layout::*,
    mul,
    ntt::{self, InverseOp},
    BoundInputs, Witness,
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
fn source(b: &BoundInputs) -> InverseSource<'_> {
    match InverseSource::new(b) {
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
fn mismatch(row: &[BabyBear], expected: &[BabyBear], at: usize) -> Option<usize> {
    if at < fp::INVERSE_START {
        return None;
    }
    row[NTT_SCRATCH..FORWARD_WIDTH]
        .iter()
        .zip(&expected[NTT_SCRATCH..FORWARD_WIDTH])
        .position(|(a, b)| a != b)
        .map(|i| NTT_SCRATCH + i)
}
fn equal(row: &[BabyBear], expected: &[BabyBear], at: usize) {
    if let Some(column) = mismatch(row, expected, at) {
        record(json!({"kind":"inverse_mismatch","row":at,"first_column":column}));
        panic!("inverse mismatch at row {at}, column {column}");
    }
}
fn golden(actual: u32, expected: u32, at: usize, column: usize) {
    if actual != expected {
        record(json!({"kind":"independent_mismatch","row":at,"first_column":column}));
        panic!("independent mismatch at row {at}, column {column}");
    }
}
struct Goldens {
    seed: [u32; 256],
    states: Vec<[[u32; 256]; 11]>,
}
impl Goldens {
    fn new() -> Self {
        let f: Value = serde_json::from_str(include_str!("../fixtures-inverse.json")).unwrap();
        let shared: Value = serde_json::from_str(include_str!(
            "../../signature-accumulator-source/fixtures-accumulator.json"
        ))
        .unwrap();
        assert_eq!(f["inverses"].as_array().unwrap().len(), 8);
        let states = f["inverses"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, t)| {
                assert_eq!(t["logical_inverse"], json!(i));
                assert_eq!(t["kind"], json!(format!("inverse_row{i}")));
                assert_eq!(t["mode"], json!(2));
                assert_eq!(t["states"].as_array().unwrap().len(), 11);
                let a = core::array::from_fn(|s| vector(&t["states"][s]));
                assert_eq!(a[0], vector(&shared["point_rows"][i]["inverse_input"]));
                a
            })
            .collect();
        Self {
            seed: vector(&shared["forward_outputs"]["t1hat"][7]),
            states,
        }
    }
    fn inputs(&self) -> [[u32; 256]; 8] {
        core::array::from_fn(|i| self.states[i][0])
    }
    fn prior(&self, i: usize) -> &[u32; 256] {
        if i == 0 {
            &self.seed
        } else {
            &self.states[i - 1][10]
        }
    }
}
/// Fixed data diagnostic only. No caller transaction acceptance interface.
pub fn fixed_inverse_controls() -> Value {
    let b = bound();
    let mut candidate = source(&b);
    let g = Goldens::new();
    let early = candidate.finish();
    record(json!({"kind":"incomplete","result":format!("{early:?}")}));
    assert!(matches!(early, Err(SourceError::Incomplete)));
    let mut reference = InverseReference::new(g.seed, g.inputs());
    for requested in [1, 3522] {
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
    let mut owned = 0usize;
    let mut states = 0usize;
    let mut partial = 0usize;
    let mut inputs = 0usize;
    let mut outputs = 0usize;
    let mut normalized = 0usize;
    let mut completions = 0usize;
    let mut carries = 0usize;
    let mut borrows = 0usize;
    let mut comparators = 0usize;
    let mut tail = 0usize;
    let mut overlap = 0usize;
    for at in 0..HEIGHT {
        if [0, 3522, 8191].contains(&at) {
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
        if at >= fp::INVERSE_START {
            owned += FORWARD_WIDTH - NTT_SCRATCH;
        }
        if at == fp::INVERSE_START {
            for (k, e) in g.seed.iter().enumerate() {
                golden(
                    row[NTT_SCRATCH + k].as_canonical_u32(),
                    *e,
                    at,
                    NTT_SCRATCH + k,
                );
            }
            record(
                json!({"kind":"seed","row":at,"coefficients":256,"source":"actual held forward scratch compared to saved T1_7"}),
            );
        }
        if at >= fp::INVERSE_START && fp::point(at).is_some() {
            overlap += 1;
        }
        if let Some((i, op)) = ntt::inverse_operation(at) {
            let relative = at - (fp::INVERSE_START + 224 * i);
            if (32..=192).contains(&relative) && (relative - 32).is_multiple_of(16) {
                let state = (relative - 32) / 16;
                for k in 0..256 {
                    golden(
                        row[NTT_SCRATCH + k].as_canonical_u32(),
                        g.states[i][state][k],
                        at,
                        NTT_SCRATCH + k,
                    );
                }
                states += 1;
                record(
                    json!({"kind":"state_checkpoint","row":at,"inverse":i,"state":state,"coefficients":256}),
                );
            }
            match op {
                InverseOp::Initialize(group) => {
                    for k in 0..256 {
                        let e = if k < 8 * group {
                            g.states[i][0][k]
                        } else {
                            g.prior(i)[k]
                        };
                        golden(
                            row[NTT_SCRATCH + k].as_canonical_u32(),
                            e,
                            at,
                            NTT_SCRATCH + k,
                        );
                        partial += 1;
                    }
                    for slot in 0..8 {
                        let k = 8 * group + slot;
                        let e = g.states[i][0][k];
                        golden(
                            row[ACCUMULATOR + 256 * i + k].as_canonical_u32(),
                            e,
                            at,
                            ACCUMULATOR + 256 * i + k,
                        );
                        golden(
                            bits(&row, NTT_WRITES + 46 * slot, 23),
                            e,
                            at,
                            NTT_WRITES + 46 * slot,
                        );
                        inputs += 1;
                    }
                }
                InverseOp::Normalize(group) => {
                    for slot in 0..8 {
                        let k = 8 * group + slot;
                        let e = g.states[i][if k < 128 { 9 } else { 10 }][k];
                        let p = NTT_PRODUCTS + slot * mul::WIDTH;
                        golden(bits(&row, p, 23), 8347681, at, p);
                        golden(
                            bits(&row, p + 23, 23),
                            row[NTT_SCRATCH + k].as_canonical_u32(),
                            at,
                            p + 23,
                        );
                        golden(bits(&row, p + 69, 23), e, at, p + 69);
                        golden(
                            bits(&row, NTT_WRITES + 46 * slot, 23),
                            e,
                            at,
                            NTT_WRITES + 46 * slot,
                        );
                        normalized += 1;
                    }
                }
                InverseOp::Output(group) => {
                    for slot in 0..8 {
                        let k = 8 * group + slot;
                        let e = g.states[i][10][k];
                        golden(
                            row[NTT_SCRATCH + k].as_canonical_u32(),
                            e,
                            at,
                            NTT_SCRATCH + k,
                        );
                        golden(
                            bits(&row, NTT_WRITES + 46 * slot, 23),
                            e,
                            at,
                            NTT_WRITES + 46 * slot,
                        );
                        outputs += 1;
                    }
                    if group == 31 {
                        completions += 1;
                        record(
                            json!({"kind":"inverse_complete","row":at,"inverse":i,"output_coefficients":256}),
                        );
                    }
                }
                InverseOp::Butterfly { .. } => {
                    for slot in 0..8 {
                        carries += usize::from(row[NTT_FLAGS + 2 * slot] == BabyBear::ONE);
                        borrows += usize::from(row[NTT_FLAGS + 2 * slot + 1] == BabyBear::ONE);
                    }
                }
            }
        }
        if [5314, 8191].contains(&at) {
            for k in 0..256 {
                golden(
                    row[NTT_SCRATCH + k].as_canonical_u32(),
                    g.states[7][10][k],
                    at,
                    NTT_SCRATCH + k,
                );
                tail += 1;
            }
            record(json!({"kind":"held_tail","row":at,"coefficients":256}));
        }
        if [3521, 3522, 3523, 3554, 3586, 3746, 5314, 8191].contains(&at) {
            record(
                json!({"kind":"boundary","row":at,"owned":at>=fp::INVERSE_START,"scratch0":row[NTT_SCRATCH].as_canonical_u32(),"scratch255":row[NTT_SCRATCH+255].as_canonical_u32()}),
            );
        }
        for (pc, column) in [
            (3522, NTT_SCRATCH + 255),
            (3522, NTT_WRITES + 8 * 46 + 23),
            (3747, NTT_SCRATCH + 255),
            (3698, NTT_SCRATCH + 128),
            (3714, NTT_FLAGS),
            (8191, NTT_SCRATCH + 255),
        ] {
            if at == pc {
                assert!(InverseState::owns(at, column));
                let before = row[column];
                row[column] += BabyBear::ONE;
                let detected = mismatch(&row, expected, at) == Some(column);
                row[column] = before;
                let restored = mismatch(&row, expected, at).is_none();
                record(
                    json!({"kind":"comparator_control","row":at,"column":column,"detected":detected,"restored":restored}),
                );
                assert!(detected && restored);
                comparators += 1;
            }
        }
    }
    let finished = candidate.finish();
    record(
        json!({"kind":"complete","result":format!("{finished:?}"),"position":candidate.position()}),
    );
    assert!(finished.is_ok());
    row.fill(marker);
    let before = candidate.position();
    let exhausted = candidate.emit_next(&mut row);
    let unchanged = before == candidate.position() && row.iter().all(|v| *v == marker);
    record(json!({"kind":"exhaustion","result":format!("{exhausted:?}"),"unchanged":unchanged}));
    assert!(matches!(exhausted, Err(SourceError::Exhausted)));
    assert!(unchanged);
    let e = reference.prepare(HEIGHT);
    let unchanged = reference.prepared() == HEIGHT;
    record(json!({"kind":"reference_exhaustion","result":format!("{e:?}"),"unchanged":unchanged}));
    assert!(matches!(e, Err(ReferenceError::Exhausted)));
    assert!(unchanged);
    let a = initial(candidate.initial_generation());
    let m = matrix(candidate.matrix_generation());
    let result = json!({"kind":"inverse_summary","rows":HEIGHT,"reference_rows":reference.prepared(),"owned_comparisons":owned,"preserved_comparisons":candidate.preserved(),"prefix_preserved":candidate.prefix_preserved(),"seed_events":1,"state_checkpoints":states,"state_coefficients":states*256,"partial_initializer_coefficients":partial,"initializer_values":inputs,"output_values":outputs,"normalized_values":normalized,"inverse_completions":completions,"held_tail_coefficients":tail,"point_overlap_rows":overlap,"carries":carries,"borrows":borrows,"comparator_controls":comparators,"restored_controls":comparators,"initial_generation":a,"matrix_generation":m,"trace_generator_calls":a[0]+m[0],"reference_hash_generations":0,"standalone_transform_oracle_calls":0});
    record(result.clone());
    assert_eq!(states, 88);
    assert_eq!(partial, 65536);
    assert_eq!(inputs, 2048);
    assert_eq!(outputs, 2048);
    assert_eq!(normalized, 2048);
    assert_eq!(completions, 8);
    assert_eq!(tail, 512);
    assert_eq!(overlap, 64);
    assert_eq!(comparators, 6);
    result
}
