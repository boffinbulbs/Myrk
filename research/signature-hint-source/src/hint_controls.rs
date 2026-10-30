//! Fixed hint reconstruction with independent saved field and byte comparisons.
use crate::{
    build::{
        decoder_state::DecodeError,
        hash_source::Generation,
        hint_reference::{HintReference, Inputs, ReferenceError},
        hint_source::{HintSource, SourceError},
        hint_state::HintState,
        matrix_overlay::MatrixGeneration,
    },
    full_program as fp, hints,
    layout::*,
    ntt, BoundInputs, Witness,
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
const FIELDS: [&str; 10] = [
    "high",
    "low",
    "positive",
    "output",
    "n",
    "u",
    "edge",
    "sign_slack",
    "borrow",
    "overflow",
];
fn source(b: &BoundInputs) -> HintSource<'_> {
    match HintSource::new(b) {
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
fn mismatch(row: &[BabyBear], expected: &[BabyBear]) -> Option<usize> {
    row[USE_HINT..ACTIVE_CHALLENGE]
        .iter()
        .zip(&expected[USE_HINT..ACTIVE_CHALLENGE])
        .position(|(a, b)| a != b)
        .map(|i| USE_HINT + i)
}
fn equal(row: &[BabyBear], expected: &[BabyBear], at: usize) {
    if let Some(column) = mismatch(row, expected) {
        record(json!({"kind":"hint_mismatch","row":at,"first_column":column}));
        panic!("hint mismatch at row {at}, column {column}");
    }
}
fn golden(actual: i64, expected: i64, at: usize, column: usize) {
    if actual != expected {
        record(json!({"kind":"independent_mismatch","row":at,"first_column":column}));
        panic!("independent mismatch at row {at}, column {column}");
    }
}
fn step(row: &[BabyBear], slot: usize) -> [i64; 10] {
    let p = USE_HINT + slot * hints::WIDTH;
    let u = i64::from(bits(row, p + hints::U, 19));
    let edge = i64::from(row[p + hints::EDGE].as_canonical_u32());
    [
        i64::from(bits(row, p + hints::HIGH, 4)),
        u - i64::from(hints::GAMMA2) + 1 - edge,
        i64::from(row[p + hints::POSITIVE].as_canonical_u32()),
        i64::from(bits(row, p + hints::OUTPUT, 4)),
        i64::from(bits(row, p + hints::N, 5)),
        u,
        edge,
        i64::from(bits(row, p + hints::SIGN_SLACK, 18)),
        i64::from(row[p + hints::BORROW].as_canonical_u32()),
        i64::from(row[p + hints::OVERFLOW].as_canonical_u32()),
    ]
}
struct Goldens {
    r: [[u32; 256]; 8],
    h: [[u8; 256]; 8],
    steps: Vec<[[i64; 256]; 10]>,
    packed: [[u8; 128]; 8],
}
impl Goldens {
    fn new() -> Self {
        let f: Value = serde_json::from_str(include_str!("../fixtures-hint.json")).unwrap();
        let inv: Value = serde_json::from_str(include_str!(
            "../../signature-inverse-source/fixtures-inverse.json"
        ))
        .unwrap();
        assert_eq!(f["rows"].as_array().unwrap().len(), 8);
        assert_eq!(f["hint_step_fields"], json!(FIELDS));
        let r = core::array::from_fn(|i| vector(&inv["inverses"][i]["states"][10]));
        let h = core::array::from_fn(|i| {
            assert_eq!(f["rows"][i]["row"], json!(i));
            let a = f["rows"][i]["hints"].as_array().unwrap();
            assert_eq!(a.len(), 256);
            core::array::from_fn(|k| {
                let x = a[k].as_u64().unwrap();
                assert!(x < 2);
                x as u8
            })
        });
        let steps = (0..8)
            .map(|i| {
                core::array::from_fn(|field| {
                    let a = f["rows"][i]["hint_step_columns"][FIELDS[field]]
                        .as_array()
                        .unwrap();
                    assert_eq!(a.len(), 256);
                    core::array::from_fn(|k| a[k].as_i64().unwrap())
                })
            })
            .collect();
        let packed =
            core::array::from_fn(|i| bytes(f["rows"][i]["packed_w1_hex"].as_str().unwrap()));
        let full = bytes::<1024>(f["packed_w1_hex"].as_str().unwrap());
        for i in 0..8 {
            assert_eq!(&full[128 * i..128 * (i + 1)], &packed[i]);
        }
        Self {
            r,
            h,
            steps,
            packed,
        }
    }
    fn inputs(&self) -> Inputs {
        Inputs {
            r: self.r,
            h: self.h,
        }
    }
}
/// Fixed synthetic component diagnostic. No transaction acceptance callback.
pub fn fixed_hint_controls() -> Value {
    let b = bound();
    let mut candidate = source(&b);
    let g = Goldens::new();
    let early = candidate.finish();
    record(json!({"kind":"incomplete","result":format!("{early:?}")}));
    assert!(matches!(early, Err(SourceError::Incomplete)));
    let mut reference = HintReference::new(g.inputs());
    for requested in [1, 3714] {
        let e = reference.prepare(requested);
        let unchanged = reference.pristine();
        record(
            json!({"kind":"reference_sequence","requested":requested,"result":format!("{e:?}"),"unchanged":unchanged}),
        );
        assert!(matches!(e, Err(ReferenceError::Sequence)));
        assert!(unchanged);
    }
    let marker = BabyBear::from_u32(17);
    let mut row = vec![marker; WIDTH];
    let mut short = vec![marker; WIDTH - 1];
    let mut active = 0usize;
    let mut dormant = 0usize;
    let mut packed_checks = 0usize;
    let mut completions = 0usize;
    let mut visible = 0usize;
    let mut comparators = 0usize;
    let (
        mut positive,
        mut nonpositive,
        mut ties,
        mut hint_zero,
        mut hint_one,
        mut edge,
        mut borrow,
        mut overflow,
    ) = (
        0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize,
    );
    for at in 0..HEIGHT {
        if [0, 3714, 8191].contains(&at) {
            let before = (
                initial(candidate.initial_generation()),
                matrix(candidate.matrix_generation()),
                candidate.position(),
            );
            let e = candidate.emit_next(&mut short);
            let after = (
                initial(candidate.initial_generation()),
                matrix(candidate.matrix_generation()),
                candidate.position(),
            );
            let unchanged = short.iter().all(|v| *v == marker);
            record(
                json!({"kind":"shape_refusal","row":at,"result":format!("{e:?}"),"before":before,"after":after,"unchanged":unchanged}),
            );
            assert!(matches!(e, Err(SourceError::RowShape)));
            assert_eq!(before, after);
            assert!(unchanged);
        }
        reference.prepare(at).unwrap();
        let expected = reference.row(at);
        row.fill(marker);
        assert_eq!(candidate.emit_next(&mut row).unwrap(), at);
        equal(&row, expected, at);
        let output = ntt::inverse_operation(at).and_then(|(i, op)| {
            if let ntt::InverseOp::Output(group) = op {
                Some((i, group))
            } else {
                None
            }
        });
        for slot in 0..8 {
            let p = USE_HINT + slot * hints::WIDTH;
            let actual = step(&row, slot);
            if let Some((i, group)) = output {
                let k = 8 * group + slot;
                let r = g.r[i][k];
                let h = g.h[i][k];
                let saved = core::array::from_fn::<i64, 10, _>(|f| g.steps[i][f][k]);
                golden(
                    i64::from(row[NTT_SCRATCH + k].as_canonical_u32()),
                    i64::from(r),
                    at,
                    NTT_SCRATCH + k,
                );
                golden(
                    i64::from(row[HINTS + 256 * i + k].as_canonical_u32()),
                    i64::from(h),
                    at,
                    HINTS + 256 * i + k,
                );
                golden(
                    i64::from(bits(&row, p + hints::R, 23)),
                    i64::from(r),
                    at,
                    p + hints::R,
                );
                golden(
                    i64::from(row[p + hints::HINT].as_canonical_u32()),
                    i64::from(h),
                    at,
                    p + hints::HINT,
                );
                for f in 0..10 {
                    golden(actual[f], saved[f], at, p);
                }
                golden(
                    i64::from(bits(&row, p + hints::R_COMPLEMENT, 23)),
                    i64::from(hints::MODULUS - 1 - r),
                    at,
                    p + hints::R_COMPLEMENT,
                );
                golden(
                    i64::from(bits(&row, p + hints::N_COMPLEMENT, 5)),
                    16 - saved[4],
                    at,
                    p + hints::N_COMPLEMENT,
                );
                golden(
                    i64::from(bits(&row, p + hints::U_COMPLEMENT, 19)),
                    i64::from(hints::ALPHA) - 1 - saved[5],
                    at,
                    p + hints::U_COMPLEMENT,
                );
                if actual[1] > 0 {
                    positive += 1;
                } else {
                    nonpositive += 1;
                }
                if actual[1] == 0 {
                    ties += 1;
                }
                if h == 0 {
                    hint_zero += 1;
                } else {
                    hint_one += 1;
                }
                edge += actual[6] as usize;
                borrow += actual[8] as usize;
                overflow += actual[9] as usize;
                active += 1;
            } else {
                let neutral = [0, 0, 0, 0, 0, 261887, 0, 0, 0, 0];
                for f in 0..10 {
                    golden(actual[f], neutral[f], at, p);
                }
                for (off, n, e) in [
                    (hints::R, 23, 0),
                    (hints::R_COMPLEMENT, 23, 8380416),
                    (hints::N_COMPLEMENT, 5, 16),
                    (hints::U_COMPLEMENT, 19, 261888),
                ] {
                    golden(i64::from(bits(&row, p + off, n)), e, at, p + off);
                }
                golden(
                    i64::from(row[p + hints::HINT].as_canonical_u32()),
                    0,
                    at,
                    p + hints::HINT,
                );
                dormant += 1;
            }
        }
        if let Some((i, 31)) = output {
            completions += 1;
            record(
                json!({"kind":"hint_row_complete","row":at,"hint_row":i,"coefficients":256,"next_visible":at+1}),
            );
        }
        for i in 0..8 {
            for byte in 0..128 {
                let producer = fp::INVERSE_START + 224 * i + 192 + byte / 4;
                let e = if at > producer { g.packed[i][byte] } else { 0 };
                golden(
                    i64::from(row[W1 + 128 * i + byte].as_canonical_u32()),
                    i64::from(e),
                    at,
                    W1 + 128 * i + byte,
                );
                packed_checks += 1;
            }
        }
        if at > fp::INVERSE_START && (at - fp::INVERSE_START).is_multiple_of(224) {
            let i = (at - fp::INVERSE_START) / 224 - 1;
            if i < 8 {
                visible += 1;
                record(json!({"kind":"packed_row_visible","row":at,"hint_row":i,"bytes":128}));
            }
        }
        if at == 8191 {
            record(json!({"kind":"terminal_packed","row":at,"bytes":1024}));
        }
        if [
            0, 75, 3713, 3714, 3715, 3745, 3746, 5313, 5314, 5316, 5370, 8191,
        ]
        .contains(&at)
        {
            record(
                json!({"kind":"boundary","row":at,"w1_0":row[W1].as_canonical_u32(),"w1_3":row[W1+3].as_canonical_u32(),"w1_1020":row[W1+1020].as_canonical_u32(),"w1_1023":row[W1+1023].as_canonical_u32()}),
            );
        }
        for (pc, column) in [
            (0, USE_HINT + hints::R_COMPLEMENT),
            (3714, USE_HINT + hints::SIGN_SLACK),
            (3714, USE_HINT + hints::HINT),
            (3714, USE_HINT + hints::OUTPUT),
            (3715, W1),
            (5313, W1 + 1023),
            (8191, W1 + 1023),
        ] {
            if pc == at {
                assert!(HintState::owns(column));
                let old = row[column];
                row[column] += BabyBear::ONE;
                let detected = mismatch(&row, expected) == Some(column);
                row[column] = old;
                let restored = mismatch(&row, expected).is_none();
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
    let e = candidate.emit_next(&mut row);
    let unchanged = before == candidate.position() && row.iter().all(|v| *v == marker);
    record(json!({"kind":"exhaustion","result":format!("{e:?}"),"unchanged":unchanged}));
    assert!(matches!(e, Err(SourceError::Exhausted)));
    assert!(unchanged);
    let e = reference.prepare(HEIGHT);
    let unchanged = reference.prepared() == HEIGHT;
    record(json!({"kind":"reference_exhaustion","result":format!("{e:?}"),"unchanged":unchanged}));
    assert!(matches!(e, Err(ReferenceError::Exhausted)));
    assert!(unchanged);
    let a = initial(candidate.initial_generation());
    let m = matrix(candidate.matrix_generation());
    let result = json!({"kind":"hint_summary","rows":HEIGHT,"reference_rows":reference.prepared(),"owned_comparisons":HEIGHT*(ACTIVE_CHALLENGE-USE_HINT),"preserved_comparisons":candidate.preserved(),"prefix_preserved":candidate.prefix_preserved(),"active_gadgets":active,"dormant_gadgets":dormant,"active_saved_fields":active*10,"packed_byte_comparisons":packed_checks,"hint_row_completions":completions,"packed_visible_rows":visible,"terminal_packed_bytes":1024,"comparator_controls":comparators,"restored_controls":comparators,"active_branches":{"positive":positive,"nonpositive":nonpositive,"ties":ties,"hint_zero":hint_zero,"hint_one":hint_one,"edge":edge,"borrow":borrow,"overflow":overflow},"initial_generation":a,"matrix_generation":m,"trace_generator_calls":a[0]+m[0],"reference_hash_generations":0,"standalone_transform_oracle_calls":0});
    record(result.clone());
    assert_eq!(active, 2048);
    assert_eq!(dormant, 63488);
    assert_eq!(packed_checks, 8388608);
    assert_eq!(completions, 8);
    assert_eq!(visible, 8);
    assert_eq!(comparators, 7);
    assert_eq!(positive + nonpositive, 2048);
    assert_eq!(hint_zero + hint_one, 2048);
    result
}
