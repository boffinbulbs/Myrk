//! Fixed final sponge construction and diagnostic terminal comparisons only.
use crate::{
    build::{
        decoder_state::DecodeError,
        final_reference::{FinalReference, ReferenceError},
        final_source::{FinalSource, SourceError},
        final_state::{FinalGeneration, FinalState},
        hash_source::Generation,
        matrix_overlay::MatrixGeneration,
    },
    full_program as fp,
    layout::*,
    BoundInputs, Witness,
};
use core::borrow::Borrow;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
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
fn source(b: &BoundInputs) -> FinalSource<'_> {
    match FinalSource::new(b) {
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
fn final_g(g: FinalGeneration) -> [usize; 3] {
    [g.attempted, g.completed, g.maximum_live]
}
fn bits(row: &[BabyBear], at: usize, n: usize) -> u32 {
    (0..n).map(|i| row[at + i].as_canonical_u32() << i).sum()
}
fn mismatch(row: &[BabyBear], expected: &[BabyBear]) -> Option<usize> {
    row[..CLOCK]
        .iter()
        .zip(&expected[..CLOCK])
        .position(|(a, b)| a != b)
        .or_else(|| {
            row[MESSAGE..RHO]
                .iter()
                .zip(&expected[MESSAGE..RHO])
                .position(|(a, b)| a != b)
                .map(|i| MESSAGE + i)
        })
}
fn equal(row: &[BabyBear], expected: &[BabyBear], at: usize) {
    if let Some(column) = mismatch(row, expected) {
        record(json!({"kind":"final_mismatch","row":at,"first_column":column}));
        panic!("final mismatch at row {at}, column {column}");
    }
}
fn golden(actual: u32, expected: u32, at: usize, column: usize) {
    if actual != expected {
        record(json!({"kind":"independent_mismatch","row":at,"first_column":column}));
        panic!("independent mismatch at row {at}, column {column}");
    }
}
fn snapshot(row: &[BabyBear]) -> Vec<BabyBear> {
    row[..CLOCK]
        .iter()
        .chain(&row[MESSAGE..RHO])
        .copied()
        .collect()
}
struct Goldens {
    mu: [u8; 64],
    w1: [u8; 1024],
    expected: [u8; 64],
    received: [u8; 64],
}
impl Goldens {
    fn new() -> Self {
        let f: Value = serde_json::from_str(include_str!("../fixtures-final.json")).unwrap();
        let shared: Value = serde_json::from_str(include_str!(
            "../../signature-hint-source/fixtures-hint.json"
        ))
        .unwrap();
        Self {
            mu: bytes(f["mu_hex"].as_str().unwrap()),
            w1: bytes(shared["packed_w1_hex"].as_str().unwrap()),
            expected: bytes(f["challenge_expected_hex"].as_str().unwrap()),
            received: bytes(f["challenge_received_hex"].as_str().unwrap()),
        }
    }
    fn message(&self, block: usize, byte: usize) -> u8 {
        if byte >= 136 {
            return 0;
        }
        let offset = 136 * block + byte;
        match offset {
            0..=63 => self.mu[offset],
            64..=1087 => self.w1[offset - 64],
            1088 => 31,
            1223 => 128,
            _ => 0,
        }
    }
}
/// Fixed diagnostic. Terminal raw comparisons are not packed-port AIR acceptance.
pub fn fixed_final_controls() -> Value {
    let b = bound();
    let mut candidate = source(&b);
    let g = Goldens::new();
    let early = candidate.finish();
    record(json!({"kind":"incomplete","result":format!("{early:?}")}));
    assert!(matches!(early, Err(SourceError::Incomplete)));
    let mut reference = FinalReference::new(g.mu, g.w1);
    for requested in [0, 5322] {
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
    let mut dummy0 = None;
    let mut dummy1 = None;
    let mut previous = [0u32; 100];
    let (
        mut owned,
        mut source_bytes,
        mut message_bytes,
        mut output_tail,
        mut join_limbs,
        mut capacity_limbs,
        mut terminal_bytes,
        mut raw_bytes,
        mut restored_fields,
        mut comparators,
        mut blocks,
    ) = (
        0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize,
    );
    for at in 0..HEIGHT {
        if [0, 5316, 8191].contains(&at) {
            let before = (
                initial(candidate.initial_generation()),
                matrix(candidate.matrix_generation()),
                final_g(candidate.final_generation()),
                candidate.position(),
            );
            let e = candidate.emit_next(&mut short);
            let after = (
                initial(candidate.initial_generation()),
                matrix(candidate.matrix_generation()),
                final_g(candidate.final_generation()),
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
        row.fill(marker);
        assert_eq!(candidate.emit_next(&mut row).unwrap(), at);
        if at == 414 {
            dummy0 = Some(snapshot(&row));
            record(json!({"kind":"dummy_capture","row":at,"phase":0,"fields":CLOCK+RHO-MESSAGE}));
        }
        if at == 415 {
            dummy1 = Some(snapshot(&row));
            record(json!({"kind":"dummy_capture","row":at,"phase":1,"fields":CLOCK+RHO-MESSAGE}));
        }
        if (fp::FINAL_START..fp::FINAL_END).contains(&at) {
            let block = (at - fp::FINAL_START) / 6;
            let local = (at - fp::FINAL_START) % 6;
            if local == 0 {
                // This runs while the real candidate final cache and held dummy are live.
                reference.prepare(at).unwrap();
                for i in 0..64 {
                    golden(
                        row[MU + i].as_canonical_u32(),
                        u32::from(g.mu[i]),
                        at,
                        MU + i,
                    );
                    source_bytes += 1;
                }
                for i in 0..1024 {
                    golden(
                        row[W1 + i].as_canonical_u32(),
                        u32::from(g.w1[i]),
                        at,
                        W1 + i,
                    );
                    source_bytes += 1;
                }
                let first: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
                for (limb, old) in previous.iter().enumerate() {
                    let message = if limb < 68 {
                        bits(&row, MESSAGE + 16 * limb, 16)
                    } else {
                        0
                    };
                    let expected = (if block == 0 { 0 } else { *old }) ^ message;
                    let actual =
                        first.preimage[limb / 20][(limb / 4) % 5][limb % 4].as_canonical_u32();
                    if actual != expected {
                        record(json!({"kind":"join_mismatch","row":at,"limb":limb}));
                        panic!("final join mismatch at row {at}, limb {limb}");
                    }
                    join_limbs += 1;
                    if block > 0 && limb >= 68 {
                        capacity_limbs += 1;
                    }
                }
                record(
                    json!({"kind":"block_start","row":at,"block":block,"rate":136,"source_bytes":1088,"preimage_limbs":100,"final_generation":final_g(candidate.final_generation()),"reference_generation":final_g(reference.generation())}),
                );
            }
            let expected = reference.row(at);
            equal(&row, expected, at);
            owned += CLOCK + RHO - MESSAGE;
            for byte in 0..168 {
                golden(
                    bits(&row, MESSAGE + 8 * byte, 8),
                    u32::from(g.message(block, byte)),
                    at,
                    MESSAGE + 8 * byte,
                );
                message_bytes += 1;
            }
            for byte in 136..168 {
                golden(bits(&row, OUTPUT + 8 * byte, 8), 0, at, OUTPUT + 8 * byte);
                output_tail += 1;
            }
            if local == 5 {
                let last: &KeccakCols<BabyBear> =
                    row[3 * NUM_KECCAK_COLS..4 * NUM_KECCAK_COLS].borrow();
                for (limb, v) in previous.iter_mut().enumerate() {
                    *v = last
                        .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                        .as_canonical_u32();
                }
                blocks += 1;
                record(
                    json!({"kind":"block_terminal","row":at,"block":block,"reference_rows":6,"fields":6*(CLOCK+RHO-MESSAGE)}),
                );
            }
            if at == fp::FINAL_END - 1 {
                for byte in 0..64 {
                    let value = bits(&row, OUTPUT + 8 * byte, 8);
                    golden(value, u32::from(g.expected[byte]), at, OUTPUT + 8 * byte);
                    golden(value, u32::from(g.received[byte]), at, OUTPUT + 8 * byte);
                    terminal_bytes += 1;
                    // Diagnostic read from this exact immutable owner, not a supplied verifier input.
                    golden(
                        value,
                        u32::from(b._witness.signature[byte]),
                        at,
                        OUTPUT + 8 * byte,
                    );
                    raw_bytes += 1;
                }
                record(
                    json!({"kind":"terminal_diagnostic","row":at,"saved_bytes":64,"same_owner_raw_bytes":64,"packed_port_equality_executed":false}),
                );
            }
            for (pc, column) in [
                (5316, 0),
                (5316, MESSAGE),
                (5322, MESSAGE + 136 * 8),
                (5322, OUTPUT + 136 * 8),
                (5364, CLOCK - 1),
                (5369, OUTPUT + 8 * 63),
            ] {
                if at == pc {
                    assert!(FinalState::owns(at, column));
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
        if at == 5370 || at == 8191 {
            let saved = if at == 5370 {
                dummy0.as_ref().unwrap()
            } else {
                dummy1.as_ref().unwrap()
            };
            let actual = snapshot(&row);
            let matches = actual == *saved;
            record(
                json!({"kind":"dummy_restoration","row":at,"source_row":if at==5370 {414} else {415},"fields":actual.len(),"matches":matches}),
            );
            assert!(matches);
            restored_fields += actual.len();
        }
        if [5315, 5316, 5321, 5322, 5364, 5369, 5370, 8191].contains(&at) {
            record(
                json!({"kind":"boundary","row":at,"owned":(fp::FINAL_START..fp::FINAL_END).contains(&at),"message0":bits(&row,MESSAGE,8),"output0":bits(&row,OUTPUT,8),"output167":bits(&row,OUTPUT+167*8,8)}),
            );
        }
    }
    let complete = candidate.finish();
    record(
        json!({"kind":"complete","result":format!("{complete:?}"),"position":candidate.position()}),
    );
    assert!(complete.is_ok());
    row.fill(marker);
    let before = candidate.position();
    let e = candidate.emit_next(&mut row);
    let unchanged = before == candidate.position() && row.iter().all(|v| *v == marker);
    record(json!({"kind":"exhaustion","result":format!("{e:?}"),"unchanged":unchanged}));
    assert!(matches!(e, Err(SourceError::Exhausted)));
    assert!(unchanged);
    let e = reference.prepare(fp::FINAL_END);
    let unchanged = reference.prepared() == 9;
    record(json!({"kind":"reference_exhaustion","result":format!("{e:?}"),"unchanged":unchanged}));
    assert!(matches!(e, Err(ReferenceError::Exhausted)));
    assert!(unchanged);
    let a = initial(candidate.initial_generation());
    let m = matrix(candidate.matrix_generation());
    let f = final_g(candidate.final_generation());
    let r = final_g(reference.generation());
    let result = json!({"kind":"final_summary","rows":HEIGHT,"reference_windows":reference.prepared(),"reference_final_rows":54,"owned_comparisons":owned,"preserved_comparisons":candidate.preserved(),"prefix_preserved":candidate.prefix_preserved(),"source_byte_comparisons":source_bytes,"message_byte_comparisons":message_bytes,"output_tail_bytes":output_tail,"preimage_join_limbs":join_limbs,"continuation_capacity_limbs":capacity_limbs,"final_blocks":blocks,"terminal_saved_bytes":terminal_bytes,"terminal_same_owner_raw_bytes":raw_bytes,"dummy_restored_fields":restored_fields,"comparator_controls":comparators,"restored_controls":comparators,"initial_generation":a,"matrix_generation":m,"final_generation":f,"reference_generation":r,"candidate_trace_generator_calls":a[0]+m[0]+f[0],"reference_trace_generator_calls":r[0],"trace_generator_calls":a[0]+m[0]+f[0]+r[0],"standalone_transform_oracle_calls":0,"new_independent_final_hash_references":0,"final_intermediate_goldens_available":false,"packed_port_equality_executed":false});
    record(result.clone());
    assert_eq!(blocks, 9);
    assert_eq!(source_bytes, 9792);
    assert_eq!(message_bytes, 9072);
    assert_eq!(output_tail, 1728);
    assert_eq!(join_limbs, 900);
    assert_eq!(capacity_limbs, 256);
    assert_eq!(terminal_bytes, 64);
    assert_eq!(raw_bytes, 64);
    assert_eq!(restored_fields, 26440);
    assert_eq!(comparators, 6);
    result
}
