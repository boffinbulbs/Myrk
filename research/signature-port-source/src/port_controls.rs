//! Fixed source construction checks, not AIR or payment acceptance.
use crate::{
    build::{
        decoder_state::DecodeError,
        port_reference::{PortReference, ReferenceError, PROBES},
        port_source::{PortSource, SourceError},
        port_state::PortState,
    },
    layout::*,
    packed::{self, Bank},
    sources, BoundInputs, Witness,
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
fn source(b: &BoundInputs) -> PortSource<'_> {
    match PortSource::new(b) {
        Ok(s) => s,
        Err(DecodeError::Encoding(e)) => panic!("synthetic encoding: {e:?}"),
        Err(_) => panic!("unexpected initialization"),
    }
}
fn mismatch(row: &[BabyBear], expected: &[BabyBear]) -> Option<usize> {
    row[CLOCK..MESSAGE]
        .iter()
        .zip(&expected[CLOCK..MESSAGE])
        .position(|(a, b)| a != b)
        .map(|i| CLOCK + i)
}
fn golden(actual: u32, expected: u32, at: usize, column: usize) {
    if actual != expected {
        record(json!({"kind":"independent_mismatch","row":at,"first_column":column}));
        panic!("source mismatch at row {at}, column {column}");
    }
}
fn bits(row: &[BabyBear], at: usize, n: usize) -> u32 {
    (0..n).map(|i| row[at + i].as_canonical_u32() << i).sum()
}
struct Goldens {
    key: [u8; 2592],
    sig: [u8; 4627],
    note: [u8; 418],
    words: Vec<u32>,
    terminal: [u8; 64],
}
impl Goldens {
    fn new() -> Self {
        let f: Value = serde_json::from_str(include_str!(
            "../../signature-matrix-source/fixtures-matrix.json"
        ))
        .unwrap();
        let final_f: Value = serde_json::from_str(include_str!(
            "../../signature-final-source/fixtures-final.json"
        ))
        .unwrap();
        let key = bytes::<2592>(f["key_hex"].as_str().unwrap());
        let sig = bytes::<4627>(f["signature_hex"].as_str().unwrap());
        let note = bytes::<418>(f["note_hex"].as_str().unwrap());
        // Independent literal packing. Only actual out-of-bank positions are zero.
        let mut words = Vec::with_capacity(2547);
        for bank in [key.as_slice(), sig.as_slice(), note.as_slice()] {
            for chunk in bank.chunks(3) {
                let mut word = [0u8; 4];
                word[..chunk.len()].copy_from_slice(chunk);
                words.push(u32::from_le_bytes(word));
            }
        }
        assert_eq!(words.len(), 2547);
        Self {
            key,
            sig,
            note,
            words,
            terminal: bytes(final_f["challenge_expected_hex"].as_str().unwrap()),
        }
    }
    fn reference(&self) -> Witness {
        Witness::from_sources(self.key, self.sig, self.note)
    }
    fn byte(&self, bank: Bank, index: usize) -> u8 {
        match bank {
            Bank::Key => self.key[index],
            Bank::Signature => self.sig[index],
            Bank::Note => self.note[index],
        }
    }
}
fn read(row: &[BabyBear], at: usize, bank: Bank, index: usize, g: &Goldens, count: &mut usize) {
    let (port, offset) = packed::port_at(at, bank, index);
    let col = SOURCE_PORTS + 24 * port + 8 * offset;
    golden(bits(row, col, 8), u32::from(g.byte(bank, index)), at, col);
    *count += 1;
}
fn range(
    row: &[BabyBear],
    at: usize,
    bank: Bank,
    start: usize,
    end: usize,
    g: &Goldens,
    count: &mut usize,
) {
    for b in start..end {
        read(row, at, bank, b, g, count);
    }
}
fn counters(s: &PortSource<'_>) -> Value {
    let a = s.initial_generation();
    let m = s.matrix_generation();
    let f = s.final_generation();
    json!([
        [a.attempted, a.completed, a.maximum_live],
        [m.attempted, m.completed, m.maximum_live],
        [f.attempted, f.completed, f.maximum_live],
        s.position()
    ])
}
/// The fixed synthetic owner is never supplied by a payment caller.
pub fn fixed_port_controls() -> Value {
    let b = bound();
    let mut candidate = source(&b); // Real prefix encoding preflight precedes any route access.
    let g = Goldens::new();
    let mut reference = PortReference::new(g.reference());
    let early = candidate.finish();
    record(json!({"kind":"incomplete","result":format!("{early:?}")}));
    assert!(matches!(early, Err(SourceError::Incomplete)));
    for requested in [1, 64] {
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
    let (
        mut clocks,
        mut words,
        mut ports,
        mut reference_fields,
        mut reads,
        mut tail_zeros,
        mut controls,
        mut used_ports,
    ) = (
        0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize,
    );
    for at in 0..HEIGHT {
        if [0, 5369, 8191].contains(&at) {
            let before = counters(&candidate);
            let e = candidate.emit_next(&mut short);
            let after = counters(&candidate);
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
        for i in 0..CLOCK_LOW + CLOCK_HIGH {
            golden(
                row[CLOCK + i].as_canonical_u32(),
                u32::from(i == at % CLOCK_LOW || i == CLOCK_LOW + at / CLOCK_LOW),
                at,
                CLOCK + i,
            );
            clocks += 1;
        }
        for (i, w) in g.words.iter().enumerate() {
            golden(row[KEY + i].as_canonical_u32(), *w, at, KEY + i);
            words += 1;
        }
        // These checks share the actual cached route addresses, not an independent route oracle.
        let ids = packed::word_ids_at(at);
        used_ports += ids.len();
        for p in 0..packed::PORTS {
            let w = ids.get(p).map_or(0, |id| g.words[usize::from(*id)]);
            for bit in 0..24 {
                let col = SOURCE_PORTS + 24 * p + bit;
                golden(row[col].as_canonical_u32(), (w >> bit) & 1, at, col);
                ports += 1;
            }
        }
        if PROBES.contains(&at) {
            reference.prepare(at).unwrap();
            let expected = reference.row(at);
            if let Some(column) = mismatch(&row, expected) {
                record(json!({"kind":"source_mismatch","row":at,"first_column":column}));
                panic!("reference mismatch at row {at}, column {column}");
            }
            reference_fields += MESSAGE - CLOCK;
            let before_reads = reads;
            range(&row, at, Bank::Signature, 4619, 4627, &g, &mut reads);
            range(&row, at, Bank::Note, 49, 81, &g, &mut reads);
            for index in 0..418 {
                if let Some(v) = sources::note_fixed(index) {
                    assert_eq!(g.note[index], v);
                    read(&row, at, Bank::Note, index, &g, &mut reads);
                }
            }
            for (start, last) in [(SIGNATURE + 1542, 4626), (NOTE + 139, 417)] {
                let value = row[start].as_canonical_u32();
                let real = if start == NOTE + 139 {
                    g.note[last]
                } else {
                    g.sig[last]
                };
                golden(value & 255, u32::from(real), at, start);
                golden((value >> 8) & 255, 0, at, start);
                golden((value >> 16) & 255, 0, at, start);
                tail_zeros += 2;
            }
            match at {
                0 => {
                    range(&row, at, Bank::Key, 0, 32, &g, &mut reads);
                    assert_eq!(packed::port_at(at, Bank::Signature, 0), (14, 0));
                    read(&row, at, Bank::Signature, 0, &g, &mut reads);
                }
                1 => {
                    assert_eq!(packed::port_at(at, Bank::Signature, 0), (4, 0));
                    read(&row, at, Bank::Signature, 0, &g, &mut reads);
                }
                74 => read(&row, at, Bank::Signature, 4618, &g, &mut reads),
                234 => range(&row, at, Bank::Note, 141, 205, &g, &mut reads),
                255 => range(&row, at, Bank::Key, 2582, 2592, &g, &mut reads),
                447 => {
                    range(&row, at, Bank::Signature, 4534, 4545, &g, &mut reads);
                    assert_eq!(packed::port_at(at, Bank::Signature, 4543), (3, 1));
                }
                5369 => {
                    range(&row, at, Bank::Signature, 0, 66, &g, &mut reads);
                    for byte in 0..66 {
                        assert_eq!(
                            packed::port_at(at, Bank::Signature, byte),
                            (byte / 3, byte % 3)
                        );
                    }
                    for byte in 0..64 {
                        let output = bits(&row, OUTPUT + 8 * byte, 8);
                        golden(output, u32::from(g.terminal[byte]), at, OUTPUT + 8 * byte);
                        let (p, o) = packed::port_at(at, Bank::Signature, byte);
                        golden(
                            output,
                            bits(&row, SOURCE_PORTS + 24 * p + 8 * o, 8),
                            at,
                            OUTPUT + 8 * byte,
                        );
                    }
                    record(
                        json!({"kind":"terminal_port_diagnostic","row":at,"bytes":64,"packed_port_air_equality_executed":false}),
                    );
                }
                5370 => assert_eq!(packed::port_at(at, Bank::Signature, 4619), (0, 2)),
                8191 => assert!(ids.len() < 125),
                _ => {}
            }
            record(
                json!({"kind":"probe","row":at,"shared_helper_fields":MESSAGE-CLOCK,"selected_source_reads":reads-before_reads,"used_ports":ids.len()}),
            );
            for (pc, column) in [
                (0, CLOCK),
                (64, CLOCK + CLOCK_LOW + 1),
                (234, NOTE + 47),
                (447, SOURCE_PORTS + 24 * 3 + 8),
                (5369, SOURCE_PORTS + 24 * 21),
                (8191, SOURCE_PORTS + 24 * 124),
            ] {
                if at == pc {
                    assert!(PortState::owns(column));
                    let old = row[column];
                    row[column] += BabyBear::ONE;
                    let detected = mismatch(&row, expected) == Some(column);
                    row[column] = old;
                    let restored = mismatch(&row, expected).is_none();
                    record(
                        json!({"kind":"comparator_control","row":at,"column":column,"detected":detected,"restored":restored}),
                    );
                    assert!(detected && restored);
                    controls += 1;
                }
            }
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
    let e = reference.prepare(8191);
    let unchanged = reference.prepared() == 21;
    record(json!({"kind":"reference_exhaustion","result":format!("{e:?}"),"unchanged":unchanged}));
    assert!(matches!(e, Err(ReferenceError::Exhausted)));
    assert!(unchanged);
    let a = candidate.initial_generation();
    let m = candidate.matrix_generation();
    let f = candidate.final_generation();
    let result = json!({"kind":"port_summary","rows":HEIGHT,"reference_rows":21,"clock_checks":clocks,"held_word_checks":words,"port_bit_checks":ports,"owned_comparisons":clocks+words+ports,"preserved_comparisons":candidate.preserved(),"prefix_preserved":candidate.prefix_preserved(),"shared_helper_comparisons":reference_fields,"selected_source_reads":reads,"virtual_zero_bytes":tail_zeros,"used_port_visits":used_ports,"comparator_controls":controls,"initial_generation":[a.attempted,a.completed,a.maximum_live],"matrix_generation":[m.attempted,m.completed,m.maximum_live],"final_generation":[f.attempted,f.completed,f.maximum_live],"candidate_trace_generator_calls":a.attempted+m.attempted+f.attempted,"reference_trace_generator_calls":0,"complete_streamed_row_walks":1,"complete_wide_trace_allocations":0,"whole_air_evaluations":0,"clock_air_evaluations":0,"packed_air_evaluations":0,"packed_port_air_equality_executed":false,"backend_proofs":0});
    record(result.clone());
    assert_eq!(
        (clocks, words, ports, reference_fields, tail_zeros, controls),
        (1572864, 20865024, 24576000, 120519, 84, 6)
    );
    result
}
