use crate::{
    codec::{self, Counts, Error},
    transport,
};
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

const FIXTURE: &[u8] = include_bytes!("../fixtures/proof.json");
const BYTE_CAP: usize = 2 * 1024 * 1024;

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(bytes.len() + 8);
    framed.extend_from_slice(b"KPV1");
    framed.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(bytes);
    framed
}

fn budget_case(bytes: &[u8], framed: bool, expected: transport::Error) {
    let mut counts = Counts::default();
    let outcome = if framed {
        codec::decode_frame(bytes, &mut counts)
    } else {
        codec::decode_json(bytes, &mut counts)
    };
    assert_eq!(outcome.err(), Some(Error::Budget(expected)));
    assert_eq!(counts.admissions, 1);
    assert_eq!(
        counts.typed_decodes, 0,
        "budget refusal precedes owned decoding"
    );
}

fn decode_case(bytes: &[u8], expected: Error) {
    let mut counts = Counts::default();
    assert_eq!(codec::decode_json(bytes, &mut counts).err(), Some(expected));
    assert_eq!(counts.typed_decodes, 1);
    assert_eq!(counts.canonical_encodings, 0);
}

fn changed(path: &str, value: Value, expected: Error) {
    let mut proof: Value = serde_json::from_slice(FIXTURE).unwrap();
    *proof.pointer_mut(path).expect("fixed existing proof field") = value;
    let bytes = serde_json::to_vec(&proof).unwrap();
    assert!(bytes.len() <= BYTE_CAP);
    decode_case(&bytes, expected);
}

/// This exercises decoding only. It creates no prover or verifier configuration.
#[allow(
    clippy::assertions_on_constants,
    reason = "Only the admitted release diagnostic may run"
)]
pub fn fixed_transport_diagnostic() {
    assert!(!cfg!(debug_assertions), "release diagnostic required");
    const { assert!(FIXTURE.len() == 596_650) };
    let mut positives = Counts::default();
    let mut decoded = codec::decode_json(FIXTURE, &mut positives).unwrap();
    assert_eq!(decoded.degree_bits, 9);
    let framed = frame(FIXTURE);
    let framed_proof = codec::decode_frame(&framed, &mut positives).unwrap();
    assert_eq!(framed_proof.opened_values.trace_local.len(), 2);
    drop(framed_proof);

    budget_case(b"KPV1", true, transport::Error::Frame);
    budget_case(b"BAD1\0\0\0\0", true, transport::Error::Frame);
    budget_case(b"KPV1\xff\xff\xff\xff", true, transport::Error::Bytes);
    budget_case(b"KPV1\0\0\0\x01", true, transport::Error::Frame);
    budget_case(&vec![b' '; BYTE_CAP + 1], false, transport::Error::Bytes);
    budget_case(&[b'['; 25], false, transport::Error::Depth);
    budget_case(b"[}", false, transport::Error::Delimiter);
    budget_case(
        format!("\"{}\"", "a".repeat(65)).as_bytes(),
        false,
        transport::Error::String,
    );
    budget_case(&[b'9'; 21], false, transport::Error::Number);
    budget_case(b"true", false, transport::Error::Lexical);
    budget_case(
        format!("[{}0]", "0,".repeat(16384)).as_bytes(),
        false,
        transport::Error::Items,
    );
    let block = format!("[{}0]", "0,".repeat(9999));
    let tokens = format!("[{}]", vec![block; 21].join(","));
    budget_case(tokens.as_bytes(), false, transport::Error::Tokens);
    budget_case(b"nulX", false, transport::Error::Lexical);
    budget_case(b"\"\x01\"", false, transport::Error::String);
    let restored = codec::decode_json(FIXTURE, &mut positives).unwrap();
    assert_eq!(restored.degree_bits, 9);
    drop(restored);

    decode_case(b"", Error::Encoding);
    decode_case(b"{}", Error::Encoding);
    decode_case(b"{\"degree_bits\":}", Error::Encoding);
    let mut trailing = FIXTURE.to_vec();
    trailing.push(b' ');
    decode_case(&trailing, Error::Canonical);
    drop(trailing);
    let mut duplicate = FIXTURE[..FIXTURE.len() - 1].to_vec();
    duplicate.extend_from_slice(b",\"degree_bits\":9}");
    decode_case(&duplicate, Error::Encoding);
    drop(duplicate);
    let mut unknown = FIXTURE[..FIXTURE.len() - 1].to_vec();
    unknown.extend_from_slice(b",\"ignored_field\":0}");
    decode_case(&unknown, Error::Canonical);
    drop(unknown);
    changed(
        "/opened_values/trace_local/0/value/0",
        json!(2013265921u32),
        Error::Encoding,
    );
    changed(
        "/opened_values/trace_local/0/value",
        json!([0, 0, 0]),
        Error::Encoding,
    );
    changed("/degree_bits", json!(10), Error::Shape);
    changed("/opened_values/trace_next", Value::Null, Error::Shape);
    changed(
        "/opening_proof/1/commit_phase_commits",
        json!([]),
        Error::Shape,
    );
    changed(
        "/commitments/trace/cap",
        json!(vec![vec![0u64; 8]; 3]),
        Error::Encoding,
    );
    changed(
        "/commitments/trace/cap",
        json!(vec![vec![0u64; 8]; 2]),
        Error::Shape,
    );
    changed(
        "/opening_proof/1/input_openings/1/opened_values/0/0",
        json!(vec![0u32; 5]),
        Error::Shape,
    );
    let final_restored = codec::decode_json(FIXTURE, &mut positives).unwrap();
    assert_eq!(final_restored.degree_bits, 9);
    drop(final_restored);

    // A schema-compatible altered commitment still decodes. No verification runs.
    decoded.commitments.trace = p3_symmetric::MerkleCap::new(vec![[0u64; 8]]);
    let altered = serde_json::to_vec(&decoded).unwrap();
    assert!(altered.len() <= BYTE_CAP);
    let mut altered_counts = Counts::default();
    let unverified = codec::decode_json(&altered, &mut altered_counts).unwrap();
    assert_eq!(unverified.commitments.trace.num_roots(), 1);
    drop(unverified);
    drop(decoded);

    let admitted = transport::admit_json(b"null").unwrap();
    let mut writer = transport::CanonicalWriter::new(&admitted);
    assert!(writer.write_all(b"x").is_err());
    assert!(writer.write_all(b"null").is_err());
    assert!(writer.flush().is_err());
    assert!(writer.finish().is_err());
    let mut writer = transport::CanonicalWriter::new(&admitted);
    assert!(writer.write_all(b"nullx").is_err());
    assert!(writer.finish().is_err());
    let mut writer = transport::CanonicalWriter::new(&admitted);
    writer.write_all(b"nu").unwrap();
    assert!(writer.finish().is_err());
    let mut writer = transport::CanonicalWriter::new(&admitted);
    writer.write_all(b"nu").unwrap();
    writer.write_all(b"ll").unwrap();
    writer.finish().unwrap();

    let report = json!({
        "format":"kova.proof-transport.native.v1", "fixture_bytes":FIXTURE.len(),
        "canonical_original_decodes":positives, "resource_refusals_before_decode":14,
        "encoding_shape_canonical_refusals":14, "canonical_writer_controls":4,
        "altered_commitment_decodes_without_verification":altered_counts,
        "proofs_produced":0, "verifier_calls":0, "pcs_instances":0,
        "full_signature_calls":0, "network_reads":0,
    });
    let bytes = serde_json::to_vec_pretty(&report).unwrap();
    assert!(bytes.len() <= 16384);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results/native.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}
