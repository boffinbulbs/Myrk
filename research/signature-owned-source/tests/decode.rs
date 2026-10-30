use kova_signature_owned_source::decode_controls;
use serde_json::json;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

fn record(value: serde_json::Value) {
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

#[test]
fn decoding_state_matches_retained_rows_and_independent_coefficients() {
    for case in [
        decode_controls::DecodeCase::Baseline,
        decode_controls::DecodeCase::ZEndpoints,
    ] {
        // The previous function's oracle, row and state have already dropped.
        let result = decode_controls::fixed_source_equivalence(case);
        record(
            json!({"kind":"decode_equivalence","rows":result.rows,"reference_rows":result.reference_rows,
        "owned_cells":result.owned_cells,"preserved_cells":result.preserved_cells,
        "case":result.case,"independent_terminal_values":result.independent_terminal_values,
        "corruption_controls":result.corruption_controls,"restored_controls":result.restored_controls,
        "public_values":result.public_values,"exhausted_without_writes":result.exhausted_without_writes}),
        );
        assert_eq!(
            (
                result.rows,
                result.reference_rows,
                result.independent_terminal_values
            ),
            (8192, 449, 5888)
        );
        assert_eq!(
            (result.corruption_controls, result.restored_controls),
            (2, 2)
        );
        assert!(result.exhausted_without_writes);
    }
}

#[test]
fn malformed_sources_reach_retained_encoding_refusals() {
    let count = decode_controls::malformed_source_refusals();
    record(json!({"kind":"encoding_refusals","count":count}));
    assert_eq!(count, 7);
}

#[test]
fn malformed_rows_preserve_storage_and_cursor() {
    let count = decode_controls::cursor_shape_guards();
    record(json!({"kind":"shape_guards","count":count}));
    assert_eq!(count, 2);
}
