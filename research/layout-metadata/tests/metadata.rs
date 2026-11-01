use kova_layout_metadata::metadata::inspect_overlay;
use kova_signature_overlay::layout;
use serde_json::json;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[test]
#[ignore = "One separately bounded fixed AIR metadata evaluation"]
fn complete_overlay_metadata() {
    assert_eq!(
        std::env::var("KOVA_LAYOUT_METADATA_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("metadata.json"))
        .unwrap();
    let observed = inspect_overlay().expect("fixed metadata construction and controls");
    let record = json!({
        "format":"kova.signature-overlay.metadata.v1",
        "height":layout::HEIGHT, "columns":layout::WIDTH, "public_values":layout::PUBLIC_VALUES,
        "assertions":observed.assertions, "degree_histogram":observed.degree_histogram,
        "attached_metadata_charges":observed.attached_metadata_charges,
        "requested_variable_bytes":observed.requested_variable_bytes,
        "variable_capacity":observed.variable_capacity, "assertion_capacity":observed.assertion_capacity,
        "expression_bytes":observed.expression_bytes, "independent_controls":observed.independent_controls,
        "actual_air_evaluations":1, "symbolic_graph_collections":0, "witness_frames":0, "proofs":0
    });
    let encoded = serde_json::to_vec(&record).unwrap();
    assert!(encoded.len() <= 4096);
    output.write_all(&encoded).unwrap();
    output.sync_all().unwrap();
    drop(output);
    assert_eq!(observed.assertions, 71623);
    assert_eq!(
        observed.degree_histogram,
        [72, 3295, 46690, 20884, 682, 0, 0, 0]
    );
    assert_eq!(observed.independent_controls, 24);
}
