use kova_signature_hash_source::hash_controls;
use serde_json::json;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[test]
fn initial_hash_sources_and_decoder_share_the_owned_witness() {
    let r = hash_controls::fixed_hash_walk();
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("observations.jsonl"))
        .unwrap();
    serde_json::to_writer(&mut output,&json!({"kind":"hash_summary",
        "hash_emissions":r.hash_emissions,"decoder_emissions":r.decoder_emissions,
        "reference_rows":r.reference_rows,"reference_blocks":r.reference_blocks,
        "owned_comparisons":r.owned_comparisons,"outside_comparisons":r.outside_comparisons,
        "composed_hash_comparisons":r.composed_hash_comparisons,"composed_outside_comparisons":r.composed_outside_comparisons,
        "independent_bank_bytes":r.independent_bank_bytes,"checkpoints":r.checkpoints,
        "corruption_controls":r.corruption_controls,"restored_controls":r.restored_controls,
        "candidate_generation":r.candidate_generation,"reference_generation":r.reference_generation})).unwrap();
    output.write_all(b"\n").unwrap();
    output.sync_all().unwrap();
    assert_eq!(
        (
            r.hash_emissions,
            r.decoder_emissions,
            r.reference_rows,
            r.reference_blocks
        ),
        (8192, 8192, 8192, 1366)
    );
    assert_eq!((r.checkpoints, r.independent_bank_bytes), (15, 8400));
    assert_eq!((r.corruption_controls, r.restored_controls), (5, 5));
    assert_eq!(r.candidate_generation, [70, 70, 1]);
    assert_eq!(r.reference_generation, [70, 70, 1]);
}
