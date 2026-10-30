use kova_signature_sample_source::sample_controls;
use serde_json::json;

#[test]
fn actual_hash_decoding_and_sampling_share_the_owned_witness() {
    let r = sample_controls::fixed_sample_walk();
    for (name, expected) in [
        ("rows", 8192),
        ("original_prefix_rows", 277),
        ("original_fill_calls", 1),
        ("checkpoints", 11),
        ("terminal_checks", 3),
        ("terminal_coefficients", 768),
        ("events", 70),
        ("takes", 60),
        ("rejects", 10),
        ("first_terminal_row", 82),
        ("comparator_controls", 5),
        ("restored_controls", 5),
        ("shape_refusals", 2),
        ("incomplete_refusals", 1),
        ("completion_checks", 1),
        ("exhaustion_refusals", 1),
        ("reference_hash_generations", 0),
    ] {
        assert_eq!(r[name], json!(expected), "{name}");
    }
    assert_eq!(r["candidate_generation"], json!([70, 70, 1]));
    assert_eq!(r["prefix_released"], json!(true));
}
