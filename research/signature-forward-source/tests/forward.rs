use kova_signature_forward_source::forward_controls;
use serde_json::json;
#[test]
fn actual_source_rows_feed_private_forward_state() {
    let r = forward_controls::fixed_forward_walk();
    for (name, value) in [
        ("rows", 8192),
        ("reference_rows", 8192),
        ("reference_windows", 256),
        ("source_values", 4096),
        ("stage_checkpoints", 144),
        ("stage_coefficients", 36864),
        ("output_checkpoints", 16),
        ("output_coefficients", 4096),
        ("comparator_controls", 6),
        ("restored_controls", 6),
        ("shape_refusals", 2),
        ("sequence_refusals", 2),
        ("incomplete_refusals", 1),
        ("exhaustion_refusals", 1),
        ("reference_exhaustion_refusals", 1),
        ("reference_hash_generations", 0),
    ] {
        assert_eq!(r[name], json!(value), "{name}");
    }
    assert_eq!(r["candidate_generation"], json!([70, 70, 1]));
}
