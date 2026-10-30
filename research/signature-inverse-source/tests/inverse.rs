use kova_signature_inverse_source::inverse_controls;
use serde_json::json;
#[test]
fn actual_accumulator_inputs_feed_inverse_with_partial_seed_preservation() {
    let r = inverse_controls::fixed_inverse_controls();
    assert_eq!(r["rows"], json!(8192));
    assert_eq!(r["reference_rows"], json!(8192));
    assert_eq!(r["state_checkpoints"], json!(88));
    assert_eq!(r["inverse_completions"], json!(8));
    assert_eq!(r["trace_generator_calls"], json!(406));
    assert_eq!(r["initial_generation"], json!([70, 70, 1]));
    assert_eq!(r["matrix_generation"], json!([336, 336, 1]));
    assert_eq!(r["reference_hash_generations"], json!(0));
    assert_eq!(r["standalone_transform_oracle_calls"], json!(0));
    assert_eq!(r["comparator_controls"], json!(6));
}
