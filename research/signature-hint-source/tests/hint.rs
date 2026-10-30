use kova_signature_hint_source::hint_controls;
use serde_json::json;
#[test]
fn actual_inverse_and_decoded_hints_produce_delayed_private_w1() {
    let r = hint_controls::fixed_hint_controls();
    assert_eq!(r["rows"], json!(8192));
    assert_eq!(r["reference_rows"], json!(8192));
    assert_eq!(r["active_gadgets"], json!(2048));
    assert_eq!(r["dormant_gadgets"], json!(63488));
    assert_eq!(r["hint_row_completions"], json!(8));
    assert_eq!(r["packed_visible_rows"], json!(8));
    assert_eq!(r["trace_generator_calls"], json!(406));
    assert_eq!(r["initial_generation"], json!([70, 70, 1]));
    assert_eq!(r["matrix_generation"], json!([336, 336, 1]));
    assert_eq!(r["reference_hash_generations"], json!(0));
    assert_eq!(r["standalone_transform_oracle_calls"], json!(0));
    assert_eq!(r["comparator_controls"], json!(7));
}
