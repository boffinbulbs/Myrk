use kova_signature_final_source::final_controls;
use serde_json::json;
#[test]
fn actual_mu_and_private_w1_feed_final_sponge_with_dummy_restoration() {
    let r = final_controls::fixed_final_controls();
    assert_eq!(r["rows"], json!(8192));
    assert_eq!(r["reference_windows"], json!(9));
    assert_eq!(r["final_blocks"], json!(9));
    assert_eq!(r["initial_generation"], json!([70, 70, 1]));
    assert_eq!(r["matrix_generation"], json!([336, 336, 1]));
    assert_eq!(r["final_generation"], json!([9, 9, 1]));
    assert_eq!(r["reference_generation"], json!([9, 9, 1]));
    assert_eq!(r["trace_generator_calls"], json!(424));
    assert_eq!(r["packed_port_equality_executed"], json!(false));
    assert_eq!(r["new_independent_final_hash_references"], json!(0));
    assert_eq!(r["comparator_controls"], json!(6));
}
