use kova_signature_accumulator_source::accumulator_controls;
use serde_json::json;
#[test]
fn actual_matrix_banks_feed_accumulation_and_terminal_failure_is_sticky() {
    let r = accumulator_controls::fixed_accumulator_controls();
    assert_eq!(r["trace_generator_calls"], json!(482));
    assert_eq!(r["main"]["rows"], json!(8192));
    assert_eq!(r["main"]["reference_rows"], json!(8192));
    assert_eq!(r["main"]["accepted"], json!(14336));
    assert_eq!(r["main"]["completion_slots"], json!(56));
    assert_eq!(r["main"]["point_values"], json!(2048));
    assert_eq!(r["main"]["initial_generation"], json!([70, 70, 1]));
    assert_eq!(r["main"]["matrix_generation"], json!([336, 336, 1]));
    assert_eq!(r["main"]["comparator_controls"], json!(8));
    assert_eq!(r["main"]["reference_hash_generations"], json!(0));
    assert_eq!(r["fault"]["position"], json!([689, 690, true]));
    assert_eq!(r["fault"]["initial_generation"], json!([70, 70, 1]));
    assert_eq!(r["fault"]["matrix_generation"], json!([6, 6, 1]));
}
