use kova_signature_stream_native::stream_controls;
use serde_json::json;
#[test]
fn complete_streamed_air_binds_hidden_owner_context_and_signature() {
    let r = stream_controls::fixed_stream_controls();
    for (key, value) in [
        ("source_rows", 8192),
        ("complete_baseline_frames", 8192),
        ("negative_evaluations", 3),
        ("restored_evaluations", 3),
        ("positive_evaluations", 8195),
        ("whole_air_evaluations", 8198),
        ("candidate_trace_generator_calls", 415),
        ("reference_trace_generator_calls", 0),
        ("complete_wide_trace_allocations", 0),
        ("backend_proofs", 0),
    ] {
        assert_eq!(r[key], json!(value));
    }
    assert_eq!(r["actual_final_signature_equality_executed"], json!(true));
    assert_eq!(r["old_controls_reexecuted"], json!(false));
    assert_eq!(r["preserved_comparisons"], json!(306683904));
    assert_eq!(
        r["prefix_preserved"],
        json!([352983912, 337117184, 341107472, 293511168, 318788736, 227713024, 217997312])
    );
}
