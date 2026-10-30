use kova_signature_frame_native::frame_controls;
use serde_json::json;
#[test]
fn genuine_frames_enforce_clock_holds_routed_bits_and_virtual_tails() {
    let r = frame_controls::fixed_frame_controls();
    for (key, value) in [
        ("source_rows", 8192),
        ("baseline_pairs", 12),
        ("negative_evaluations", 7),
        ("restored_evaluations", 7),
        ("combined_frame_evaluations", 26),
        ("positive_evaluations", 19),
        ("clock_evaluations", 26),
        ("packed_evaluations", 26),
        ("candidate_trace_generator_calls", 415),
        ("reference_trace_generator_calls", 0),
        ("whole_air_evaluations", 0),
        ("backend_proofs", 0),
    ] {
        assert_eq!(r[key], json!(value));
    }
    assert_eq!(
        r["packed_port_air_signature_equality_executed"],
        json!(false)
    );
    assert_eq!(r["old_controls_reexecuted"], json!(false));
    assert_eq!(r["preserved_comparisons"], json!(306683904));
    assert_eq!(
        r["prefix_preserved"],
        json!([352983912, 337117184, 341107472, 293511168, 318788736, 227713024, 217997312])
    );
}
