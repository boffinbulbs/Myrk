use kova_signature_port_source::port_controls;
use serde_json::json;
#[test]
fn immutable_owner_streams_clock_words_and_private_source_ports() {
    let r = port_controls::fixed_port_controls();
    for (key, value) in [
        ("rows", 8192),
        ("reference_rows", 21),
        ("owned_comparisons", 47013888),
        ("preserved_comparisons", 306683904),
        ("candidate_trace_generator_calls", 415),
        ("reference_trace_generator_calls", 0),
        ("comparator_controls", 6),
        ("complete_streamed_row_walks", 1),
        ("complete_wide_trace_allocations", 0),
        ("whole_air_evaluations", 0),
        ("backend_proofs", 0),
    ] {
        assert_eq!(r[key], json!(value));
    }
    assert_eq!(
        r["prefix_preserved"],
        json!([352983912, 337117184, 341107472, 293511168, 318788736, 227713024, 217997312])
    );
    assert_eq!(r["packed_port_air_equality_executed"], json!(false));
}
