#[test]
fn source_consuming_masking_matches_retained_commitment() {
    let result = kova_quotient_mask::fixed_masking();
    assert_eq!(result["candidate_input_commits"], 2);
    assert_eq!(result["chunk_fields_compared"], 262144);
    assert_eq!(result["proofs"], 0);
}
