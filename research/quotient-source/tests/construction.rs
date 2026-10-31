#[test]
fn committed_view_and_canonical_quotient_share_one_owner() {
    let result = kova_quotient_source::fixed_construction();
    assert_eq!(result["input_commits"], 1);
    assert_eq!(result["proofs"], 0);
    assert_eq!(result["quotient_coefficients"], 8192);
}
