#[test]
fn normalized_eight_domain_mask_capture() {
    let result = kova_mask_normalization::fixed_normalization();
    assert_eq!(result["final_coordinates"], 2048);
    assert_eq!(result["coupled_updates"], 14336);
    assert_eq!(result["shape_refusals"], 2);
}
