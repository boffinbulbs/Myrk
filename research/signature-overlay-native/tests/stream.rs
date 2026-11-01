#[test]
#[ignore = "One separately bounded complete native source walk"]
fn complete_overlay_stream_binds_sources_and_ownership() {
    const { assert!(!cfg!(feature = "native-execution")) };
    assert_eq!(
        std::env::var("KOVA_OVERLAY_STREAM_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let result = kova_signature_overlay_native::stream_controls::fixed_overlay_stream();
    assert_eq!(result["complete_air_calls"], 8216);
    assert_eq!(result["baseline_frames"], 8192);
    assert_eq!(result["negative_frames"], 12);
    assert_eq!(result["restored_frames"], 12);
    assert_eq!(result["backend_proofs"], 0);
}
