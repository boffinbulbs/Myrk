use kova_signature_matrix_source::matrix_controls;
use serde_json::json;
#[test]
fn actual_owned_rows_drive_matrix_hashes_and_squeeze_banks() {
    let r = matrix_controls::fixed_matrix_walk();
    for (name, value) in [
        ("rows", 8192),
        ("reference_rows", 8192),
        ("reference_windows", 1366),
        ("last_reference_rows", 2),
        ("hash_rows", 2016),
        ("hash_comparisons", 26651520),
        ("xof_comparisons", 8257536),
        ("preserved_comparisons", 318788736),
        ("rho_bytes", 10752),
        ("squeeze_checkpoints", 336),
        ("squeeze_bytes", 56448),
        ("bank_checkpoints", 340),
        ("comparator_controls", 7),
        ("restored_controls", 7),
        ("shape_refusals", 2),
        ("sequence_refusals", 2),
        ("incomplete_refusals", 1),
        ("exhaustion_refusals", 1),
        ("reference_exhaustion_refusals", 1),
    ] {
        assert_eq!(r[name], json!(value), "{name}");
    }
    assert_eq!(r["initial_generation"], json!([70, 70, 1]));
    assert_eq!(r["matrix_generation"], json!([336, 336, 1]));
    assert_eq!(r["reference_generation"], json!([336, 336, 1]));
}
