//! Native cross checks of the independent transparent verification reference.
//! All keys and signatures below are deliberately public synthetic fixtures.

use ml_dsa::{EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};
use serde_json::Value;

#[test]
fn native_verification_agrees_with_independent_complete_signature_cases() {
    let data: Value =
        serde_json::from_str(include_str!("../../../research/signatures/cases.json")).unwrap();
    assert_eq!(data["public_synthetic_fixture"], true);
    let cases = data["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 49);
    for case in cases {
        let bytes = |field: &str| hex::decode(case[field].as_str().unwrap()).unwrap();
        let key = bytes("public_key_hex");
        let signature = bytes("signature_hex");
        let actual = match (
            EncodedVerifyingKey::<MlDsa87>::try_from(key.as_slice()),
            Signature::<MlDsa87>::try_from(signature.as_slice()),
        ) {
            (Ok(encoded), Ok(signature)) => VerifyingKey::decode(&encoded).verify_with_context(
                &bytes("message_hex"),
                &bytes("context_hex"),
                &signature,
            ),
            _ => false,
        };
        assert_eq!(
            actual,
            case["expected_valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
    assert_eq!(
        cases
            .iter()
            .filter(|case| case["expected_valid"] == true)
            .count(),
        5
    );
}
