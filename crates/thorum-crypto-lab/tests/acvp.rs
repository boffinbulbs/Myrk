//! Selected published NIST ACVP answers, independent of lab-generated round trips.
//!
//! Every secret and deterministic input below is public, synthetic test data.
//! Expanded-key imports and fixed known-answer entropy are restricted to this
//! integration test and are not exposed by the operational lab API.

use std::sync::OnceLock;

use ml_dsa::{
    EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa87, Signature,
    SigningKey, VerifyingKey,
};
use ml_kem::{
    ml_kem_1024::{
        Ciphertext as KemCiphertext, DecapsulationKey as KemDecapsulationKey,
        EncapsulationKey as KemEncapsulationKey,
    },
    Decapsulate, KeyExport,
};
use serde_json::Value;

const SELECTED: &str = include_str!("../../../research/crypto/vectors/selected.json");
const UPSTREAM_COMMIT: &str = "975de31eb83d87039ec88934fdc47d8c312b892d";

fn case(identifier: &str) -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    let fixture = FIXTURE.get_or_init(|| serde_json::from_str(SELECTED).expect("frozen ACVP JSON"));
    assert_eq!(fixture["upstream_commit"], UPSTREAM_COMMIT);
    let cases = fixture["cases"].as_array().expect("ACVP case array");
    assert_eq!(cases.len(), 8);
    cases
        .iter()
        .find(|case| case["id"] == identifier)
        .expect("selected ACVP case exists")
}

fn bytes(case: &Value, section: &str, field: &str) -> Vec<u8> {
    hex::decode(case[section][field].as_str().expect("ACVP hex field"))
        .expect("valid published ACVP hexadecimal")
}

#[test]
#[allow(deprecated)] // The official answer uses expanded bytes, not the preferred seed encoding.
fn ml_dsa_87_keygen_matches_official_public_and_expanded_secret_keys() {
    let case = case("ml_dsa_87_keygen");
    assert_eq!(case["tgId"], 3);
    assert_eq!(case["tcId"], 51);
    let seed = ml_dsa::Seed::try_from(bytes(case, "input", "seed").as_slice()).unwrap();
    let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
    let expanded = signing_key.expanded_key();
    assert_eq!(
        expanded.verifying_key().encode().as_slice(),
        bytes(case, "expected", "pk")
    );
    assert_eq!(
        expanded.to_expanded().as_slice(),
        bytes(case, "expected", "sk")
    );
}

#[test]
#[allow(deprecated)] // Trusted published test key, never attacker-provided operational key bytes.
fn ml_dsa_87_deterministic_external_pure_signature_matches_official_bytes() {
    let case = case("ml_dsa_87_sign_external_pure");
    assert_eq!(case["group"]["signatureInterface"], "external");
    assert_eq!(case["group"]["preHash"], "pure");
    assert_eq!(case["group"]["deterministic"], true);
    let encoded =
        ExpandedSigningKeyBytes::<MlDsa87>::try_from(bytes(case, "input", "sk").as_slice())
            .unwrap();
    let signing_key = ExpandedSigningKey::<MlDsa87>::from_expanded(&encoded);
    let message = bytes(case, "input", "message");
    let context = bytes(case, "input", "context");
    let signature = signing_key.sign_deterministic(&message, &context).unwrap();
    assert_eq!(
        signature.encode().as_slice(),
        bytes(case, "expected", "signature")
    );
    assert!(signing_key
        .verifying_key()
        .verify_with_context(&message, &context, &signature));
}

#[test]
fn ml_dsa_87_verification_matches_official_valid_and_invalid_answers() {
    for identifier in ["ml_dsa_87_verify_invalid", "ml_dsa_87_verify_valid"] {
        let case = case(identifier);
        assert_eq!(case["group"]["signatureInterface"], "external");
        assert_eq!(case["group"]["preHash"], "pure");
        let encoded =
            EncodedVerifyingKey::<MlDsa87>::try_from(bytes(case, "input", "pk").as_slice())
                .unwrap();
        let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded);
        let signature =
            Signature::<MlDsa87>::try_from(bytes(case, "input", "signature").as_slice()).unwrap();
        let result = verifying_key.verify_with_context(
            &bytes(case, "input", "message"),
            &bytes(case, "input", "context"),
            &signature,
        );
        assert_eq!(
            result,
            case["expected"]["testPassed"].as_bool().unwrap(),
            "{identifier}"
        );
    }
}

#[test]
#[allow(deprecated)] // Serialize the expanded format required by the official expected answer.
fn ml_kem_1024_keygen_matches_official_encapsulation_and_decapsulation_keys() {
    let case = case("ml_kem_1024_keygen");
    assert_eq!(case["tgId"], 3);
    assert_eq!(case["tcId"], 51);
    // ML-KEM's preferred seed encoding is d || z, in that order.
    let mut seed = bytes(case, "input", "d");
    seed.extend(bytes(case, "input", "z"));
    let seed = ml_kem::Seed::try_from(seed.as_slice()).unwrap();
    let decapsulation_key = KemDecapsulationKey::from_seed(seed);
    assert_eq!(
        decapsulation_key.encapsulation_key().to_bytes().as_slice(),
        bytes(case, "expected", "ek")
    );
    assert_eq!(
        ml_kem::ExpandedKeyEncoding::to_expanded_bytes(&decapsulation_key).as_slice(),
        bytes(case, "expected", "dk")
    );
}

#[test]
fn ml_kem_1024_encapsulation_matches_official_ciphertext_and_shared_secret() {
    let case = case("ml_kem_1024_encapsulate");
    let encoded =
        ml_kem::Key::<KemEncapsulationKey>::try_from(bytes(case, "input", "ek").as_slice())
            .unwrap();
    let encapsulation_key = KemEncapsulationKey::new(&encoded).unwrap();
    let randomness = ml_kem::B32::try_from(bytes(case, "input", "m").as_slice()).unwrap();
    // Fixed encapsulation randomness is used only for this public known-answer vector.
    let (ciphertext, secret) = encapsulation_key.encapsulate_deterministic(&randomness);
    assert_eq!(ciphertext.as_slice(), bytes(case, "expected", "c"));
    assert_eq!(secret.as_slice(), bytes(case, "expected", "k"));
}

#[test]
#[allow(deprecated)] // Official test cases supply checked expanded keys rather than seeds.
fn ml_kem_1024_decapsulation_matches_valid_and_implicit_rejection_secrets() {
    for identifier in [
        "ml_kem_1024_decapsulate_valid",
        "ml_kem_1024_decapsulate_implicit_rejection",
    ] {
        let case = case(identifier);
        let key_bytes = bytes(case, "input", "dk");
        let encoded =
            ml_kem::ml_kem_1024::ExpandedDecapsulationKey::try_from(key_bytes.as_slice()).unwrap();
        let decapsulation_key = KemDecapsulationKey::from_expanded(&encoded).unwrap();
        let ciphertext_bytes = bytes(case, "input", "c");
        let ciphertext = KemCiphertext::try_from(ciphertext_bytes.as_slice()).unwrap();
        // A modified, correctly sized ML-KEM ciphertext yields an implicit-rejection
        // secret. It is not an explicit ciphertext-validity error or flag.
        let secret = decapsulation_key.decapsulate(&ciphertext);
        assert_eq!(
            secret.as_slice(),
            bytes(case, "expected", "k"),
            "{identifier}"
        );
        if identifier.ends_with("implicit_rejection") {
            assert_eq!(case["annotations"]["reason"], "modified ciphertext");
            // The extractor independently checks the published answer against
            // SHAKE256(z || c, 32). This test compares the actual KEM result with
            // that published answer, rather than expecting an explicit error.
        } else {
            assert_eq!(case["annotations"]["reason"], "valid decapsulation");
        }
    }
}
