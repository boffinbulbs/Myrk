//! Deterministic signatures over public synthetic authorization test data.
//! The retained official seed must never be used as operational authority.

use ml_dsa::{Keypair, MlDsa87, Seed, Signature, SigningKey};
use serde_json::{json, Value};
use std::{env, fs, path::PathBuf};

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("fixture hex field")).expect("fixture hex")
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join("research/signatures/synthetic_authorization.json");
    let selected: Value = serde_json::from_slice(
        &fs::read(root.join("research/crypto/vectors/selected.json")).unwrap(),
    )
    .unwrap();
    let case = selected["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "ml_dsa_87_keygen")
        .unwrap();
    let seed = Seed::try_from(bytes(&case["input"]["seed"]).as_slice()).unwrap();
    let key = SigningKey::<MlDsa87>::from_seed(&seed);
    assert_eq!(
        key.verifying_key().encode().as_slice(),
        bytes(&case["expected"]["pk"])
    );
    let application: Value = serde_json::from_slice(
        &fs::read(root.join("research/hash-proofs/application_inputs.json")).unwrap(),
    )
    .unwrap();
    let message = bytes(&application["authorization_input_hex"]);
    let context = bytes(&application["fips_context_hex"]);
    assert_eq!(message.len(), 196);
    assert_eq!(context, b"Thorum crypto laboratory authorization v1");
    let signature = key
        .expanded_key()
        .sign_deterministic(&message, &context)
        .unwrap();
    let typed = Signature::<MlDsa87>::try_from(signature.encode().as_slice()).unwrap();
    assert!(key
        .verifying_key()
        .verify_with_context(&message, &context, &typed));
    let empty = key
        .expanded_key()
        .sign_deterministic(&message, &[])
        .unwrap();
    assert!(key
        .verifying_key()
        .verify_with_context(&message, &[], &empty));
    assert!(!key
        .verifying_key()
        .verify_with_context(&message, &context, &empty));
    let mut changed_message = message.clone();
    *changed_message.last_mut().unwrap() ^= 1;
    let changed = key
        .expanded_key()
        .sign_deterministic(&changed_message, &context)
        .unwrap();
    assert!(key
        .verifying_key()
        .verify_with_context(&changed_message, &context, &changed));
    assert!(!key
        .verifying_key()
        .verify_with_context(&message, &context, &changed));
    let mut other_seed = seed;
    other_seed[0] ^= 1;
    let other_key = SigningKey::<MlDsa87>::from_seed(&other_seed);
    let other = other_key
        .expanded_key()
        .sign_deterministic(&message, &context)
        .unwrap();
    assert!(other_key
        .verifying_key()
        .verify_with_context(&message, &context, &other));
    assert!(!key
        .verifying_key()
        .verify_with_context(&message, &context, &other));
    let key_hex = hex::encode(key.verifying_key().encode());
    let fixture = json!({
        "format": "thorum.signature-reference.synthetic-authorization.v1",
        "public_synthetic_fixture": true,
        "scope": "Valid pure contextual signature over structurally encoded synthetic transaction bytes. Recipient encryption, a private signature AIR and transaction acceptance are not established.",
        "seed_source_case": "ml_dsa_87_keygen",
        "upstream_commit": selected["upstream_commit"],
        "public_key_hex": key_hex,
        "signature_hex": hex::encode(signature.encode()),
        "message_hex": hex::encode(&message), "context_hex": hex::encode(&context),
        "expected_valid": true,
        "alternate_signatures": [
            {"name": "empty_fips_context", "public_key_hex": key_hex,
             "message_hex": hex::encode(&message), "context_hex": "",
             "signature_hex": hex::encode(empty.encode())},
            {"name": "different_authorization", "public_key_hex": key_hex,
             "message_hex": hex::encode(&changed_message), "context_hex": hex::encode(&context),
             "signature_hex": hex::encode(changed.encode())},
            {"name": "different_owner", "public_key_hex": hex::encode(other_key.verifying_key().encode()),
             "message_hex": hex::encode(&message), "context_hex": hex::encode(&context),
             "signature_hex": hex::encode(other.encode())}
        ]
    });
    let mut encoded = serde_json::to_vec_pretty(&fixture).unwrap();
    encoded.push(b'\n');
    if env::args().any(|arg| arg == "--check") {
        assert_eq!(
            fs::read(path).unwrap(),
            encoded,
            "synthetic signature fixture"
        );
        println!("Synthetic contextual signature fixture matches");
    } else {
        fs::write(path, encoded).unwrap();
        println!("Synthetic contextual signature fixture generated and verified");
    }
}
