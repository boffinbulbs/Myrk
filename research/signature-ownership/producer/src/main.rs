//! Deterministic synthetic signature production and independent native checks.
//! Public fixture seeds are never operational authority. No proof is generated.

#![forbid(unsafe_code)]

#[path = "../../authorization.rs"]
mod authorization;

use ml_dsa::{Keypair, MlDsa87, Seed, Signature, SigningKey};
use serde_json::{json, Value};
use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thorum_core::Amount;
use thorum_crypto_lab::SealedNote;
use thorum_relation_lab::{PaymentOutput, PaymentStatement};

const MAX_RAW_BYTES: usize = 512 * 1024;
const SIGNATURE_BYTES: usize = 4627;

fn decoded(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("fixture hex")
}

fn transaction(fee: u64) -> PaymentStatement {
    PaymentStatement {
        chain_id: core::array::from_fn(|i| i as u8),
        protocol_version: 7,
        validation_tag: [0x33; 32],
        anchor: [0x44; 64],
        input_nullifiers: vec![[0x50; 64], [0x51; 64]],
        outputs: (0..2)
            .map(|i| PaymentOutput {
                commitment: [0x60 + i; 64],
                envelope: SealedNote {
                    kem_ciphertext: vec![0x70 + i; 1568],
                    nonce: [0x80 + i; 12],
                    ciphertext: vec![0x90 + i; 32],
                },
            })
            .collect(),
        native_fee: Amount::from_atomic(fee),
    }
}

fn native_verdict(
    key: &SigningKey<MlDsa87>,
    source: &authorization::ExpectedAuthorization,
    context: &[u8],
    encoded: &[u8],
) -> (bool, bool, bool) {
    assert_eq!(encoded.len(), SIGNATURE_BYTES, "signature length");
    let parsed = Signature::<MlDsa87>::try_from(encoded).expect("canonical signature");
    let own =
        key.verifying_key()
            .verify_with_context(source.authorization_input(), context, &parsed);
    let fixed = key.verifying_key().verify_with_context(
        source.authorization_input(),
        authorization::PURE_CONTEXT,
        &parsed,
    );
    let wrapper = thorum_crypto_lab::verify_authorization(
        key.verifying_key().encode().as_slice(),
        source.context(),
        source.message(),
        encoded,
    );
    assert_eq!(wrapper.is_ok(), fixed, "native verification paths disagree");
    if !fixed {
        assert_eq!(wrapper, Err(thorum_crypto_lab::Error::SignatureFailed));
    }
    (own, fixed, wrapper.is_ok())
}

fn verify_only(
    path: &Path,
    expected: &Value,
    plans: &[(&str, &str, usize, Vec<u8>); 6],
    keys: &[SigningKey<MlDsa87>; 2],
    mapped: &[authorization::ExpectedAuthorization],
) {
    let source = fs::File::open(path).expect("existing raw fixture");
    assert!(
        source.metadata().expect("fixture metadata").is_file(),
        "regular fixture file"
    );
    let mut bytes = Vec::new();
    source
        .take((MAX_RAW_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .expect("bounded fixture read");
    assert!(bytes.len() <= MAX_RAW_BYTES, "raw fixture exceeds 512 KiB");
    let raw: Value = serde_json::from_slice(&bytes).expect("fixture JSON");
    // Canonical roundtrip also rejects duplicate object keys and trailing data.
    let mut canonical = serde_json::to_vec_pretty(&raw).expect("canonical fixture JSON");
    canonical.push(b'\n');
    assert!(bytes == canonical, "raw fixture is not canonical JSON");
    assert_eq!(
        raw.as_object().expect("root object").len(),
        7,
        "root field count"
    );
    for field in [
        "format",
        "scope",
        "signing_api_calls",
        "public_seed_source",
        "keys",
        "transactions",
    ] {
        assert!(raw[field] == expected[field], "fixed fixture field {field}");
    }
    let records = raw["signatures"].as_array().expect("signature records");
    assert_eq!(records.len(), 6, "six fixed signature records");
    for ((id, key_id, tid, context), record) in plans.iter().zip(records) {
        assert_eq!(
            record.as_object().expect("signature object").len(),
            9,
            "signature field count"
        );
        let source = &mapped[*tid];
        assert!(record["id"] == *id, "signature identifier {id}");
        assert!(
            record["key_id"] == *key_id,
            "verification key identifier {id}"
        );
        assert!(
            record["transaction_id"] == format!("T{tid}"),
            "transaction identifier {id}"
        );
        assert!(
            record["context_hex"] == hex::encode(context),
            "signature context {id}"
        );
        assert!(
            record["message_hex"] == hex::encode(source.authorization_input()),
            "signature message {id}"
        );
        let encoded = decoded(&record["signature_hex"]);
        let key = &keys[usize::from(*key_id == "B")];
        let (own, fixed, wrapper) = native_verdict(key, source, context, &encoded);
        assert!(own, "own context verification {id}");
        assert_eq!(
            fixed,
            context.as_slice() == authorization::PURE_CONTEXT.as_slice(),
            "fixed context verification {id}"
        );
        assert!(
            record["native_own_context_valid"] == own,
            "own context record {id}"
        );
        assert!(
            record["native_fixed_context_valid"] == fixed,
            "fixed context record {id}"
        );
        assert!(
            record["native_wrapper_valid"] == wrapper,
            "wrapper record {id}"
        );
    }
    println!("Six existing synthetic signatures verified through both native paths. No signatures created");
}

fn main() {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    assert_eq!(
        arguments.len(),
        2,
        "required: --verify-only RAW_JSON or --output NEW_FILE"
    );
    let verify = arguments[0] == "--verify-only";
    assert!(verify || arguments[0] == "--output", "unsupported mode");
    let path = PathBuf::from(&arguments[1]);
    // Output mode reserves its new destination before key derivation or signing.
    let mut destination = if verify {
        None
    } else {
        Some(
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("new output file in an existing directory"),
        )
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let selected: Value = serde_json::from_slice(
        &fs::read(root.join("research/crypto/vectors/selected.json")).unwrap(),
    )
    .unwrap();
    let original: Value = serde_json::from_slice(
        &fs::read(root.join("research/signatures/synthetic_authorization.json")).unwrap(),
    )
    .unwrap();
    let case = selected["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "ml_dsa_87_keygen")
        .unwrap();
    let seed_a = Seed::try_from(decoded(&case["input"]["seed"]).as_slice()).unwrap();
    let mut seed_b = seed_a;
    seed_b[0] ^= 1;
    let keys = [
        SigningKey::<MlDsa87>::from_seed(&seed_a),
        SigningKey::<MlDsa87>::from_seed(&seed_b),
    ];
    assert!(keys[0].verifying_key().encode().as_slice() == decoded(&case["expected"]["pk"]));
    assert!(keys[0].verifying_key().encode().as_slice() == decoded(&original["public_key_hex"]));
    let retained_b = original["alternate_signatures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "different_owner")
        .unwrap();
    assert!(keys[1].verifying_key().encode().as_slice() == decoded(&retained_b["public_key_hex"]));
    let statements = [transaction(5), transaction(6)];
    let mapped: Vec<_> = statements
        .iter()
        .map(|t| authorization::ExpectedAuthorization::from_transaction(t).unwrap())
        .collect();
    assert!(mapped[0].authorization_input().as_slice() != decoded(&original["message_hex"]));
    let mut wrong_context = authorization::PURE_CONTEXT.to_vec();
    *wrong_context.last_mut().unwrap() = b'0';
    let plans = [
        ("A0", "A", 0, authorization::PURE_CONTEXT.to_vec()),
        ("A1", "A", 1, authorization::PURE_CONTEXT.to_vec()),
        ("B0", "B", 0, authorization::PURE_CONTEXT.to_vec()),
        ("B1", "B", 1, authorization::PURE_CONTEXT.to_vec()),
        ("A0_empty_context", "A", 0, Vec::new()),
        ("A0_wrong_context41", "A", 0, wrong_context),
    ];
    let transactions: Vec<_> = mapped
        .iter()
        .enumerate()
        .map(|(i, m)| {
            json!({
                "id": format!("T{i}"), "fee_atoms": 5+i,
                "canonical_T_hex": hex::encode(m.canonical_public_bytes()),
                "authorization_message_hex": hex::encode(m.message()),
                "Context80_hex": hex::encode(m.context().encode()),
                "A196_hex": hex::encode(m.authorization_input()),
                "pure_fips_message239_hex": hex::encode(m.pure_message()),
            })
        })
        .collect();
    let mut value = json!({
        "format": "thorum.private-signature-owner.raw.v1",
        "scope": "Public synthetic signatures over structural typed transactions. No payment, encryption, private AIR or proof acceptance.",
        "signing_api_calls": 6,
        "public_seed_source": {"case": "ml_dsa_87_keygen", "upstream_commit": selected["upstream_commit"],
            "seed_a_hex": hex::encode(seed_a), "seed_b_hex": hex::encode(seed_b),
            "mutation": "seed_b[0] = seed_a[0] XOR 1. No seed search or fixture retries."},
        "keys": [
            {"id": "A", "public_key_hex": hex::encode(keys[0].verifying_key().encode())},
            {"id": "B", "public_key_hex": hex::encode(keys[1].verifying_key().encode())}
        ],
        "transactions": transactions, "signatures": [],
    });
    if verify {
        verify_only(&path, &value, &plans, &keys, &mapped);
        return;
    }
    let mut signatures = Vec::with_capacity(6);
    let mut signing_calls = 0;
    for (id, key_id, transaction_index, context) in plans {
        let key = &keys[usize::from(key_id == "B")];
        let source = &mapped[transaction_index];
        let signature = key
            .expanded_key()
            .sign_deterministic(source.authorization_input(), &context)
            .unwrap();
        signing_calls += 1;
        let encoded = signature.encode();
        let (own, fixed, wrapper) = native_verdict(key, source, &context, encoded.as_slice());
        assert!(own, "own context verification {id}");
        assert_eq!(
            fixed,
            context.as_slice() == authorization::PURE_CONTEXT.as_slice()
        );
        signatures.push(json!({
            "id": id, "key_id": key_id, "transaction_id": format!("T{transaction_index}"),
            "context_hex": hex::encode(&context), "message_hex": hex::encode(source.authorization_input()),
            "signature_hex": hex::encode(encoded), "native_own_context_valid": own,
            "native_fixed_context_valid": fixed, "native_wrapper_valid": wrapper,
        }));
    }
    assert_eq!(signing_calls, 6);
    value["signatures"] = Value::Array(signatures);
    let destination = destination.as_mut().expect("reserved output destination");
    serde_json::to_writer_pretty(&mut *destination, &value).unwrap();
    destination.write_all(b"\n").unwrap();
    destination.sync_all().unwrap();
    println!("Six synthetic signatures written to a new record");
}
