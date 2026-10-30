use kova_proof_preflight::preflight::Refusal;
use kova_signature_packed::Witness;
use kova_signature_proof_contract::{AssessmentFailure, BoundInputs, assess_retained_class};
use p3_field::PrimeField32;
use serde_json::json;
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use thorum_core::Amount;
use thorum_crypto_lab::{KEM_CIPHERTEXT_BYTES, SealedNote};
use thorum_relation_lab::{PaymentOutput, PaymentStatement, RelationError};

pub mod observed;

fn write_record(value: serde_json::Value) {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("observations.jsonl"))
        .unwrap();
    serde_json::to_writer(&mut output, &value).unwrap();
    output.write_all(b"\n").unwrap();
    output.sync_all().unwrap();
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
                    kem_ciphertext: vec![0x70 + i; KEM_CIPHERTEXT_BYTES],
                    nonce: [0x80 + i; 12],
                    ciphertext: vec![0x90 + i; 32],
                },
            })
            .collect(),
        native_fee: Amount::from_atomic(fee),
    }
}

fn opaque_witness() -> Witness {
    // Correct lengths deliberately establish no private encoding or validity.
    Witness::from_sources([0xff; 2592], [0xff; 4627], [0xff; 418])
}

fn decode(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn canonical_transactions_bind_to_retained_public_vectors() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures-public.json")).unwrap();
    let records = fixtures["transactions"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    let mut values = Vec::new();
    for record in records {
        let mut external = transaction(record["fee_atoms"].as_u64().unwrap());
        let canonical = decode(record["canonical_T_hex"].as_str().unwrap());
        let expected = decode(record["A196_hex"].as_str().unwrap());
        let canonical_equal = external.canonical_bytes().unwrap() == canonical;
        let bound = BoundInputs::bind(opaque_witness(), external.clone()).unwrap();
        let public = bound.public_values();
        let actual: Vec<u8> = public
            .iter()
            .map(|f| u8::try_from(f.as_canonical_u32()).unwrap())
            .collect();
        // An independently owned transaction cannot alter the retained input.
        external.native_fee = Amount::from_atomic(99);
        external.outputs[0].commitment[0] ^= 1;
        let unchanged = bound.public_values() == public;
        write_record(json!({"kind":"public_binding", "transaction":record["id"],
            "canonical_bytes":canonical.len(), "canonical_equal":canonical_equal,
            "public_values":actual.len(), "public_equal":actual == expected,
            "unchanged_after_external_mutation":unchanged}));
        assert!(canonical_equal && unchanged);
        assert_eq!(actual.len(), 196);
        assert_eq!(actual, expected);
        values.push(actual);
    }
    assert_ne!(values[0], values[1]);
}

#[test]
fn malformed_public_statements_preserve_canonical_refusals() {
    let mut no_inputs = transaction(5);
    no_inputs.input_nullifiers.clear();
    let mut no_outputs = transaction(5);
    no_outputs.outputs.clear();
    for (name, transaction) in [("empty_inputs", no_inputs), ("empty_outputs", no_outputs)] {
        let result = BoundInputs::bind(opaque_witness(), transaction);
        let error = result.as_ref().err();
        write_record(json!({"kind":"canonical_refusal", "case":name,
            "error":format!("{error:?}")}));
        assert!(matches!(result, Err(RelationError::LimitExceeded)));
    }
}

#[test]
fn actual_packed_resource_denial_has_no_observed_effects() {
    // The second PCS changes a later parameter. RawWidth alone certifies
    // neither configuration, and does not reach the later parameter checks.
    for queries in [64, 1] {
        let (pcs, audit) = observed::config(queries);
        let before = audit.snapshot();
        let result = assess_retained_class(&pcs);
        let after = audit.snapshot();
        write_record(json!({"kind":"resource_refusal", "queries":queries,
            "result":format!("{result:?}"), "before":before, "after":after}));
        assert_eq!(result, Err(AssessmentFailure::Resource(Refusal::RawWidth)));
        assert_eq!(before, [0; 3]);
        assert_eq!(after, before);
    }
}
