use serde_json::Value;
use thorum_hash_proof_lab::{Error, Mode, Statement, Witness, prove_hash, verify_hash};

const EXAMPLES: &str = include_str!("../../../research/hash-proofs/hash_preimages.json");

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn retained_public_key_and_context_examples_prove_exact_hash_primitives() {
    let document: Value = serde_json::from_str(EXAMPLES).unwrap();
    for name in [
        "mldsa87_public_key_owner_sha3_512",
        "mldsa87_public_key_tr_shake256",
        "pure_contextual_mldsa_mu_shake256",
        "mldsa_matrix_seed_shake128_five_output_blocks",
    ] {
        let case = document["hashes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        let mode = match case["mode"].as_u64().unwrap() {
            1 => Mode::Sha3_512,
            2 => Mode::Shake128,
            3 => Mode::Shake256,
            other => panic!("unknown primitive {other}"),
        };
        let input = bytes(&case["input_hex"]);
        let output = bytes(&case["output_hex"]);
        let witness = Witness::from_bytes(&input).unwrap();
        let statement = Statement::new(mode, input.len(), &output, [0x61; 64]).unwrap();
        let proof = prove_hash(&witness, &statement).unwrap();
        verify_hash(&proof, &statement).unwrap();
        let mut changed_output = output.clone();
        changed_output[0] ^= 1;
        let changed = Statement::new(mode, input.len(), &changed_output, [0x61; 64]).unwrap();
        assert_eq!(verify_hash(&proof, &changed), Err(Error::InvalidProof));
        let changed_context = Statement::new(mode, input.len(), &output, [0x62; 64]).unwrap();
        assert_eq!(
            verify_hash(&proof, &changed_context),
            Err(Error::InvalidProof)
        );
    }
}
