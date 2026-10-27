use serde_json::Value;
use thorum_hash_proof_lab::challenge_sampler::{
    Error, MAX_PROOF_BYTES, Statement, Witness, prove_challenge_sampler, verify_challenge_sampler,
};

#[test]
fn expected_sparse_coefficients_and_context_bind_the_public_diagnostic_interface() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/challenge-sampling/vectors.json"
    ))
    .unwrap();
    let case = &data["genuine"][5];
    let text = case["seed_hex"].as_str().unwrap();
    let seed = core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap());
    let coefficients = core::array::from_fn(|i| case["normal"][i].as_u64().unwrap() as u32);
    let context = [0xa7; 64];
    let statement = Statement::new(coefficients, context).unwrap();
    let witness = Witness::from_challenge_seed(seed);
    let proof = prove_challenge_sampler(&witness, &statement).unwrap();
    assert!(proof.len() <= MAX_PROOF_BYTES);
    verify_challenge_sampler(&proof, &statement).unwrap();
    let mut changed = context;
    changed[63] ^= 1;
    assert_eq!(
        verify_challenge_sampler(&proof, &Statement::new(coefficients, changed).unwrap()),
        Err(Error::InvalidProof)
    );
    let mut different = coefficients;
    let position = different.iter().position(|value| *value != 0).unwrap();
    different[position] = if different[position] == 1 {
        8_380_416
    } else {
        1
    };
    assert_eq!(
        verify_challenge_sampler(&proof, &Statement::new(different, context).unwrap()),
        Err(Error::InvalidProof)
    );
    assert!(Statement::new([0; 256], context).is_err());
    different[position] = 2;
    assert!(Statement::new(different, context).is_err());
}
