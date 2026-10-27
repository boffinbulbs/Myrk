use serde_json::Value;
use thorum_hash_proof_lab::challenge_sampler::{
    self,
    signature::{
        Error, MAX_PROOF_BYTES, Statement, Witness, prove_signature_challenge,
        verify_signature_challenge,
    },
};

#[test]
fn private_signature_tail_and_challenge_require_the_joint_profile() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/signature-challenge/vectors.json"
    ))
    .unwrap();
    let case = data["cases"].as_array().unwrap().last().unwrap();
    let text = case["signature_hex"].as_str().unwrap();
    let signature: [u8; 4627] =
        core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap());
    let coefficients =
        core::array::from_fn(|i| case["challenge_normal"][i].as_u64().unwrap() as u32);
    let context = [0x8b; 64];
    let statement = Statement::new(coefficients, context).unwrap();
    let proof = prove_signature_challenge(&Witness::from_signature(signature), &statement).unwrap();
    assert!(proof.len() <= MAX_PROOF_BYTES);
    verify_signature_challenge(&proof, &statement).unwrap();
    assert!(challenge_sampler::verify_challenge_sampler(&proof, &statement).is_err());
    let parent = challenge_sampler::prove_challenge_sampler(
        &challenge_sampler::Witness::from_challenge_seed(signature[..64].try_into().unwrap()),
        &statement,
    )
    .unwrap();
    assert_eq!(
        verify_signature_challenge(&parent, &statement),
        Err(Error::InvalidProof)
    );
    let mut changed = context;
    changed[63] ^= 1;
    assert_eq!(
        verify_signature_challenge(&proof, &Statement::new(coefficients, changed).unwrap()),
        Err(Error::InvalidProof)
    );
    let mut different = coefficients;
    let index = different.iter().position(|v| *v != 0).unwrap();
    different[index] = if different[index] == 1 { 8380416 } else { 1 };
    assert_eq!(
        verify_signature_challenge(&proof, &Statement::new(different, context).unwrap()),
        Err(Error::InvalidProof)
    );
}
