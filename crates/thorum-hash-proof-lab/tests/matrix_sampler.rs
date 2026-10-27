use serde_json::Value;
use thorum_hash_proof_lab::matrix_sampler::{
    Error, MAX_PROOF_BYTES, Statement, Witness, prove_matrix_sampler, verify_matrix_sampler,
};

#[test]
fn expected_matrix_and_context_bind_the_public_diagnostic_interface() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/matrix-sampling/vectors.json"
    ))
    .unwrap();
    let case = &data["genuine"][223];
    let text = case["rho_hex"].as_str().unwrap();
    let rho = core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap());
    let coefficients = core::array::from_fn(|i| case["coefficients"][i].as_u64().unwrap() as u32);
    let context = [0xa5; 64];
    let statement = Statement::new(7, 6, coefficients, context).unwrap();
    let witness = Witness::from_rho(rho);
    let proof = prove_matrix_sampler(&witness, &statement).unwrap();
    assert!(proof.len() <= MAX_PROOF_BYTES);
    verify_matrix_sampler(&proof, &statement).unwrap();
    let mut changed = context;
    changed[63] ^= 1;
    assert_eq!(
        verify_matrix_sampler(
            &proof,
            &Statement::new(7, 6, coefficients, changed).unwrap()
        ),
        Err(Error::InvalidProof)
    );
    let mut different = coefficients;
    different[255] = (different[255] + 1) % 8_380_417;
    assert_eq!(
        verify_matrix_sampler(&proof, &Statement::new(7, 6, different, context).unwrap()),
        Err(Error::InvalidProof)
    );
    assert!(Statement::new(8, 6, coefficients, context).is_err());
    assert!(Statement::new(7, 7, coefficients, context).is_err());
}
