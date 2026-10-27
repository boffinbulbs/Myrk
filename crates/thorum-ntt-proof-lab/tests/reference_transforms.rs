//! Public polynomial fixtures exercise the standalone transform interface.
//! Signature authorization remains outside this relation.

use serde_json::Value;
use thorum_arithmetic_proof_lab::mul::MODULUS;
use thorum_ntt_proof_lab::{Error, Mode, Statement, Witness, prove_ntt, verify_ntt};

fn reference(name: &str) -> (Mode, [u32; 256], [u32; 256], [u8; 64]) {
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/ntt-proofs/ntt_vectors.json"
    ))
    .unwrap();
    let case = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str() == Some(name))
        .expect("named independent transform fixture");
    assert_eq!(case["expected"]["valid_component"], true);
    let public = &case["public"];
    let mode = match public["mode"].as_u64().unwrap() {
        1 => Mode::Forward,
        2 => Mode::Inverse,
        _ => panic!("unsupported fixture mode"),
    };
    let input = core::array::from_fn(|i| public["input"][i].as_u64().unwrap() as u32);
    let output = core::array::from_fn(|i| public["output"][i].as_u64().unwrap() as u32);
    let hex = public["context_hex"].as_str().unwrap();
    assert_eq!(hex.len(), 128);
    let context = core::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap());
    (mode, input, output, context)
}

#[test]
fn independent_forward_and_inverse_statements_use_the_public_proof_interface() {
    // The inverse fixture is independently chosen rather than derived from the
    // preceding forward output. Both expected arrays come from reference data.
    for name in [
        "dense_deterministic_0_forward",
        "sparse_boundary_coefficients_inverse",
    ] {
        let (mode, input, output, context) = reference(name);
        let statement = Statement::new(mode, input, output, context).unwrap();
        let witness = Witness::from_input(input).unwrap();
        let proof = prove_ntt(&witness, &statement).unwrap();
        verify_ntt(&proof, &statement).unwrap();

        let mut altered_output = output;
        altered_output[128] = (altered_output[128] + 1) % MODULUS;
        let altered = Statement::new(mode, input, altered_output, context).unwrap();
        assert_eq!(verify_ntt(&proof, &altered), Err(Error::InvalidProof));

        let mut altered_context = context;
        altered_context[63] ^= 1;
        let altered = Statement::new(mode, input, output, altered_context).unwrap();
        assert_eq!(verify_ntt(&proof, &altered), Err(Error::InvalidProof));
        verify_ntt(&proof, &statement).unwrap();

        let mut invalid_input = input;
        invalid_input[255] = MODULUS;
        assert!(matches!(
            Witness::from_input(invalid_input),
            Err(Error::InvalidWitness)
        ));
        assert!(matches!(
            Statement::new(mode, invalid_input, output, context),
            Err(Error::InvalidStatement)
        ));
        let mut invalid_output = output;
        invalid_output[0] = MODULUS;
        assert!(matches!(
            Statement::new(mode, input, invalid_output, context),
            Err(Error::InvalidStatement)
        ));
    }
}
