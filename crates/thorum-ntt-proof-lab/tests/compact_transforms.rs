use serde_json::Value;
use thorum_ntt_proof_lab::{Error, Mode, Statement, Witness, compact, verify_ntt};

#[test]
fn shared_typed_statements_verify_only_under_the_compact_profile() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/ntt-proofs/ntt_vectors.json"
    ))
    .unwrap();
    for (mode, name) in [
        (Mode::Forward, "dense_deterministic_0_forward"),
        (Mode::Inverse, "dense_deterministic_0_inverse"),
    ] {
        let case = data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        let public = &case["public"];
        let input = core::array::from_fn(|i| public["input"][i].as_u64().unwrap() as u32);
        let output = core::array::from_fn(|i| public["output"][i].as_u64().unwrap() as u32);
        let text = public["context_hex"].as_str().unwrap();
        let context =
            core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap());
        let witness = Witness::from_input(input).unwrap();
        let statement = Statement::new(mode, input, output, context).unwrap();
        let proof = compact::prove_compact_ntt(&witness, &statement).unwrap();
        compact::verify_compact_ntt(&proof, &statement).unwrap();
        assert!(proof.len() <= compact::MAX_PROOF_BYTES);
        assert_eq!(verify_ntt(&proof, &statement), Err(Error::InvalidProof));
        let mut different_context = context;
        different_context[63] ^= 1;
        let changed = Statement::new(mode, input, output, different_context).unwrap();
        assert_eq!(
            compact::verify_compact_ntt(&proof, &changed),
            Err(Error::InvalidProof)
        );
    }
}
