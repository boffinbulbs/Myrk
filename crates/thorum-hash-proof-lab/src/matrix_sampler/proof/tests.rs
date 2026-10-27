#[cfg(not(debug_assertions))]
use super::super::tests::{FAULTS, attack};
use super::super::tests::{data, fixture};
use super::*;
use p3_uni_stark::StarkGenericConfig;
use serde_json::json;

fn sample() -> &'static Vec<u8> {
    static PROOF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| {
        let data = data();
        let (w, s) = fixture(&data["genuine"][0]);
        prove_matrix_sampler(&w, &s).unwrap()
    })
}

#[test]
fn honest_freshness_public_and_canonical_transport() {
    let data = data();
    let (w, s) = fixture(&data["genuine"][0]);
    verify_matrix_sampler(sample(), &s).unwrap();
    let fresh = prove_matrix_sampler(&w, &s).unwrap();
    verify_matrix_sampler(&fresh, &s).unwrap();
    assert_ne!(sample(), &fresh);
    let first: serde_json::Value = serde_json::from_slice(sample()).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&fresh).unwrap();
    assert_ne!(first["commitments"], second["commitments"]);
    let proof: Proof<Config> = serde_json::from_slice(sample()).unwrap();
    validate_shape(&proof).unwrap();
    let expected = public_values(&s);
    let config = verifier_config();
    for index in 0..expected.len() {
        let mut changed = expected.clone();
        changed[index] += BabyBear::ONE;
        assert!(
            verify(&config, &MatrixSamplerAir, &proof, &changed).is_err(),
            "public {index}"
        );
    }
    let wrong = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.matrix-sampler-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong, &MatrixSamplerAir, &proof, &expected).is_err());
    for index in 0..10 {
        let mut altered: serde_json::Value = serde_json::from_slice(sample()).unwrap();
        match index {
            0 => altered["degree_bits"] = json!(9),
            1 => {
                altered["opened_values"]["trace_local"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            2 => altered["opened_values"]["trace_next"] = json!(null),
            3 => {
                altered["opened_values"]["quotient_chunks"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            4 => altered["opened_values"]["random"] = json!(null),
            5 => altered["commitments"]["trace"]["cap"][0][0] = json!(1),
            6 => altered["opening_proof"][1]["query_pow_witness"] = json!(1),
            7 => altered["opening_proof"][1]["final_poly"][0]["value"][0] = json!(1),
            8 => altered["ignored"] = json!(0),
            9 => altered["opened_values"]["trace_local"][0]["value"][0] = json!(1),
            _ => unreachable!(),
        }
        let mut encoded = serde_json::to_vec(&altered).unwrap();
        if index != 8
            && let Ok(decoded) = serde_json::from_slice::<Proof<Config>>(&encoded)
        {
            encoded = serde_json::to_vec(&decoded).unwrap();
        }
        assert!(
            verify_matrix_sampler(&encoded, &s).is_err(),
            "transport {index}"
        );
    }
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_matrix_sampler(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(
        verify_matrix_sampler(&trailing, &s),
        Err(Error::InvalidEncoding)
    );
    println!(
        "2 honest proofs verified, fresh commitments,1090 public mutations, wrong profile and16 canonical corruptions rejected"
    );
}

#[cfg(not(debug_assertions))]
#[test]
fn thirteen_raw_false_proofs_reject_at_the_backend() {
    let mut results = Vec::new();
    for fault in FAULTS {
        let (trace, s) = attack(fault);
        let public = public_values(&s);
        assert!(!check_all_constraints(&MatrixSamplerAir, &trace, &public, Some(16)).is_ok());
        let proof = prove(&prover_config().unwrap(), &MatrixSamplerAir, trace, &public)
            .expect("raw construction bypassing witness checks");
        validate_shape(&proof).unwrap();
        let error = verify(&verifier_config(), &MatrixSamplerAir, &proof, &public)
            .expect_err("false proof backend rejection");
        let encoded = serde_json::to_vec(&proof).unwrap();
        let expected = if s.validate().is_ok() {
            Error::InvalidProof
        } else {
            Error::InvalidStatement
        };
        assert_eq!(
            verify_matrix_sampler(&encoded, &s),
            Err(expected),
            "{fault:?}"
        );
        results.push(json!({"fault": format!("{fault:?}"), "backend_error": format!("{error:?}"), "encoded_bytes": encoded.len()}));
    }
    assert_eq!(results.len(), 13);

    println!(
        "13 raw false proofs constructed without witness prechecks and rejected by backend verification"
    );
}

#[test]
fn fixed_profile_and_expected_statement_bounds_precede_proof_decoding() {
    assert_eq!(
        (air::HEIGHT, air::WIDTH, air::PUBLIC_VALUES),
        (512, 7276, 1090)
    );
    for (row, column, value) in [
        (8, 0, 0),
        (0, 7, 0),
        (0, 0, super::super::MODULUS),
        (0, 0, u32::MAX),
    ] {
        let bad = Statement {
            row,
            column,
            coefficients: [value; 256],
            context: [0; 64],
        };
        assert_eq!(
            verify_matrix_sampler(&[], &bad),
            Err(Error::InvalidStatement)
        );
    }
    for bytes in [
        vec![b'['; 25],
        vec![b'0'; 21],
        vec![0xff; 16],
        vec![b' '; MAX_PROOF_BYTES + 1],
        format!("[{}]", "0,".repeat(MAX_JSON_ITEMS)).into_bytes(),
        format!("\"{}\"", "a".repeat(65)).into_bytes(),
    ] {
        assert!(json_preflight(&bytes).is_err());
    }
    let inner = format!("[{}0]", "0,".repeat(8191));
    let tokens = format!("[{}]", vec![inner; 256].join(","));
    assert!(tokens.len() < MAX_PROOF_BYTES);
    assert_eq!(json_preflight(tokens.as_bytes()), Err(Error::LimitExceeded));
}
