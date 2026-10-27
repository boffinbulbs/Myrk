//! Compact profile proof verification, canonical transport and rejection tests.

use super::*;
use p3_uni_stark::StarkGenericConfig;
use serde_json::{Value, json};

fn fixture(mode: Mode) -> (Witness, Statement) {
    let data: Value = serde_json::from_str(include_str!(
        "../../../../research/ntt-proofs/ntt_vectors.json"
    ))
    .unwrap();
    let name = match mode {
        Mode::Forward => "dense_deterministic_0_forward",
        Mode::Inverse => "dense_deterministic_0_inverse",
    };
    let case = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    assert_eq!(case["expected"]["valid_component"], true);
    let public = &case["public"];
    let input = core::array::from_fn(|i| public["input"][i].as_u64().unwrap() as u32);
    let output = core::array::from_fn(|i| public["output"][i].as_u64().unwrap() as u32);
    let text = public["context_hex"].as_str().unwrap();
    let context =
        core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap());
    (
        Witness::from_input(input).unwrap(),
        Statement::new(mode, input, output, context).unwrap(),
    )
}

fn parsed(bytes: &[u8]) -> Proof<Config> {
    let proof: Proof<Config> = serde_json::from_slice(bytes).unwrap();
    validate_shape(&proof).expect("fixed compact profile shape");
    assert_eq!(serde_json::to_vec(&proof).unwrap(), bytes);
    assert!(bytes.len() <= MAX_PROOF_BYTES);
    proof
}

#[test]
fn prepared_proof_fixtures_are_valid_without_proving() {
    for mode in [Mode::Forward, Mode::Inverse] {
        let (witness, statement) = fixture(mode);
        assert!(trace_is_valid(&trace(&witness, &statement), &statement));
    }
}

fn transport_faults(bytes: &[u8], statement: &Statement) -> usize {
    let changes: [fn(&mut Value); 11] = [
        |p| p["degree_bits"] = json!(8),
        |p| p["commitments"]["trace"]["cap"][0][0] = json!(1),
        |p| p["opened_values"]["trace_local"][0]["value"][0] = json!(1),
        |p| {
            p["opened_values"]["trace_local"]
                .as_array_mut()
                .unwrap()
                .pop()
                .unwrap();
        },
        |p| p["opened_values"]["trace_next"] = json!(null),
        |p| p["opened_values"]["quotient_chunks"][0] = json!([]),
        |p| p["opened_values"]["random"] = json!(null),
        |p| p["opening_proof"][0][0][0][0][0]["value"][0] = json!(1),
        |p| p["opening_proof"][1]["query_pow_witness"] = json!(1),
        |p| p["opening_proof"][1]["final_poly"][0]["value"][0] = json!(1),
        |p| {
            p["opening_proof"][1]["input_openings"][1]["opened_values"]
                .as_array_mut()
                .unwrap()
                .pop()
                .unwrap();
        },
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let mut changed: Value = serde_json::from_slice(bytes).unwrap();
        change(&mut changed);
        assert!(
            verify_compact_ntt(&serde_json::to_vec(&changed).unwrap(), statement).is_err(),
            "transport mutation{index}"
        );
    }
    let mut salt_shape = parsed(bytes);
    let _ = salt_shape.opening_proof.1.input_openings[1].opening_proof.0[0][0]
        .pop()
        .unwrap();
    assert!(verify_compact_ntt(&serde_json::to_vec(&salt_shape).unwrap(), statement).is_err());
    for malformed in [
        vec![b'['; 25],
        vec![b'0'; 21],
        vec![0xff; 100],
        vec![b' '; MAX_PROOF_BYTES + 1],
        format!("[{}]", "0,".repeat(MAX_JSON_ITEMS)).into_bytes(),
        format!("\"{}\"", "a".repeat(65)).into_bytes(),
    ] {
        assert!(verify_compact_ntt(&malformed, statement).is_err());
    }
    let mut unknown: Value = serde_json::from_slice(bytes).unwrap();
    unknown["ignored"] = json!(0);
    assert!(verify_compact_ntt(&serde_json::to_vec(&unknown).unwrap(), statement).is_err());
    for end in [0, 1, 10, bytes.len() / 2, bytes.len() - 1] {
        assert!(verify_compact_ntt(&bytes[..end], statement).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(b' ');
    assert_eq!(
        verify_compact_ntt(&trailing, statement),
        Err(Error::InvalidEncoding)
    );
    25
}

fn public_binding(proof: &Proof<Config>, statement: &Statement) -> Value {
    let honest = public_values(statement);
    let config = verifier_config();
    let air = NttAir::new(statement);
    let mut selected = vec![0];
    for base in [1, 1025] {
        for index in [0, 7, 8, 127, 128, 247, 248, 255] {
            selected.extend([base + index * 4, base + index * 4 + 2]);
        }
    }
    selected.extend(
        [
            0, 1, 2, 3, 7, 8, 15, 16, 23, 24, 31, 32, 39, 40, 47, 48, 55, 56, 63,
        ]
        .map(|offset| 2049 + offset),
    );
    assert_eq!(selected.len(), 52);
    for index in selected {
        let mut changed = honest.clone();
        changed[index] += BabyBear::ONE;
        assert!(
            verify(&config, &air, proof, &changed).is_err(),
            "public field{index}"
        );
    }
    for output in [false, true] {
        for coefficient in [0, 255] {
            let value = if output {
                statement.output[coefficient]
            } else {
                statement.input[coefficient]
            };
            let mut changed = honest.clone();
            let start = (if output { 1025 } else { 1 }) + coefficient * 4;
            for (byte, value) in (value + 2013265921).to_le_bytes().into_iter().enumerate() {
                changed[start + byte] = BabyBear::from_u8(value);
            }
            assert!(verify(&config, &air, proof, &changed).is_err());
        }
    }
    let wrong = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.compact-ntt-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong, &air, proof, &honest).is_err());
    json!({"targeted_public_mutations_rejected": 52, "bytewise_field_aliases_rejected": 4,
           "wrong_profile_rejected": true, "verification_calls_use_backend_directly": true})
}

#[test]
fn inverse_freshness_transport_and_public_binding() {
    let (witness, statement) = fixture(Mode::Forward);
    let first = prove_compact_ntt(&witness, &statement).unwrap();
    let proof = parsed(&first);
    verify_compact_ntt(&first, &statement).unwrap();
    let second = prove_compact_ntt(&witness, &statement).unwrap();
    parsed(&second);
    verify_compact_ntt(&second, &statement).unwrap();
    assert_ne!(first, second, "independent fresh masks and salts");
    let (inverse_witness, inverse_statement) = fixture(Mode::Inverse);
    let inverse = prove_compact_ntt(&inverse_witness, &inverse_statement).unwrap();
    parsed(&inverse);
    verify_compact_ntt(&inverse, &inverse_statement).unwrap();
    let public_result = public_binding(&proof, &statement);
    let transport_count = transport_faults(&first, &statement);
    let mut changed = statement;
    changed.context[63] ^= 1;
    assert_eq!(
        verify_compact_ntt(&first, &changed),
        Err(Error::InvalidProof)
    );
    let mut noncanonical = statement;
    noncanonical.input[0] = mul::MODULUS;
    assert_eq!(
        verify_compact_ntt(&first, &noncanonical),
        Err(Error::InvalidStatement)
    );
    noncanonical = statement;
    noncanonical.output[255] = u32::MAX;
    assert_eq!(
        verify_compact_ntt(&first, &noncanonical),
        Err(Error::InvalidStatement)
    );
    changed = statement;
    changed.mode = Mode::Inverse;
    assert_eq!(
        verify_compact_ntt(&first, &changed),
        Err(Error::InvalidProof)
    );
    changed = statement;
    changed.output[255] = (changed.output[255] + 1) % mul::MODULUS;
    assert_eq!(
        verify_compact_ntt(&first, &changed),
        Err(Error::InvalidProof)
    );
    assert_eq!(public_result["targeted_public_mutations_rejected"], 52);
    assert_eq!(transport_count, 25);
    assert!(crate::verify_ntt(&first, &statement).is_err());
}

#[test]
#[cfg(not(debug_assertions))]
fn eight_raw_false_proofs_reject() {
    use causal::Attack;
    let mut results = Vec::new();
    for (mode, attack) in [
        (Mode::Forward, Attack::WrongTwiddle),
        (Mode::Forward, Attack::DetachedMultiplicand),
        (Mode::Forward, Attack::UnauthorizedBankWrite),
        (Mode::Inverse, Attack::MissingNormalization),
        (Mode::Forward, Attack::DetachedOutputRead),
        (Mode::Inverse, Attack::ChangedFirstOutputBank),
        (Mode::Forward, Attack::ChangedPaddingBank),
        (Mode::Inverse, Attack::UninitializedBank),
    ] {
        let (trace, statement) = causal::attack_trace(mode, attack);
        assert!(!trace_is_valid(&trace, &statement), "{mode:?} {attack:?}");
        // This bypasses prove_trace and its local witness check deliberately.
        let proof = prove(
            &prover_config().unwrap(),
            &NttAir::new(&statement),
            trace,
            &public_values(&statement),
        )
        .expect("raw false trace proof construction");
        validate_shape(&proof).expect("unchanged fixed proof shape");
        let direct_error = verify(
            &verifier_config(),
            &NttAir::new(&statement),
            &proof,
            &public_values(&statement),
        )
        .expect_err("direct backend must reject the false trace proof");
        let bytes = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_compact_ntt(&bytes, &statement),
            Err(Error::InvalidProof),
            "{mode:?} {attack:?}"
        );
        results.push(json!({"mode": format!("{mode:?}"), "attack": format!("{attack:?}"),
            "local_constraint_report_rejected": true, "witness_precheck_bypassed_for_proof_construction": true,
            "raw_proof_constructed": true, "fixed_shape_validated": true, "proof_size_bytes": bytes.len(),
            "direct_backend_rejected": true, "direct_backend_error": format!("{direct_error:?}"),
            "canonical_wrapper_result": "InvalidProof"}));
    }
    assert_eq!(results.len(), 8);
}
