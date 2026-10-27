#[cfg(not(debug_assertions))]
use super::super::tests::{HASH_FAULTS, STATE_FAULTS, hash_attack, state_attack};
use super::super::tests::{data, fixture};
use super::*;
use p3_uni_stark::StarkGenericConfig;
use serde_json::json;

fn sample() -> &'static Vec<u8> {
    static PROOF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| {
        let data = data();
        let (w, s) = fixture(&data["genuine"][0]);
        prove_challenge_sampler(&w, &s).unwrap()
    })
}

#[test]
fn honest_freshness_public_and_canonical_transport() {
    let data = data();
    let (w, s) = fixture(&data["genuine"][0]);
    verify_challenge_sampler(sample(), &s).unwrap();
    let fresh = prove_challenge_sampler(&w, &s).unwrap();
    verify_challenge_sampler(&fresh, &s).unwrap();
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
            verify(&config, &ChallengeSamplerAir, &proof, &changed).is_err(),
            "public {index}"
        );
    }
    let wrong = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.challenge-sampler-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong, &ChallengeSamplerAir, &proof, &expected).is_err());
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
            verify_challenge_sampler(&encoded, &s).is_err(),
            "transport {index}"
        );
    }
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_challenge_sampler(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(
        verify_challenge_sampler(&trailing, &s),
        Err(Error::InvalidEncoding)
    );
    println!(
        "2 honest proofs verified, fresh commitments,1088 public mutations, wrong profile and16 canonical corruptions rejected"
    );
}

#[cfg(not(debug_assertions))]
#[test]
fn thirteen_raw_false_proofs_reject_at_the_backend() {
    let data = data();
    let (witness, statement) = fixture(&data["genuine"][0]);
    let original = trace(&witness, &statement).unwrap();
    let mut results = Vec::new();
    let mut attacks = Vec::new();
    for fault in HASH_FAULTS {
        attacks.push((format!("{fault:?}"), hash_attack(fault)));
    }
    for fault in STATE_FAULTS {
        attacks.push((format!("{fault:?}"), state_attack(fault)));
    }
    for name in [
        "UnusedByteAlias",
        "CounterSkip",
        "CursorReset",
        "PaddingTake",
    ] {
        let mut changed = original.clone();
        match name {
            "UnusedByteAlias" => {
                for row in changed.values.chunks_exact_mut(air::WIDTH) {
                    row[air::XOF + 260] += BabyBear::from_u32(256);
                    row[air::XOF + 261] -= BabyBear::ONE;
                }
            }
            "CounterSkip" => {
                let row = &mut changed.values[10 * air::WIDTH..11 * air::WIDTH];
                row[air::COUNT..air::CANDIDATE].fill(BabyBear::ZERO);
                row[air::COUNT + 11] = BabyBear::ONE;
            }
            "CursorReset" => {
                changed.values[100 * air::WIDTH + air::CURSOR..101 * air::WIDTH]
                    .fill(BabyBear::ZERO);
            }
            "PaddingTake" => changed.values[400 * air::WIDTH + air::TAKE] = BabyBear::ONE,
            _ => unreachable!(),
        }
        attacks.push((name.to_owned(), (changed, statement)));
    }
    for (name, (trace, s)) in attacks {
        let public = public_values(&s);
        assert!(s.validate().is_ok());
        assert!(!check_all_constraints(&ChallengeSamplerAir, &trace, &public, Some(16)).is_ok());
        let proof = prove(
            &prover_config().unwrap(),
            &ChallengeSamplerAir,
            trace,
            &public,
        )
        .expect("raw construction bypassing witness checks");
        validate_shape(&proof).unwrap();
        let error = verify(&verifier_config(), &ChallengeSamplerAir, &proof, &public)
            .expect_err("false proof backend rejection");
        let encoded = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_challenge_sampler(&encoded, &s),
            Err(Error::InvalidProof),
            "{name}"
        );
        results.push(json!({"fault": name, "backend_error": format!("{error:?}"), "encoded_bytes": encoded.len()}));
    }
    assert_eq!(results.len(), 13);

    println!(
        "13 raw false proofs constructed without witness prechecks and rejected by backend verification"
    );
}

#[test]
fn fixed_profile_statement_validation_and_transport_preflight_precede_decoding() {
    assert_eq!(
        (air::HEIGHT, air::WIDTH, air::PUBLIC_VALUES),
        (512, 6598, 1088)
    );
    let data = data();
    let (_, statement) = fixture(&data["genuine"][0]);
    for index in 0..5 {
        let mut bad = statement;
        match index {
            0 => bad.coefficients.fill(0),
            1 => bad.coefficients[0] = 2,
            2 => bad.coefficients[0] = u32::MAX,
            3 => bad.coefficients[0] += 2_013_265_921,
            4 => {
                let nonzero = bad.coefficients.iter_mut().find(|v| **v != 0).unwrap();
                *nonzero = 0;
            }
            _ => unreachable!(),
        }
        assert_eq!(
            verify_challenge_sampler(&[], &bad),
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
    let row = format!("[{}0]", "0,".repeat(8191));
    let total = format!("[{}0]", (row + ",").repeat(256));
    assert!(total.len() < MAX_PROOF_BYTES);
    assert_eq!(json_preflight(total.as_bytes()), Err(Error::LimitExceeded));
}
