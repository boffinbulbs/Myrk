use super::*;
use p3_matrix::Matrix;
use serde_json::Value;
use serde_json::json;
use std::sync::OnceLock;

fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    let text = value.as_str().unwrap();
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}
pub(crate) fn fixture(index: usize) -> (Witness, Statement, bool) {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../research/nullifier-proofs/nullifier_vectors.json"
    ))
    .unwrap();
    let case = &vectors["cases"][index];
    let p = &case["public"];
    let w = &case["witness"];
    let statement = Statement {
        fee: p["fee"].as_u64().unwrap(),
        chain: bytes(&p["chain_hex"]),
        output_creation_versions: core::array::from_fn(|i| {
            p["output_creation_versions"][i].as_u64().unwrap() as u32
        }),
        asset: bytes(&p["asset_hex"]),
        root: bytes(&p["root_hex"]),
        output_commitments: core::array::from_fn(|i| bytes(&p["output_commitments_hex"][i])),
        nullifiers: core::array::from_fn(|i| bytes(&p["nullifiers_hex"][i])),
        context: bytes(&p["context_hex"]),
    };
    let witness = Witness::from_openings_secrets_and_paths(
        core::array::from_fn(|i| bytes(&w["openings_hex"][i])),
        core::array::from_fn(|i| bytes(&w["nullifier_secrets_hex"][i])),
        core::array::from_fn(|i| w["inputs"][i]["index"].as_u64().unwrap() as u32),
        core::array::from_fn(|i| {
            core::array::from_fn(|j| bytes(&w["inputs"][i]["siblings_hex"][j]))
        }),
    );
    (
        witness,
        statement,
        case["expected"]["valid_component"].as_bool().unwrap(),
    )
}
#[test]
fn exact_profile_and_valid_depth32_fixture() {
    let (w, s, _) = fixture(0);
    let t = trace(&w, &s);
    eprintln!(
        "width={} height={} public={}",
        t.width(),
        t.height(),
        sponge::public_values(&s).len()
    );
    assert!(trace_is_valid(&t, &s));
    let layout = p3_air::symbolic::AirLayout {
        main_width: sponge::WIDTH,
        num_public_values: sponge::PUBLIC_VALUES,
        ..Default::default()
    };
    let degree = p3_air::symbolic::get_max_constraint_degree_extension::<BabyBear, Challenge, _>(
        &NullifierAir,
        layout,
        sponge::HEIGHT,
    );
    assert_eq!(degree, 4);
    assert_eq!(t.width(), 4801);
    assert_eq!(t.height(), 8192);
    assert_eq!(sponge::public_values(&s).len(), 520);
}

#[test]
fn independent_fixtures_cover_private_paths_stable_nullifiers_and_integer_boundaries() {
    for index in 0..64 {
        let (w, s, expected) = fixture(index);
        let t = trace(&w, &s);
        assert_eq!(trace_is_valid(&t, &s), expected, "fixture {index}");
        // Only one full trace is retained at a time.
    }
}

#[test]
fn duplicate_hidden_inputs_fail_the_complete_local_witness_check() {
    let (w, s, _) = fixture(33);
    assert_eq!(prove_nullifiers(&w, &s), Err(Error::DuplicateNullifier));
    assert!(!trace_is_valid(&trace(&w, &s), &s));
}

fn sample() -> &'static Vec<u8> {
    static PROOF: OnceLock<Vec<u8>> = OnceLock::new();
    PROOF.get_or_init(|| {
        let (w, s, _) = fixture(0);
        prove_nullifiers(&w, &s).unwrap()
    })
}

#[test]
fn every_public_statement_byte_is_transcript_bound() {
    let (_, s, _) = fixture(0);
    verify_nullifiers(sample(), &s).unwrap();
    for bit in 0..64 {
        let mut changed = s;
        changed.fee ^= 1 << bit;
        assert_eq!(
            verify_nullifiers(sample(), &changed),
            Err(Error::InvalidProof)
        );
    }
    for byte in 0..32 {
        let mut changed = s;
        changed.chain[byte] ^= 1;
        assert_eq!(
            verify_nullifiers(sample(), &changed),
            Err(Error::InvalidProof)
        );
        changed = s;
        changed.asset[byte] ^= 1;
        assert_eq!(
            verify_nullifiers(sample(), &changed),
            Err(Error::InvalidProof)
        );
    }
    for byte in 0..64 {
        let mut changed = s;
        changed.root[byte] ^= 1;
        assert_eq!(
            verify_nullifiers(sample(), &changed),
            Err(Error::InvalidProof)
        );
        changed = s;
        changed.context[byte] ^= 1;
        assert_eq!(
            verify_nullifiers(sample(), &changed),
            Err(Error::InvalidProof)
        );
        for output in 0..2 {
            changed = s;
            changed.output_commitments[output][byte] ^= 1;
            assert_eq!(
                verify_nullifiers(sample(), &changed),
                Err(Error::InvalidProof)
            );
        }
        for input in 0..2 {
            changed = s;
            changed.nullifiers[input][byte] ^= 1;
            assert_eq!(
                verify_nullifiers(sample(), &changed),
                Err(Error::InvalidProof)
            );
        }
    }
    for output in 0..2 {
        for bit in 0..32 {
            let mut changed = s;
            changed.output_creation_versions[output] ^= 1 << bit;
            assert_eq!(
                verify_nullifiers(sample(), &changed),
                Err(Error::InvalidProof)
            );
        }
    }
}

fn mutation(change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut proof: Value = serde_json::from_slice(sample()).unwrap();
    change(&mut proof);
    let bytes = serde_json::to_vec(&proof).unwrap();
    match serde_json::from_slice::<Proof<Config>>(&bytes) {
        Ok(p) => serde_json::to_vec(&p).unwrap(),
        Err(_) => bytes,
    }
}

#[test]
fn malformed_or_tampered_proof_transport_is_rejected() {
    let (_, s, _) = fixture(0);
    for bytes in [
        mutation(|p| p["degree_bits"] = json!(13)),
        mutation(|p| p["commitments"]["trace"]["cap"][0][0] = json!(1)),
        mutation(|p| p["opened_values"]["trace_local"][0]["value"][0] = json!(1)),
        mutation(|p| {
            p["opened_values"]["trace_local"]
                .as_array_mut()
                .unwrap()
                .pop()
                .map(|_| ())
                .unwrap()
        }),
        mutation(|p| p["opening_proof"][0][0][0][0][0]["value"][0] = json!(1)),
        mutation(|p| p["opening_proof"][1]["query_pow_witness"] = json!(1)),
        mutation(|p| p["opening_proof"][1]["final_poly"][0]["value"][0] = json!(1)),
        vec![b'['; 25],
        vec![b'0'; 21],
        vec![0xff; 100],
        vec![b' '; MAX_PROOF_BYTES + 1],
        format!("[{}]", "0,".repeat(MAX_JSON_ITEMS)).into_bytes(),
        format!("\"{}\"", "a".repeat(65)).into_bytes(),
    ] {
        assert!(verify_nullifiers(&bytes, &s).is_err());
    }
    let mut unknown: Value = serde_json::from_slice(sample()).unwrap();
    unknown["ignored_field"] = json!(0);
    assert!(verify_nullifiers(&serde_json::to_vec(&unknown).unwrap(), &s).is_err());
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_nullifiers(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(
        verify_nullifiers(&trailing, &s),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn fresh_real_proofs_randomize_reused_private_membership_witnesses() {
    let (w, s, _) = fixture(0);
    let fresh = prove_nullifiers(&w, &s).unwrap();
    verify_nullifiers(&fresh, &s).unwrap();
    assert_ne!(sample(), &fresh);
    let a: Value = serde_json::from_slice(sample()).unwrap();
    let b: Value = serde_json::from_slice(&fresh).unwrap();
    assert_ne!(a["commitments"], b["commitments"]);
    for field in [
        "openings",
        "inputs",
        "indices",
        "siblings",
        "input_commitments",
        "input_creation_versions",
        "secrets",
        "nullifier_secrets",
        "bindings",
    ] {
        assert!(a.get(field).is_none());
    }
}

#[test]
fn public_duplicate_nullifiers_and_wrong_profile_are_rejected() {
    use p3_uni_stark::StarkGenericConfig;
    let (w, mut s, _) = fixture(0);
    s.nullifiers[1] = s.nullifiers[0];
    assert_eq!(prove_nullifiers(&w, &s), Err(Error::DuplicateNullifier));
    assert_eq!(
        verify_nullifiers(sample(), &s),
        Err(Error::DuplicateNullifier)
    );
    let (_, s, _) = fixture(0);
    let honest = verifier_config();
    let other_profile = Config::new(
        honest.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.nullifier-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    let proof: Proof<Config> = serde_json::from_slice(sample()).unwrap();
    assert!(verify(&other_profile, &NullifierAir, &proof, &public_values(&s)).is_err());
}

// Each causal trace retains valid standalone Keccak computations. These raw
// proofs bypass the local witness precheck. The duplicate case also bypasses
// the public duplicate nullifier precheck at the backend verification call.
#[cfg(not(debug_assertions))]
#[test]
fn raw_invalid_nullifier_proofs_fail_the_real_verifier() {
    use crate::causal::Attack;
    for attack in [
        Attack::BindingToOpeningLow,
        Attack::BindingToOpeningHigh,
        Attack::NullifierCommitmentLow,
        Attack::NullifierCommitmentHigh,
        Attack::NullifierKey,
        Attack::GlobalSecretConstancy,
    ] {
        let (t, s) = crate::causal::attack_trace(attack);
        assert!(!trace_is_valid(&t, &s));
        let proof = prove(
            &prover_config().unwrap(),
            &NullifierAir,
            t,
            &public_values(&s),
        )
        .expect("raw proof construction");
        validate_shape(&proof).expect("fixed profile shape");
        let bytes = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_nullifiers(&bytes, &s),
            Err(Error::InvalidProof),
            "attack {attack:?}"
        );
    }
    for index in [45, 33] {
        let (w, s, _) = fixture(index);
        let t = trace(&w, &s);
        assert!(!trace_is_valid(&t, &s));
        let proof = prove(
            &prover_config().unwrap(),
            &NullifierAir,
            t,
            &public_values(&s),
        )
        .expect("raw proof construction");
        validate_shape(&proof).expect("fixed profile shape");
        assert!(
            verify(
                &verifier_config(),
                &NullifierAir,
                &proof,
                &public_values(&s)
            )
            .is_err()
        );
        let bytes = serde_json::to_vec(&proof).unwrap();
        let expected = if index == 33 {
            Error::DuplicateNullifier
        } else {
            Error::InvalidProof
        };
        assert_eq!(
            verify_nullifiers(&bytes, &s),
            Err(expected),
            "fixture {index}"
        );
    }
}
