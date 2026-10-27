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
        "../../../research/owner-bindings/owner_binding_vectors.json"
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
    let witness = Witness::from_openings_keys_secrets_and_paths(
        core::array::from_fn(|i| bytes(&w["openings_hex"][i])),
        core::array::from_fn(|i| bytes(&w["owner_public_keys_hex"][i])),
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
        &OwnerBindingAir,
        layout,
        sponge::HEIGHT,
    );
    assert_eq!(degree, 4);
    assert_eq!(t.width(), 5003);
    assert_eq!(t.height(), 8192);
    assert_eq!(sponge::public_values(&s).len(), 520);
}

#[test]
fn independent_fixtures_cover_owner_bindings_private_paths_and_stable_nullifiers() {
    for index in 0..85 {
        let (w, s, expected) = fixture(index);
        let t = trace(&w, &s);
        assert_eq!(trace_is_valid(&t, &s), expected, "fixture {index}");
        // Only one full trace is retained at a time.
    }
}

#[test]
fn duplicate_hidden_inputs_fail_the_complete_local_witness_check() {
    let (w, s, _) = fixture(33);
    assert_eq!(prove_owner_binding(&w, &s), Err(Error::DuplicateNullifier));
    assert!(!trace_is_valid(&trace(&w, &s), &s));
}

fn sample() -> &'static Vec<u8> {
    static PROOF: OnceLock<Vec<u8>> = OnceLock::new();
    PROOF.get_or_init(|| {
        let (w, s, _) = fixture(0);
        prove_owner_binding(&w, &s).unwrap()
    })
}

#[test]
fn every_public_statement_byte_is_transcript_bound() {
    let (_, s, _) = fixture(0);
    verify_owner_binding(sample(), &s).unwrap();
    for bit in 0..64 {
        let mut changed = s;
        changed.fee ^= 1 << bit;
        assert_eq!(
            verify_owner_binding(sample(), &changed),
            Err(Error::InvalidProof)
        );
    }
    for byte in 0..32 {
        let mut changed = s;
        changed.chain[byte] ^= 1;
        assert_eq!(
            verify_owner_binding(sample(), &changed),
            Err(Error::InvalidProof)
        );
        changed = s;
        changed.asset[byte] ^= 1;
        assert_eq!(
            verify_owner_binding(sample(), &changed),
            Err(Error::InvalidProof)
        );
    }
    for byte in 0..64 {
        let mut changed = s;
        changed.root[byte] ^= 1;
        assert_eq!(
            verify_owner_binding(sample(), &changed),
            Err(Error::InvalidProof)
        );
        changed = s;
        changed.context[byte] ^= 1;
        assert_eq!(
            verify_owner_binding(sample(), &changed),
            Err(Error::InvalidProof)
        );
        for output in 0..2 {
            changed = s;
            changed.output_commitments[output][byte] ^= 1;
            assert_eq!(
                verify_owner_binding(sample(), &changed),
                Err(Error::InvalidProof)
            );
        }
        for input in 0..2 {
            changed = s;
            changed.nullifiers[input][byte] ^= 1;
            assert_eq!(
                verify_owner_binding(sample(), &changed),
                Err(Error::InvalidProof)
            );
        }
    }
    for output in 0..2 {
        for bit in 0..32 {
            let mut changed = s;
            changed.output_creation_versions[output] ^= 1 << bit;
            assert_eq!(
                verify_owner_binding(sample(), &changed),
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
        assert!(verify_owner_binding(&bytes, &s).is_err());
    }
    let mut unknown: Value = serde_json::from_slice(sample()).unwrap();
    unknown["ignored_field"] = json!(0);
    assert!(verify_owner_binding(&serde_json::to_vec(&unknown).unwrap(), &s).is_err());
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_owner_binding(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(
        verify_owner_binding(&trailing, &s),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn fresh_real_proofs_randomize_reused_owner_key_and_note_witnesses() {
    let (w, s, _) = fixture(0);
    let fresh = prove_owner_binding(&w, &s).unwrap();
    verify_owner_binding(&fresh, &s).unwrap();
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
        "public_keys",
        "owner_public_keys",
        "owners",
    ] {
        assert!(a.get(field).is_none());
    }
}

#[test]
fn public_duplicate_nullifiers_and_wrong_profile_are_rejected() {
    use p3_uni_stark::StarkGenericConfig;
    let (w, mut s, _) = fixture(0);
    s.nullifiers[1] = s.nullifiers[0];
    assert_eq!(prove_owner_binding(&w, &s), Err(Error::DuplicateNullifier));
    assert_eq!(
        verify_owner_binding(sample(), &s),
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
    assert!(verify(&other_profile, &OwnerBindingAir, &proof, &public_values(&s)).is_err());
}

#[test]
fn exact_unframed_owner_key_padding_and_substituted_keys() {
    let (mut witness, statement, _) = fixture(0);
    let message = sponge::owner_message(&witness.public_keys[0]);
    assert_eq!(message.len(), 2664);
    assert_eq!(&message[..2592], &witness.public_keys[0]);
    assert_eq!(message[2592], 6);
    assert!(message[2593..2663].iter().all(|b| *b == 0));
    assert_eq!(message[2663], 128);
    witness.public_keys[0][2591] ^= 1;
    assert!(!trace_is_valid(&trace(&witness, &statement), &statement));
    witness.public_keys[0][2591] ^= 1;
    witness.public_keys[1][0] ^= 1;
    assert!(!trace_is_valid(&trace(&witness, &statement), &statement));
}

// Every causal trace retains genuine standalone Keccak computations and the
// same public membership root and nullifier identities. Raw proving bypasses
// the local witness check. The duplicate input case also bypasses the public
// duplicate nullifier precheck when invoking the backend verifier.
#[cfg(not(debug_assertions))]
#[test]
fn raw_detached_owner_proofs_fail_the_actual_verifier() {
    use crate::causal::Attack;
    for (input, attack) in [
        (0, Attack::OpeningLow),
        (0, Attack::OpeningHigh),
        (1, Attack::WrongKey),
        (0, Attack::WrongSuffix),
        (1, Attack::CapacityContinuation),
        (1, Attack::GlobalOwnerConstancy),
        (0, Attack::RollingPollution),
    ] {
        let (t, s) = crate::causal::attack_trace(input, attack);
        assert!(!trace_is_valid(&t, &s));
        let proof = prove(
            &prover_config().unwrap(),
            &OwnerBindingAir,
            t,
            &public_values(&s),
        )
        .expect("raw proof construction");
        validate_shape(&proof).expect("fixed profile shape");
        let bytes = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_owner_binding(&bytes, &s),
            Err(Error::InvalidProof),
            "{input} {attack:?}"
        );
    }
    let (w, s, _) = fixture(33);
    assert_eq!(s.nullifiers[0], s.nullifiers[1]);
    let t = trace(&w, &s);
    assert!(!trace_is_valid(&t, &s));
    let proof = prove(
        &prover_config().unwrap(),
        &OwnerBindingAir,
        t,
        &public_values(&s),
    )
    .expect("raw proof construction");
    validate_shape(&proof).expect("fixed profile shape");
    assert!(
        verify(
            &verifier_config(),
            &OwnerBindingAir,
            &proof,
            &public_values(&s)
        )
        .is_err()
    );
    let bytes = serde_json::to_vec(&proof).unwrap();
    assert_eq!(
        verify_owner_binding(&bytes, &s),
        Err(Error::DuplicateNullifier)
    );
}
