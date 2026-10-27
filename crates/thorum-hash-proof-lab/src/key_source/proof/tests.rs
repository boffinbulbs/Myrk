use super::*;
use p3_symmetric::CryptographicHasher;
#[cfg(not(debug_assertions))]
use p3_uni_stark::StarkGenericConfig;
#[cfg(not(debug_assertions))]
use serde_json::json;

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

fn fixture() -> Witness {
    let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../research/signatures/synthetic_authorization.json"
    )))
    .unwrap();
    let other = data["alternate_signatures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "different_owner")
        .unwrap();
    Witness::from_keys([
        bytes(data["public_key_hex"].as_str().unwrap()),
        bytes(other["public_key_hex"].as_str().unwrap()),
    ])
}

#[test]
fn exact_profile_and_preflight_limits_are_independently_selected() {
    assert_eq!(
        (air::HEIGHT, air::WIDTH, air::PUBLIC_VALUES),
        (1024, 20168, 64)
    );
    assert_eq!(MAX_PROOF_BYTES, 24 * 1024 * 1024);
    assert_eq!(MAX_JSON_TOKENS, 2_000_000);
    assert_eq!(MAX_JSON_ITEMS, 32768);
    for value in [vec![b'['; 25], vec![b'x'; MAX_PROOF_BYTES + 1]] {
        assert_eq!(json_preflight(&value), Err(Error::LimitExceeded));
    }
    assert_eq!(json_preflight(&[b'1'; 21]), Err(Error::InvalidEncoding));
    assert!(json_preflight(br#"{"x":"escaped\n"}"#).is_err());
    assert_eq!(
        verify_key_slots(&[], &Statement::new([0; 64])),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn all_fresh_namespace_digest_words_match_independent_sha3() {
    for line in include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../research/key-source/hash_vectors.csv"
    ))
    .lines()
    .skip(1)
    {
        let fields: Vec<_> = line.split(',').collect();
        let expected: Vec<u64> = fields[3].split(':').map(|v| v.parse().unwrap()).collect();
        let actual = match fields[0] {
            "leaf" => LeafHash.hash_iter([0, 1, 2013265920, 0x12345678].map(BabyBear::from_u32)),
            "node" => NodeHash.hash_iter([0, 1, u64::MAX].into_iter().chain(0..13)),
            "transcript" => {
                let digest = TranscriptHash.hash_iter(0u8..64);
                core::array::from_fn(|i| {
                    u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().unwrap())
                })
            }
            _ => unreachable!(),
        };
        assert_eq!(actual.as_slice(), expected);
    }
}

#[test]
fn opaque_context_does_not_claim_canonical_transaction_constraints() {
    let witness = fixture();
    let t = trace(&witness);
    assert!(trace_is_valid(&t, &Statement::new([0x61; 64])));
    assert!(trace_is_valid(&t, &Statement::new([0x62; 64])));
}

#[test]
fn one_honest_key_source_proof() {
    let statement = Statement::new([0x61; 64]);
    let encoded = prove_key_slots(&fixture(), &statement).unwrap();
    verify_key_slots(&encoded, &statement).unwrap();
    let proof: Proof<Config> = serde_json::from_slice(&encoded).unwrap();
    validate_shape(&proof).unwrap();
    println!(
        "single key source proof verified, encoded bytes {}",
        encoded.len()
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn fresh_private_sources_public_mutations_and_transport() {
    let statement = Statement::new([0x61; 64]);
    let witness = fixture();
    let first = prove_key_slots(&witness, &statement).unwrap();
    let second = prove_key_slots(&witness, &statement).unwrap();
    verify_key_slots(&first, &statement).unwrap();
    verify_key_slots(&second, &statement).unwrap();
    assert_ne!(first, second);
    let a: serde_json::Value = serde_json::from_slice(&first).unwrap();
    let b: serde_json::Value = serde_json::from_slice(&second).unwrap();
    assert_ne!(a["commitments"], b["commitments"]);
    let swapped = Witness::from_keys([witness.keys[1], witness.keys[0]]);
    let alternate = prove_key_slots(&swapped, &statement).unwrap();
    verify_key_slots(&alternate, &statement).unwrap();
    let proof: Proof<Config> = serde_json::from_slice(&first).unwrap();
    let expected = public_values(&statement);
    let config = verifier_config();
    for index in 0..expected.len() {
        let mut changed = expected.clone();
        changed[index] += BabyBear::ONE;
        assert!(
            verify(&config, &KeySlotsAir, &proof, &changed).is_err(),
            "transcript input {index}"
        );
    }
    let wrong = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.private-key-source-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong, &KeySlotsAir, &proof, &expected).is_err());
    for index in 0..10 {
        let mut changed = a.clone();
        match index {
            0 => changed["degree_bits"] = json!(10),
            1 => {
                changed["opened_values"]["trace_local"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            2 => changed["opened_values"]["trace_next"] = json!(null),
            3 => {
                changed["opened_values"]["quotient_chunks"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            4 => changed["opened_values"]["random"] = json!(null),
            5 => {
                let old = changed["commitments"]["trace"]["cap"][0][0]
                    .as_u64()
                    .unwrap();
                changed["commitments"]["trace"]["cap"][0][0] = json!(old ^ 1);
            }
            6 => changed["opening_proof"][1]["query_pow_witness"] = json!(1),
            7 => {
                let old = changed["opening_proof"][1]["final_poly"][0]["value"][0]
                    .as_u64()
                    .unwrap();
                changed["opening_proof"][1]["final_poly"][0]["value"][0] =
                    json!((old + 1) % 2013265921);
            }
            8 => changed["ignored"] = json!(0),
            9 => {
                let old = changed["opened_values"]["trace_local"][0]["value"][0]
                    .as_u64()
                    .unwrap();
                changed["opened_values"]["trace_local"][0]["value"][0] =
                    json!((old + 1) % 2013265921);
            }
            _ => unreachable!(),
        }
        let mut encoded = serde_json::to_vec(&changed).unwrap();
        if index != 8
            && let Ok(typed) = serde_json::from_slice::<Proof<Config>>(&encoded)
        {
            encoded = serde_json::to_vec(&typed).unwrap();
        }
        assert!(
            verify_key_slots(&encoded, &statement).is_err(),
            "transport {index}"
        );
    }
    for end in [0, 1, 10, first.len() / 2, first.len() - 1] {
        assert!(verify_key_slots(&first[..end], &statement).is_err());
    }
    let mut trailing = first.clone();
    trailing.push(b' ');
    assert_eq!(
        verify_key_slots(&trailing, &statement),
        Err(Error::InvalidEncoding)
    );
    println!(
        "three fresh source proofs verified,64 transcript mutations,wrong profile and16 canonical corruptions rejected"
    );
}

#[cfg(not(debug_assertions))]
#[path = "raw_tests.rs"]
mod raw_tests;
