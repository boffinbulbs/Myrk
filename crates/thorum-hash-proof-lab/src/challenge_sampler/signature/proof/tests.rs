use super::super::tests::{data, fixture};
use super::*;
use p3_uni_stark::StarkGenericConfig;
use serde_json::json;

fn sample() -> &'static Vec<u8> {
    static PROOF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| {
        let data = data();
        let (w, s) = fixture(&data["cases"][0]);
        prove_signature_challenge(&w, &s).unwrap()
    })
}

#[test]
fn honest_freshness_public_and_canonical_transport() {
    let data = data();
    let (w, s) = fixture(&data["cases"][0]);
    verify_signature_challenge(sample(), &s).unwrap();
    let fresh = prove_signature_challenge(&w, &s).unwrap();
    verify_signature_challenge(&fresh, &s).unwrap();
    assert_ne!(sample(), &fresh);
    let first: serde_json::Value = serde_json::from_slice(sample()).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&fresh).unwrap();
    assert_ne!(first["commitments"], second["commitments"]);
    let (joined, joined_statement) = fixture(data["cases"].as_array().unwrap().last().unwrap());
    let joined_proof = prove_signature_challenge(&joined, &joined_statement).unwrap();
    verify_signature_challenge(&joined_proof, &joined_statement).unwrap();
    let proof: Proof<Config> = serde_json::from_slice(sample()).unwrap();
    validate_shape(&proof).unwrap();
    let expected = public_values(&s);
    let config = verifier_config();
    for index in 0..expected.len() {
        let mut changed = expected.clone();
        changed[index] += BabyBear::ONE;
        assert!(
            verify(&config, &SignatureChallengeAir, &proof, &changed).is_err(),
            "public {index}"
        );
    }
    let wrong = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.signature-challenge-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong, &SignatureChallengeAir, &proof, &expected).is_err());
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
            verify_signature_challenge(&encoded, &s).is_err(),
            "transport {index}"
        );
    }
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_signature_challenge(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(
        verify_signature_challenge(&trailing, &s),
        Err(Error::InvalidEncoding)
    );
    println!(
        "3 honest limited-relation proofs verified including a represented joined string, fresh commitments,1088 public mutations, wrong profile and16 canonical corruptions rejected"
    );
}

#[test]
fn fixed_profile_statement_validation_and_transport_preflight_precede_decoding() {
    assert_eq!(
        (air::HEIGHT, air::WIDTH, air::PUBLIC_VALUES),
        (512, 16650, 1088)
    );
    let data = data();
    let (_, statement) = fixture(&data["cases"][0]);
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
            verify_signature_challenge(&[], &bad),
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

#[cfg(not(debug_assertions))]
#[path = "raw_tests.rs"]
mod raw_tests;

#[test]
fn proof_namespace_goldens_match_all_digest_words() {
    use super::super::hash::{LeafHash, NodeHash, TranscriptHash};
    use p3_symmetric::CryptographicHasher;
    for line in include_str!("../../../../../../research/signature-challenge/hash_vectors.csv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = line.split(',').collect();
        let expected: Vec<u64> = fields[3]
            .split(':')
            .map(|word| word.parse().unwrap())
            .collect();
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
