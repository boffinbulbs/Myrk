use super::*;
use p3_matrix::Matrix;
use serde_json::Value;
use sha3::{
    Digest, Sha3_512,
    digest::{ExtendableOutput, Update, XofReader},
};
use shake::{Shake128, Shake256};

pub(crate) fn expected(mode: Mode, input: &[u8], length: usize) -> Vec<u8> {
    match mode {
        Mode::Sha3_512 => Sha3_512::digest(input).to_vec(),
        Mode::Shake128 => {
            let mut hash = Shake128::default();
            Update::update(&mut hash, input);
            let mut output = vec![0; length];
            hash.finalize_xof().read(&mut output);
            output
        }
        Mode::Shake256 => {
            let mut hash = Shake256::default();
            Update::update(&mut hash, input);
            let mut output = vec![0; length];
            hash.finalize_xof().read(&mut output);
            output
        }
    }
}
pub(crate) fn fixture(
    mode: Mode,
    input_length: usize,
    output_length: usize,
) -> (Witness, Statement) {
    let input: Vec<u8> = (0..input_length).map(|i| i as u8).collect();
    let output = expected(mode, &input, output_length);
    (
        Witness::from_bytes(&input).unwrap(),
        Statement::new(mode, input_length, &output, [0x73; 64]).unwrap(),
    )
}

pub(crate) fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert_eq!(text.len() % 2, 0);
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

pub(crate) fn reference_case(case: &Value) -> (Witness, Statement) {
    let p = &case["public"];
    let mode = match p["mode"].as_u64().unwrap() {
        1 => Mode::Sha3_512,
        2 => Mode::Shake128,
        3 => Mode::Shake256,
        _ => panic!("unsupported fixture mode"),
    };
    let output_length = p["output_length"].as_u64().unwrap() as usize;
    let output = bytes(&p["output_hex"]);
    let statement = Statement::new(
        mode,
        p["input_length"].as_u64().unwrap() as usize,
        &output[..output_length],
        bytes(&p["context_hex"]).try_into().unwrap(),
    )
    .unwrap();
    let witness = Witness::from_bytes(&bytes(&case["witness"]["input_hex"])).unwrap();
    (witness, statement)
}

#[test]
fn independent_fixtures_and_all_public_values_match() {
    use p3_field::PrimeField32;
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/hash-proofs/hash_relation_vectors.json"
    ))
    .unwrap();
    for case in data["cases"].as_array().unwrap() {
        let (w, s) = reference_case(case);
        let values: Vec<_> = public_values(&s)
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect();
        let recorded: Vec<_> = case["public_values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(values, recorded, "{}", case["name"]);
        if w.input.len() != s.input_length {
            assert_eq!(prove_hash(&w, &s), Err(Error::InvalidWitness));
            continue;
        }
        assert_eq!(
            trace_is_valid(&trace(&w, &s), &s),
            case["expected"]["valid_component"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn fixed_dimensions_degree_and_honest_sha3_shake_boundaries() {
    for (mode, input_length, output_length) in [
        (Mode::Sha3_512, 2592, 64),
        (Mode::Sha3_512, 71, 64),
        (Mode::Sha3_512, 72, 64),
        (Mode::Shake128, 34, 840),
        (Mode::Shake128, 167, 840),
        (Mode::Shake128, 168, 169),
        (Mode::Shake256, 2592, 64),
        (Mode::Shake256, 135, 840),
        (Mode::Shake256, 136, 137),
        (Mode::Shake256, 303, 64),
        (Mode::Shake256, 0, 1),
    ] {
        let (w, s) = fixture(mode, input_length, output_length);
        let t = trace(&w, &s);
        assert!(
            trace_is_valid(&t, &s),
            "{mode:?} {input_length} {output_length}"
        );
        assert_eq!(t.width(), 5359);
        assert_eq!(t.height(), 1024);
        assert_eq!(public_values(&s).len(), 913);
        let layout = p3_air::symbolic::AirLayout {
            main_width: sponge::WIDTH,
            num_public_values: sponge::PUBLIC_VALUES,
            ..Default::default()
        };
        let degree = p3_air::symbolic::get_max_constraint_degree_extension::<BabyBear, Challenge, _>(
            &HashAir::new(&s),
            layout,
            sponge::HEIGHT,
        );
        assert_eq!(degree, if HashAir::new(&s).absorbs() > 1 { 4 } else { 3 });
    }
}

fn sample() -> &'static Vec<u8> {
    static PROOF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| {
        let (w, s) = fixture(Mode::Shake128, 34, 840);
        prove_hash(&w, &s).unwrap()
    })
}

#[test]
fn every_public_field_element_is_bound_by_the_actual_verifier() {
    use p3_uni_stark::StarkGenericConfig;
    let (_, s) = fixture(Mode::Shake128, 34, 840);
    verify_hash(sample(), &s).unwrap();
    let proof: Proof<Config> = serde_json::from_slice(sample()).unwrap();
    let config = verifier_config();
    let air = HashAir::new(&s);
    let honest = public_values(&s);
    for index in 0..honest.len() {
        let mut changed = honest.clone();
        changed[index] += BabyBear::ONE;
        assert!(
            verify(&config, &air, &proof, &changed).is_err(),
            "public field {index}"
        );
    }
    let wrong_profile = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.hash-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong_profile, &air, &proof, &honest).is_err());
}

#[test]
fn typed_statement_bounds_and_zero_tail_are_checked_before_proof_decoding() {
    for mode in [Mode::Sha3_512, Mode::Shake128, Mode::Shake256] {
        for length in [0, 841, usize::MAX] {
            let (_, mut s) = fixture(mode, 34, if mode == Mode::Sha3_512 { 64 } else { 840 });
            s.output_length = length;
            assert_eq!(verify_hash(&[], &s), Err(Error::InvalidStatement));
            let w = Witness::from_bytes(&[0; 34]).unwrap();
            assert_eq!(prove_hash(&w, &s), Err(Error::InvalidStatement));
        }
    }
    for length in [2593, usize::MAX] {
        let (_, mut s) = fixture(Mode::Shake256, 34, 64);
        s.input_length = length;
        assert_eq!(verify_hash(&[], &s), Err(Error::InvalidStatement));
    }
    for length in [0, 63, 65, 840] {
        assert!(matches!(
            Statement::new(Mode::Sha3_512, 34, &vec![0; length], [0; 64]),
            Err(Error::InvalidStatement)
        ));
    }
    for mode in [Mode::Shake128, Mode::Shake256] {
        assert!(matches!(
            Statement::new(mode, 34, &[], [0; 64]),
            Err(Error::InvalidStatement)
        ));
    }
    let (_, mut s) = fixture(Mode::Shake256, 34, 64);
    s.output[839] = 1;
    assert_eq!(verify_hash(&[], &s), Err(Error::InvalidStatement));
    assert!(matches!(
        Witness::from_bytes(&[0; 2593]),
        Err(Error::InvalidWitness)
    ));
    let (w, mut s) = fixture(Mode::Shake128, 34, 840);
    s.input_length = 35;
    assert_eq!(prove_hash(&w, &s), Err(Error::InvalidWitness));
}

#[test]
fn real_proofs_cover_every_mode_and_randomize_reused_private_inputs() {
    let (w, s) = fixture(Mode::Shake128, 34, 840);
    let fresh = prove_hash(&w, &s).unwrap();
    verify_hash(&fresh, &s).unwrap();
    assert_ne!(sample(), &fresh);
    let a: Value = serde_json::from_slice(sample()).unwrap();
    let b: Value = serde_json::from_slice(&fresh).unwrap();
    assert_ne!(a["commitments"], b["commitments"]);
    for field in [
        "input",
        "input_bytes",
        "private_input",
        "public_key",
        "signature",
        "witness",
    ] {
        assert!(a.get(field).is_none());
    }
    for mode in [Mode::Sha3_512, Mode::Shake256] {
        let (w, s) = fixture(mode, 2592, 64);
        let proof = prove_hash(&w, &s).unwrap();
        verify_hash(&proof, &s).unwrap();
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
    use serde_json::json;
    let (_, s) = fixture(Mode::Shake128, 34, 840);
    for bytes in [
        mutation(|p| p["degree_bits"] = json!(10)),
        mutation(|p| p["commitments"]["trace"]["cap"][0][0] = json!(1)),
        mutation(|p| p["opened_values"]["trace_local"][0]["value"][0] = json!(1)),
        mutation(|p| {
            p["opened_values"]["trace_local"]
                .as_array_mut()
                .unwrap()
                .pop()
                .unwrap();
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
        assert!(verify_hash(&bytes, &s).is_err());
    }
    let mut unknown: Value = serde_json::from_slice(sample()).unwrap();
    unknown["ignored_field"] = json!(0);
    assert!(verify_hash(&serde_json::to_vec(&unknown).unwrap(), &s).is_err());
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_hash(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(verify_hash(&trailing, &s), Err(Error::InvalidEncoding));
}

// The raw prover deliberately bypasses the local constraint precheck. Each
// attack retains genuine standalone permutations and publishes their actual
// output. Only the required sponge relation is false.
#[cfg(not(debug_assertions))]
#[test]
fn raw_invalid_sponge_proofs_fail_the_actual_verifier() {
    use crate::causal::Attack;
    for (mode, attack) in [
        (Mode::Sha3_512, Attack::CombinedSuffix),
        (Mode::Sha3_512, Attack::ExactRatePaddingBlock),
        (Mode::Shake128, Attack::SqueezeCapacity),
        (Mode::Shake256, Attack::SqueezeRate),
        (Mode::Shake128, Attack::SqueezeAbsorption),
        (Mode::Shake256, Attack::SqueezeReset),
    ] {
        let (t, s) = crate::causal::attack_trace(mode, attack);
        assert!(!trace_is_valid(&t, &s));
        let proof = prove(
            &prover_config().unwrap(),
            &HashAir::new(&s),
            t,
            &public_values(&s),
        )
        .expect("raw proof construction");
        validate_shape(&proof).expect("fixed profile shape");
        let bytes = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_hash(&bytes, &s),
            Err(Error::InvalidProof),
            "{mode:?} {attack:?}"
        );
    }
}
