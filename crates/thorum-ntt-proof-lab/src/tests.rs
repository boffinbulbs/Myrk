use super::*;
use p3_matrix::Matrix;
use serde_json::Value;

pub(crate) fn fixture(mode: Mode, input: [u32; 256]) -> (Witness, Statement) {
    let rows = ntt::rows_for_input(input, mode);
    let output = rows.last().unwrap().polynomial;
    (
        Witness::from_input(input).unwrap(),
        Statement::new(mode, input, output, [0x82; 64]).unwrap(),
    )
}
fn power(mut x: u64, mut e: u64) -> u32 {
    let mut r = 1u64;
    let q = u64::from(mul::MODULUS);
    while e != 0 {
        if e & 1 != 0 {
            r = r * x % q;
        }
        x = x * x % q;
        e >>= 1;
    }
    r as u32
}
fn direct_forward(input: &[u32; 256]) -> [u32; 256] {
    let q = u64::from(mul::MODULUS);
    core::array::from_fn(|i| {
        let root = power(1753, 2 * u64::from((i as u8).reverse_bits()) + 1);
        input.iter().rev().fold(0u64, |value, c| {
            (value * u64::from(root) + u64::from(*c)) % q
        }) as u32
    })
}

#[test]
fn exact_dimensions_degree_and_direct_negacyclic_evaluations() {
    let input =
        core::array::from_fn(|i| ((i as u64 * 81_731 + 9001) % u64::from(mul::MODULUS)) as u32);
    let (w, s) = fixture(Mode::Forward, input);
    assert_eq!(s.output, direct_forward(&input));
    let t = trace(&w, &s);
    assert!(trace_is_valid(&t, &s));
    assert_eq!(t.width(), 39051);
    assert_eq!(t.height(), 256);
    assert_eq!(public_values(&s).len(), 2113);
    let (inverse_w, inverse_s) = fixture(Mode::Inverse, s.output);
    assert_eq!(inverse_s.output, input);
    assert!(trace_is_valid(&trace(&inverse_w, &inverse_s), &inverse_s));
    for s in [s, inverse_s] {
        let layout = p3_air::symbolic::AirLayout {
            main_width: air::WIDTH,
            num_public_values: air::PUBLIC_VALUES,
            ..Default::default()
        };
        let degree = p3_air::symbolic::get_max_constraint_degree_extension::<BabyBear, Challenge, _>(
            &NttAir::new(&s),
            layout,
            air::HEIGHT,
        );
        assert_eq!(degree, 2);
    }
}

pub(crate) fn reference_case(case: &Value) -> (Witness, Statement) {
    let p = &case["public"];
    let mode = match p["mode"].as_u64().unwrap() {
        1 => Mode::Forward,
        2 => Mode::Inverse,
        _ => panic!("fixture mode"),
    };
    let input = core::array::from_fn(|i| p["input"][i].as_u64().unwrap() as u32);
    let output = core::array::from_fn(|i| p["output"][i].as_u64().unwrap() as u32);
    let hex = p["context_hex"].as_str().unwrap();
    let context = core::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap());
    (
        Witness::from_input(input).unwrap(),
        Statement::new(mode, input, output, context).unwrap(),
    )
}

#[test]
fn independent_full_transform_vectors_and_public_values_match() {
    use p3_field::PrimeField32;
    let data: Value = serde_json::from_str(include_str!(
        "../../../research/ntt-proofs/ntt_vectors.json"
    ))
    .unwrap();
    for case in data["cases"].as_array().unwrap() {
        let (w, s) = reference_case(case);
        let actual = public_values(&s)
            .iter()
            .map(|v| v.as_canonical_u32())
            .collect::<Vec<_>>();
        let expected = case["public_values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{}", case["name"]);
        assert_eq!(
            trace_is_valid(&trace(&w, &s), &s),
            case["expected"]["valid_component"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

fn sample_input() -> [u32; 256] {
    core::array::from_fn(|i| i as u32)
}

#[test]
fn independent_stage_states_and_integer_auxiliaries_match() {
    let cases: Value = serde_json::from_str(include_str!(
        "../../../research/ntt-proofs/ntt_vectors.json"
    ))
    .unwrap();
    let stages: Value = serde_json::from_str(include_str!(
        "../../../research/ntt-proofs/stage_vectors.json"
    ))
    .unwrap();
    let mut honest = std::collections::BTreeMap::new();
    let mut states_checked = 0;
    for case in cases["cases"].as_array().unwrap() {
        if case["expected"]["valid_component"] != true {
            continue;
        }
        let (w, s) = reference_case(case);
        let rows = ntt::rows(&w, &s);
        let name = case["name"].as_str().unwrap();
        let independent = stages["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == name)
            .unwrap();
        assert_eq!(rows.len(), independent["states"].as_array().unwrap().len());
        for (row, expected) in rows.iter().zip(independent["states"].as_array().unwrap()) {
            for (actual, value) in row.polynomial.iter().zip(expected.as_array().unwrap()) {
                assert_eq!(u64::from(*actual), value.as_u64().unwrap(), "{name}");
            }
            states_checked += 1;
        }
        honest.insert(name.to_owned(), rows);
    }
    assert_eq!(honest.len(), 31);
    assert_eq!(states_checked, 309);
    let mut products_checked = 0;
    for line in include_str!("../../../research/ntt-proofs/butterfly_operations.csv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = line.split(',').collect();
        let Some(rows) = honest.get(fields[0]) else {
            continue;
        };
        let stage: usize = fields[1].parse().unwrap();
        let slot: usize = fields[3].parse().unwrap();
        let row = &rows[stage];
        let product = row.products[slot];
        for (actual, expected) in product.values.into_iter().zip(&fields[12..16]) {
            assert_eq!(
                actual,
                expected.parse::<u32>().unwrap(),
                "{} {stage} {slot}",
                fields[0]
            );
        }
        assert_eq!(product.carry0, fields[16].parse::<i32>().unwrap());
        assert_eq!(product.carry1, fields[17].parse::<i32>().unwrap());
        assert_eq!(
            u8::from(row.carries[slot][0]),
            fields[18].parse::<u8>().unwrap()
        );
        assert_eq!(
            u8::from(row.carries[slot][1]),
            fields[19].parse::<u8>().unwrap()
        );
        products_checked += 1;
    }
    assert_eq!(products_checked, 35_584);
}

#[test]
fn independent_hash_adapters_match_full_digest_words() {
    use p3_symmetric::CryptographicHasher;
    let leaf = LeafHash.hash_iter([0, 1, 0x7800_0000, 0x1234_5678].map(BabyBear::from_u32));
    let node = NodeHash.hash_iter([0, 1, u64::MAX].into_iter().chain(0..13));
    let transcript = TranscriptHash.hash_iter(0..64);
    let transcript_words: [u64; 8] = core::array::from_fn(|i| {
        u64::from_le_bytes(transcript[i * 8..i * 8 + 8].try_into().unwrap())
    });
    let actual = [leaf, node, transcript_words];
    for (digest, line) in actual.iter().zip(
        include_str!("../../../research/ntt-proofs/hash_vectors.csv")
            .lines()
            .skip(1),
    ) {
        let expected: Vec<u64> = line
            .split(',')
            .nth(3)
            .unwrap()
            .split(':')
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(digest.as_slice(), expected);
    }
}
fn sample() -> &'static Vec<u8> {
    static PROOF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| {
        let (w, s) = fixture(Mode::Forward, sample_input());
        prove_ntt(&w, &s).unwrap()
    })
}

#[test]
fn real_proofs_cover_both_modes_and_randomize_the_same_input() {
    let (w, s) = fixture(Mode::Forward, sample_input());
    let fresh = prove_ntt(&w, &s).unwrap();
    verify_ntt(&fresh, &s).unwrap();
    assert_ne!(sample(), &fresh);
    let a: Proof<Config> = serde_json::from_slice(sample()).unwrap();
    let b: Proof<Config> = serde_json::from_slice(&fresh).unwrap();
    assert_ne!(
        serde_json::to_vec(&a.commitments).unwrap(),
        serde_json::to_vec(&b.commitments).unwrap()
    );
    let (w, s) = fixture(Mode::Inverse, s.output);
    assert_eq!(s.output, sample_input());
    let proof = prove_ntt(&w, &s).unwrap();
    verify_ntt(&proof, &s).unwrap();
}

#[test]
fn public_coefficient_boundaries_mode_context_and_profile_are_bound() {
    use p3_uni_stark::StarkGenericConfig;
    let (_, s) = fixture(Mode::Forward, sample_input());
    verify_ntt(sample(), &s).unwrap();
    let proof: Proof<Config> = serde_json::from_slice(sample()).unwrap();
    let config = verifier_config();
    let air = NttAir::new(&s);
    let honest = public_values(&s);
    let mut indices = vec![0, 2049, 2080, 2112];
    for base in [1, 1025] {
        for coefficient in [0, 1, 127, 128, 254, 255] {
            for byte in 0..4 {
                indices.push(base + coefficient * 4 + byte);
            }
        }
    }
    for index in indices {
        let mut changed = honest.clone();
        changed[index] += BabyBear::ONE;
        assert!(
            verify(&config, &air, &proof, &changed).is_err(),
            "public field {index}"
        );
    }
    let mut changed = s;
    changed.mode = Mode::Inverse;
    assert_eq!(verify_ntt(sample(), &changed), Err(Error::InvalidProof));
    let wrong = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.ntt-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong, &air, &proof, &honest).is_err());
}

#[test]
fn canonical_polynomial_bounds_are_rechecked_before_decoding() {
    for mode in [Mode::Forward, Mode::Inverse] {
        for coefficient in [0, 127, 128, 255] {
            let (_, s) = fixture(mode, sample_input());
            let mut changed = s;
            changed.input[coefficient] = mul::MODULUS;
            assert_eq!(verify_ntt(&[], &changed), Err(Error::InvalidStatement));
            assert!(matches!(
                Statement::new(mode, changed.input, s.output, s.context),
                Err(Error::InvalidStatement)
            ));
            assert!(matches!(
                Witness::from_input(changed.input),
                Err(Error::InvalidWitness)
            ));
            changed = s;
            changed.output[coefficient] = u32::MAX;
            assert_eq!(verify_ntt(&[], &changed), Err(Error::InvalidStatement));
        }
    }
    let (w, mut s) = fixture(Mode::Forward, sample_input());
    s.output[17] += 1;
    assert_eq!(prove_ntt(&w, &s), Err(Error::InvalidWitness));
}

fn mutation(change: fn(&mut Value)) -> Vec<u8> {
    let mut p: Value = serde_json::from_slice(sample()).unwrap();
    change(&mut p);
    let bytes = serde_json::to_vec(&p).unwrap();
    match serde_json::from_slice::<Proof<Config>>(&bytes) {
        Ok(p) => serde_json::to_vec(&p).unwrap(),
        Err(_) => bytes,
    }
}

#[test]
fn bounded_canonical_transport_rejects_shape_and_proof_corruption() {
    use serde_json::json;
    let (_, s) = fixture(Mode::Forward, sample_input());
    let changes: [fn(&mut Value); 7] = [
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
        |p| p["opening_proof"][0][0][0][0][0]["value"][0] = json!(1),
        |p| p["opening_proof"][1]["query_pow_witness"] = json!(1),
        |p| p["opening_proof"][1]["final_poly"][0]["value"][0] = json!(1),
    ];
    for change in changes {
        assert!(verify_ntt(&mutation(change), &s).is_err());
    }
    for bytes in [
        vec![b'['; 25],
        vec![b'0'; 21],
        vec![0xff; 100],
        vec![b' '; MAX_PROOF_BYTES + 1],
        format!("[{}]", "0,".repeat(MAX_JSON_ITEMS)).into_bytes(),
        format!("\"{}\"", "a".repeat(65)).into_bytes(),
    ] {
        assert!(verify_ntt(&bytes, &s).is_err());
    }
    let mut unknown: Value = serde_json::from_slice(sample()).unwrap();
    unknown["ignored"] = json!(0);
    assert!(verify_ntt(&serde_json::to_vec(&unknown).unwrap(), &s).is_err());
    drop(unknown);
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_ntt(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(verify_ntt(&trailing, &s), Err(Error::InvalidEncoding));
}

// Each raw trace retains canonical, exact integer modular products and a
// matching public final polynomial. The required transform dataflow is false.
// The local witness precheck is deliberately bypassed during raw proving.
#[cfg(not(debug_assertions))]
#[test]
fn raw_locally_correct_but_detached_transform_proofs_are_rejected() {
    use crate::causal::Attack;
    for (mode, attack) in [
        (Mode::Forward, Attack::WrongTwiddle),
        (Mode::Forward, Attack::DetachedMultiplicand),
        (Mode::Forward, Attack::SkippedStageProgramCounter),
        (Mode::Inverse, Attack::OmittedNormalization),
        (Mode::Inverse, Attack::FirstHalfCopy),
        (Mode::Inverse, Attack::SecondHalfCopy),
        (Mode::Forward, Attack::DetachedFinalState),
    ] {
        let (t, s) = crate::causal::attack_trace(mode, attack);
        assert!(!trace_is_valid(&t, &s));
        let proof = prove(
            &prover_config().unwrap(),
            &NttAir::new(&s),
            t,
            &public_values(&s),
        )
        .expect("raw proof construction");
        validate_shape(&proof).expect("fixed profile shape");
        let bytes = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_ntt(&bytes, &s),
            Err(Error::InvalidProof),
            "{mode:?} {attack:?}"
        );
    }
}
