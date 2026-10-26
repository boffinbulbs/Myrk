use super::*;
use p3_matrix::Matrix;

pub(crate) fn fixture(x: u32, y: u32) -> (Witness, Statement) {
    let z = (u64::from(x) * u64::from(y) % u64::from(mul::MODULUS)) as u32;
    (
        Witness::for_operands(x, y).unwrap(),
        Statement::new(x, y, z, [0x81; 64]).unwrap(),
    )
}

#[test]
fn exact_dimensions_degree_and_corner_products() {
    let corners = [
        0,
        1,
        2,
        4095,
        4096,
        4097,
        mul::MODULUS - 2,
        mul::MODULUS - 1,
    ];
    for x in corners {
        for y in corners {
            let (w, s) = fixture(x, y);
            let t = trace(&w, &s);
            assert!(trace_is_valid(&t, &s), "{x} {y}");
            assert_eq!(t.width(), 211);
            assert_eq!(t.height(), 256);
            assert_eq!(public_values(&s).len(), 76);
        }
    }
    let layout = p3_air::symbolic::AirLayout {
        main_width: air::WIDTH,
        num_public_values: air::PUBLIC_VALUES,
        ..Default::default()
    };
    let degree = p3_air::symbolic::get_max_constraint_degree_extension::<BabyBear, Challenge, _>(
        &MultiplicationAir,
        layout,
        air::HEIGHT,
    );
    assert_eq!(degree, 2);
}

#[test]
fn canonical_naive_field_aliases_fail_the_bounded_integer_relation() {
    for (x, y, k, z) in [
        (0, 0, 240, 1_965_841),
        (8_380_416, 8_380_416, 8_380_174, 6_414_577),
    ] {
        let residual =
            i64::from(x) * i64::from(y) - i64::from(mul::MODULUS) * i64::from(k) - i64::from(z);
        assert_eq!(residual.abs(), 2_013_265_921);
        let low = |v: u32| i64::from(v & 4095);
        let high = |v: u32| i64::from(v >> 12);
        let c0 = (low(x) * low(y) - low(k) - low(z)) / 4096;
        let c1 =
            (low(x) * high(y) + high(x) * low(y) - 2046 * low(k) - high(k) - high(z) + c0) / 4096;
        let s = Statement::new(x, y, z, [0; 64]).unwrap();
        let t = air::trace_with_values([x, y, k, z], c0 as i32, c1 as i32);
        assert!(!trace_is_valid(&t, &s));
    }
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../research/arithmetic-proofs/multiplication_vectors.json"
    ))
    .unwrap()
}
fn reference_case(case: &serde_json::Value) -> (RowMajorMatrix<BabyBear>, Statement) {
    let p = &case["public"];
    let hex = p["context_hex"].as_str().unwrap();
    let context = core::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap());
    let s = Statement {
        x: p["x"].as_u64().unwrap() as u32,
        y: p["y"].as_u64().unwrap() as u32,
        z: p["z"].as_u64().unwrap() as u32,
        context,
    };
    let row: Vec<_> = case["witness"]["raw_bits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| BabyBear::from_u32(v.as_u64().unwrap() as u32))
        .collect();
    assert_eq!(row.len(), air::WIDTH);
    (RowMajorMatrix::new(row.repeat(air::HEIGHT), air::WIDTH), s)
}

#[test]
fn independent_integer_and_field_alias_vectors_match_the_actual_air() {
    use p3_field::PrimeField32;
    let data = vectors();
    for case in data["cases"].as_array().unwrap() {
        let (t, s) = reference_case(case);
        let p = public_values(&s);
        let expected: Vec<_> = case["public_values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(
            p.iter().map(|v| v.as_canonical_u32()).collect::<Vec<_>>(),
            expected,
            "{}",
            case["name"]
        );
        assert_eq!(
            s.validate().is_ok(),
            case["expected"]["statement_valid"].as_bool().unwrap()
        );
        let actual = check_all_constraints(&MultiplicationAir, &t, &p, Some(1)).is_ok();
        assert_eq!(
            actual,
            case["expected"]["valid_component"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

fn sample() -> &'static Vec<u8> {
    static PROOF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| {
        let (w, s) = fixture(mul::MODULUS - 1, mul::MODULUS - 1);
        prove_mod_mul(&w, &s).unwrap()
    })
}

#[test]
fn every_public_field_and_wrong_profile_are_bound_by_the_actual_verifier() {
    use p3_uni_stark::StarkGenericConfig;
    let (_, s) = fixture(mul::MODULUS - 1, mul::MODULUS - 1);
    verify_mod_mul(sample(), &s).unwrap();
    let proof: Proof<Config> = serde_json::from_slice(sample()).unwrap();
    let config = verifier_config();
    let p = public_values(&s);
    for index in 0..p.len() {
        let mut changed = p.clone();
        changed[index] += BabyBear::ONE;
        assert!(
            verify(&config, &MultiplicationAir, &proof, &changed).is_err(),
            "public field {index}"
        );
    }
    let wrong = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.arithmetic-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong, &MultiplicationAir, &proof, &p).is_err());
}

#[test]
fn canonical_statement_bounds_are_rechecked_before_decoding() {
    for v in [mul::MODULUS, mul::MODULUS + 1, u32::MAX] {
        assert!(matches!(
            Statement::new(v, 1, 1, [0; 64]),
            Err(Error::InvalidStatement)
        ));
        assert!(matches!(
            Statement::new(1, v, 1, [0; 64]),
            Err(Error::InvalidStatement)
        ));
        assert!(matches!(
            Statement::new(1, 1, v, [0; 64]),
            Err(Error::InvalidStatement)
        ));
        let (_, mut s) = fixture(1, 1);
        s.x = v;
        assert_eq!(verify_mod_mul(&[], &s), Err(Error::InvalidStatement));
    }
    assert!(matches!(
        Witness::for_operands(mul::MODULUS, 1),
        Err(Error::InvalidWitness)
    ));
    let (w, mut s) = fixture(3, 7);
    s.z += 1;
    assert_eq!(prove_mod_mul(&w, &s), Err(Error::InvalidWitness));
}

#[test]
fn fresh_real_proofs_randomize_the_reused_quotient_and_carries() {
    let (w, s) = fixture(mul::MODULUS - 1, mul::MODULUS - 1);
    let fresh = prove_mod_mul(&w, &s).unwrap();
    verify_mod_mul(&fresh, &s).unwrap();
    assert_ne!(sample(), &fresh);
    let a: serde_json::Value = serde_json::from_slice(sample()).unwrap();
    let b: serde_json::Value = serde_json::from_slice(&fresh).unwrap();
    assert_ne!(a["commitments"], b["commitments"]);
    for field in ["quotient", "carry0", "carry1", "witness"] {
        assert!(a.get(field).is_none());
    }
    for (x, y) in [(0, mul::MODULUS - 1), (4095, 4096)] {
        let (w, s) = fixture(x, y);
        verify_mod_mul(&prove_mod_mul(&w, &s).unwrap(), &s).unwrap();
    }
}

fn mutation(change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut p: serde_json::Value = serde_json::from_slice(sample()).unwrap();
    change(&mut p);
    let bytes = serde_json::to_vec(&p).unwrap();
    match serde_json::from_slice::<Proof<Config>>(&bytes) {
        Ok(p) => serde_json::to_vec(&p).unwrap(),
        Err(_) => bytes,
    }
}

#[test]
fn malformed_or_tampered_proof_transport_is_rejected() {
    use serde_json::json;
    let (_, s) = fixture(mul::MODULUS - 1, mul::MODULUS - 1);
    for bytes in [
        mutation(|p| p["degree_bits"] = json!(8)),
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
        assert!(verify_mod_mul(&bytes, &s).is_err());
    }
    let mut unknown: serde_json::Value = serde_json::from_slice(sample()).unwrap();
    unknown["ignored"] = json!(0);
    assert!(verify_mod_mul(&serde_json::to_vec(&unknown).unwrap(), &s).is_err());
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_mod_mul(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(verify_mod_mul(&trailing, &s), Err(Error::InvalidEncoding));
}

// These raw constructions bypass both the local witness precheck and, for the
// public integer alias, the typed statement validation. Backend rejection is
// checked separately from the public API's canonical statement rejection.
#[cfg(not(debug_assertions))]
#[test]
fn raw_false_integer_and_field_alias_proofs_fail_the_actual_verifier() {
    use crate::causal::Attack;
    for attack in [
        Attack::NegativeFieldAlias,
        Attack::PositiveFieldAlias,
        Attack::CarryFieldAlias,
        Attack::PublicIntegerAlias,
        Attack::NonbooleanOperand,
        Attack::QuotientAtModulus,
    ] {
        let (t, s) = crate::causal::attack_trace(attack);
        let p = public_values(&s);
        assert!(!check_all_constraints(&MultiplicationAir, &t, &p, Some(1)).is_ok());
        let proof = prove(&prover_config().unwrap(), &MultiplicationAir, t, &p)
            .expect("raw proof construction");
        validate_shape(&proof).expect("fixed profile shape");
        assert!(verify(&verifier_config(), &MultiplicationAir, &proof, &p).is_err());
        let bytes = serde_json::to_vec(&proof).unwrap();
        let expected = if s.validate().is_ok() {
            Error::InvalidProof
        } else {
            Error::InvalidStatement
        };
        assert_eq!(verify_mod_mul(&bytes, &s), Err(expected), "{attack:?}");
    }
    let data = vectors();
    let case = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str() == Some("field_limb_alias_+1_unbounded_carry"))
        .unwrap();
    let (t, s) = reference_case(case);
    let p = public_values(&s);
    assert!(
        case["expected"]["field_limb_equations_valid"]
            .as_bool()
            .unwrap()
    );
    assert!(!case["expected"]["carry_bits_valid"].as_bool().unwrap());
    assert!(!check_all_constraints(&MultiplicationAir, &t, &p, Some(1)).is_ok());
    let proof = prove(&prover_config().unwrap(), &MultiplicationAir, t, &p)
        .expect("raw proof construction");
    validate_shape(&proof).expect("fixed profile shape");
    let bytes = serde_json::to_vec(&proof).unwrap();
    assert_eq!(verify_mod_mul(&bytes, &s), Err(Error::InvalidProof));
}
