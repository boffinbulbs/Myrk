use super::super::*;
use super::*;
use p3_symmetric::CryptographicHasher;
use serde_json::{Value, json};

fn statement(r: u32, hint: u8, output: u8) -> Statement {
    Statement::new(r, hint, output, [0xA7; 64]).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    TieQuotient,
    RemainderBound,
    EdgeHigh,
    ZeroSign,
    QEdgeSign,
    OverflowWrap,
    OutputDetach,
    PublicIntegerAlias,
}
const FAULTS: [Fault; 8] = [
    Fault::TieQuotient,
    Fault::RemainderBound,
    Fault::EdgeHigh,
    Fault::ZeroSign,
    Fault::QEdgeSign,
    Fault::OverflowWrap,
    Fault::OutputDetach,
    Fault::PublicIntegerAlias,
];

fn attack(fault: Fault) -> (RowMajorMatrix<BabyBear>, Statement) {
    use proof_air::{bits, row_for_input};
    let mut s = match fault {
        Fault::TieQuotient => statement(GAMMA2, 1, 0),
        Fault::RemainderBound => statement(GAMMA2 + 1, 1, 1),
        Fault::EdgeHigh => statement(MODULUS - 1, 1, 0),
        Fault::ZeroSign => statement(0, 1, 1),
        Fault::QEdgeSign => statement(MODULUS - 1, 1, 1),
        Fault::OverflowWrap => statement(15 * ALPHA + 1, 1, 15),
        Fault::OutputDetach => statement(ALPHA, 0, 0),
        Fault::PublicIntegerAlias => statement(GAMMA2, 1, 1),
    };
    let mut row = row_for_input(s.r, s.hint);
    match fault {
        Fault::TieQuotient => {
            bits(&mut row, N, 1, 5);
            bits(&mut row, N_COMPLEMENT, 15, 5);
            row[U..U_COMPLEMENT].fill(BabyBear::ZERO);
            row[U] = -BabyBear::ONE;
            bits(&mut row, U_COMPLEMENT, i64::from(ALPHA), 19);
            bits(&mut row, HIGH, 1, 4);
            row[EDGE] = BabyBear::ZERO;
            row[POSITIVE] = BabyBear::ZERO;
            bits(&mut row, SIGN_SLACK, i64::from(GAMMA2), 18);
            row[BORROW] = BabyBear::ZERO;
            row[OVERFLOW] = BabyBear::ZERO;
            bits(&mut row, OUTPUT, 0, 4);
        }
        Fault::RemainderBound => {
            bits(&mut row, N, 0, 5);
            bits(&mut row, N_COMPLEMENT, 16, 5);
            bits(&mut row, U, i64::from(ALPHA), 19);
            bits(&mut row, U_COMPLEMENT, -1, 19);
            bits(&mut row, HIGH, 0, 4);
            row[POSITIVE] = BabyBear::ONE;
            bits(&mut row, SIGN_SLACK, i64::from(GAMMA2), 18);
            row[BORROW] = BabyBear::ZERO;
            row[OVERFLOW] = BabyBear::ZERO;
            bits(&mut row, OUTPUT, 1, 4);
        }
        Fault::EdgeHigh => {
            bits(&mut row, HIGH, 1, 4);
            row[BORROW] = BabyBear::ZERO;
            bits(&mut row, OUTPUT, 0, 4);
        }
        Fault::ZeroSign | Fault::QEdgeSign => {
            row[POSITIVE] = BabyBear::ONE;
            bits(&mut row, SIGN_SLACK, 0, 18);
            row[BORROW] = BabyBear::ZERO;
            bits(&mut row, OUTPUT, 1, 4);
        }
        Fault::OverflowWrap => {
            row[OVERFLOW] = BabyBear::ZERO;
            bits(&mut row, OUTPUT, 15, 4);
        }
        Fault::OutputDetach => {}
        Fault::PublicIntegerAlias => {
            s.r += 2_013_265_921;
        }
    }
    (RowMajorMatrix::new(row.repeat(HEIGHT), WIDTH), s)
}

#[test]
fn test_only_proof_profile_shape_and_honest_traces_are_fixed() {
    let layout = p3_air::symbolic::AirLayout {
        main_width: WIDTH,
        num_public_values: PUBLIC_VALUES,
        ..Default::default()
    };
    assert_eq!(
        p3_air::symbolic::get_max_constraint_degree::<BabyBear, _>(&ProofAir, layout, HEIGHT),
        2
    );
    assert_eq!(WIDTH, 125);
    assert_eq!(HEIGHT, 256);
    assert_eq!(PUBLIC_VALUES, 70);
    for (r, hint, output) in [
        (0, 0, 0),
        (0, 1, 15),
        (GAMMA2, 1, 1),
        (GAMMA2 + 1, 1, 0),
        (MODULUS - GAMMA2, 1, 15),
        (MODULUS - 1, 1, 15),
        (15 * ALPHA + 1, 1, 0),
    ] {
        let s = statement(r, hint, output);
        assert!(trace_is_valid(&trace(&s), &s));
    }
}

#[test]
fn all_eight_raw_false_statements_fail_constraints_without_host_validation() {
    for fault in FAULTS {
        let (trace, s) = attack(fault);
        assert!(
            !check_all_constraints(&ProofAir, &trace, &public_values(&s), Some(1)).is_ok(),
            "{fault:?}"
        );
        if !matches!(fault, Fault::PublicIntegerAlias) {
            assert!(s.validate().is_ok());
        }
    }
}

#[test]
fn expected_statement_bounds_and_preflight_reject_before_backend_work() {
    for (r, hint, out) in [
        (MODULUS, 0, 0),
        (u32::MAX, 0, 0),
        (0, 2, 0),
        (0, 255, 0),
        (0, 0, 16),
        (0, 0, 255),
    ] {
        let s = Statement {
            r,
            hint,
            output: out,
            context: [0; 64],
        };
        assert!(matches!(
            Statement::new(r, hint, out, [0; 64]),
            Err(Error::InvalidStatement)
        ));
        assert_eq!(verify_diagnostic(&[], &s), Err(Error::InvalidStatement));
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
}

#[test]
fn namespace_hash_adapters_match_independent_goldens() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../../../research/coefficient-constraints/hash_adapter_vectors.json"
    ))
    .unwrap();
    for vector in data["vectors"].as_array().unwrap() {
        let inputs: Vec<u64> = vector["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        let expected: Vec<u64> = vector["little_endian_u64_words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        let actual = match vector["domain_suffix"].as_str().unwrap() {
            "leaf.v1" => LeafHash.hash_iter(inputs.iter().map(|v| BabyBear::from_u32(*v as u32))),
            "node.v1" => NodeHash.hash_iter(inputs.iter().copied()),
            "transcript.v1" => {
                let bytes = TranscriptHash.hash_iter(inputs.iter().map(|v| *v as u8));
                core::array::from_fn(|i| {
                    u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap())
                })
            }
            _ => unreachable!(),
        };
        assert_eq!(actual.as_slice(), expected);
    }
}

fn sample() -> &'static Vec<u8> {
    static PROOF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| prove_diagnostic(&statement(MODULUS - 1, 1, 15)).unwrap())
}

#[test]
fn honest_proofs_round_trip_and_repeated_witnesses_randomize() {
    let s = statement(MODULUS - 1, 1, 15);
    verify_diagnostic(sample(), &s).unwrap();
    let fresh = prove_diagnostic(&s).unwrap();
    verify_diagnostic(&fresh, &s).unwrap();
    assert_ne!(sample(), &fresh);
    let first: Value = serde_json::from_slice(sample()).unwrap();
    let second: Value = serde_json::from_slice(&fresh).unwrap();
    assert_ne!(first["commitments"], second["commitments"]);
    for name in ["witness", "low", "high", "n", "u", "hint"] {
        assert!(first.get(name).is_none());
    }
    for s in [statement(GAMMA2, 1, 1), statement(15 * ALPHA + 1, 1, 0)] {
        verify_diagnostic(&prove_diagnostic(&s).unwrap(), &s).unwrap();
    }
}

#[test]
fn public_fields_profile_and_canonical_transport_are_bound() {
    use p3_uni_stark::StarkGenericConfig;
    let s = statement(MODULUS - 1, 1, 15);
    let proof: Proof<Config> = serde_json::from_slice(sample()).unwrap();
    validate_shape(&proof).unwrap();
    let public = public_values(&s);
    let config = verifier_config();
    for index in 0..public.len() {
        let mut changed = public.clone();
        changed[index] += BabyBear::ONE;
        assert!(
            verify(&config, &ProofAir, &proof, &changed).is_err(),
            "public value {index}"
        );
    }
    let wrong = Config::new(
        config.pcs().clone(),
        Challenger::new(HashChallenger::new(
            b"thorum.use-hint-proof-lab.wrong-profile.v1".to_vec(),
            TranscriptHash,
        )),
    );
    assert!(verify(&wrong, &ProofAir, &proof, &public).is_err());
    for change in 0..7 {
        let mut altered: Value = serde_json::from_slice(sample()).unwrap();
        match change {
            0 => altered["degree_bits"] = json!(8),
            1 => {
                altered["opened_values"]["trace_local"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            2 => altered["opened_values"]["trace_local"][0]["value"][0] = json!(1),
            3 => altered["opening_proof"][1]["query_pow_witness"] = json!(1),
            4 => altered["opening_proof"][1]["final_poly"][0]["value"][0] = json!(1),
            5 => altered["ignored"] = json!(0),
            6 => {
                altered["opened_values"]["quotient_chunks"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            _ => unreachable!(),
        }
        let mut bytes = serde_json::to_vec(&altered).unwrap();
        if change != 5
            && let Ok(decoded) = serde_json::from_slice::<Proof<Config>>(&bytes)
        {
            bytes = serde_json::to_vec(&decoded).unwrap();
        }
        assert!(
            verify_diagnostic(&bytes, &s).is_err(),
            "transport mutation {change}"
        );
    }
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_diagnostic(&sample()[..end], &s).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(
        verify_diagnostic(&trailing, &s),
        Err(Error::InvalidEncoding)
    );
}

#[cfg(not(debug_assertions))]
#[test]
fn eight_raw_false_proofs_bypass_local_checks_and_fail_verification() {
    for fault in FAULTS {
        let (trace, s) = attack(fault);
        let public = public_values(&s);
        let proof = prove(&prover_config().unwrap(), &ProofAir, trace, &public)
            .expect("raw construction bypassing host checks");
        validate_shape(&proof).unwrap();
        assert!(
            verify(&verifier_config(), &ProofAir, &proof, &public).is_err(),
            "raw backend {fault:?}"
        );
        let bytes = serde_json::to_vec(&proof).unwrap();
        let expected = if s.validate().is_ok() {
            Error::InvalidProof
        } else {
            Error::InvalidStatement
        };
        assert_eq!(
            verify_diagnostic(&bytes, &s),
            Err(expected),
            "closed wrapper {fault:?}"
        );
    }
}
