use super::*;
use air::*;
use p3_field::PrimeCharacteristicRing;
use serde_json::{Value, json};
use std::sync::OnceLock;

fn statement() -> Statement {
    Statement {
        fee: 3,
        context: [0x42; 64],
    }
}

fn sample() -> &'static Vec<u8> {
    static PROOF: OnceLock<Vec<u8>> = OnceLock::new();
    PROOF.get_or_init(|| prove_conservation([9, 0, 3, 3], &statement()).unwrap())
}

#[test]
fn checked_integer_boundary_cases_have_real_valid_hiding_proofs() {
    for (amounts, fee) in [
        ([0, 0, 0, 0], 0),
        ([9, 0, 3, 3], 3), // Output carry reaches two after bit one.
        ([u64::MAX, 0, 0, 0], u64::MAX),
        ([u64::MAX - 1, 1, u64::MAX, 0], 0),
    ] {
        let statement = Statement {
            fee,
            context: [7; 64],
        };
        let proof = prove_conservation(amounts, &statement).unwrap();
        verify_conservation(&proof, &statement).unwrap();
    }
}

fn invalid_integer_traces() -> Vec<RowMajorMatrix<BabyBear>> {
    vec![
        trace([10, 0, 3, 3], 3),
        trace([2_013_265_921, 0, 0, 0], 0), // BabyBear modulus, not integer zero.
        trace([u64::MAX, u64::MAX, u64::MAX, u64::MAX], 0),
        trace([u64::MAX, 0, u64::MAX, 1], u64::MAX),
    ]
}

fn invalid_cell_traces() -> Vec<RowMajorMatrix<BabyBear>> {
    let valid = trace([9, 0, 3, 3], 3);
    // Each tuple changes one independently checked schedule, range, repeat or
    // boundary condition. The final arithmetic remains active on row255.
    [
        (0, CARRY_A, 1),
        (0, CARRY_B, 1),
        (255, NEXT_A, 1),
        (255, NEXT_B, 1),
        (255, A0, 1),
        (5, A0, 1),
        (4, CARRY_A, 1),
        (10, PHASE, 1),
        (20, SELECTOR, 1),
        (8, A0, 2),
        (8, SUM, 2),
        (8, CARRY_A, 2),
        (8, CARRY_B, 3),
    ]
    .into_iter()
    .map(|(row, column, value)| {
        let mut changed = valid.clone();
        changed.values[row * WIDTH + column] = BabyBear::from_u64(value);
        changed
    })
    .collect()
}

#[test]
fn incorrect_integer_witnesses_and_targeted_cells_fail_air_constraints() {
    let mut invalid = invalid_cell_traces();
    // The integer corpus uses a different public fee per case.
    for (index, trace) in invalid_integer_traces().into_iter().enumerate() {
        let fee = [3, 0, 0, u64::MAX][index];
        assert!(!trace_is_valid(
            &trace,
            &Statement {
                fee,
                context: [0; 64]
            }
        ));
    }
    for trace in invalid.drain(..) {
        assert!(!trace_is_valid(&trace, &statement()));
    }
    assert_eq!(
        prove_conservation([10, 0, 3, 3], &statement()),
        Err(Error::InvalidWitness)
    );
}

#[test]
fn every_context_byte_and_each_fee_bit_are_bound_to_the_serialized_proof() {
    verify_conservation(sample(), &statement()).unwrap();
    for index in 0..64 {
        let mut changed = statement();
        changed.context[index] ^= 1;
        assert_eq!(
            verify_conservation(sample(), &changed),
            Err(Error::InvalidProof)
        );
    }
    for bit in 0..64 {
        let mut changed = statement();
        changed.fee ^= 1u64 << bit;
        assert_eq!(
            verify_conservation(sample(), &changed),
            Err(Error::InvalidProof)
        );
    }
}

fn serialized_mutation(change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut proof: Value = serde_json::from_slice(sample()).unwrap();
    change(&mut proof);
    // Value maps have different ordering from struct serialization. Decode the
    // edited object and reencode its exact typed field order when well shaped.
    let bytes = serde_json::to_vec(&proof).unwrap();
    if let Ok(proof) = serde_json::from_slice::<Proof<Config>>(&bytes) {
        serde_json::to_vec(&proof).unwrap()
    } else {
        bytes
    }
}

#[test]
fn tampered_commitments_openings_masks_and_fixed_dimensions_are_rejected() {
    type Mutation = Box<dyn FnOnce(&mut Value)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|p| p["commitments"]["trace"]["cap"][0][0] = json!(1)),
        Box::new(|p| p["opened_values"]["trace_local"][0]["value"][0] = json!(1)),
        Box::new(|p| p["opening_proof"][0][0][0][0][0]["value"][0] = json!(1)),
        Box::new(|p| p["opening_proof"][1]["final_poly"][0]["value"][0] = json!(1)),
        Box::new(|p| p["degree_bits"] = json!(10)),
        Box::new(|p| p["degree_bits"] = json!(0)),
        Box::new(|p| p["degree_bits"] = json!(u64::MAX)),
        Box::new(|p| p["ood_pow_witness"] = json!(1)),
        Box::new(|p| p["opening_proof"][1]["query_pow_witness"] = json!(1)),
        Box::new(|p| {
            p["opened_values"]["trace_local"]
                .as_array_mut()
                .unwrap()
                .pop()
                .map(|_| ())
                .unwrap()
        }),
        Box::new(|p| {
            p["opening_proof"][1]["input_openings"][1]["opened_values"][0][0]
                .as_array_mut()
                .unwrap()
                .push(json!(0))
        }),
        Box::new(|p| {
            p["opening_proof"][1]["commit_phase_openings"][0]["opening_proof"][0][0][0]
                .as_array_mut()
                .unwrap()
                .pop()
                .map(|_| ())
                .unwrap()
        }),
    ];
    for mutate in mutations {
        assert!(verify_conservation(&serialized_mutation(mutate), &statement()).is_err());
    }
}

#[test]
fn transport_is_canonical_bounded_and_rejects_declared_length_style_inputs() {
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_conservation(&sample()[..end], &statement()).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(
        verify_conservation(&trailing, &statement()),
        Err(Error::InvalidEncoding)
    );
    let mut unknown: Value = serde_json::from_slice(sample()).unwrap();
    unknown["ignored_field"] = json!(0);
    assert!(verify_conservation(&serde_json::to_vec(&unknown).unwrap(), &statement()).is_err());
    for bytes in [
        vec![b'['; 25],
        vec![b'0'; 21],
        vec![0xff; 100],
        vec![b' '; MAX_PROOF_BYTES + 1],
        format!("[{}]", "0,".repeat(MAX_JSON_ITEMS)).into_bytes(),
        format!("\"{}\"", "a".repeat(65)).into_bytes(),
    ] {
        assert!(verify_conservation(&bytes, &statement()).is_err());
    }
}

#[test]
fn repeated_proofs_use_fresh_masks_and_salts_without_witness_transport() {
    let another = prove_conservation([9, 0, 3, 3], &statement()).unwrap();
    assert_ne!(&another, sample());
    let first: Value = serde_json::from_slice(sample()).unwrap();
    let second: Value = serde_json::from_slice(&another).unwrap();
    assert_ne!(first["commitments"], second["commitments"]);
    assert!(first.get("amounts").is_none());
    assert!(first.get("trace").is_none());
    verify_conservation(&another, &statement()).unwrap();
}

// This bypasses both wrapper preflight and upstream debug constraints. Its
// successful proving followed by real verifier rejection is distinct evidence
// from the local constraint checks above.
#[cfg(not(debug_assertions))]
#[test]
fn raw_invalid_traces_produce_proofs_that_the_real_verifier_rejects() {
    let corpus = invalid_integer_traces()
        .into_iter()
        .enumerate()
        .map(|(index, trace)| {
            (
                trace,
                Statement {
                    fee: [3, 0, 0, u64::MAX][index],
                    context: [0; 64],
                },
            )
        })
        .chain(
            invalid_cell_traces()
                .into_iter()
                .map(|trace| (trace, statement())),
        );
    for (index, (trace, statement)) in corpus.enumerate() {
        let config = prover_config().unwrap();
        let proof = prove(
            &config,
            &ConservationAir,
            trace,
            &public_values(statement.fee, &statement.context),
        )
        .expect("raw invalid proof construction");
        validate_shape(&proof).expect("raw proof retains fixed shape");
        let bytes = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_conservation(&bytes, &statement),
            Err(Error::InvalidProof),
            "raw case {index}"
        );
    }
}
