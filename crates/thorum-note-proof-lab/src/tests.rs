use super::*;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_matrix::Matrix;
use serde_json::{Value, json};
use sha3::{Digest, Sha3_512};
use std::{borrow::Borrow, sync::OnceLock};

fn fixture(amounts: [u64; 4], fee: u64) -> (Witness, Statement) {
    let mut statement = Statement {
        fee,
        chain: [7; 32],
        creation_versions: [1, 2, 3, 4],
        asset: [0; 32],
        commitments: [[0; 64]; 4],
        context: [9; 64],
    };
    let openings =
        core::array::from_fn(|note| sponge::opening_bytes(amounts[note], note, &statement));
    bind(&openings, &mut statement);
    (Witness::from_openings(openings), statement)
}

fn bind(openings: &[[u8; 418]; 4], statement: &mut Statement) {
    for (note, opening) in openings.iter().enumerate() {
        statement.commitments[note] = Sha3_512::digest(&sponge::padded(opening)[..464]).into();
    }
}

fn sample() -> &'static Vec<u8> {
    static PROOF: OnceLock<Vec<u8>> = OnceLock::new();
    PROOF.get_or_init(|| {
        let (witness, statement) = fixture([50, 50, 60, 39], 1);
        prove_note_conservation(&witness, &statement).unwrap()
    })
}

fn digest_from_trace(trace: &RowMajorMatrix<BabyBear>, note: usize) -> [u8; 64] {
    let row = trace.row_slice(note * 168 + 167).unwrap();
    let keccak: &KeccakCols<BabyBear> = row[..NUM_KECCAK_COLS].borrow();
    let mut bytes = [0; 64];
    for limb in 0..32 {
        bytes[limb * 2..limb * 2 + 2].copy_from_slice(
            &(keccak
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .as_canonical_u32() as u16)
                .to_le_bytes(),
        );
    }
    bytes
}

#[test]
fn all_four_actual_note_commitments_are_linked_to_checked_integer_amounts() {
    let (_, statement) = fixture([50, 50, 60, 39], 1);
    verify_note_conservation(sample(), &statement).unwrap();
    let (witness, statement) = fixture([u64::MAX - 1000, 0, u64::MAX - 1002, 1], 1);
    let proof = prove_note_conservation(&witness, &statement).unwrap();
    verify_note_conservation(&proof, &statement).unwrap();
}

#[test]
fn raw_sponge_output_matches_the_exact_canonical_sha3_digest() {
    let layout = p3_air::symbolic::AirLayout {
        main_width: sponge::WIDTH,
        num_public_values: sponge::PUBLIC_VALUES,
        ..Default::default()
    };
    assert_eq!(
        p3_air::symbolic::get_max_constraint_degree_extension::<BabyBear, Challenge, _>(
            &NoteConservationAir,
            layout,
            sponge::HEIGHT
        ),
        4
    );
    let (witness, statement) = fixture([50, 50, 60, 39], 1);
    let trace = trace(&witness.openings, &statement);
    assert!(trace_is_valid(&trace, &statement));
    for note in 0..4 {
        assert_eq!(digest_from_trace(&trace, note), statement.commitments[note]);
    }
    assert_eq!(sponge::WIDTH, 4262);
    assert_eq!(sponge::HEIGHT, 1024);
    assert_eq!(sponge::public_values(&statement).len(), 464);
}

fn invalid_corpus() -> Vec<(&'static str, RowMajorMatrix<BabyBear>, Statement)> {
    let mut result = Vec::new();
    for (name, amounts, fee) in [
        ("inflation", [50, 50, 60, 40], 1),
        ("modulus alias", [2_013_265_921, 0, 0, 0], 0),
        ("equal overflow", [u64::MAX, 1, u64::MAX, 1], 0),
        ("fee overflow", [u64::MAX, 0, u64::MAX, 0], u64::MAX),
    ] {
        let (witness, statement) = fixture(amounts, fee);
        result.push((name, trace(&witness.openings, &statement), statement));
    }
    // These altered messages have matching SHA3 digests. Only canonical encoding
    // or public field consistency makes their AIR traces invalid.
    for (name, index) in [
        ("zero length byte", 0),
        ("encoding version", 43),
        ("policy tag", 417),
        ("chain", 49),
        ("creation version", 85),
        ("asset", 93),
    ] {
        let (mut witness, mut statement) = fixture([50, 50, 60, 39], 1);
        witness.openings[0][index] ^= 1;
        bind(&witness.openings, &mut statement);
        result.push((name, trace(&witness.openings, &statement), statement));
    }
    for (name, overrides) in [
        ("initial rate", vec![(0, 0, 1)]),
        ("initial capacity", vec![(0, 9, 1)]),
        ("first capacity continuity", vec![(1, 9, 1)]),
        ("first rate continuity", vec![(1, 0, 1)]),
        ("last capacity continuity", vec![(6, 24, 1)]),
        ("last rate continuity", vec![(6, 8, 1)]),
    ] {
        let (witness, mut statement) = fixture([50, 50, 60, 39], 1);
        let messages = witness.openings.map(|opening| sponge::padded(&opening));
        let trace =
            sponge::trace_with_messages(&witness.openings, &statement, &messages, &overrides);
        statement.commitments[0] = digest_from_trace(&trace, 0);
        assert!(keccak_only_is_valid(&trace), "{name}");
        result.push((name, trace, statement));
    }
    for (name, index) in [
        ("SHA3 suffix", 464),
        ("padding zero", 465),
        ("padding terminator", 503),
    ] {
        let (witness, mut statement) = fixture([50, 50, 60, 39], 1);
        let mut messages = witness.openings.map(|opening| sponge::padded(&opening));
        messages[0][index] ^= 1;
        let trace = sponge::trace_with_messages(&witness.openings, &statement, &messages, &[]);
        statement.commitments[0] = digest_from_trace(&trace, 0);
        assert!(keccak_only_is_valid(&trace), "{name}");
        result.push((name, trace, statement));
    }
    let (witness, statement) = fixture([50, 50, 60, 39], 1);
    let valid = trace(&witness.openings, &statement);
    // The replacement integer witness remains balanced and constant. Only its
    // connection to the amount bytes inside the four commitments is broken.
    let (other_witness, _) = fixture([51, 49, 60, 39], 1);
    let other = trace(&other_witness.openings, &statement);
    let mut disconnected = valid.clone();
    for row in 0..sponge::HEIGHT {
        disconnected.values[row * sponge::WIDTH + sponge::AMOUNTS..(row + 1) * sponge::WIDTH]
            .copy_from_slice(
                &other.values[row * sponge::WIDTH + sponge::AMOUNTS..(row + 1) * sponge::WIDTH],
            );
    }
    result.push(("balanced amount disconnection", disconnected, statement));
    for (name, row, column, value) in [
        ("amount binding", 0, sponge::AMOUNTS, 1),
        ("schedule", 0, sponge::SELECTORS, 0),
        ("nonboolean amount", 0, sponge::AMOUNTS, 2),
        ("nonboolean message", 0, sponge::MESSAGE, 2),
        ("nonboolean output", 23, sponge::OUTPUT, 2),
        ("integer constancy", 1, sponge::SUM, 1),
        ("input final carry", 0, sponge::INPUT_CARRY + 63, 1),
        ("output final carry", 0, sponge::OUTPUT_CARRY + 63, 1),
    ] {
        let mut changed = valid.clone();
        changed.values[row * sponge::WIDTH + column] = BabyBear::from_u8(value);
        result.push((name, changed, statement));
    }
    result
}

fn keccak_only_is_valid(trace: &RowMajorMatrix<BabyBear>) -> bool {
    let values = trace
        .values
        .chunks_exact(sponge::WIDTH)
        .flat_map(|row| row[..NUM_KECCAK_COLS].iter().copied())
        .collect();
    check_all_constraints(
        &p3_keccak_air::KeccakAir {},
        &RowMajorMatrix::new(values, NUM_KECCAK_COLS),
        &[],
        Some(1),
    )
    .is_ok()
}

#[test]
fn malformed_hash_schedules_encodings_and_integer_witnesses_fail_air_constraints() {
    for (name, trace, statement) in invalid_corpus() {
        assert!(!trace_is_valid(&trace, &statement), "{name}");
    }
    let (witness, statement) = fixture([50, 50, 60, 40], 1);
    assert_eq!(
        prove_note_conservation(&witness, &statement),
        Err(Error::InvalidWitness)
    );
}

#[test]
fn every_statement_field_is_bound_and_duplicate_inputs_are_rejected() {
    let (_, statement) = fixture([50, 50, 60, 39], 1);
    let mut changed = statement;
    changed.fee ^= 1;
    assert_eq!(
        verify_note_conservation(sample(), &changed),
        Err(Error::InvalidProof)
    );
    for index in [0, 31] {
        changed = statement;
        changed.chain[index] ^= 1;
        assert_eq!(
            verify_note_conservation(sample(), &changed),
            Err(Error::InvalidProof)
        );
        changed = statement;
        changed.asset[index] ^= 1;
        assert_eq!(
            verify_note_conservation(sample(), &changed),
            Err(Error::InvalidProof)
        );
    }
    for note in 0..4 {
        changed = statement;
        changed.creation_versions[note] ^= 1;
        assert_eq!(
            verify_note_conservation(sample(), &changed),
            Err(Error::InvalidProof)
        );
        for byte in [0, 63] {
            changed = statement;
            changed.commitments[note][byte] ^= 1;
            assert_eq!(
                verify_note_conservation(sample(), &changed),
                Err(Error::InvalidProof)
            );
        }
    }
    for byte in [0, 63] {
        changed = statement;
        changed.context[byte] ^= 1;
        assert_eq!(
            verify_note_conservation(sample(), &changed),
            Err(Error::InvalidProof)
        );
    }
    let (witness, mut changed) = fixture([50, 50, 60, 39], 1);
    changed.commitments[1] = changed.commitments[0];
    assert_eq!(
        prove_note_conservation(&witness, &changed),
        Err(Error::DuplicateInput)
    );
    assert_eq!(
        verify_note_conservation(&[], &changed),
        Err(Error::DuplicateInput)
    );
}

fn mutation(change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut proof: Value = serde_json::from_slice(sample()).unwrap();
    change(&mut proof);
    let bytes = serde_json::to_vec(&proof).unwrap();
    match serde_json::from_slice::<Proof<Config>>(&bytes) {
        Ok(proof) => serde_json::to_vec(&proof).unwrap(),
        Err(_) => bytes,
    }
}

#[test]
fn malformed_and_tampered_transport_is_rejected_before_acceptance() {
    let (_, statement) = fixture([50, 50, 60, 39], 1);
    for bytes in [
        mutation(|p| p["degree_bits"] = json!(9)),
        mutation(|p| p["commitments"]["trace"]["cap"][0][0] = json!(1)),
        mutation(|p| p["opened_values"]["trace_local"][0]["value"][0] = json!(1)),
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
        assert!(verify_note_conservation(&bytes, &statement).is_err());
    }
    let mut unknown: Value = serde_json::from_slice(sample()).unwrap();
    unknown["ignored_field"] = json!(0);
    assert!(verify_note_conservation(&serde_json::to_vec(&unknown).unwrap(), &statement).is_err());
    for end in [0, 1, 10, sample().len() / 2, sample().len() - 1] {
        assert!(verify_note_conservation(&sample()[..end], &statement).is_err());
    }
    let mut trailing = sample().clone();
    trailing.push(b' ');
    assert_eq!(
        verify_note_conservation(&trailing, &statement),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn repeated_real_proofs_use_fresh_hiding_commitments() {
    let (witness, statement) = fixture([50, 50, 60, 39], 1);
    let proof = prove_note_conservation(&witness, &statement).unwrap();
    assert_ne!(sample(), &proof);
    let left: Value = serde_json::from_slice(sample()).unwrap();
    let right: Value = serde_json::from_slice(&proof).unwrap();
    assert_ne!(left["commitments"], right["commitments"]);
    assert!(left.get("openings").is_none());
    assert!(left.get("amounts").is_none());
    verify_note_conservation(&proof, &statement).unwrap();
}

// Release mode bypasses wrapper validation and upstream debug assertions. These
// are real invalid proof constructions followed by actual verifier rejection.
#[cfg(not(debug_assertions))]
#[test]
fn raw_invalid_proofs_fail_the_real_verifier() {
    for (name, trace, statement) in invalid_corpus() {
        let proof = prove(
            &prover_config().unwrap(),
            &NoteConservationAir,
            trace,
            &public_values(&statement),
        )
        .expect("raw proof construction");
        validate_shape(&proof).expect("fixed profile shape");
        let bytes = serde_json::to_vec(&proof).unwrap();
        assert_eq!(
            verify_note_conservation(&bytes, &statement),
            Err(Error::InvalidProof),
            "{name}"
        );
    }
}
