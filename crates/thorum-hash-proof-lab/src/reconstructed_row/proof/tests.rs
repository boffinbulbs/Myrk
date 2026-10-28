use super::*;
use p3_field::BasedVectorSpace;
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
use p3_symmetric::{CryptographicHasher, MerkleCap};
use p3_uni_stark::{Commitments, OpenedValues};

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}
fn fixture() -> (Witness, Statement) {
    let d: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../research/reconstructed-row/vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let input = &d["cases"][0]["input"];
    let w = Witness::from_inputs(
        bytes(input["rho_hex"].as_str().unwrap()),
        core::array::from_fn(|c| {
            core::array::from_fn(|i| input["zhat"][c][i].as_u64().unwrap() as u32)
        }),
        core::array::from_fn(|i| input["t1"][i].as_u64().unwrap() as u16),
        core::array::from_fn(|i| input["chat"][i].as_u64().unwrap() as u32),
        core::array::from_fn(|i| input["hint"][i].as_u64().unwrap() as u8),
    );
    (
        w,
        Statement::new(input["row"].as_u64().unwrap() as u8, [0x71; 64]).unwrap(),
    )
}

#[test]
fn exact_private_profile_and_all_transport_limits_are_fixed() {
    assert_eq!(
        (air::HEIGHT, air::WIDTH, air::PUBLIC_VALUES),
        (1024, 24794, 65)
    );
    assert_eq!(
        PROFILE,
        b"thorum.reconstructed-row-proof-lab.mldsa87.private-row.four-rounds.serial.p3-0.8.0.v1"
    );
    assert_eq!(
        (
            MAX_PROOF_BYTES,
            MAX_JSON_TOKENS,
            MAX_JSON_ITEMS,
            MAX_JSON_DEPTH
        ),
        (32 * 1024 * 1024, 3_000_000, 32768, 24)
    );
    let statement = Statement::new(0, [0; 64]).unwrap();
    assert_eq!(
        verify_reconstructed_row(&[], &statement),
        Err(Error::InvalidEncoding)
    );
    assert!(Statement::new(8, [0; 64]).is_err());
    let invalid = Statement {
        row: 8,
        context: [0; 64],
    };
    assert_eq!(
        verify_reconstructed_row(&[], &invalid),
        Err(Error::InvalidStatement)
    );
    let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<BabyBear, _>(
        &ReconstructedRowAir::default(),
        p3_air::symbolic::AirLayout {
            main_width: air::WIDTH,
            num_public_values: air::PUBLIC_VALUES,
            ..Default::default()
        },
        air::HEIGHT,
        1,
    );
    assert_eq!(log_chunks, 2);
    assert_eq!(1usize << (log_chunks + 1), 8);
    assert_eq!(air::HEIGHT.ilog2() + 1, 11);
    assert_eq!(64 * (11 + 3), 896);
}
#[test]
fn fresh_full_sha3_domains_match_independent_framed_vectors() {
    for line in include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../research/reconstructed-row/hash_vectors.csv"
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
fn preflight_bounds_bytes_depth_members_strings_integers_and_total_tokens() {
    assert_eq!(json_preflight(&[b'['; 25]), Err(Error::LimitExceeded));
    assert_eq!(
        json_preflight(&vec![b' '; MAX_PROOF_BYTES + 1]),
        Err(Error::LimitExceeded)
    );
    let members = |n: usize| {
        let mut v = Vec::with_capacity(n * 2 + 1);
        v.push(b'[');
        for i in 0..n {
            if i > 0 {
                v.push(b',');
            }
            v.push(b'0');
        }
        v.push(b']');
        v
    };
    assert!(json_preflight(&members(MAX_JSON_ITEMS)).is_ok());
    assert_eq!(
        json_preflight(&members(MAX_JSON_ITEMS + 1)),
        Err(Error::LimitExceeded)
    );
    let string = |n: usize| {
        let mut v = vec![b'"'];
        v.extend(vec![b'a'; n]);
        v.push(b'"');
        v
    };
    assert!(json_preflight(&string(64)).is_ok());
    assert_eq!(json_preflight(&string(65)), Err(Error::InvalidEncoding));
    assert!(json_preflight(b"18446744073709551615").is_ok());
    assert_eq!(json_preflight(&[b'1'; 21]), Err(Error::InvalidEncoding));
    assert!(json_preflight(br#"{"x":"escaped\n"}"#).is_err());
    for invalid in [b"-1".as_slice(), b"1.0", b"1e2", b"true", b"]", b"["] {
        assert!(json_preflight(invalid).is_err());
    }
    let mut tokens = vec![b'['];
    for i in 0..100 {
        if i > 0 {
            tokens.push(b',');
        }
        tokens.extend(members(30000));
    }
    tokens.push(b']');
    assert!(tokens.len() < MAX_PROOF_BYTES);
    assert_eq!(json_preflight(&tokens), Err(Error::LimitExceeded));
}

fn synthetic_maximum_shape() -> Proof<Config> {
    let base = BabyBear::from_u32(2013265920);
    let ext = Challenge::from_basis_coefficients_fn(|_| base);
    let cap = MerkleCap::<BabyBear, [u64; 8]>::new(vec![[u64::MAX; 8]]);
    let auth = |matrices: usize| -> MerkleMultiProof {
        (
            vec![vec![vec![base; 16]; matrices]; 64],
            PrunedMerklePaths {
                sibling_hashes: vec![[u64::MAX; 8]; 896],
            },
        )
    };
    let inputs = vec![(1, 8), (1, air::WIDTH + 4), (8, 8)]
        .into_iter()
        .map(
            |(matrices, width)| BatchMultiOpening::<BabyBear, HidingMmcs> {
                opened_values: vec![vec![vec![base; width]; matrices]; 64],
                opening_proof: auth(matrices),
            },
        )
        .collect();
    let masks = vec![
        vec![vec![vec![ext; 4]; 1]; 1],
        vec![vec![vec![ext; 4]; 2]; 1],
        vec![vec![vec![ext; 4]; 1]; 8],
    ];
    Proof {
        commitments: Commitments {
            trace: cap.clone(),
            quotient_chunks: cap.clone(),
            random: Some(cap.clone()),
        },
        opened_values: OpenedValues {
            trace_local: vec![ext; air::WIDTH],
            trace_next: Some(vec![ext; air::WIDTH]),
            preprocessed: None,
            quotient_chunks: vec![vec![ext; 4]; 8],
            random: Some(vec![ext; 4]),
        },
        opening_proof: (
            masks,
            FriProof {
                batch_pow_witness: BabyBear::ZERO,
                commit_phase_commits: vec![cap; 11],
                commit_pow_witnesses: vec![BabyBear::ZERO; 11],
                input_openings: inputs,
                commit_phase_openings: (0..11)
                    .map(|_| CommitPhaseMultiStep::<Challenge, ChallengeMmcs> {
                        sibling_values: vec![vec![ext]; 64],
                        opening_proof: auth(1),
                    })
                    .collect(),
                final_poly: vec![ext],
                query_pow_witness: BabyBear::ZERO,
            },
        ),
        degree_bits: 11,
        ood_pow_witness: BabyBear::ZERO,
    }
}
#[test]
fn maximum_canonical_shape_fits_closed_transport_without_claiming_a_valid_proof() {
    let proof = synthetic_maximum_shape();
    validate_shape(&proof).unwrap();
    let encoded = serde_json::to_vec(&proof).unwrap();
    json_preflight(&encoded).unwrap();
    let decoded: Proof<Config> = serde_json::from_slice(&encoded).unwrap();
    validate_shape(&decoded).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
    println!("synthetic maximum closed envelope bytes {}", encoded.len());
    assert!(encoded.len() < MAX_PROOF_BYTES);
}

#[test]
fn canonical_transport_rejects_spacing_extra_fields_and_duplicate_fields_before_backend() {
    let encoded = serde_json::to_vec(&synthetic_maximum_shape()).unwrap();
    let statement = Statement::new(0, [0x71; 64]).unwrap();
    let mut trailing = encoded.clone();
    trailing.push(b' ');
    assert_eq!(
        verify_reconstructed_row(&trailing, &statement),
        Err(Error::InvalidEncoding)
    );
    let mut extra = encoded.clone();
    extra.pop();
    extra.extend_from_slice(b",\"ignored\":0}");
    assert_eq!(
        verify_reconstructed_row(&extra, &statement),
        Err(Error::InvalidEncoding)
    );
    let mut duplicate = encoded;
    duplicate.pop();
    duplicate.extend_from_slice(b",\"degree_bits\":11}");
    assert_eq!(
        verify_reconstructed_row(&duplicate, &statement),
        Err(Error::InvalidEncoding)
    );
}
#[test]
fn fixed_shape_rejects_other_degrees_roots_widths_masks_queries_salts_and_siblings() {
    let mut p = synthetic_maximum_shape();
    assert!(validate_shape(&p).is_ok());
    p.degree_bits = 10;
    assert!(validate_shape(&p).is_err());
    p.degree_bits = 11;
    p.ood_pow_witness = BabyBear::ONE;
    assert!(validate_shape(&p).is_err());
    p.ood_pow_witness = BabyBear::ZERO;
    let cap = p.commitments.trace.clone();
    p.commitments.trace = MerkleCap::new(vec![[0u64; 8]; 2]);
    assert!(validate_shape(&p).is_err());
    p.commitments.trace = cap;
    let value = p.opened_values.trace_local.pop().unwrap();
    assert!(validate_shape(&p).is_err());
    p.opened_values.trace_local.push(value);
    let next = p.opened_values.trace_next.take();
    assert!(validate_shape(&p).is_err());
    p.opened_values.trace_next = next;
    let chunk = p.opened_values.quotient_chunks.pop().unwrap();
    assert!(validate_shape(&p).is_err());
    p.opened_values.quotient_chunks.push(chunk);
    let random = p.opened_values.random.take();
    assert!(validate_shape(&p).is_err());
    p.opened_values.random = random;
    let mask = p.opening_proof.0.pop().unwrap();
    assert!(validate_shape(&p).is_err());
    p.opening_proof.0.push(mask);
    let cap = p.opening_proof.1.commit_phase_commits.pop().unwrap();
    assert!(validate_shape(&p).is_err());
    p.opening_proof.1.commit_phase_commits.push(cap);
    let final_value = p.opening_proof.1.final_poly[0];
    p.opening_proof.1.final_poly.push(final_value);
    assert!(validate_shape(&p).is_err());
    p.opening_proof.1.final_poly.pop();
    let input = &mut p.opening_proof.1.input_openings[1];
    let cell = input.opened_values[0][0].pop().unwrap();
    assert!(validate_shape(&p).is_err());
    p.opening_proof.1.input_openings[1].opened_values[0][0].push(cell);
    p.opening_proof.1.input_openings[1]
        .opening_proof
        .1
        .sibling_hashes
        .push([0; 8]);
    assert!(validate_shape(&p).is_err());
    p.opening_proof.1.input_openings[1]
        .opening_proof
        .1
        .sibling_hashes
        .pop();
    p.opening_proof.1.input_openings[0].opening_proof.0[0][0].pop();
    assert!(validate_shape(&p).is_err());
    p.opening_proof.1.input_openings[0].opening_proof.0[0][0].push(BabyBear::ZERO);
    let query = p.opening_proof.1.commit_phase_openings[0]
        .sibling_values
        .pop()
        .unwrap();
    assert!(validate_shape(&p).is_err());
    p.opening_proof.1.commit_phase_openings[0]
        .sibling_values
        .push(query);
    assert!(validate_shape(&p).is_ok());
}

#[test]
#[ignore = "Serial conditional row proof corpus"]
fn one_honest_private_reconstructed_row_proof() {
    let (w, s) = fixture();
    let encoded = prove_reconstructed_row(&w, &s).unwrap();
    verify_reconstructed_row(&encoded, &s).unwrap();
    let p: Proof<Config> = serde_json::from_slice(&encoded).unwrap();
    validate_shape(&p).unwrap();
    println!(
        "single private conditional row proof verified, encoded bytes {}",
        encoded.len()
    );
}

#[path = "corpus_tests.rs"]
mod corpus_tests;
