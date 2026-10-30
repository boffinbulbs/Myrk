include!("../../source-stark/tests/common.rs");
use p3_uni_stark::{Proof, StarkConfig, VerificationError};
use serde::Serialize;

type DenseConfig = StarkConfig<Dense, Challenge, Challenger>;
const CAP: usize = 2 * 1024 * 1024;
const CAPTURE: usize = 1_048_064;
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > CAP)
        {
            return Err(std::io::Error::other("fixed proof transport cap exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(value: &impl Serialize) -> Vec<u8> {
    let mut out = Bounded(vec![]);
    serde_json::to_writer(&mut out, value).unwrap();
    out.0
}
fn parse(bytes: &[u8]) -> Proof<DenseConfig> {
    assert!(!bytes.is_empty() && bytes.len() <= CAP);
    let proof = serde_json::from_slice(bytes).unwrap();
    assert_eq!(bytes, encode(&proof));
    proof
}
fn counts(o: &Observation) -> [usize; 5] {
    [
        &o.audit.input_commits,
        &o.audit.extension_commits,
        &o.audit.input_opens,
        &o.audit.extension_opens,
        &o.audit.scalar_opens,
    ]
    .map(|v| v.load(Ordering::SeqCst))
}
fn mutated() -> Vec<BabyBear> {
    let rows: Vec<Vec<u32>> =
        serde_json::from_str(include_str!("../../storage-pcs/fixtures/trace.json")).unwrap();
    assert_eq!(rows.len(), 256);
    let original = rows
        .into_iter()
        .flat_map(|row| {
            assert_eq!(row.len(), 2);
            row
        })
        .map(|v| {
            assert!(v < BabyBear::ORDER_U32);
            BabyBear::from_u32(v)
        })
        .collect::<Vec<_>>();
    assert_eq!(original, air::trace().values);
    let mut changed = original.clone();
    assert_eq!(changed[254].as_canonical_u32(), 132);
    assert_eq!(changed[255].as_canonical_u32(), 303_595_776);
    changed[255] += BabyBear::ONE;
    assert_eq!(changed[255].as_canonical_u32(), 303_595_777);
    assert_eq!(changed.len(), 512);
    assert_eq!(
        changed
            .iter()
            .zip(&original)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect::<Vec<_>>(),
        vec![255]
    );
    for i in (0..512).step_by(2) {
        assert_eq!(changed[i], original[i]);
    }
    assert_eq!(changed[0].as_canonical_u32(), 5);
    assert_eq!(changed[510].as_canonical_u32(), 260);
    changed
}
fn write(name: &str, bytes: &[u8]) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
#[allow(
    clippy::assertions_on_constants,
    reason = "The raw backend control must refuse host debug checks."
)]
fn canonical_false_witness_reaches_retained_air_rejection() {
    assert!(
        !cfg!(debug_assertions),
        "release false witness selection required"
    );
    fs::create_dir_all(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results")).unwrap();
    let (reference, b) = dense();
    let reference = StarkConfig::new(reference, challenger());
    let before_reference = (b.mask.bytes(), b.salt.bytes());
    assert!(b.mask.bytes().is_empty());
    assert_eq!(b.salt.bytes(), b.initial_salt);
    {
        let positive = parse(include_bytes!("../../source-stark/fixtures/proof.json"));
        p3_uni_stark::verify(&reference, &air::QuarticAir, &positive, &air::public()).unwrap();
    }
    assert_eq!(counts(&b), [0; 5]);
    assert_eq!((b.mask.bytes(), b.salt.bytes()), before_reference);
    let (anchor, anchor_o) = anchor();
    let before_anchor = (anchor_o.mask.bytes(), anchor_o.salt.bytes());
    let (base, a) = base(64);
    assert!(a.mask.bytes().is_empty());
    assert_eq!(a.salt.bytes(), a.initial_salt);
    let context = Arc::new(Context::new(base, challenger(), &anchor).unwrap());
    *a.audit.owner.lock().unwrap() = Some(Arc::downgrade(&context));
    let changed = mutated();
    write(
        "witness.json",
        &serde_json::to_vec(
            &changed
                .iter()
                .map(|v| v.as_canonical_u32())
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    );
    // The unchanged owned entry must return a real complete proof. A refusal,
    // panic or parser error is not the intended constraint rejection.
    let proof = context.prove(changed).unwrap();
    let state = context.snapshot().unwrap();
    assert_eq!(state.phase, Phase::ProofProduced);
    assert!(state.failure.is_none());
    assert_eq!(
        (state.reserved_files, state.reserved_bytes),
        (12, 1_292_288)
    );
    assert_eq!(proof.degree_bits, 9);
    assert_eq!(counts(&a), [3, 9, 3, 9, 0]);
    let encoded = encode(&proof);
    write("proof.json", &encoded);
    let leaves = a.audit.leaves.lock().unwrap().clone();
    assert_eq!(leaves.len(), CAPTURE);
    write("leaf-digests.bin", &leaves);
    let parsed = parse(&encoded);
    let roots = a.audit.roots.lock().unwrap().clone();
    let shape = a.audit.shapes.lock().unwrap().clone();
    assert_eq!(roots.len(), 12);
    let full = serde_json::to_value(&proof).unwrap();
    assert_eq!(full["commitments"]["trace"], roots[0]);
    assert_eq!(full["commitments"]["quotient_chunks"], roots[1]);
    assert_eq!(full["commitments"]["random"], roots[2]);
    assert_eq!(
        full["opening_proof"][1]["commit_phase_commits"],
        serde_json::to_value(&roots[3..]).unwrap()
    );
    let before_owned = (a.mask.bytes(), a.salt.bytes());
    let outcome = p3_uni_stark::verify(&reference, &air::QuarticAir, &parsed, &air::public());
    // Preserve the observed result before interpreting its exact error class.
    write(
        "verification.json",
        &serde_json::to_vec(&serde_json::json!({"observed":format!("{outcome:?}")})).unwrap(),
    );
    assert!(matches!(
        outcome,
        Err(VerificationError::OodEvaluationMismatch { index: None })
    ));
    assert_eq!(counts(&a), [3, 9, 3, 9, 0]);
    assert_eq!(counts(&b), [0; 5]);
    assert_eq!((a.mask.bytes(), a.salt.bytes()), before_owned);
    assert_eq!((b.mask.bytes(), b.salt.bytes()), before_reference);
    assert_eq!(context.snapshot().unwrap().phase, Phase::ProofProduced);
    assert_eq!(
        (anchor_o.mask.bytes(), anchor_o.salt.bytes()),
        before_anchor
    );
    write(
        "measurement.json",
        &serde_json::to_vec(&serde_json::json!({
            "whole_stark_proofs":1,"false_air_proofs":1,"fresh_positive_proofs":0,
            "retained_verifier_rejects":1,"retained_positive_fixture_accepts":1,
            "verifier_error":"OodEvaluationMismatch","verifier_error_index":null,
            "changed_flat_index":255,"original_value":303595776,"changed_value":303595777,
            "public_values":[5,260],"degree_bits":9,"input_mmcs_commits":3,"fri_mmcs_commits":9,
            "input_multi_open_calls":3,"fri_multi_open_calls":9,"scalar_open_calls":0,
            "reserved_files":12,"reserved_field_bytes":1292288,"encoded_proof_bytes":encoded.len(),
            "leaf_digest_bytes":leaves.len(),"commit_shapes":shape,"commit_roots":roots
        }))
        .unwrap(),
    );
    *a.audit.owner.lock().unwrap() = None;
}
