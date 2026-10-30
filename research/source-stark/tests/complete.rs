include!("common.rs");
use p3_uni_stark::{Proof, StarkConfig};
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
fn raw() -> Vec<BabyBear> {
    let independent: Vec<Vec<u32>> =
        serde_json::from_str(include_str!("../../storage-pcs/fixtures/trace.json")).unwrap();
    assert_eq!(independent.len(), 256);
    let values = independent
        .into_iter()
        .flat_map(|r| {
            assert_eq!(r.len(), 2);
            r
        })
        .map(|v| {
            assert!(v < BabyBear::ORDER_U32);
            BabyBear::from_u32(v)
        })
        .collect::<Vec<_>>();
    assert_eq!(values, air::trace().values);
    values
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
    reason = "The raw backend experiment must refuse host debug checks."
)]
fn owned_whole_proof_matches_retained_proving_and_verification() {
    assert!(
        !cfg!(debug_assertions),
        "release whole-proof selection required"
    );
    fs::create_dir_all(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results")).unwrap();
    let (anchor, anchor_o) = anchor();
    let anchor_before = (anchor_o.mask.bytes(), anchor_o.salt.bytes());
    let (base, a) = base(64);
    let context = Arc::new(Context::new(base, challenger(), &anchor).unwrap());
    *a.audit.owner.lock().unwrap() = Some(Arc::downgrade(&context));
    let (reference, b) = dense();
    let reference = StarkConfig::new(reference, challenger());
    let proof = context.prove(raw()).unwrap();
    assert_eq!(proof.degree_bits, 9);
    let state = context.snapshot().unwrap();
    assert_eq!(state.phase, Phase::ProofProduced);
    assert_eq!(
        (state.reserved_files, state.reserved_bytes),
        (12, 1_292_288)
    );
    assert!(state.failure.is_none());
    assert_eq!(counts(&a), [3, 9, 3, 9, 0]);
    let actual = encode(&proof);
    let parsed: Proof<DenseConfig> = serde_json::from_slice(&actual).unwrap();
    assert_eq!(actual, encode(&parsed));
    let reference_before = (b.mask.bytes(), b.salt.bytes());
    p3_uni_stark::verify(&reference, &air::QuarticAir, &parsed, &air::public()).unwrap();
    assert_eq!((b.mask.bytes(), b.salt.bytes()), reference_before);
    assert_eq!(counts(&b), [0; 5]);
    let retained =
        p3_uni_stark::prove(&reference, &air::QuarticAir, air::trace(), &air::public()).unwrap();
    let expected = encode(&retained);
    assert_eq!(actual, expected);
    p3_uni_stark::verify(&reference, &air::QuarticAir, &retained, &air::public()).unwrap();
    assert_eq!(counts(&b), [3, 9, 3, 9, 0]);
    assert_eq!(a.mask.bytes(), b.mask.bytes());
    assert_eq!(a.salt.bytes(), b.salt.bytes());
    assert_eq!(
        *a.audit.shapes.lock().unwrap(),
        *b.audit.shapes.lock().unwrap()
    );
    assert_eq!(
        *a.audit.roots.lock().unwrap(),
        *b.audit.roots.lock().unwrap()
    );
    assert_eq!(
        *a.audit.leaves.lock().unwrap(),
        *b.audit.leaves.lock().unwrap()
    );
    let leaves = a.audit.leaves.lock().unwrap().clone();
    assert_eq!(leaves.len(), CAPTURE);
    let roots = a.audit.roots.lock().unwrap().clone();
    assert_eq!(roots.len(), 12);
    let shape = a.audit.shapes.lock().unwrap().clone();
    let full = serde_json::to_value(&proof).unwrap();
    assert_eq!(full["commitments"]["trace"], roots[0]);
    assert_eq!(full["commitments"]["quotient_chunks"], roots[1]);
    assert_eq!(full["commitments"]["random"], roots[2]);
    assert_eq!(
        full["opening_proof"][1]["commit_phase_commits"],
        serde_json::to_value(&roots[3..]).unwrap()
    );
    let before = (a.mask.bytes(), a.salt.bytes());
    assert!(context.prove(raw()).is_err());
    assert_eq!((a.mask.bytes(), a.salt.bytes()), before);
    assert_eq!(counts(&a), [3, 9, 3, 9, 0]);
    assert_eq!(context.snapshot().unwrap().phase, Phase::ProofProduced);
    assert_eq!(
        (anchor_o.mask.bytes(), anchor_o.salt.bytes()),
        anchor_before
    );
    let measurement = serde_json::json!({"whole_stark_proofs":2,"retained_verifier_accepts":2,
        "input_mmcs_commits":6,"fri_mmcs_commits":18,"input_multi_open_calls":6,"fri_multi_open_calls":18,"scalar_open_calls":0,
        "degree_bits":9,"raw_height":256,"main_width":2,"public_values":[5,260],"queries":64,"extension_degree":4,
        "reserved_files":12,"reserved_field_bytes":1_292_288,"encoded_proof_bytes":actual.len(),"leaf_digest_bytes":leaves.len(),
        "commit_shapes":shape,"commit_roots":roots,"same_complete_proof_bytes":true,"false_air_proofs":0});
    write("proof.json", &actual);
    write("leaf-digests.bin", &leaves);
    write(
        "measurement.json",
        &serde_json::to_vec(&measurement).unwrap(),
    );
    *a.audit.owner.lock().unwrap() = None;
}

#[test]
#[allow(
    clippy::assertions_on_constants,
    reason = "The constructor experiment is selected only in release mode."
)]
fn context_profile_and_raw_shape_refusals_do_not_prove() {
    assert!(
        !cfg!(debug_assertions),
        "release constructor selection required"
    );
    let (anchor, anchor_o) = anchor();
    let before = (anchor_o.mask.bytes(), anchor_o.salt.bytes());
    let (bad, a) = base(63);
    assert!(Context::new(bad, challenger(), &anchor).is_err());
    assert_eq!(counts(&a), [0; 5]);
    assert!(a.mask.bytes().is_empty());
    assert_eq!(a.salt.bytes(), a.initial_salt);
    let (valid, b) = base(64);
    let context = Context::new(valid, challenger(), &anchor).unwrap();
    assert!(context.prove([BabyBear::ONE; 3]).is_err());
    assert_eq!(context.snapshot().unwrap().phase, Phase::Failed);
    assert_eq!(counts(&b), [0; 5]);
    assert!(b.mask.bytes().is_empty());
    assert_eq!(b.salt.bytes(), b.initial_salt);
    assert_eq!((anchor_o.mask.bytes(), anchor_o.salt.bytes()), before);
}
