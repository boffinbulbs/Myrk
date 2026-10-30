include!("common.rs");

use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{CommitmentOpening, MatrixOpening, OpenedValues, OpeningRequest, PointOpening};
use p3_field::BasedVectorSpace;
use serde::Serialize;

type Root = <Spy as Mmcs<BabyBear>>::Commitment;
type RetainedProof = <Dense as Pcs<Challenge, Challenger>>::Proof;
type Claims = Vec<CommitmentOpening<Challenge, Root, TwoAdicMultiplicativeCoset<BabyBear>>>;
const CAP: usize = 2 * 1024 * 1024;
const CAPTURE: usize = 752896;

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("proof size overflow"))?;
        if length > CAP {
            return Err(std::io::Error::other("encoded proof exceeds fixed cap"));
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
fn coefficients(value: Challenge) -> Vec<u32> {
    <Challenge as BasedVectorSpace<BabyBear>>::as_basis_coefficients_slice(&value)
        .iter()
        .map(|v| v.as_canonical_u32())
        .collect()
}
fn statement(root: &Root) -> ([Challenge; 2], Challenger) {
    let mut transcript = Challenger::new(HashChallenger::new(
        b"kova.storage-pcs.quartic.v1".to_vec(),
        hash::TranscriptHash,
    ));
    transcript.observe(root.clone());
    let points = [
        transcript.sample_algebra_element::<Challenge>(),
        transcript.sample_algebra_element::<Challenge>(),
    ];
    assert_ne!(points[0], points[1]);
    for point in points {
        assert_ne!(point, Challenge::ZERO);
        assert!(coefficients(point)[1..].iter().any(|&v| v != 0));
    }
    (points, transcript)
}
fn claims(root: Root, points: [Challenge; 2], opened: &OpenedValues<Challenge>) -> Claims {
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].len(), 1);
    assert_eq!(opened[0][0].len(), 2);
    let points = points
        .into_iter()
        .zip(&opened[0][0])
        .map(|(point, values)| {
            assert_eq!(values.len(), 2);
            PointOpening {
                point,
                values: values.clone(),
            }
        })
        .collect();
    vec![CommitmentOpening {
        commitment: root,
        matrices: vec![MatrixOpening {
            domain: domain(),
            points,
        }],
    }]
}
fn counters(o: &Observation) -> [usize; 5] {
    [
        &o.audit.input_commits,
        &o.audit.extension_commits,
        &o.audit.input_opens,
        &o.audit.extension_opens,
        &o.audit.scalar_opens,
    ]
    .map(|v| v.load(Ordering::SeqCst))
}
struct Bundle {
    root: Root,
    points: [Challenge; 2],
    opened: OpenedValues<Challenge>,
    proof: Vec<u8>,
    pre: Challenger,
    after: Challenge,
    leaves: Vec<u8>,
}
fn run<P>(pcs: &P, data: &P::ProverData, root: Root, o: &Observation, refuse_clone: bool) -> Bundle
where
    P: Pcs<Challenge, Challenger, Domain = TwoAdicMultiplicativeCoset<BabyBear>, Commitment = Root>,
    P::ProverData: Clone,
    P::Proof: Serialize,
{
    assert_eq!(counters(o), [1, 0, 0, 0, 0]);
    let duplicate = if refuse_clone {
        Some(data.clone())
    } else {
        None
    };
    let (points, mut prover) = statement(&root);
    let pre = prover.clone();
    let mask = o.mask.bytes();
    let salt = o.salt.bytes();
    let (opened, proof) = pcs
        .open(
            vec![OpeningRequest {
                prover_data: data,
                points: vec![points.to_vec()],
            }],
            &mut prover,
        )
        .unwrap();
    assert_eq!(counters(o), [1, 9, 1, 9, 0]);
    assert_eq!(mask, o.mask.bytes());
    assert_eq!(salt, o.salt.bytes());
    assert_eq!(
        *o.audit.shapes.lock().unwrap(),
        std::iter::once([4096, 6])
            .chain((0..9).map(|r| [2048 >> r, 8]))
            .collect::<Vec<_>>()
    );
    let encoded = encode(&proof);
    drop(proof);
    if let Some(duplicate) = duplicate {
        let before = counters(o);
        let capture_len = o.audit.leaves.lock().unwrap().len();
        let failure = catch_unwind(AssertUnwindSafe(|| {
            pcs.open(
                vec![OpeningRequest {
                    prover_data: &duplicate,
                    points: vec![points.to_vec()],
                }],
                &mut pre.clone(),
            )
        }))
        .err()
        .unwrap();
        let text = if let Some(v) = failure.downcast_ref::<String>() {
            v.as_str()
        } else if let Some(v) = failure.downcast_ref::<&str>() {
            v
        } else {
            panic!("wrong consumed-clone failure type")
        };
        assert!(text.contains("already opened"));
        assert_eq!(counters(o), before);
        assert_eq!(o.mask.bytes(), mask);
        assert_eq!(o.salt.bytes(), salt);
        assert_eq!(o.audit.leaves.lock().unwrap().len(), capture_len);
    }
    let leaves = std::mem::take(&mut *o.audit.leaves.lock().unwrap());
    assert_eq!(leaves.len(), CAPTURE);
    // Each round uses the continuing child salt stream. The public test also
    // checks that its first salt row does not repeat between the nine rounds.
    let mut offset = 4096 * 22 * 4;
    let mut prefixes = vec![];
    for round in 0..9 {
        prefixes.push(leaves[offset + 8 * 4..offset + 24 * 4].to_vec());
        offset += (2048 >> round) * 24 * 4;
    }
    assert_eq!(offset, CAPTURE);
    for i in 0..prefixes.len() {
        for j in 0..i {
            assert_ne!(prefixes[i], prefixes[j]);
        }
    }
    Bundle {
        root,
        points,
        opened,
        proof: encoded,
        pre,
        after: prover.sample_algebra_element(),
        leaves,
    }
}
fn verify_good(reference: &Dense, b: &Bundle) -> RetainedProof {
    assert!(b.proof.len() <= CAP);
    let decoded: RetainedProof = serde_json::from_slice(&b.proof).unwrap();
    assert_eq!(encode(&decoded), b.proof);
    assert_eq!(decoded.1.commit_phase_commits.len(), 9);
    assert_eq!(decoded.1.commit_phase_openings.len(), 9);
    assert_eq!(decoded.1.final_poly.len(), 1);
    assert_eq!(decoded.1.input_openings.len(), 1);
    assert_eq!(decoded.0.len(), 1);
    assert_eq!(decoded.0[0].len(), 1);
    assert_eq!(decoded.0[0][0].len(), 2);
    assert!(decoded.0[0][0].iter().all(|v| v.len() == 4));
    let (points, mut verifier) = statement(&b.root);
    assert_eq!(points, b.points);
    reference
        .verify(
            claims(b.root.clone(), points, &b.opened),
            &decoded,
            &mut verifier,
        )
        .unwrap();
    assert_eq!(verifier.sample_algebra_element::<Challenge>(), b.after);
    decoded
}
fn compare(reference: &Dense, baseline: &Bundle, current: Bundle) {
    assert_eq!(baseline.root, current.root);
    assert_eq!(baseline.points, current.points);
    assert_eq!(baseline.opened, current.opened);
    assert_eq!(baseline.proof, current.proof);
    assert_eq!(baseline.after, current.after);
    assert_eq!(baseline.leaves, current.leaves);
    drop(verify_good(reference, &current));
}

#[test]
#[allow(
    clippy::assertions_on_constants,
    reason = "The proof experiment requires the admitted release executable"
)]
fn source_openings_match_retained_verification_and_reject_tampering() {
    assert!(!cfg!(debug_assertions));
    let (anchor, anchor_o) = anchor();
    let anchor_mask = anchor_o.mask.bytes();
    let anchor_salt = anchor_o.salt.bytes();
    let (reference, reference_o) = dense();
    let (root, data) =
        <_ as Pcs<Challenge, Challenger>>::commit(&reference, [(domain(), air::trace())]).unwrap();
    let baseline = run(&reference, &data, root, &reference_o, false);
    drop(data);
    drop(verify_good(&reference, &baseline));
    {
        let (pcs, store, o) = owned(&anchor, 64);
        let raw = store.write_raw(values()).unwrap();
        let (root, data) = pcs.commit_owned_source(domain(), raw).unwrap();
        let result = run(&pcs, &data, root, &o, true);
        compare(&reference, &baseline, result);
        assert_eq!(
            store.snapshot().unwrap().construction.reserved_bytes,
            112640
        );
        assert_eq!(store.snapshot().unwrap().phase, Phase::Committed);
        assert_eq!(counters(&o), [1, 9, 1, 9, 0]);
        drop(data);
    }
    {
        let (pcs, store, o) = owned(&anchor, 64);
        let (root, data) = pcs.commit_dense_source(domain(), air::trace()).unwrap();
        let result = run(&pcs, &data, root, &o, false);
        compare(&reference, &baseline, result);
        assert_eq!(
            store.snapshot().unwrap().construction.reserved_bytes,
            110592
        );
        assert_eq!(store.snapshot().unwrap().phase, Phase::Committed);
        assert_eq!(counters(&o), [1, 9, 1, 9, 0]);
        drop(data);
    }
    assert_eq!(anchor_o.mask.bytes(), anchor_mask);
    assert_eq!(anchor_o.salt.bytes(), anchor_salt);
    assert_eq!(anchor_salt, anchor_o.initial_salt);
    assert_eq!(counters(&anchor_o), [0; 5]);
    let original = verify_shape(&baseline);
    {
        let proof: RetainedProof = serde_json::from_slice(&baseline.proof).unwrap();
        let mut changed = claims(baseline.root.clone(), baseline.points, &baseline.opened);
        let mut roots = changed[0].commitment.clone().into_roots();
        roots[0][0] ^= 1;
        changed[0].commitment = Root::new(roots);
        assert!(
            reference
                .verify(changed, &proof, &mut baseline.pre.clone())
                .is_err()
        );
    }
    {
        let proof: RetainedProof = serde_json::from_slice(&baseline.proof).unwrap();
        let mut changed = claims(baseline.root.clone(), baseline.points, &baseline.opened);
        changed[0].matrices[0].points[0].values[0] += Challenge::ONE;
        assert!(
            reference
                .verify(changed, &proof, &mut baseline.pre.clone())
                .is_err()
        );
    }
    {
        let mut proof: RetainedProof = serde_json::from_slice(&baseline.proof).unwrap();
        let nodes = &mut proof.1.input_openings[0].opening_proof.1.sibling_hashes;
        assert!(!nodes.is_empty());
        nodes[0][0] ^= 1;
        assert!(
            reference
                .verify(
                    claims(baseline.root.clone(), baseline.points, &baseline.opened),
                    &proof,
                    &mut baseline.pre.clone()
                )
                .is_err()
        );
    }
    assert_eq!(counters(&reference_o), [1, 9, 1, 9, 0]);
    assert!(reference_o.audit.leaves.lock().unwrap().is_empty());
    let record = serde_json::json!({
        "format":"kova.source-opening.fixture.v1","base_modulus":2013265921u64,"extension_nonresidue":11,
        "raw_height":256,"domain_height":512,"original_width":2,"main_lde_shape":[4096,6],"queries":64,
        "points":baseline.points.map(coefficients),"opened":baseline.opened[0][0].iter().map(|v|v.iter().copied().map(coefficients).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "input_root":baseline.root.roots(),"fri_roots":original.1.commit_phase_commits.iter().map(|v|v.roots()).collect::<Vec<_>>(),
        "proof_bytes":baseline.proof.len(),"captured_leaf_bytes":baseline.leaves.len(),"transcript_after":coefficients(baseline.after),
        "input_commit_calls":3,"fri_commit_calls":27,"successful_openings":3,"refused_clone_openings":1,
        "input_multi_open_calls":3,"fri_multi_open_calls":27,"scalar_open_calls":0,"positive_verifications":3,"negative_verifications":3,"stark_proofs":0
    });
    let results = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    fs::create_dir_all(&results).unwrap();
    for (name, bytes) in [
        ("proof.json", baseline.proof),
        ("salted-leaves.bin", baseline.leaves),
    ] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(results.join(name))
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(results.join("measurement.json"))
        .unwrap();
    serde_json::to_writer_pretty(output, &record).unwrap();
}
// This parse inspects shape only and does not invoke another verifier.
fn verify_shape(b: &Bundle) -> RetainedProof {
    serde_json::from_slice(&b.proof).unwrap()
}
