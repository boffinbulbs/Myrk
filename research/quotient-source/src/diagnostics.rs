// Fixed synthetic construction diagnostics. No wallet or ledger entry uses this.
use crate::diagnostics_setup as setup;
use crate::quotient_kernel::CommittedRead;
use p3_commit::UnivariateStarkPcs;
use p3_field::{BasedVectorSpace, PrimeField32};
use p3_matrix::Matrix;
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

fn capture_main<D, I, F, R, C>(
    pcs: &HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>,
    data: &HidingFriPcsProverData<I::ProverData<Stored>>,
    domain: TwoAdicMultiplicativeCoset<BabyBear>,
) -> Result<Vec<[u32; 2]>, Error>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<Challenge>,
    R: CryptoRng + Send + Sync,
    C: FieldChallenger<BabyBear>
        + GrindingChallenger<Witness = BabyBear>
        + CanObserve<I::Commitment>
        + CanObserve<F::Commitment>,
{
    let view = pcs.main_quotient_view(data, domain)?;
    let original =
        <_ as UnivariateStarkPcs<Challenge, C>>::get_evaluations_on_domain(pcs, data, 0, domain);
    assert_eq!([original.height(), original.width()], [2048, 2]);
    let mut captured = Vec::with_capacity(2048);
    for row in 0..2048 {
        let fields = crate::quotient_kernel::CommittedRead::read_window(&view, row, 0, 2)?;
        assert_eq!(fields.len(), 2);
        assert_eq!(fields, original.row_slice(row).unwrap().as_ref());
        captured.push([fields[0].as_canonical_u32(), fields[1].as_canonical_u32()]);
    }
    assert_eq!(view.read_window(0, 0, 3).unwrap_err(), Error::Shape);
    assert_eq!(view.read_window(2048, 0, 2).unwrap_err(), Error::Shape);
    assert_eq!(view.read_window(0, 2, 1).unwrap_err(), Error::Shape);
    Ok(captured)
}

fn save(name: &str, value: &Value) {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let bytes = serde_json::to_vec(value).unwrap();
    let cap = match name {
        "synthetic-capture.json" => 196608,
        "measurement.json" => 16384,
        _ => panic!("unknown fixed diagnostic artifact"),
    };
    assert!(bytes.len() <= cap);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

/// Execute only the fixed laboratory fixture. Returns public effect counts.
/// Synthetic intermediate fields stay in explicit local diagnostic artifacts.
pub fn fixed_construction() -> Value {
    let (anchor, anchor_audit) = setup::anchor();
    let anchor_before = anchor_audit.counts();
    let (pcs, audit) = setup::base();
    let context: setup::OwnedContext = Context::new(pcs, setup::challenger(), &anchor).unwrap();
    let packet = context
        .construct_quotient(setup::rawliteral(), &audit)
        .unwrap();
    assert_eq!(
        context.snapshot().unwrap().phase,
        crate::Phase::QuotientReady
    );
    let state = context.snapshot().unwrap();
    assert_eq!(
        (state.reserved_files, state.reserved_bytes),
        (13, 1_325_056)
    );
    assert_eq!(packet.quotient.dimensions().unwrap(), [2048, 4]);
    context
        .store
        .check_quotient_input(&packet.quotient)
        .unwrap();
    audit.assert_main_only();
    let before_reads = audit.counts();
    let mut candidate = Vec::with_capacity(2048);
    for row in 0..2048 {
        let values = packet.quotient.try_window(row, 0, 4).unwrap();
        candidate.push(
            values
                .into_iter()
                .map(|v| v.as_canonical_u32())
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(audit.counts(), before_reads);
    assert_eq!(anchor_audit.counts(), anchor_before);
    let alpha =
        <Challenge as BasedVectorSpace<BabyBear>>::as_basis_coefficients_slice(&packet.alpha)
            .iter()
            .map(|v| v.as_canonical_u32())
            .collect::<Vec<_>>();
    let root = serde_json::to_value(&packet.main_commitment).unwrap();
    let capture = json!({
        "main":&packet.main_capture,"candidate":candidate,"alpha":alpha,
        "public":packet.public.map(|v|v.as_canonical_u32()),
        "trace_domain":{"height":packet.trace_domain.size(),"shift":packet.trace_domain.shift().as_canonical_u32()},
        "quotient_domain":{"height":packet.quotient_domain.size(),"shift":packet.quotient_domain.shift().as_canonical_u32()}
    });
    save("synthetic-capture.json", &capture);
    let effects = audit.counts();
    assert_eq!(effects[0], 1, "one actual main commitment");
    assert_eq!(&effects[1..4], &[0, 0, 0], "no extension commit or opening");
    assert_eq!(effects[4], 2, "two actual main extension tile calls");
    assert_eq!(packet.after_commit_effects, packet.after_quotient_effects);
    assert_eq!(effects, packet.after_quotient_effects);
    // An incorrect domain must fail before any fallback DFT or new commitment.
    let pcs = packet.config.pcs();
    let wrong = <_ as Pcs<Challenge, setup::Challenger>>::natural_domain_for_degree(pcs, 2048);
    let result = pcs.main_quotient_view(&packet.main_data, wrong);
    assert!(matches!(result, Err(Error::Domain)));
    assert_eq!(context.snapshot().unwrap().phase, crate::Phase::Failed);
    assert_eq!(context.snapshot().unwrap().failure, Some(Error::Domain));
    assert!(packet.quotient.try_window(0, 0, 4).is_err());
    assert_eq!(audit.counts(), effects);
    drop(packet);
    assert!(
        context
            .construct_quotient(setup::rawliteral(), &audit)
            .is_err()
    );
    assert_eq!(audit.counts(), effects);
    audit.assert_main_only();
    let controls = crate::composite::owner_controls::fixed_controls(&anchor);
    let measurement = json!({
        "raw_height":256,"main_width":2,"quotient_rows":2048,"quotient_coefficients":8192,
        "main_fast_view_fields_compared":4096,"input_commits":effects[0],
        "extension_commits":effects[1],"input_openings":effects[2],"extension_openings":effects[3],
        "coset_lde_boundary_calls":effects[4],"dft_batch_boundary_calls":effects[5],
        "mask_rng_bytes":effects[6],"salt_rng_bytes":effects[7],"main_commitment":root,
        "view_bounds_controls":3,"domain_rejections":1,"closed_owner_rejections":2,"owner_controls":controls,
        "detailed_effects":audit.detailed_counts(),"initial_salt_bytes":audit.initial_salt(),
        "reserved_files":13,"reserved_field_bytes":1_325_056,
        "proofs":0,"source_scope":"fixed synthetic Quartic construction only"
    });
    save("measurement.json", &measurement);
    measurement
}
