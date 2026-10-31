// Synthetic construction observations. No wallet, ledger or verifier entry.
use crate::diagnostics_setup as setup;
use p3_commit::UnivariateStarkPcs;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

pub fn fixed_masking() -> Value {
    let (anchor, anchor_audit) = setup::anchor();
    let anchor_before = anchor_audit.detailed_counts();
    let (pcs, audit) = setup::base();
    let context: setup::OwnedContext = Context::new(pcs, setup::challenger(), &anchor).unwrap();
    let packet = context.construct_quotient(setup::rawliteral()).unwrap();
    assert_eq!(
        context.snapshot().unwrap().phase,
        crate::Phase::QuotientReady
    );
    let before_mask = audit.detailed_counts();

    // Only the diagnostic reference materializes the full small quotient.
    // The candidate accepts the original sealed, non-Clone source instead.
    let mut reference_values = Vec::with_capacity(8192);
    for row in 0..2048 {
        reference_values.extend(packet.quotient.try_window(row, 0, 4).unwrap());
    }
    assert_eq!(reference_values.len(), 8192);
    let quotient_domain = packet.quotient_domain;
    let committed = packet.commit().unwrap();
    let snapshot = context.snapshot().unwrap();
    assert_eq!(snapshot.phase, crate::Phase::QuotientCommitted);
    assert_eq!(
        (snapshot.reserved_files, snapshot.reserved_bytes),
        (13, 1_325_056)
    );
    assert!(
        snapshot.entries[3..11]
            .iter()
            .all(|e| e.state == crate::composite::FileState::Complete)
    );
    assert_eq!(
        snapshot.entries[11].state,
        crate::composite::FileState::Planned
    );

    // This is the original dense PCS route in the same nominal backend, with
    // fresh identical synthetic seeds and no file-backed reference namespace.
    let (reference, reference_audit) = setup::base();
    let main_domain =
        <_ as Pcs<Challenge, setup::Challenger>>::natural_domain_for_degree(&reference, 512);
    let (reference_main, reference_main_data) = <_ as Pcs<Challenge, setup::Challenger>>::commit(
        &reference,
        [(main_domain, RowMajorMatrix::new(setup::rawliteral(), 2))],
    )
    .unwrap();
    assert_eq!(committed.main_commitment, reference_main);
    assert_eq!(before_mask.mask, reference_audit.detailed_counts().mask);
    assert_eq!(before_mask.salt, reference_audit.detailed_counts().salt);
    let (reference_root, reference_data) =
        <_ as UnivariateStarkPcs<Challenge, setup::Challenger>>::commit_quotient(
            &reference,
            quotient_domain,
            RowMajorMatrix::new(reference_values, 4),
            8,
        )
        .unwrap();
    assert_eq!(committed.quotient_commitment, reference_root);

    let candidate_pcs = committed.config.pcs();
    let main = candidate_pcs.diagnostic_matrices(&committed.main_data);
    let reference_main = reference.diagnostic_matrices(&reference_main_data);
    let candidate = candidate_pcs.diagnostic_matrices(&committed.quotient_data);
    let retained = reference.diagnostic_matrices(&reference_data);
    assert_eq!(
        (
            main.len(),
            reference_main.len(),
            candidate.len(),
            retained.len()
        ),
        (1, 1, 8, 8)
    );
    let main_lease = Stored::clone(main[0]);
    let chunk_lease = Stored::clone(candidate[7]);
    let mut compared = 0;
    for row in 0..4096 {
        assert_eq!(
            main[0].try_window(row, 0, 6).unwrap(),
            reference_main[0].row_slice(row).unwrap().as_ref()
        );
        for chunk in 0..8 {
            assert_eq!(
                candidate[chunk].try_window(row, 0, 8).unwrap(),
                retained[chunk].row_slice(row).unwrap().as_ref()
            );
            compared += 8;
        }
    }
    assert_eq!(compared, 262144);
    drop((main, candidate));
    let c = audit.detailed_counts();
    let r = reference_audit.detailed_counts();
    assert_eq!((c.input_commits, r.input_commits), (2, 2));
    assert_eq!(
        (
            c.extension_commits,
            c.input_openings,
            c.extension_openings,
            c.verify_calls
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        (
            r.extension_commits,
            r.input_openings,
            r.extension_openings,
            r.verify_calls
        ),
        (0, 0, 0, 0)
    );
    assert_eq!((c.mmcs_clones, r.mmcs_clones), (1, 1));
    assert_eq!((c.dft.coset_lde_batch, r.dft.coset_lde_batch), (2, 1));
    assert_eq!((c.dft.coset_idft_batch, r.dft.coset_idft_batch), (8, 8));
    assert_eq!((c.dft.dft_batch, r.dft.dft_batch), (8, 8));
    assert_eq!((c.mask, c.salt), (r.mask, r.salt));
    assert_eq!(
        audit.delivered_fingerprints(),
        reference_audit.delivered_fingerprints()
    );
    let marker = candidate_pcs.diagnostic_mask_marker();
    assert_eq!(marker, reference.diagnostic_mask_marker());
    assert_eq!(
        audit.delivered_fingerprints(),
        reference_audit.delivered_fingerprints()
    );
    drop(committed);
    assert!(main_lease.try_window(0, 0, 6).is_err());
    assert!(chunk_lease.try_window(0, 0, 8).is_err());
    assert_eq!(context.snapshot().unwrap().phase, crate::Phase::Failed);
    assert_eq!(anchor_audit.detailed_counts(), anchor_before);
    let controls = crate::composite::mask_controls::fixed_controls(&anchor);
    let result = json!({
        "candidate_input_commits":2,"reference_input_commits":2,"proofs":0,
        "chunk_fields_compared":compared,"main_fields_compared":24576,
        "main_roots_equal":true,"quotient_roots_equal":true,"delivered_rng_fingerprints_equal":true,
        "continuing_mask_marker_equal":true,"candidate":c,"retained_dense":r,
        "marker_draws_per_side":8,"marker_bytes_per_side":32,
        "candidate_compact_counts":audit.counts(),"initial_salt_bytes":audit.initial_salt(),
        "reserved_files":13,"reserved_field_bytes":1_325_056,
        "post_attempt_closed_leases":2,"controls":controls,
        "scope":"fixed synthetic coupled commitment equivalence, no opening or proof"
    });
    let bytes = serde_json::to_vec_pretty(&result).unwrap();
    assert!(bytes.len() <= 16384);
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("measurement.json"))
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    result
}
