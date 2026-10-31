//! Actual private opening refusals under the same committed owner.
#![forbid(unsafe_code)]
use crate::{
    Context, HidingFriProverError, Phase, StorageError, diagnostics_setup as setup,
    hiding_pcs::OpeningCase,
};
use serde::Serialize;
use std::{fs::OpenOptions, io::Write, path::PathBuf, sync::Arc};

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > 16_384)
        {
            return Err(std::io::Error::other("fixed opening report cap exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(value: &impl Serialize) -> Vec<u8> {
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, value).unwrap();
    output.0
}
fn assert_effects(counts: setup::Counts, duplicate: bool) {
    assert_eq!(counts.input_commits, 1);
    assert_eq!(counts.extension_commits, 0);
    assert_eq!(counts.scalar_opens, 0);
    assert_eq!(counts.input_openings, 0);
    assert_eq!(counts.extension_openings, 0);
    assert_eq!(counts.input_multi_opens, 0);
    assert_eq!(counts.extension_multi_opens, 0);
    assert_eq!(counts.verify_calls, 0);
    assert_eq!(counts.get_matrices, if duplicate { 3 } else { 2 });
    assert_eq!(counts.mmcs_clones, 1);
    assert_eq!(counts.mask.bytes, 10_948);
    assert_eq!(counts.salt.bytes, 279_800);
    assert_eq!(counts.initial_salt_bytes, 32);
    assert_eq!(counts.dft.coset_lde_batch, 2);
    assert_eq!(counts.dft.coset_idft_batch, 0);
    assert_eq!(counts.dft.dft_batch, 0);
    assert_eq!(counts.dft.idft_batch, 0);
    assert_eq!(counts.dft.coset_dft_batch, 0);
    assert_eq!(counts.dft.lde_batch, 0);
    assert_eq!(counts.dft.coset_lde_batch_with_transform, 0);
    assert_eq!(counts.dft.coset_lde_batch_with_blocks, 0);
}

/// Two fixed actual opening calls. No flag setter or witness verdict is accepted.
#[allow(
    clippy::assertions_on_constants,
    reason = "The selected diagnostic requires release and unwinding."
)]
pub fn fixed_private_opening_controls() {
    assert!(!cfg!(debug_assertions), "release diagnostic required");
    assert!(
        cfg!(panic = "unwind"),
        "actual duplicate guard unwind required"
    );
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let output = directory.join("measurement.json");
    assert!(!output.exists(), "fresh exclusive output required");
    let mut cases = Vec::new();
    for selected in [
        OpeningCase::ExcessPoints,
        OpeningCase::SharedPrivateRequests,
    ] {
        let duplicate = selected == OpeningCase::SharedPrivateRequests;
        let (anchor, anchor_audit) = setup::anchor();
        let anchor_before = anchor_audit.detailed_counts();
        let (pcs, audit) = setup::base();
        let context = Arc::new(Context::new(pcs, setup::challenger(), &anchor).unwrap());
        audit.bind_owner(&context);
        let observation = context
            .opening_prefix(setup::rawliteral(), selected)
            .unwrap();
        let expected_cause = if duplicate {
            StorageError::Unwind
        } else {
            StorageError::Mask(HidingFriProverError::HidingBudgetExceeded {
                mask_height: 256,
                num_queries: 64,
                num_opening_points: 17,
                extension_degree: 4,
            })
        };
        assert_eq!(observation.cause, expected_cause);
        assert_eq!(observation.original_opened, duplicate);
        assert_eq!(observation.clone_opened, duplicate);
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Failed);
        assert_eq!(state.failure, Some(expected_cause.clone()));
        assert_eq!(
            (state.reserved_files, state.reserved_bytes),
            (13, 1_325_056)
        );
        assert!(state.cleanup_failures.is_empty());
        let flags = [observation.original_opened, observation.clone_opened];
        for alias in [observation.lease.clone(), observation.lease] {
            assert_eq!(alias.try_window(0, 0, 2), Err(StorageError::Failed));
        }
        assert_eq!(
            context.snapshot().unwrap().failure,
            Some(expected_cause.clone())
        );
        let effects = audit.detailed_counts();
        assert_effects(effects, duplicate);
        assert!(context.prove(setup::rawliteral()).is_err());
        assert_eq!(audit.detailed_counts(), effects);
        assert_eq!(context.snapshot().unwrap().failure, Some(expected_cause));
        assert_eq!(anchor_audit.detailed_counts(), anchor_before);
        assert_eq!(audit.roots().len(), 1);
        cases.push(serde_json::json!({
            "case": if duplicate { "shared_private_requests" } else { "excess_points" },
            "actual_pcs_open_calls":1,
            "supplied_points_per_request":if duplicate { vec![1,1] } else { vec![17] },
            "shared_private_flags_after":flags,
            "next_challenger_sample_equal":true,
            "public_challenger_clone_samples":2,
            "actual_committed_lease_aliases_refused":2,
            "reentry_refused_without_protocol_effects":true,
            "reserved_files":state.reserved_files,
            "reserved_field_bytes":state.reserved_bytes,
            "observations":effects,
            "actual_main_root":audit.roots()[0],
            "delivered_rng_fingerprints":audit.delivered_fingerprints()
        }));
    }
    let bytes = encode(&serde_json::json!({
        "profile":"quartic-private-consumption-v1", "cases":cases,
        "inner_mmcs_openings":0,"completed_proofs":0,"verifier_calls":0,
        "scope":"actual private preflight and shared consumption refusals, not proof verification"
    }));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}
