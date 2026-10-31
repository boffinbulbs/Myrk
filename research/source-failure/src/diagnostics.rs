//! Two actual live filesystem failures. No successful proof is generated.
#![forbid(unsafe_code)]
use crate::{
    Context, Phase, StorageError,
    composite::faults::{Kind, Run},
    context::OwnedError,
    diagnostics_setup as setup,
};
use kova_storage_matrix::StorageError as AccessError;
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
            return Err(std::io::Error::other("fixed report cap exceeded"));
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
fn assert_effects(observed: setup::Counts, auxiliary: bool) {
    assert_eq!(observed.input_commits, if auxiliary { 2 } else { 1 });
    assert_eq!(observed.extension_commits, 0);
    assert_eq!(observed.scalar_opens, 0);
    assert_eq!(observed.input_openings, 0);
    assert_eq!(observed.extension_openings, 0);
    assert_eq!(observed.input_multi_opens, 0);
    assert_eq!(observed.extension_multi_opens, 0);
    assert_eq!(observed.verify_calls, 0);
    assert_eq!(observed.get_matrices, 1);
    assert_eq!(observed.mmcs_clones, 1);
    assert_eq!(observed.dft.coset_lde_batch, if auxiliary { 3 } else { 2 });
    assert_eq!(observed.dft.coset_idft_batch, if auxiliary { 8 } else { 0 });
    assert_eq!(observed.dft.dft_batch, if auxiliary { 8 } else { 0 });
    assert_eq!(observed.dft.idft_batch, 0);
    assert_eq!(observed.dft.coset_dft_batch, 0);
    assert_eq!(observed.dft.lde_batch, 0);
    assert_eq!(observed.dft.coset_lde_batch_with_transform, 0);
    assert_eq!(observed.dft.coset_lde_batch_with_blocks, 0);
    assert_eq!(
        observed.mask.bytes,
        if auxiliary { 124_664 } else { 107_188 }
    );
    assert_eq!(
        observed.salt.bytes,
        if auxiliary { 2_517_396 } else { 279_800 }
    );
}

/// Fixed faults modify real owned files and never supply a proof acceptance predicate.
#[allow(
    clippy::assertions_on_constants,
    reason = "The diagnostic requires the selected release unwind binary."
)]
pub fn fixed_live_source_failures() {
    assert!(!cfg!(debug_assertions), "release diagnostic required");
    assert!(cfg!(panic = "unwind"), "actual unwind boundary required");
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("measurement.json");
    assert!(!path.exists(), "fresh exclusive output required");
    let mut records = Vec::new();
    for kind in [Kind::TruncatedQuotient, Kind::AuxiliaryCollision] {
        let (anchor, anchor_audit) = setup::anchor();
        let before_anchor = anchor_audit.detailed_counts();
        let (pcs, audit) = setup::base();
        let context = Arc::new(Context::new(pcs, setup::challenger(), &anchor).unwrap());
        audit.bind_owner(&context);
        let fault = Run::new(kind);
        let auxiliary = kind == Kind::AuxiliaryCollision;
        let cause = if auxiliary {
            StorageError::Io(std::io::ErrorKind::AlreadyExists)
        } else {
            StorageError::Access(AccessError::Length)
        };
        if auxiliary {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                context.prove_fault(setup::rawliteral(), &fault)
            }));
            let payload = match result {
                Err(payload) => payload,
                Ok(_) => panic!("the actual infallible storage collision must unwind"),
            };
            assert_eq!(payload.downcast_ref::<StorageError>(), Some(&cause));
        } else {
            match context.prove_fault(setup::rawliteral(), &fault) {
                Err(OwnedError::Storage { phase, source }) => {
                    assert_eq!(phase, "quotient commitment");
                    assert_eq!(source, cause);
                }
                _ => panic!("actual truncated source must return its typed failure"),
            }
        }
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Failed);
        assert_eq!(state.failure, Some(cause.clone()));
        assert_eq!(
            (state.reserved_files, state.reserved_bytes),
            (13, 1_325_056)
        );
        assert!(state.cleanup_failures.is_empty());
        assert_eq!(fault.assert_closed_leases(cause.clone()), 2);
        fault.assert_source_metadata(!auxiliary);
        assert_eq!(fault.remove_preserved_sentinel().unwrap(), auxiliary);
        let effects = audit.detailed_counts();
        assert_effects(effects, auxiliary);
        assert!(context.prove(setup::rawliteral()).is_err());
        assert_eq!(audit.detailed_counts(), effects);
        assert_eq!(context.snapshot().unwrap().failure, Some(cause));
        assert_eq!(anchor_audit.detailed_counts(), before_anchor);
        records.push(serde_json::json!({
            "case": if auxiliary { "auxiliary_collision" } else { "truncated_quotient" },
            "failure_boundary": if auxiliary { "actual unwind" } else { "typed return" },
            "expected_first_cause": if auxiliary { "Io(AlreadyExists)" } else { "Access(Length)" },
            "closed_actual_lease_aliases": 2,
            "sentinel_preserved_and_removed": auxiliary,
            "reentry_refused_without_protocol_effects": true,
            "reserved_files": state.reserved_files,
            "reserved_field_bytes": state.reserved_bytes,
            "observations": effects,
            "actual_commit_roots": audit.roots(),
            "delivered_rng_fingerprints": audit.delivered_fingerprints()
        }));
    }
    let bytes = encode(&serde_json::json!({
        "profile": "quartic-live-source-failures-v1", "cases": records,
        "completed_proofs": 0, "verifier_calls": 0,
        "scope": "actual file failures and source owner closure, not verifier rejection"
    }));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}
