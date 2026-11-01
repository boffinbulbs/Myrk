//! Finite actual raw admission controls, distinct from natural OOD sampling.
#![forbid(unsafe_code)]
use crate::{
    DomainError, Phase, StorageError,
    composite::{Challenge, Stored},
    diagnostics_setup as setup,
};
use p3_baby_bear::BabyBear as F;
use p3_field::{PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset};
use std::{
    fs::OpenOptions,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(crate) struct TraceObservation {
    pub cause: DomainError,
    pub lease: Stored,
    pub flag_before: bool,
    pub flag_after: bool,
    pub before_guard: setup::Counts,
    pub after_guard: setup::Counts,
}

struct Deferred {
    initialized: Arc<AtomicUsize>,
}
impl IntoIterator for Deferred {
    type Item = Result<F, kova_fallible_input::Error>;
    type IntoIter = std::iter::Empty<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.initialized.fetch_add(1, Ordering::SeqCst);
        std::iter::empty()
    }
}

pub fn trace_domain_controls() {
    assert_eq!(
        std::env::var("KOVA_TRACE_DOMAIN_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let raw = TwoAdicMultiplicativeCoset::new(F::ONE, 8).unwrap();
    let expected = DomainError::RawTracePoint { trace_height: 256 };
    for point in [1, 2_013_265_920, 0x6745_6167] {
        assert_eq!(
            crate::trace_admission::admit_raw(raw, Challenge::from(F::from_u32(point))),
            Err(expected)
        );
    }
    for point in [0, 31, 0x6884_42f9] {
        assert_eq!(
            crate::trace_admission::admit_raw(raw, Challenge::from(F::from_u32(point))),
            Ok(())
        );
    }
    let (base, audit) = setup::base();
    let (anchor, _) = setup::anchor();
    let context = Arc::new(crate::Context::new(base, setup::challenger(), &anchor).unwrap());
    audit.bind_owner(&context);
    let observation = context
        .trace_domain_refusal(setup::rawliteral().into_iter().map(Ok), &audit)
        .unwrap();
    assert_eq!(observation.cause, expected);
    assert!(!observation.flag_before && !observation.flag_after);
    assert_eq!(observation.before_guard, observation.after_guard);
    assert!(observation.lease.try_window(0, 0, 1).is_err());
    let state = context.snapshot().unwrap();
    assert_eq!(state.phase, Phase::Failed);
    assert_eq!(state.failure, Some(StorageError::OpeningDomain(expected)));
    assert_eq!(
        (state.reserved_files, state.reserved_bytes),
        (13, 1_325_056)
    );
    let initialized = Arc::new(AtomicUsize::new(0));
    let reentry = context.try_prove(Deferred {
        initialized: initialized.clone(),
    });
    assert!(matches!(
        reentry,
        Err(crate::OwnedError::Storage {
            source: StorageError::Failed,
            ..
        })
    ));
    assert_eq!(initialized.load(Ordering::SeqCst), 0);
    assert_eq!(context.snapshot().unwrap().failure, state.failure);
    let counts = audit.detailed_counts();
    assert_eq!(
        (
            counts.input_commits,
            counts.extension_commits,
            counts.verify_calls
        ),
        (1, 0, 0)
    );
    assert_eq!(
        (
            counts.input_multi_opens,
            counts.extension_multi_opens,
            counts.scalar_opens
        ),
        (0, 0, 0)
    );
    assert_eq!(counts.mmcs_clones, 1);
    assert_eq!(audit.roots().len(), 1);
    let result = serde_json::json!({
        "format": "kova.trace-domain.native.v1", "literal_controls": 6,
        "same_owner_refusals": 1, "flag_before": observation.flag_before,
        "flag_after": observation.flag_after, "guard_counts_equal": true,
        "failed_reentries": 1, "producer_initializations": initialized.load(Ordering::SeqCst),
        "reserved_files": state.reserved_files, "reserved_bytes": state.reserved_bytes,
        "counts": counts, "proofs_produced": 0, "live_ood_samples": 0,
        "shared_read_closed": true
    });
    let encoded = serde_json::to_vec(&result).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("results/native-v1.json");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    output.write_all(&encoded).unwrap();
    println!("{}", String::from_utf8(encoded).unwrap());
}
