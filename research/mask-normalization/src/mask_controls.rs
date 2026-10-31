// Whitebox owner fixtures for the new mask entry, not committed provenance.
// Each fixture writes a constant sealed source without running a main proof.
use super::*;
use crate::diagnostics_setup::{self as setup, Anchor};
use p3_commit::PolynomialSpace;
use p3_field::{PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset};
use serde_json::{Value, json};

fn fixture(anchor: &Anchor) -> (CompositeStore, QuotientInput) {
    let store = CompositeStore::new(anchor).unwrap();
    store
        .transition(Phase::Ready, Phase::MainCommitted)
        .unwrap();
    let mut writer = store.begin_quotient_evaluations().unwrap();
    for row in 0..2048 {
        writer.write_row(row, &[BabyBear::ONE; 4]).unwrap();
    }
    let input = writer.finish().unwrap();
    (store, input)
}

fn domain() -> TwoAdicMultiplicativeCoset<BabyBear> {
    TwoAdicMultiplicativeCoset::new(BabyBear::GENERATOR, 11).unwrap()
}

fn shifts() -> [BabyBear; 8] {
    domain()
        .split_domains(8)
        .into_iter()
        .map(|d| BabyBear::GENERATOR / d.shift())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn failed(store: &CompositeStore) {
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.phase, Phase::Failed);
    assert_eq!(
        (snapshot.reserved_files, snapshot.reserved_bytes),
        (13, 1_325_056)
    );
    assert!(store.check_phase(Phase::QuotientReady).is_err());
    assert!(store.begin_quotient_evaluations().is_err());
}

pub(crate) fn fixed_controls(anchor: &Anchor) -> Value {
    let mut names = Vec::new();
    {
        let (store, input) = fixture(anchor);
        let other = CompositeStore::new(anchor).unwrap();
        let (pcs, audit) = setup::base();
        let before = audit.detailed_counts();
        assert_eq!(
            other.begin_quotient_source(&input, shifts()),
            Err(Error::Owner)
        );
        store.0.state.lock().unwrap().entries[10].shape = [4096, 7];
        assert_eq!(
            store.begin_quotient_source(&input, shifts()),
            Err(Error::Phase)
        );
        store.0.state.lock().unwrap().entries[10].shape = [4096, 8];
        store.0.state.lock().unwrap().phase = Phase::QuotientCommitted;
        assert_eq!(
            store.begin_quotient_source(&input, shifts()),
            Err(Error::Phase)
        );
        store.0.state.lock().unwrap().phase = Phase::QuotientReady;
        store.begin_quotient_source(&input, shifts()).unwrap();
        assert_eq!(
            store.begin_quotient_source(&input, shifts()),
            Err(Error::Phase)
        );
        let result = store.extend_quotient_owned(
            &setup::counting_dft(&audit),
            RowMajorMatrix::new(vec![BabyBear::ONE; 2048], 8),
            &[BabyBear::ZERO; 2048],
            3,
            BabyBear::ZERO,
        );
        assert!(matches!(result, Err(Error::Domain)));
        failed(&store);
        assert!(input.try_window(0, 0, 4).is_err());
        assert_eq!(audit.detailed_counts(), before);
        drop(pcs);
        names.extend([
            "foreign_owner",
            "reserved_chunk_shape",
            "wrong_phase",
            "duplicate_claim",
            "wrong_shift_before_dft",
        ]);
    }
    {
        let (store, input) = fixture(anchor);
        let (_, audit) = setup::base();
        store.begin_quotient_source(&input, shifts()).unwrap();
        let before = audit.detailed_counts();
        let result = store.extend_quotient_owned(
            &setup::counting_dft(&audit),
            RowMajorMatrix::new(vec![BabyBear::ONE; 8], 8),
            &[BabyBear::ZERO; 2048],
            3,
            shifts()[0],
        );
        assert!(matches!(result, Err(Error::Shape)));
        assert_eq!(audit.detailed_counts(), before);
        failed(&store);
        names.push("chunk_shape_before_dft");
    }
    {
        let (store, input) = fixture(anchor);
        let (pcs, audit) = setup::base();
        let pcs = pcs.with_storage(store.clone());
        let before = audit.detailed_counts();
        let wrong = TwoAdicMultiplicativeCoset::new(BabyBear::ONE, 11).unwrap();
        assert!(matches!(
            pcs.commit_quotient_source(wrong, input),
            Err(Error::Domain)
        ));
        assert_eq!(audit.detailed_counts(), before);
        assert_eq!(store.snapshot().unwrap().phase, Phase::QuotientReady);
        names.push("domain_before_entropy");
    }
    let mut source_failures = Vec::new();
    for mode in ["noncanonical_source", "short_source"] {
        let (store, input) = fixture(anchor);
        let (pcs, audit) = setup::base();
        let pcs = pcs.with_storage(store.clone());
        let mut file = OpenOptions::new().write(true).open(store.path(12)).unwrap();
        if mode == "noncanonical_source" {
            file.write_all(&BabyBear::ORDER_U32.to_le_bytes()).unwrap();
        } else {
            file.set_len(1).unwrap();
        }
        file.sync_all().unwrap();
        drop(file);
        assert!(matches!(
            pcs.commit_quotient_source(domain(), input),
            Err(Error::Access(_))
        ));
        failed(&store);
        let counts = audit.detailed_counts();
        assert_eq!(counts.input_commits, 0);
        assert_eq!(counts.dft, setup::zero_dft_counts());
        assert!(counts.mask.bytes > 0);
        assert_eq!(counts.salt.bytes, counts.initial_salt_bytes);
        source_failures.push(json!({"name":mode,"counts":counts}));
        names.push(mode);
    }
    let late;
    {
        let (store, input) = fixture(anchor);
        let (pcs, audit) = setup::base();
        let pcs = pcs.with_storage(store.clone());
        let sentinel = store.path(10);
        fs::write(&sentinel, b"unowned late chunk sentinel").unwrap();
        assert!(matches!(
            pcs.commit_quotient_source(domain(), input),
            Err(Error::Io(std::io::ErrorKind::AlreadyExists))
        ));
        failed(&store);
        let snapshot = store.snapshot().unwrap();
        assert!(
            snapshot.entries[3..10]
                .iter()
                .all(|e| e.state == FileState::Complete)
        );
        assert_eq!(snapshot.entries[10].state, FileState::Uncreated);
        assert!(!snapshot.entries[10].owned);
        assert_eq!(fs::read(&sentinel).unwrap(), b"unowned late chunk sentinel");
        let counts = audit.detailed_counts();
        assert_eq!(counts.input_commits, 0);
        assert_eq!(counts.dft.dft_batch, 8);
        assert_eq!(counts.dft.coset_idft_batch, 8);
        assert_eq!(counts.salt.bytes, counts.initial_salt_bytes);
        late = json!({"counts":counts,"completed_chunks":7,"uncreated_chunks":1});
        drop(pcs);
        drop(store);
        assert_eq!(fs::read(&sentinel).unwrap(), b"unowned late chunk sentinel");
        // Only this fixture owns the sentinel, independently of failed create_new.
        fs::remove_file(&sentinel).unwrap();
        fs::remove_dir(sentinel.parent().unwrap()).unwrap();
        names.push("late_chunk_collision_preserves_sentinel");
    }
    json!({"completed":names,"sealed_constant_fixtures":6,"empty_foreign_owners":1,
        "actual_main_commitments":0,"actual_quotient_commits":0,
        "source_failures":source_failures,"late_file_failure":late,
        "scope":"whitebox storage and source-entry controls, not committed provenance"})
}
