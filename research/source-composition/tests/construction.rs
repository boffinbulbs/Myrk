include!("common.rs");
use sha3::{Digest, Sha3_256};

fn source_values() -> impl Iterator<Item = BabyBear> {
    (5..261).flat_map(|n| {
        let a = BabyBear::from_u32(n);
        [a, a.exp_u64(4)]
    })
}
fn domain() -> TwoAdicMultiplicativeCoset<BabyBear> {
    TwoAdicMultiplicativeCoset::new(BabyBear::ONE, 9).unwrap()
}
fn quotient_domain() -> TwoAdicMultiplicativeCoset<BabyBear> {
    TwoAdicMultiplicativeCoset::new(BabyBear::GENERATOR, 11).unwrap()
}
fn quotient() -> RowMajorMatrix<BabyBear> {
    // Canonical synthetic evaluations exercise storage and coupled masks.
    // These values are not claimed to be an AIR quotient.
    RowMajorMatrix::new(
        (0..8192)
            .map(|i| BabyBear::from_u32((i * 17 + 29) as u32))
            .collect(),
        4,
    )
}
fn counts(o: &Observation) -> [usize; 3] {
    [
        &o.audit.input_commits,
        &o.audit.extension_commits,
        &o.audit.opens,
    ]
    .map(|c| c.load(Ordering::SeqCst))
}
fn retained(o: &Observation) -> Vec<Vec<Vec<u32>>> {
    o.audit.fields.lock().unwrap().clone()
}
fn write(path: &str, bytes: &[u8]) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn composite_roots_fields_entropy_and_failed_read_closure() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    fs::create_dir_all(&directory).unwrap();
    let (anchor, anchor_o) = anchor();
    let amask = anchor_o.mask.bytes();
    let asalt = anchor_o.salt.bytes();
    let store = CompositeStore::new(&anchor).unwrap();
    let s = store.snapshot().unwrap();
    assert_eq!((s.reserved_files, s.reserved_bytes), (12, 1_292_288));
    assert!(s.entries.iter().all(|e| e.state == FileState::Planned));
    let (base, owned_o) = base(64);
    *owned_o.audit.owner.lock().unwrap() = Some(store.clone());
    let owned: Owned = base.with_storage(store.clone());
    let (reference, dense_o) = dense();
    let raw = store.write_raw(source_values()).unwrap();
    let duplicate = raw.clone();
    let guard = store.begin_attempt(&raw).unwrap();
    let bad = TwoAdicMultiplicativeCoset::new(BabyBear::ONE, 8).unwrap();
    assert_eq!(
        owned.commit_composite_main(bad, duplicate).err(),
        Some(Error::Domain)
    );
    assert_eq!(counts(&owned_o), [0, 0, 0]);
    assert!(owned_o.mask.bytes().is_empty());
    assert_eq!(owned_o.salt.bytes(), owned_o.initial_salt);

    let (mr, md) = owned.commit_composite_main(domain(), raw).unwrap();
    let (dr, dd) =
        <_ as Pcs<Challenge, Challenger>>::commit(&reference, [(domain(), air::trace())]).unwrap();
    assert_eq!(mr, dr);
    assert_eq!(store.snapshot().unwrap().phase, Phase::MainCommitted);
    assert_eq!(owned_o.mask.bytes(), dense_o.mask.bytes());
    assert_eq!(owned_o.salt.bytes(), dense_o.salt.bytes());

    let before = (owned_o.mask.bytes(), owned_o.salt.bytes());
    assert!(
        owned
            .commit_composite_quotient::<Challenger>(quotient_domain(), quotient(), 7)
            .is_err()
    );
    assert_eq!((owned_o.mask.bytes(), owned_o.salt.bytes()), before);
    assert_eq!(counts(&owned_o), [1, 0, 0]);
    assert_eq!(store.snapshot().unwrap().phase, Phase::MainCommitted);
    let (qr, qd) = owned
        .commit_composite_quotient::<Challenger>(quotient_domain(), quotient(), 8)
        .unwrap();
    let (eqr, eqd) = <_ as UnivariateStarkPcs<Challenge, Challenger>>::commit_quotient(
        &reference,
        quotient_domain(),
        quotient(),
        8,
    )
    .unwrap();
    assert_eq!(qr, eqr);
    assert_eq!(store.snapshot().unwrap().phase, Phase::QuotientCommitted);
    assert_eq!(owned_o.mask.bytes(), dense_o.mask.bytes());
    assert_eq!(owned_o.salt.bytes(), dense_o.salt.bytes());

    let before = (owned_o.mask.bytes(), owned_o.salt.bytes());
    assert!(owned.commit_composite_auxiliary::<Challenger>(bad).is_err());
    assert_eq!((owned_o.mask.bytes(), owned_o.salt.bytes()), before);
    assert_eq!(counts(&owned_o), [2, 0, 0]);
    assert_eq!(store.snapshot().unwrap().phase, Phase::QuotientCommitted);
    let (ar, ad) = owned
        .commit_composite_auxiliary::<Challenger>(domain())
        .unwrap();
    let (ear, ead) =
        <_ as UnivariateStarkPcs<Challenge, Challenger>>::get_opt_randomization_poly_commitment(
            &reference,
            [domain()],
        )
        .unwrap()
        .unwrap();
    assert_eq!(ar, ear);
    let s = store.snapshot().unwrap();
    assert_eq!(s.phase, Phase::AuxiliaryCommitted);
    assert!(s.entries.iter().all(|e| e.state == FileState::Complete));
    assert_eq!(counts(&owned_o), [3, 0, 0]);
    assert_eq!(counts(&dense_o), [3, 0, 0]);
    assert_eq!(owned_o.mask.bytes(), dense_o.mask.bytes());
    assert_eq!(owned_o.salt.bytes(), dense_o.salt.bytes());
    assert_eq!(retained(&owned_o), retained(&dense_o));

    // These are actual retained prefix views of committed private data.
    let read_domain = TwoAdicMultiplicativeCoset::new(BabyBear::GENERATOR, 12).unwrap();
    let main_view =
        <_ as UnivariateStarkPcs<Challenge, Challenger>>::get_evaluations_on_domain_no_random(
            &owned,
            &md,
            0,
            read_domain,
        );
    let q_view =
        <_ as UnivariateStarkPcs<Challenge, Challenger>>::get_evaluations_on_domain_no_random(
            &owned,
            &qd,
            7,
            read_domain,
        );
    let a_view =
        <_ as UnivariateStarkPcs<Challenge, Challenger>>::get_evaluations_on_domain_no_random(
            &owned,
            &ad,
            0,
            read_domain,
        );
    assert_eq!(main_view.row(0).unwrap().into_iter().count(), 6);
    assert_eq!(q_view.row(0).unwrap().into_iter().count(), 8);
    assert_eq!(a_view.row(0).unwrap().into_iter().count(), 8);
    let roots = serde_json::json!({"main":mr,"quotient":qr,"auxiliary":ar});
    let fields = retained(&owned_o);
    let bytes = fields
        .iter()
        .flatten()
        .flatten()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();
    assert_eq!(bytes.len(), 1_277_952);
    let hashes = fields
        .iter()
        .flatten()
        .map(|m| {
            let b = m.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>();
            Sha3_256::digest(b)
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    let measurement = serde_json::json!({"input_mmcs_commits":6,"fri_mmcs_commits":0,"pcs_openings":0,"stark_proofs":0,
        "reserved_files":s.reserved_files,"reserved_bytes":s.reserved_bytes,"captured_bytes":bytes.len(),"matrix_sha3_256":hashes});
    write("fields.bin", &bytes);
    write("roots.json", &serde_json::to_vec(&roots).unwrap());
    write(
        "measurement.json",
        &serde_json::to_vec(&measurement).unwrap(),
    );
    drop(guard);
    assert_eq!(store.snapshot().unwrap().phase, Phase::Failed);
    for refused in [
        catch_unwind(AssertUnwindSafe(|| {
            main_view.row(0).unwrap().into_iter().collect::<Vec<_>>()
        })),
        catch_unwind(AssertUnwindSafe(|| {
            q_view.row(0).unwrap().into_iter().collect::<Vec<_>>()
        })),
        catch_unwind(AssertUnwindSafe(|| {
            a_view.row(0).unwrap().into_iter().collect::<Vec<_>>()
        })),
    ] {
        assert!(refused.is_err());
    }
    assert_eq!(
        store.clone().snapshot().unwrap().reserved_bytes,
        RESERVED_BYTES
    );
    assert!(store.cleanup_orphans().unwrap().is_empty());
    assert_eq!(store.snapshot().unwrap().entries, s.entries);
    assert_eq!(counts(&owned_o), [3, 0, 0]);
    assert_eq!(counts(&dense_o), [3, 0, 0]);
    drop((dd, eqd, ead));
    assert_eq!(anchor_o.mask.bytes(), amask);
    assert_eq!(anchor_o.salt.bytes(), asalt);
    *owned_o.audit.owner.lock().unwrap() = None;
}

#[test]
fn shape_ownership_and_raw_unwind_controls_do_not_commit() {
    let (anchor, observation) = anchor();
    let before_mask = observation.mask.bytes();
    let before_salt = observation.salt.bytes();
    let first = CompositeStore::new(&anchor).unwrap();
    let second = CompositeStore::new(&anchor).unwrap();
    let a = first.write_raw(source_values()).unwrap();
    let b = second.write_raw(source_values()).unwrap();
    assert!(matches!(first.begin_attempt(&b), Err(Error::Owner)));
    assert_eq!(first.snapshot().unwrap().phase, Phase::RawReady);
    assert!(
        catch_unwind(AssertUnwindSafe(
            || first.store(RowMajorMatrix::new(vec![BabyBear::ONE], 1))
        ))
        .is_err()
    );
    assert_eq!(first.snapshot().unwrap().phase, Phase::RawReady);
    let attempt = first.begin_attempt(&a).unwrap();
    assert!(matches!(first.begin_attempt(&a), Err(Error::Phase)));
    drop(attempt);
    assert!(matches!(first.begin_attempt(&a), Err(Error::Failed)));

    let short = CompositeStore::new(&anchor).unwrap();
    let clone = short.clone();
    assert!(short.write_raw([BabyBear::ONE; 3]).is_err());
    let snapshot = clone.snapshot().unwrap();
    assert_eq!(snapshot.phase, Phase::Failed);
    assert_eq!(
        (snapshot.reserved_files, snapshot.reserved_bytes),
        (12, 1_292_288)
    );
    assert_ne!(snapshot.entries[0].state, FileState::Complete);
    assert!(matches!(
        clone.write_raw(source_values()),
        Err(Error::Failed)
    ));

    let unwind = CompositeStore::new(&anchor).unwrap();
    let clone = unwind.clone();
    let values = (0..512).map(|i| {
        assert_ne!(i, 3, "injected raw iterator unwind");
        BabyBear::ONE
    });
    assert!(catch_unwind(AssertUnwindSafe(|| unwind.write_raw(values))).is_err());
    let snapshot = clone.snapshot().unwrap();
    assert_eq!(snapshot.phase, Phase::Failed);
    assert_eq!(
        (snapshot.reserved_files, snapshot.reserved_bytes),
        (12, 1_292_288)
    );
    assert_ne!(snapshot.entries[0].state, FileState::Complete);
    assert_eq!(counts(&observation), [0, 0, 0]);
    assert_eq!(observation.mask.bytes(), before_mask);
    assert_eq!(observation.salt.bytes(), before_salt);
}
