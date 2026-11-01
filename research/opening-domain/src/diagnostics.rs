//! Finite actual admission controls. No proof generation or healthy verifier replay.
#![forbid(unsafe_code)]
use crate::composite::{Challenge, Stored};
use crate::{DomainError, OpeningChecked, OpeningVerifyError, diagnostics_setup as setup};
use p3_baby_bear::BabyBear as F;
use p3_commit::{CommitmentOpening, Pcs, UnivariateStarkPcs};
use p3_field::{Field, PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset};
use p3_matrix::dense::RowMajorMatrix;
use std::{fs::OpenOptions, io::Write, sync::Arc};

pub(crate) struct PrivateObservation {
    pub cause: DomainError,
    pub lease: Stored,
    pub flag_before: bool,
    pub flag_after_refusal: bool,
    pub flag_after_shared_requests: bool,
}

fn literal_cases() -> usize {
    let mut cases = 0;
    // Independent canonical literals for GENERATOR and its additive inverse.
    assert_eq!(F::GENERATOR, F::from_u32(31));
    for point in [31, 2_013_265_890] {
        let matrix = RowMajorMatrix::new(vec![F::ZERO; 4], 2);
        let error = crate::domain::matrices::<F, Challenge, _>(
            &[&matrix],
            &[vec![Challenge::from(F::from_u32(point))]],
            2,
        );
        assert_eq!(
            error,
            Err(DomainError::PointInDomain {
                batch: 2,
                matrix: 0,
                point: 0,
                physical_height: 2,
            })
        );
        cases += 1;
    }
    for point in [
        Challenge::ZERO,
        Challenge::ONE,
        Challenge::new([F::ZERO, F::ONE, F::ZERO, F::ZERO]),
    ] {
        let matrix = RowMajorMatrix::new(vec![F::ZERO; 8], 2);
        assert_eq!(
            crate::domain::matrices::<F, Challenge, _>(&[&matrix], &[vec![point]], 0),
            Ok(())
        );
        cases += 1;
    }
    let short = RowMajorMatrix::new(vec![F::ZERO; 2], 2);
    let tall = RowMajorMatrix::new(vec![F::ZERO; 4], 2);
    assert_eq!(
        crate::domain::matrices::<F, Challenge, _>(
            &[&short, &tall],
            &[
                vec![Challenge::ONE],
                vec![Challenge::ONE, -Challenge::from(F::from_u32(31))]
            ],
            1,
        ),
        Err(DomainError::PointInDomain {
            batch: 1,
            matrix: 1,
            point: 1,
            physical_height: 2
        })
    );
    cases += 1;
    let odd = RowMajorMatrix::new(vec![F::ZERO; 6], 2);
    assert_eq!(
        crate::domain::matrices::<F, Challenge, _>(&[&odd], &[vec![Challenge::ONE]], 0),
        Err(DomainError::Height {
            batch: 0,
            matrix: 0,
            height: 3
        })
    );
    cases += 1;
    let claims: Vec<CommitmentOpening<Challenge, (), TwoAdicMultiplicativeCoset<F>>> = vec![
        (
            (),
            vec![(
                TwoAdicMultiplicativeCoset::new(F::ONE, 27).unwrap(),
                vec![(Challenge::ONE, vec![])],
            )],
        )
            .into(),
    ];
    assert!(matches!(
        crate::domain::claims(&claims, usize::MAX),
        Err(DomainError::HeightOverflow { .. })
    ));
    assert!(matches!(
        crate::domain::claims(&claims, 3),
        Err(DomainError::Height { .. })
    ));
    cases += 2;
    cases
}

pub fn fixed_domain_controls() {
    assert_eq!(
        std::env::var("KOVA_OPENING_DOMAIN_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let literal_controls = literal_cases();
    let (base, audit) = setup::base();
    let (anchor, _) = setup::anchor();
    let context = Arc::new(crate::Context::new(base, setup::challenger(), &anchor).unwrap());
    audit.bind_owner(&context);
    let observation = context.domain_refusal(setup::rawliteral()).unwrap();
    let state = context.snapshot().unwrap();
    assert_eq!(state.phase, crate::Phase::Failed);
    assert_eq!(
        state.failure,
        Some(crate::StorageError::OpeningDomain(observation.cause))
    );
    assert!(observation.lease.try_window(0, 0, 1).is_err());
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
            counts.mmcs_clones
        ),
        (0, 0, 1)
    );
    // Independently saved main-only source record, including constructor salt fork.
    assert_eq!((counts.mask.bytes, counts.salt.bytes), (10_948, 279_800));
    assert_eq!(audit.roots().len(), 1);
    assert!(
        !observation.flag_before
            && !observation.flag_after_refusal
            && observation.flag_after_shared_requests
    );

    // This typed object comes from the saved proof, not a new witness or prover.
    const SAVED: &[u8] = include_bytes!("../../proof-transport/fixtures/proof.json");
    const { assert!(SAVED.len() == 596_650) };
    let saved: crate::OwnedProof<
        setup::CountingDft,
        setup::InputSpy,
        p3_commit::ExtensionMmcs<F, Challenge, setup::InputSpy>,
        setup::Observed,
        setup::Challenger,
    > = serde_json::from_slice(SAVED).unwrap();
    let (other, other_audit) = setup::base();
    let checked = OpeningChecked::new(other);
    let mut challenger = setup::challenger();
    use p3_challenger::FieldChallenger;
    let before: Challenge = challenger.clone().sample_algebra_element();
    let mut verifier_controls = 0;
    for preprocessing in [false, true] {
        let rounds = vec![
            (
                saved.commitments.trace.clone(),
                vec![(
                    TwoAdicMultiplicativeCoset::new(F::ONE, 9).unwrap(),
                    vec![(
                        Challenge::from(F::from_u32(31)),
                        saved.opened_values.trace_local.clone(),
                    )],
                )],
            )
                .into(),
        ];
        let result = if preprocessing {
            <_ as UnivariateStarkPcs<Challenge, setup::Challenger>>::verify_with_preprocessing(
                &checked,
                rounds,
                &saved.opening_proof,
                &mut challenger,
                None,
            )
        } else {
            <_ as Pcs<Challenge, setup::Challenger>>::verify(
                &checked,
                rounds,
                &saved.opening_proof,
                &mut challenger,
            )
        };
        assert!(matches!(
            result,
            Err(OpeningVerifyError::Domain(DomainError::PointInDomain {
                batch: 0,
                matrix: 0,
                point: 0,
                physical_height: 4096,
            }))
        ));
        let after: Challenge = challenger.clone().sample_algebra_element();
        assert_eq!(before, after);
        verifier_controls += 1;
    }
    assert_eq!(other_audit.detailed_counts().verify_calls, 0);
    let (plain, plain_audit) = setup::plain();
    for preprocessing in [false, true] {
        let rounds = vec![
            (
                saved.commitments.trace.clone(),
                vec![(
                    TwoAdicMultiplicativeCoset::new(F::ONE, 9).unwrap(),
                    vec![(
                        Challenge::from(F::from_u32(31)),
                        saved.opened_values.trace_local.clone(),
                    )],
                )],
            )
                .into(),
        ];
        let result = if preprocessing {
            <_ as UnivariateStarkPcs<Challenge, setup::Challenger>>::verify_with_preprocessing(
                &plain,
                rounds,
                &saved.opening_proof.1,
                &mut challenger,
                None,
            )
        } else {
            <_ as Pcs<Challenge, setup::Challenger>>::verify(
                &plain,
                rounds,
                &saved.opening_proof.1,
                &mut challenger,
            )
        };
        assert!(matches!(
            result,
            Err(OpeningVerifyError::Domain(DomainError::PointInDomain {
                batch: 0,
                matrix: 0,
                point: 0,
                physical_height: 4096,
            }))
        ));
        let after: Challenge = challenger.clone().sample_algebra_element();
        assert_eq!(before, after);
        verifier_controls += 1;
    }
    assert_eq!(plain_audit.detailed_counts().verify_calls, 0);
    let result = serde_json::json!({
        "format": "kova.opening-domain.native.v1", "literal_controls": literal_controls,
        "typed_prover_refusals": 1, "typed_verifier_refusals": verifier_controls,
        "flag_after_refusal": observation.flag_after_refusal,
        "flag_after_shared_requests": observation.flag_after_shared_requests,
        "input_commits": counts.input_commits, "proofs_produced": 0,
        "get_matrices": counts.get_matrices,
        "mask_bytes": counts.mask.bytes, "salt_bytes": counts.salt.bytes,
        "reserved_files": state.reserved_files, "reserved_bytes": state.reserved_bytes,
        "cryptographic_verifier_calls": counts.verify_calls + other_audit.detailed_counts().verify_calls
            + plain_audit.detailed_counts().verify_calls,
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
