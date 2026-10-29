mod common;
#[path = "common/preparation_tests.rs"]
mod preparation_tests;
#[path = "common/quotient_tests.rs"]
mod quotient_tests;
#[path = "common/stream_tests.rs"]
mod stream_tests;

use common::{air, store::FileStore};
use p3_commit::{Pcs, UnivariateStarkPcs};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_uni_stark::{Proof, StarkGenericConfig};

#[test]
fn independent_trace_and_actual_quartic_degree() {
    let expected: Vec<Vec<u32>> =
        serde_json::from_str(include_str!("../fixtures/trace.json")).unwrap();
    let trace = air::trace();
    for (row, expected) in expected.iter().enumerate() {
        use p3_field::PrimeField32;
        let actual = trace
            .row(row)
            .unwrap()
            .into_iter()
            .map(|v| v.as_canonical_u32())
            .collect::<Vec<_>>();
        assert_eq!(&actual, expected);
    }
    assert_eq!(expected.len(), 256);
    let layout = p3_air::symbolic::AirLayout::from_air::<p3_baby_bear::BabyBear>(&air::QuarticAir);
    assert_eq!(
        p3_air::symbolic::get_max_constraint_degree::<p3_baby_bear::BabyBear, _>(
            &air::QuarticAir,
            layout,
            256
        ),
        4
    );
}

#[test]
fn committed_domain_views_and_ownership() {
    let files = FileStore::new();
    let stored = common::stored(files.clone());
    let dense = common::dense();
    let domain = TwoAdicMultiplicativeCoset::new(p3_baby_bear::BabyBear::ONE, 9).unwrap();
    let (stored_root, data) = <_ as Pcs<common::Challenge, common::Challenger>>::commit(
        stored.pcs(),
        [(domain, air::trace())],
    )
    .unwrap();
    let (dense_root, dense_data) = <_ as Pcs<common::Challenge, common::Challenger>>::commit(
        dense.pcs(),
        [(domain, air::trace())],
    )
    .unwrap();
    assert_eq!(stored_root, dense_root);
    for (shift, log) in [
        (p3_baby_bear::BabyBear::GENERATOR, 9),
        (p3_baby_bear::BabyBear::GENERATOR, 11),
        (p3_baby_bear::BabyBear::ONE, 9),
    ] {
        let target = TwoAdicMultiplicativeCoset::new(shift, log).unwrap();
        let actual = <common::AdaptedPcs<FileStore> as UnivariateStarkPcs<
            common::Challenge,
            common::Challenger,
        >>::get_evaluations_on_domain(stored.pcs(), &data, 0, target);
        let expected = <common::DensePcs as UnivariateStarkPcs<
            common::Challenge,
            common::Challenger,
        >>::get_evaluations_on_domain(dense.pcs(), &dense_data, 0, target);
        assert_eq!(actual.dimensions(), expected.dimensions());
        for row in 0..actual.height() {
            assert_eq!(
                actual.row(row).unwrap().into_iter().collect::<Vec<_>>(),
                expected.row(row).unwrap().into_iter().collect::<Vec<_>>()
            );
        }
    }
    assert_eq!(files.shapes(), vec![[4096, 6]]);
    let events = files.streamed();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].input, [512, 6]);
    assert_eq!(events[0].column_dft_calls, 6);
}

#[test]
#[ignore = "Explicit admitted full proof experiment"]
#[allow(
    clippy::assertions_on_constants,
    reason = "The backend test must fail when compiled with host debug checks."
)]
fn complete_stored_proof_matches_retained_dense_verifier() {
    assert!(
        !cfg!(debug_assertions),
        "raw backend validation requires release mode"
    );
    let files = FileStore::new();
    let stored = common::stored(files.clone());
    let candidate =
        p3_uni_stark::prove(&stored, &air::QuarticAir, air::trace(), &air::public()).unwrap();
    let encoded = serde_json::to_vec(&candidate).unwrap();
    assert!(encoded.len() <= 2 * 1024 * 1024);
    let retained: Proof<common::DenseConfig> = serde_json::from_slice(&encoded).unwrap();
    p3_uni_stark::verify(
        &common::dense(),
        &air::QuarticAir,
        &retained,
        &air::public(),
    )
    .unwrap();
    let dense = p3_uni_stark::prove(
        &common::dense(),
        &air::QuarticAir,
        air::trace(),
        &air::public(),
    )
    .unwrap();
    let expected = serde_json::to_vec(&dense).unwrap();
    assert_eq!(encoded, expected);
    let mut expected_shapes = vec![[4096, 6]];
    expected_shapes.extend(vec![[4096, 8]; 9]);
    assert_eq!(files.shapes(), expected_shapes);
    let preparations = files.preparations();
    assert_eq!(preparations.len(), 1);
    assert_eq!(preparations[0].raw, [256, 2]);
    assert_eq!(preparations[0].prepared, [512, 6]);
    assert_eq!(preparations[0].random_field_draws, 2560);
    assert_eq!(files.file_count(), 11);
    assert_eq!(files.field_bytes(), 1290240);
    println!(
        "prepared_source_bytes=12288 prepared_field_draws=2560 total_field_bytes={}",
        files.field_bytes()
    );
    let events = files.streamed();
    assert_eq!(events.len(), 10);
    assert_eq!(events[0].input, [512, 6]);
    assert!(!events[0].quotient);
    assert_eq!(events[9].input, [512, 8]);
    assert!(!events[9].quotient);
    for event in &events[1..9] {
        assert!(event.quotient);
        assert_eq!(event.input, [256, 8]);
        assert_eq!(event.inverse_column_dft_calls, 8);
    }
    for event in &events {
        assert_eq!(event.column_dft_calls, event.input[1]);
        assert_eq!(event.largest_output_column_fields, 4096);
        assert_eq!(event.written_fields, event.output[0] * event.output[1]);
        assert_eq!(event.source_fields, event.input[0] * event.input[1]);
        assert_eq!(
            event.source_windows,
            event.input[0] * event.input[1].div_ceil(4)
        );
        assert_eq!(
            event.output_write_calls,
            event.output[0] * event.output[1].div_ceil(4)
        );
        assert!(event.largest_input_tile_fields <= 2048);
        assert!(event.largest_output_tile_fields <= 16384);
    }
    assert_eq!(
        events
            .iter()
            .map(|event| event.source_windows)
            .sum::<usize>(),
        6144
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.output_write_calls)
            .sum::<usize>(),
        81920
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.forward_dft_batches)
            .sum::<usize>(),
        20
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.inverse_dft_batches)
            .sum::<usize>(),
        16
    );
    println!(
        "tile_columns=4 source_windows=6144 output_write_calls=81920 forward_batches=20 inverse_batches=16 max_input_tile_fields=2048 max_output_tile_fields=16384"
    );
    println!(
        "streamed_columns={} max_output_column_fields={}",
        events.iter().map(|e| e.column_dft_calls).sum::<usize>(),
        events
            .iter()
            .map(|e| e.largest_output_column_fields)
            .max()
            .unwrap()
    );
    println!(
        "proof_bytes={} stored_shapes={:?}",
        encoded.len(),
        files.shapes()
    );
    for kind in 0..5 {
        let mut altered: Proof<common::DenseConfig> = serde_json::from_slice(&encoded).unwrap();
        match kind {
            0 => altered.opened_values.trace_local[0] += common::Challenge::ONE,
            1 => altered.opened_values.quotient_chunks[0][0] += common::Challenge::ONE,
            2 => altered.opened_values.random.as_mut().unwrap()[0] += common::Challenge::ONE,
            3 => {
                altered.opening_proof.1.input_openings[0].opened_values[0][0][0] +=
                    p3_baby_bear::BabyBear::ONE
            }
            4 => altered.opening_proof.0[0][0][0][0] += common::Challenge::ONE,
            _ => unreachable!(),
        }
        assert!(
            p3_uni_stark::verify(&common::dense(), &air::QuarticAir, &altered, &air::public())
                .is_err(),
            "alteration {kind}"
        );
    }
    let mut wrong_public = air::public();
    wrong_public[1] += p3_baby_bear::BabyBear::ONE;
    assert!(
        p3_uni_stark::verify(&common::dense(), &air::QuarticAir, &retained, &wrong_public).is_err()
    );
}

#[test]
#[ignore = "Explicit admitted raw false trace proof experiment"]
#[allow(
    clippy::assertions_on_constants,
    reason = "A raw false trace must reach the backend without host debug checks."
)]
fn raw_false_trace_reaches_backend_and_retained_verifier_rejects() {
    assert!(
        !cfg!(debug_assertions),
        "host constraint checks must be disabled"
    );
    let files = FileStore::new();
    let mut trace = air::trace();
    trace.values[2 * 73 + 1] += p3_baby_bear::BabyBear::ONE;
    let candidate = p3_uni_stark::prove(
        &common::stored(files.clone()),
        &air::QuarticAir,
        trace,
        &air::public(),
    )
    .unwrap();
    let encoded = serde_json::to_vec(&candidate).unwrap();
    assert!(encoded.len() <= 2 * 1024 * 1024);
    let retained: Proof<common::DenseConfig> = serde_json::from_slice(&encoded).unwrap();
    assert!(
        p3_uni_stark::verify(
            &common::dense(),
            &air::QuarticAir,
            &retained,
            &air::public()
        )
        .is_err()
    );
    println!(
        "false_proof_bytes={} stored_shapes={:?}",
        encoded.len(),
        files.shapes()
    );
    assert_eq!(files.preparations()[0].random_field_draws, 2560);
    assert_eq!(files.field_bytes(), 1290240);
    println!(
        "prepared_source_bytes=12288 prepared_field_draws=2560 total_field_bytes={}",
        files.field_bytes()
    );
}
