use super::*;
use p3_air::{check_all_constraints, DebugConstraintBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

type Builder<'a> = DebugConstraintBuilder<'a, BabyBear>;

#[test]
fn independent_small_clock_and_all_interval_selectors() {
    let expected: Vec<Vec<u32>> =
        serde_json::from_str(include_str!("../clock-reference.json")).unwrap();
    let trace = clock::trace(4, 8);
    assert!(check_all_constraints(&clock::FactorClockAir::<4, 8>, &trace, &[], Some(1)).is_ok());
    for (position, expected_row) in expected.iter().enumerate() {
        let row = trace.row_slice(position).unwrap();
        assert_eq!(
            row.iter().map(|v| v.as_canonical_u32()).collect::<Vec<_>>(),
            *expected_row
        );
        for selected in 0..32 {
            assert_eq!(
                clock::at::<Builder<'_>>(&row, 0, 4, 8, selected),
                BabyBear::from_bool(selected == position)
            );
        }
        for from in 0..=32 {
            for to in from..=32 {
                assert_eq!(
                    clock::interval::<Builder<'_>>(&row, 0, 4, 8, from, to),
                    BabyBear::from_bool((from..to).contains(&position))
                );
            }
        }
    }
}

#[test]
fn invalid_clock_routes_are_rejected_with_restoration_controls() {
    let original = clock::trace(4, 8);
    for kind in 0..8 {
        let mut altered = original.clone();
        match kind {
            0 => altered.values[0] = BabyBear::ZERO,
            1 => altered.values[1] = BabyBear::ONE,
            2 => {
                altered.values[0] = BabyBear::TWO;
                altered.values[1] = BabyBear::NEG_ONE;
            }
            3 => {
                altered.values[2 * 12 + 4] = BabyBear::ZERO;
                altered.values[2 * 12 + 5] = BabyBear::ONE;
            }
            4 => {
                let previous = altered.values[3 * 12..4 * 12].to_vec();
                altered.values[4 * 12..5 * 12].copy_from_slice(&previous);
            }
            5 => {
                let later = altered.values[8 * 12..9 * 12].to_vec();
                altered.values[7 * 12..8 * 12].copy_from_slice(&later);
            }
            6 => altered.values[31 * 12 + 11] = BabyBear::ZERO,
            7 => {
                altered.values[4 * 12] = BabyBear::ZERO;
                altered.values[4 * 12 + 1] = BabyBear::ONE;
            }
            _ => unreachable!(),
        }
        assert!(
            !check_all_constraints(&clock::FactorClockAir::<4, 8>, &altered, &[], Some(1)).is_ok(),
            "kind {kind}"
        );
        assert!(
            check_all_constraints(&clock::FactorClockAir::<4, 8>, &original, &[], Some(1)).is_ok()
        );
    }
}

#[test]
fn repeated_whole_schedule_cannot_extend_the_clock() {
    let trace = clock::trace(4, 8);
    let values = trace.values.iter().chain(&trace.values).copied().collect();
    let repeated = RowMajorMatrix::new(values, 12);
    assert!(
        !check_all_constraints(&clock::FactorClockAir::<4, 8>, &repeated, &[], Some(1)).is_ok()
    );
}

#[test]
fn full_schedule_selector_and_source_dimensions() {
    use layout::*;
    assert_eq!(
        (HEIGHT, WIDTH, PUBLIC_VALUES, KEY - CLOCK),
        (8192, 47058, 196, 192)
    );
    let mut row = vec![BabyBear::ZERO; WIDTH];
    for position in 0..HEIGHT {
        row[CLOCK..KEY].fill(BabyBear::ZERO);
        row[CLOCK + position % CLOCK_LOW] = BabyBear::ONE;
        row[CLOCK + CLOCK_LOW + position / CLOCK_LOW] = BabyBear::ONE;
        assert_eq!(program::at::<Builder<'_>>(&row, position), BabyBear::ONE);
        assert_eq!(
            program::at::<Builder<'_>>(&row, (position + 1) % HEIGHT),
            BabyBear::ZERO
        );
        for (from, to) in [
            (0, 0),
            (0, HEIGHT),
            (12, 276),
            (642, 3330),
            (3522, 5314),
            (5316, 5370),
        ] {
            assert_eq!(
                program::range::<Builder<'_>>(&row, from, to),
                BabyBear::from_bool((from..to).contains(&position))
            );
        }
    }
}

#[test]
#[ignore = "Separate expression memory admission, no native trace construction"]
fn actual_complete_symbolic_relation_shape() {
    assert_eq!(
        std::env::var("KOVA_SCHEDULE_SYMBOLIC_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    let air = FactorSignatureOwnerAir;
    let shape = AirLayout::from_air::<BabyBear>(&air);
    assert_eq!(
        (
            shape.main_width,
            shape.num_public_values,
            shape.preprocessed_width,
            shape.num_periodic_columns
        ),
        (47058, 196, 0, 0)
    );
    let constraints = get_symbolic_constraints::<BabyBear, _>(&air, shape);
    let count = constraints.len();
    let degree = constraints
        .iter()
        .map(|value| value.degree_multiple())
        .max()
        .unwrap();
    assert!((140000..220000).contains(&count));
    assert_eq!(degree, 4);
    println!("native_width=47058 constraints_per_row={count} degree={degree} native_trace_allocations=0 backend_proofs=0");
}
