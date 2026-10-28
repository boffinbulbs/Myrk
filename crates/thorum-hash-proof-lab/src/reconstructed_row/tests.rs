use super::*;
use air::*;
use p3_air::{
    check_all_constraints,
    symbolic::{AirLayout, get_max_constraint_degree},
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
mod causal;
mod reference;

fn synthetic() -> (Witness, Statement) {
    (
        Witness::from_inputs(
            core::array::from_fn(|i| (i * 7 + 11) as u8),
            core::array::from_fn(|column| {
                core::array::from_fn(|i| {
                    ((i as u32 * 32749) + (column as u32 * 65537) + 9) % MODULUS
                })
            }),
            core::array::from_fn(|i| ((i * 17 + 3) % 1024) as u16),
            core::array::from_fn(|i| (i as u32 * 1048573 + 7) % MODULUS),
            core::array::from_fn(|i| (i % 7 == 0) as u8),
        ),
        Statement::new(3, [0x61; 64]).unwrap(),
    )
}
fn check(t: &RowMajorMatrix<BabyBear>, s: &Statement) -> bool {
    check_all_constraints(
        &ReconstructedRowAir::default(),
        t,
        &public_values(s),
        Some(4),
    )
    .is_ok()
}
#[test]
fn actual_layout_and_symbolic_degree() {
    assert_eq!((HEIGHT, WIDTH, PUBLIC_VALUES), (1024, 24794, 65));
    let actual = get_max_constraint_degree::<BabyBear, _>(
        &ReconstructedRowAir::default(),
        AirLayout {
            main_width: WIDTH,
            num_public_values: PUBLIC_VALUES,
            ..Default::default()
        },
        HEIGHT,
    );
    println!("actual reconstructed row degree {actual}");
    assert_eq!(actual, 3);
}
#[test]
fn real_private_inputs_hashes_routing_and_output_pass_the_actual_air() {
    let (w, s) = synthetic();
    let t = trace(&w, &s).unwrap();
    let report = check_all_constraints(
        &ReconstructedRowAir::default(),
        &t,
        &public_values(&s),
        Some(16),
    );
    assert!(report.is_ok(), "{report:?}");
    let first = t.row_slice(0).unwrap();
    assert!(
        first[ACCUMULATOR..COUNT]
            .iter()
            .all(|v| *v == BabyBear::ZERO)
    );
    let loaded = t.row_slice(32).unwrap();
    for i in 0..256 {
        assert_eq!(
            loaded[WORK + i].as_canonical_u32(),
            8192 * u32::from(w.t1[i])
        );
    }
    let output = t.row_slice(646).unwrap();
    let final_row = t.row_slice(HEIGHT - 1).unwrap();
    assert_eq!(&output[W1..COUNT], &final_row[W1..COUNT]);
    assert!(
        final_row[W1..COUNT]
            .iter()
            .all(|v| v.as_canonical_u32() < 256)
    );
    assert_eq!(final_row[COUNT + 256], BabyBear::ONE);
}
#[test]
fn changed_private_sources_routes_boundaries_and_holds_reject() {
    let (w, s) = synthetic();
    let original = trace(&w, &s).unwrap();
    for (at, column, persistent) in [
        (1, RHO, true),
        (41, XOF, true),
        (42, XOF + 1007, true),
        (0, ZHAT + 256, true),
        (31, T1 + 255, true),
        (422, CHAT, true),
        (421, WORK + 255, true),
        (454, ACCUMULATOR + 255, true),
        (614, HINTS + 255, true),
        (646, W1 + 127, true),
        (700, ACCUMULATOR, true),
        (293, COUNT + 8 * 257 + 256, false),
    ] {
        let mut changed = original.clone();
        for row in at..if persistent { HEIGHT } else { at + 1 } {
            changed.values[row * WIDTH + column] += BabyBear::ONE;
        }
        assert!(!check(&changed, &s), "{at}/{column}");
    }
}
