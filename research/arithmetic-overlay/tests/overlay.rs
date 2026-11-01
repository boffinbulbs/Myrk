use kova_arithmetic_overlay::{OverlayAir, fixture, layout::*};
use p3_air::{
    Air, DebugConstraintBuilder, check_all_constraints,
    symbolic::{AirLayout, get_symbolic_constraints},
};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::ViewPair,
};
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

fn frame(trace: &RowMajorMatrix<BabyBear>, public: &[BabyBear], row: usize) -> Vec<usize> {
    let next = (row + 1) % HEIGHT;
    let main = ViewPair::new(
        RowMajorMatrixView::new_row(&trace.values[row * WIDTH..(row + 1) * WIDTH]),
        RowMajorMatrixView::new_row(&trace.values[next * WIDTH..(next + 1) * WIDTH]),
    );
    let empty: &[BabyBear] = &[];
    let preprocessed = ViewPair::new(
        RowMajorMatrixView::new(empty, 0),
        RowMajorMatrixView::new(empty, 0),
    );
    let mut builder = DebugConstraintBuilder::new(
        row,
        main,
        preprocessed,
        public,
        BabyBear::from_bool(row == 0),
        BabyBear::from_bool(row == HEIGHT - 1),
        BabyBear::from_bool(row != HEIGHT - 1),
        empty,
    );
    OverlayAir.eval(&mut builder);
    builder.failures().iter().map(|f| f.constraint).collect()
}
fn changed_frames(
    trace: &RowMajorMatrix<BabyBear>,
    public: &[BabyBear],
    row: usize,
) -> [Vec<usize>; 2] {
    [
        frame(trace, public, (row + HEIGHT - 1) % HEIGHT),
        frame(trace, public, row),
    ]
}
fn mutation(
    trace: &mut RowMajorMatrix<BabyBear>,
    public: &[BabyBear],
    name: &str,
    row: usize,
    column: usize,
    replacement: BabyBear,
) -> Value {
    let index = row * WIDTH + column;
    let old = trace.values[index];
    assert_ne!(old, replacement);
    trace.values[index] = replacement;
    let failures = changed_frames(trace, public, row);
    assert!(
        failures.iter().any(|f| !f.is_empty()),
        "{name} must fail actual constraints"
    );
    trace.values[index] = old;
    assert!(
        changed_frames(trace, public, row).iter().all(Vec::is_empty),
        "{name} restoration"
    );
    json!({"case":name,"row":row,"column":column,
        "failure_counts":failures.iter().map(Vec::len).collect::<Vec<_>>(),
        "first_indices":failures.iter().map(|f|f.iter().copied().take(8).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "restored_positive_frames":2})
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > 16384)
        {
            return Err(std::io::Error::other("fixed overlay report cap exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
#[ignore = "Separate reviewed native resource admission"]
#[allow(
    clippy::assertions_on_constants,
    reason = "The selected diagnostic requires release."
)]
fn clock_bound_arithmetic_overlay_and_hostile_controls() {
    assert!(!cfg!(debug_assertions));
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("measurement.json"))
        .unwrap();
    let air = OverlayAir;
    let layout = AirLayout::from_air::<BabyBear>(&air);
    assert_eq!((layout.main_width, layout.num_public_values), (1930, 16));
    let symbolic = get_symbolic_constraints::<BabyBear, _>(&air, layout);
    let constraint_count = symbolic.len();
    let degree = symbolic.iter().map(|c| c.degree_multiple()).max().unwrap();
    assert_eq!(constraint_count, 5889);
    assert!(degree <= 4);
    drop(symbolic);
    let fixture = fixture::load();
    let (mut trace, public, modes) = fixture::fixed_trace(&fixture);
    assert_eq!(modes, [3328, 256, 4608]);
    assert_eq!(trace.values.len() * 4, 63_242_240);
    let baseline = check_all_constraints(&air, &trace, &public, Some(1));
    assert!(
        baseline.is_ok(),
        "complete overlay component must pass: {:?}",
        baseline.failures
    );
    assert_eq!(
        (baseline.total_rows, baseline.total_constraints_per_row),
        (8192, constraint_count)
    );
    for slot in 0..8 {
        assert_eq!(
            trace.values[(HEIGHT - 1) * WIDTH + PRODUCT_SINK + slot].as_canonical_u32(),
            fixture.products[slot].result
        );
        assert_eq!(
            trace.values[(HEIGHT - 1) * WIDTH + HINT_SINK + slot].as_canonical_u32(),
            fixture.hints[slot].result
        );
    }
    let mut controls = Vec::new();
    for (name, row, column, value) in [
        ("product_mode_suppression", 482, PRODUCT_MODE, 0),
        ("simultaneous_modes", 482, HINT_MODE, 1),
        ("hint_mode_suppression", 3714, HINT_MODE, 0),
        ("idle_mode_forgery", 6000, PRODUCT_MODE, 1),
        ("nonboolean_product_bit", 482, BANK, 2),
        ("wrong_product_result", 482, BANK + 69, 1),
        ("wrong_active_source", 483, SOURCE, 1),
        ("wrong_hint_source", 3714, SOURCE + 3, 1),
        ("hint_suffix_stale_value", 3714, BANK + HINT_WIDTH, 1),
        ("idle_stale_value", 6000, BANK, 1),
        ("wrong_product_consumer", 484, PRODUCT_SINK, 1),
        ("wrong_hint_consumer", 3715, HINT_SINK, 1),
        ("last_clock_indicator", 8191, LOW + 127, 0),
    ] {
        controls.push(mutation(
            &mut trace,
            &public,
            name,
            row,
            column,
            BabyBear::from_u32(value),
        ));
    }
    let carry = BANK + 184;
    let carry_old = trace.values[482 * WIDTH + carry];
    controls.push(mutation(
        &mut trace,
        &public,
        "wrong_integer_carry",
        482,
        carry,
        BabyBear::ONE - carry_old,
    ));
    let hint_bit = BANK + 100;
    let hint_old = trace.values[3714 * WIDTH + hint_bit];
    controls.push(mutation(
        &mut trace,
        &public,
        "wrong_hint_bit",
        3714,
        hint_bit,
        BabyBear::ONE - hint_old,
    ));
    let mut changed_public = public.clone();
    changed_public[0] += BabyBear::ONE;
    let failed = changed_frames(&trace, &changed_public, HEIGHT - 1);
    assert!(failed.iter().any(|f| !f.is_empty()));
    assert!(
        changed_frames(&trace, &public, HEIGHT - 1)
            .iter()
            .all(Vec::is_empty)
    );
    controls.push(json!({"case":"wrong_public_consumer","row":8191,
        "failure_counts":failed.iter().map(Vec::len).collect::<Vec<_>>(),"restored_positive_frames":2}));
    let record = json!({"profile":"clock-bound-arithmetic-overlay-v1","height":HEIGHT,"width":WIDTH,
        "public_values":PUBLIC_VALUES,"constraints_per_row":constraint_count,"degree":degree,
        "symbolic_collections":1,"constructed_traces":1,"maximum_live_traces":1,
        "full_positive_scans":1,"native_trace_field_bytes":63_242_240,
        "mode_rows":modes,"independent_product_outputs":8,"independent_hint_outputs":8,
        "product_fixture_names":fixture.products.iter().map(|p|&p.name).collect::<Vec<_>>(),
        "hint_fixture_names":fixture.hints.iter().map(|h|&h.name).collect::<Vec<_>>(),
        "negative_borrowed_frames":2*controls.len(),"restored_positive_frames":2*controls.len(),
        "controls":controls,"backend_proofs":0,"full_signature_layout_integrated":false,
        "scope":"actual clock and shared integer gadget constraints, not a private payment proof"});
    let mut encoded = Bounded(Vec::new());
    serde_json::to_writer(&mut encoded, &record).unwrap();
    output.write_all(&encoded.0).unwrap();
    output.sync_all().unwrap();
}
