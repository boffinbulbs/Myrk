use super::*;
use p3_air::{DebugConstraintBuilder, check_all_constraints};
use p3_field::PrimeField32;
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::ViewPair,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/certificate.json")).unwrap()
}

fn trace() -> RowMajorMatrix<BabyBear> {
    let data = fixture();
    let sources: Vec<BabyBear> = data["sources"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|x| {
            x.as_array()
                .unwrap()
                .iter()
                .map(|value| BabyBear::from_u64(value.as_u64().unwrap()))
        })
        .collect();
    let mut values = vec![BabyBear::ZERO; HEIGHT * WIDTH];
    let mut dedicated = [BabyBear::ZERO; 32];
    let mut shared = [BabyBear::ZERO; 18];
    for (position, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        row[position % 64] = BabyBear::ONE;
        row[64 + position / 64] = BabyBear::ONE;
        row[SOURCE..DEDICATED].copy_from_slice(&sources);
        row[DEDICATED..SHARED].copy_from_slice(&dedicated);
        row[SHARED..WIDTH].copy_from_slice(&shared);
        for logical in 0..16 {
            for coordinate in 0..2 {
                if position == write_row(logical, coordinate) {
                    dedicated[2 * logical + coordinate] = sources[2 * logical + coordinate];
                    shared[2 * BANKS[logical] + coordinate] = sources[2 * logical + coordinate];
                }
            }
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}

fn row_failures(
    air: &LifetimeAir,
    local: &[BabyBear],
    next: &[BabyBear],
    row: usize,
) -> Vec<usize> {
    let main = ViewPair::new(
        RowMajorMatrixView::new_row(local),
        RowMajorMatrixView::new_row(next),
    );
    let empty: &[BabyBear] = &[];
    let pre = ViewPair::new(
        RowMajorMatrixView::new(empty, 0),
        RowMajorMatrixView::new(empty, 0),
    );
    let mut builder = DebugConstraintBuilder::new(
        row,
        main,
        pre,
        &[],
        BabyBear::from_bool(row == 0),
        BabyBear::from_bool(row == HEIGHT - 1),
        BabyBear::from_bool(row != HEIGHT - 1),
        &[],
    );
    air.eval(&mut builder);
    builder
        .failures()
        .iter()
        .map(|failure| failure.constraint)
        .collect()
}

fn valid_row(air: &LifetimeAir, local: &[BabyBear], next: &[BabyBear], row: usize) -> bool {
    row_failures(air, local, next, row).is_empty()
}

fn restored_mutation(
    trace: &mut RowMajorMatrix<BabyBear>,
    row: usize,
    column: usize,
    value: BabyBear,
) {
    assert!(row > 0 && row + 1 < HEIGHT);
    let air = LifetimeAir::candidate();
    let index = row * WIDTH + column;
    let original = trace.values[index];
    assert_ne!(value, original);
    let affected_valid = |trace: &RowMajorMatrix<BabyBear>| {
        [row - 1, row].iter().all(|&r| {
            valid_row(
                &air,
                &trace.values[r * WIDTH..(r + 1) * WIDTH],
                &trace.values[(r + 1) * WIDTH..(r + 2) * WIDTH],
                r,
            )
        })
    };
    assert!(affected_valid(trace));
    trace.values[index] = value;
    assert!(!affected_valid(trace), "row {row} column {column}");
    trace.values[index] = original;
    assert!(affected_valid(trace));
}

#[test]
fn integer_lifetime_certificate_and_source_rows() {
    let data = fixture();
    assert_eq!(data["map"], serde_json::json!(BANKS));
    assert_eq!(data["read_checks"], 5728);
    for logical in 0..16 {
        assert_eq!(write_row(logical, 1) - write_row(logical, 0), 31);
        assert!(
            read_windows(logical)
                .iter()
                .all(|&(start, end)| start > write_row(logical, 1) && start < end)
        );
    }
    assert_eq!(read_windows(6).last(), Some(&(3288, 3330)));
}

#[test]
#[ignore = "Separate expression resource admission"]
fn symbolic_lifetime_shape() {
    assert_eq!(
        std::env::var("KOVA_OUTPUT_LIFETIME_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    use p3_air::symbolic::{AirLayout, get_symbolic_constraints};
    let air = LifetimeAir::candidate();
    let constraints =
        get_symbolic_constraints::<BabyBear, _>(&air, AirLayout::from_air::<BabyBear>(&air));
    let degree = constraints
        .iter()
        .map(|x| x.degree_multiple())
        .max()
        .unwrap();
    assert_eq!(constraints.len(), 776);
    assert_eq!(degree, 3);
    println!(
        "height=8192 width=274 constraints={} degree={degree} native_traces=0 backend_proofs=0",
        constraints.len()
    );
}

#[test]
#[ignore = "One finite synthetic trace under external resource admission"]
fn native_lifetime_and_rejection_controls() {
    assert_eq!(
        std::env::var("KOVA_OUTPUT_LIFETIME_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let air = LifetimeAir::candidate();
    let mut trace = trace();
    assert!(check_all_constraints(&air, &trace, &[], Some(1)).is_ok());
    let data = fixture();
    let mut checksum = BabyBear::ZERO;
    let mut reads = 0;
    for (logical, bank) in BANKS.iter().enumerate() {
        for (start, end) in read_windows(logical) {
            for position in start..end {
                for coordinate in 0..2 {
                    let value = trace.values[position * WIDTH + SHARED + 2 * bank + coordinate];
                    checksum += value
                        * BabyBear::from_usize((position + 1) * (logical + 1) * (coordinate + 1));
                    reads += 1;
                }
            }
        }
    }
    assert_eq!(reads, data["read_checks"].as_u64().unwrap());
    assert_eq!(
        u64::from(checksum.as_canonical_u32()),
        data["read_checksum"].as_u64().unwrap()
    );
    let controls = [
        (611, SHARED, BabyBear::ZERO),
        (610, SHARED, BabyBear::from_u32(10000)),
        (642, SHARED + 1, BabyBear::ZERO),
        (2147, SHARED, BabyBear::from_u32(10000)),
        (3299, SHARED + 12, BabyBear::from_u32(10518)),
        (3300, SHARED + 16, BabyBear::ZERO),
        (648, DEDICATED, BabyBear::ZERO),
        (4000, SOURCE, BabyBear::ZERO),
        (3330, SOURCE + 28, BabyBear::ZERO),
        (3298, 3298 % 64, BabyBear::ZERO),
        (5000, SHARED + 17, BabyBear::ZERO),
        (642, DEDICATED + 1, BabyBear::ZERO),
    ];
    for (row, column, value) in controls {
        restored_mutation(&mut trace, row, column, value);
    }
    // The unsafe layout writes the first T1_6 coordinate at row3298. Its
    // same-row consumer still sees Z6, but row3299 sees the overwritten value.
    let unsafe_air = LifetimeAir::overlap_control();
    let row = 3299;
    let mut local = trace.values[row * WIDTH..(row + 1) * WIDTH].to_vec();
    let mut next = trace.values[(row + 1) * WIDTH..(row + 2) * WIDTH].to_vec();
    local[SHARED + 12] = local[SOURCE + 28];
    next[SHARED + 12] = local[SOURCE + 28];
    // All transition and source constraints at this row are satisfied. The
    // actual consumer comparison rejects the alias while Z6 is still live.
    assert_eq!(row_failures(&unsafe_air, &local, &next, row), vec![663]);
    assert!(valid_row(
        &air,
        &trace.values[row * WIDTH..(row + 1) * WIDTH],
        &trace.values[(row + 1) * WIDTH..(row + 2) * WIDTH],
        row
    ));
    println!(
        "native_traces=1 full_positive=1 read_checks={reads} restored_cell_rejects=12 unsafe_alias_rejects=1 backend_proofs=0"
    );
}
