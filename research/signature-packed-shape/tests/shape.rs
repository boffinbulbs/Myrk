use kova_signature_packed::PackedSignatureOwnerAir;
use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
use p3_baby_bear::BabyBear;
use serde_json::json;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[test]
#[ignore = "Separate symbolic memory admission without a native trace"]
fn complete_packed_symbolic_shape() {
    assert_eq!(
        std::env::var("KOVA_PACKED_SYMBOLIC_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    // Reserve an exclusive record before collection, without replacing evidence.
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("symbolic.json"))
        .unwrap();
    let air = PackedSignatureOwnerAir;
    let layout = AirLayout::from_air::<BabyBear>(&air);
    assert_eq!(
        (
            layout.main_width,
            layout.num_public_values,
            layout.preprocessed_width,
            layout.num_periodic_columns,
            layout.permutation_width,
            layout.num_permutation_challenges,
            layout.num_permutation_values,
        ),
        (43176, 196, 0, 0, 0, 0, 0)
    );
    // One complete collection, no second degree-inference collection.
    let constraints = get_symbolic_constraints::<BabyBear, _>(&air, layout);
    let count = constraints.len();
    let mut histogram = [0usize; 8];
    let mut degree = 0;
    let mut outside_histogram = 0;
    for expression in &constraints {
        let current = expression.degree_multiple();
        degree = degree.max(current);
        if let Some(slot) = histogram.get_mut(current) {
            *slot += 1;
        } else {
            outside_histogram += 1;
        }
    }
    let result = json!({
        "columns":43176,"public_values":196,"constraints":count,"degree":degree,
        "degree_histogram":histogram,"degrees_outside_histogram":outside_histogram,
        "symbolic_collections":1,"native_traces":0,"backend_proofs":0
    });
    output
        .write_all(serde_json::to_string(&result).unwrap().as_bytes())
        .unwrap();
    output.sync_all().unwrap();
    drop(output);
    drop(constraints);
    // Original 71141 minus 7637 holds, plus 2547 holds, 3000 Boolean
    // assertions, 125 port equalities and at most 2 * 125 tail assertions.
    assert!((69176..=69426).contains(&count));
    assert_eq!(degree, 4);
    assert_eq!(outside_histogram, 0);
    assert_eq!(histogram.into_iter().sum::<usize>(), count);
}
