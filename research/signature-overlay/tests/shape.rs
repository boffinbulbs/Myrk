use kova_signature_overlay::{layout, PackedSignatureOwnerAir};
use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
use p3_baby_bear::BabyBear;
use serde_json::json;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[test]
#[ignore = "One separately bounded full symbolic collection"]
fn complete_overlay_symbolic_shape() {
    const { assert!(!cfg!(feature = "native-execution")) };
    assert_eq!(
        std::env::var("KOVA_OVERLAY_SYMBOLIC_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("symbolic.json"))
        .unwrap();
    let air = PackedSignatureOwnerAir;
    let shape = AirLayout::from_air::<BabyBear>(&air);
    assert_eq!(
        (
            shape.main_width,
            shape.num_public_values,
            shape.preprocessed_width,
            shape.num_periodic_columns,
            shape.permutation_width,
            shape.num_permutation_challenges,
            shape.num_permutation_values,
        ),
        (42178, 196, 0, 0, 0, 0, 0)
    );
    assert_eq!((layout::HEIGHT, layout::WIDTH), (8192, 42178));
    assert_eq!(layout::NTT_PRODUCTS, layout::USE_HINT);
    // One complete collection. No trace construction or degree recollection.
    let constraints = get_symbolic_constraints::<BabyBear, _>(&air, shape);
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
        "format":"kova.signature-overlay.symbolic.v1",
        "height":8192,"columns":42178,"public_values":196,
        "constraints":count,"degree":degree,"degree_histogram":histogram,
        "degrees_outside_histogram":outside_histogram,
        "symbolic_collections":1,"native_traces":0,"backend_proofs":0,
        "full_signature_witness_checked":false
    });
    let encoded = serde_json::to_vec(&result).unwrap();
    assert!(encoded.len() <= 4096);
    output.write_all(&encoded).unwrap();
    output.sync_all().unwrap();
    drop(output);
    drop(constraints);
    // Original 69242 roots plus 5 bound mode assertions, 1688 idle zeros
    // and 688 hint suffix zeros. Gating existing assertions adds no roots.
    assert_eq!(count, 71623);
    assert_eq!(degree, 4);
    assert_eq!(outside_histogram, 0);
    assert_eq!(histogram.into_iter().sum::<usize>(), count);
}
