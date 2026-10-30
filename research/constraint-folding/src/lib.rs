#![forbid(unsafe_code)]
//! Finite retained constraint folding probe without a proof backend call.

#[cfg(test)]
#[path = "../../storage-pcs/tests/common/hash.rs"]
mod hash;

#[cfg(test)]
mod tests {
    use kova_signature_scheduling::{FactorSignatureOwnerAir, layout::WIDTH};
    use p3_air::{Air, RowWindow, symbolic::ConstraintLayout};
    use p3_baby_bear::BabyBear as F;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::{ExtensionMmcs, PolynomialSpace};
    use p3_dft::Radix2DitParallel;
    use p3_field::{
        BasedVectorSpace, PackedFieldExtension, PackedValue, PrimeCharacteristicRing, PrimeField32,
        coset::TwoAdicMultiplicativeCoset, extension::BinomialExtensionField,
    };
    use p3_matrix::dense::RowMajorMatrixView;
    use p3_merkle_tree::MerkleTreeHidingMmcs;
    use p3_symmetric::CompressionFunctionFromHasher;
    use p3_uni_stark::{PackedChallenge, PackedVal, ProverConstraintFolder, StarkConfig};
    use rand::rngs::StdRng;
    use std::{fs::OpenOptions, io::Write, time::Instant};

    use super::hash;
    type EF = BinomialExtensionField<F, 4>;
    type Compress = CompressionFunctionFromHasher<hash::NodeHash, 2, 8>;
    type Input = MerkleTreeHidingMmcs<F, u64, hash::LeafHash, Compress, StdRng, 2, 8, 16>;
    type Ext = ExtensionMmcs<F, EF, Input>;
    type Challenger = SerializingChallenger32<F, HashChallenger<u8, hash::TranscriptHash, 64>>;
    type Pcs = p3_fri::HidingFriPcs<F, Radix2DitParallel<F>, Input, Ext, StdRng>;
    type Config = StarkConfig<Pcs, EF, Challenger>;
    type Pack = PackedVal<Config>;
    const COUNT: usize = 74725;

    fn save(name: &str, data: &[u8]) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("results")
            .join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        assert!(data.len() <= 1024 * 1024);
        file.write_all(data).unwrap();
    }
    fn coefficients(value: EF) -> [u32; 4] {
        core::array::from_fn(|index| {
            <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(&value)[index]
                .as_canonical_u32()
        })
    }

    #[test]
    #[ignore = "Separate finite actual row-group and external resource admission"]
    fn actual_retained_folder_and_scalar_reference() {
        assert_eq!(
            std::env::var("KOVA_FOLD_PROBE_GATE").as_deref(),
            Ok("reviewed-external-resource-admission")
        );
        assert_eq!(WIDTH, 47058);
        let alpha = EF::from_basis_coefficients_fn(|index| F::from_u32([3, 5, 7, 11][index]));
        let layout = ConstraintLayout {
            base_indices: (0..COUNT).collect(),
            ext_indices: vec![],
        };
        let (base_powers, ext_powers) = layout.decompose_alpha(alpha);
        let domain = TwoAdicMultiplicativeCoset::new(F::ONE, 13).unwrap();
        let quotient = domain.create_disjoint_domain(65536);
        let mut main = vec![Pack::ZERO; 2 * WIDTH];
        let mut reports = vec![];
        let mut integrity_mismatches = 0;
        for group in 0..2 {
            for (index, value) in main.iter_mut().enumerate() {
                *value =
                    Pack::from_fn(|lane| F::from_usize(1 + 31 * index + 13 * lane + 1009 * group));
            }
            let public: Vec<F> = (0..196)
                .map(|i| F::from_usize(17 * (i + 1) + 43 * group))
                .collect();
            let points: Vec<F> = (0..Pack::WIDTH)
                .map(|lane| {
                    (0..group * 17 + lane).fold(quotient.first_point(), |point, _| {
                        quotient.next_point(point).unwrap()
                    })
                })
                .collect();
            let selectors: Vec<_> = points
                .iter()
                .map(|point| domain.selectors_at_point(*point))
                .collect();
            let first = Pack::from_fn(|lane| selectors[lane].is_first_row);
            let last = Pack::from_fn(|lane| selectors[lane].is_last_row);
            let transition = Pack::from_fn(|lane| selectors[lane].is_transition);
            let inverse = Pack::from_fn(|lane| selectors[lane].inv_vanishing);
            assert!(first.as_slice().iter().all(|x| *x != F::ZERO));
            assert!(last.as_slice().iter().all(|x| *x != F::ZERO));
            assert!(transition.as_slice().iter().all(|x| *x != F::ZERO));
            let empty = RowMajorMatrixView::new(&[], 0);
            let mut folder = ProverConstraintFolder::<Config> {
                main: RowMajorMatrixView::new(&main, WIDTH),
                preprocessed: empty,
                preprocessed_window: RowWindow::from_view(&empty),
                periodic_values: &[],
                public_values: &public,
                is_first_row: first,
                is_last_row: last,
                is_transition: transition,
                base_alpha_powers: &base_powers,
                ext_alpha_powers: &ext_powers,
                base_constraints: Vec::with_capacity(COUNT),
                ext_constraints: vec![],
                constraint_index: 0,
                constraint_count: COUNT,
            };
            let timer = Instant::now();
            FactorSignatureOwnerAir.eval(&mut folder);
            let eval_ns = timer.elapsed().as_nanos();
            assert_eq!(folder.constraint_index, COUNT);
            assert_eq!(folder.base_constraints.len(), COUNT);
            assert!(folder.ext_constraints.is_empty());
            let timer = Instant::now();
            let folded = folder.finalize_constraints();
            let fold_ns = timer.elapsed().as_nanos();
            let mut expected = vec![];
            for lane in 0..Pack::WIDTH {
                let scalar = folder
                    .base_constraints
                    .iter()
                    .fold(EF::ZERO, |acc, value| acc * alpha + value.as_slice()[lane]);
                assert_eq!(
                    <PackedChallenge<Config> as PackedFieldExtension<F, EF>>::extract(
                        &folded, lane
                    ),
                    scalar
                );
                assert_ne!(scalar, EF::ZERO);
                expected.push(coefficients(scalar));
            }
            if group == 0 {
                let mut raw = Vec::with_capacity(COUNT * 4);
                for value in &folder.base_constraints {
                    raw.extend(value.as_slice()[0].as_canonical_u32().to_le_bytes());
                }
                save("residuals.bin", &raw);
                let index = folder
                    .base_constraints
                    .iter()
                    .position(|value| value.as_slice()[0] != F::ZERO)
                    .unwrap();
                let original = folder.base_constraints[index];
                folder.base_constraints[index] += Pack::ONE;
                assert_ne!(folder.finalize_constraints(), folded);
                folder.base_constraints[index] = original;
                assert_eq!(folder.finalize_constraints(), folded);
                integrity_mismatches += 1;
                let residuals = core::mem::take(&mut folder.base_constraints);
                drop(folder);
                let mut tampered_powers = base_powers.clone();
                tampered_powers[0][index] += F::ONE;
                // The altered weights use the actual retained finalizer on
                // the original collected residuals, without reevaluating AIR.
                let mut changed = ProverConstraintFolder::<Config> {
                    main: RowMajorMatrixView::new(&main, WIDTH),
                    preprocessed: empty,
                    preprocessed_window: RowWindow::from_view(&empty),
                    periodic_values: &[],
                    public_values: &public,
                    is_first_row: first,
                    is_last_row: last,
                    is_transition: transition,
                    base_alpha_powers: &tampered_powers,
                    ext_alpha_powers: &ext_powers,
                    base_constraints: residuals,
                    ext_constraints: vec![],
                    constraint_index: COUNT,
                    constraint_count: COUNT,
                };
                assert_ne!(changed.finalize_constraints(), folded);
                changed.base_alpha_powers = &base_powers;
                assert_eq!(changed.finalize_constraints(), folded);
                drop(changed);
                integrity_mismatches += 1;
            }
            reports.push(serde_json::json!({"group":group,"eval_ns":eval_ns,"fold_ns":fold_ns,"folded":expected,
                "inverse_vanishing":inverse.as_slice().iter().map(|x|x.as_canonical_u32()).collect::<Vec<_>>(),
                "points":points.iter().map(|x|x.as_canonical_u32()).collect::<Vec<_>>() }));
        }
        let report = serde_json::json!({"format":"kova.fold-probe.v1","constraints":COUNT,"width":WIDTH,"packed_lanes":Pack::WIDTH,
            "main_bytes":2*WIDTH*core::mem::size_of::<Pack>(),"constraint_bytes":COUNT*core::mem::size_of::<Pack>(),
            "alpha":[3,5,7,11],"base_modulus":2013265921u32,"extension_nonresidue":11,"groups":reports,
            "fold_integrity_mismatches":integrity_mismatches,"signature_trace_allocations":0,"backend_proofs":0});
        save(
            "report.json",
            serde_json::to_string_pretty(&report).unwrap().as_bytes(),
        );
        println!(
            "actual_air_row_groups=2 scalar_folds=pass fold_integrity_mismatches=2 signature_trace_allocations=0 backend_proofs=0"
        );
    }

    #[test]
    fn independent_extension_reference_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/extension-reference.json")).unwrap();
        assert_eq!(cases["base_modulus"].as_u64(), Some(2013265921));
        for case in cases["cases"].as_array().unwrap() {
            let alpha = EF::from_basis_coefficients_fn(|index| {
                F::from_u64(case["alpha"][index].as_u64().unwrap())
            });
            let result = case["residuals"]
                .as_array()
                .unwrap()
                .iter()
                .fold(EF::ZERO, |acc, value| {
                    acc * alpha + F::from_u64(value.as_u64().unwrap())
                });
            let expected: Vec<u32> = case["folded"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(coefficients(result).as_slice(), expected);
        }
    }
}
