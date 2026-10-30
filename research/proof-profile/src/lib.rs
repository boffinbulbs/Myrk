#![forbid(unsafe_code)]
//! Conditional arithmetic and retained classical model without a prover.

#[cfg(test)]
mod tests {
    use p3_security::{
        fri::FriRegime,
        grinding::GrindingSites,
        shape::{InstanceShape, StarkAirParams},
        stark::proven_security_report,
    };
    use p3_uni_stark::{OpeningShape, num_batched_openings};
    use std::{fs::OpenOptions, io::Write};
    const HEIGHT: usize = 8192;
    const WIDTH: usize = 47058;

    fn checked_cost(extension: usize, random: usize, queries: usize) -> Option<serde_json::Value> {
        if ![4, 8].contains(&extension)
            || random < extension
            || random > 16
            || queries == 0
            || queries > 4096
        {
            return None;
        }
        let hiding_budget = 2usize.checked_mul(queries.checked_add(extension.checked_mul(2)?)?)?;
        if hiding_budget > HEIGHT {
            return None;
        }
        let chunks = 8usize;
        let prepared_rows = 2usize.checked_mul(HEIGHT)?;
        let lde_rows = 8usize.checked_mul(prepared_rows)?;
        let main_width = WIDTH.checked_add(random)?;
        let auxiliary_width = extension.checked_add(random)?;
        let width_sum = main_width.checked_add((chunks + 1).checked_mul(auxiliary_width)?)?;
        let prepared_bytes = prepared_rows.checked_mul(main_width)?.checked_mul(4)?;
        let committed_bytes = lde_rows.checked_mul(width_sum)?.checked_mul(4)?;
        let query_bytes = queries.checked_mul(main_width)?.checked_mul(4)?;
        Some(
            serde_json::json!({"extension_degree":extension,"random_codewords":random,"queries":queries,
            "minimum_mask_height":hiding_budget,"prepared_field_bytes":prepared_bytes,"commitment_field_bytes":committed_bytes,
            "all_field_bytes":prepared_bytes.checked_add(committed_bytes)?,"main_query_field_bytes_at_distinct_indices":query_bytes,
            "current_shape_limit_accepts":false,"current_two_mib_limit_accepts":false}),
        )
    }

    fn report_data() -> serde_json::Value {
        let cases = [
            ("before_routing", 181221, 4, 4, 64, 123),
            ("current_comparison", 74725, 4, 4, 64, 123),
            ("more_queries", 74725, 4, 4, 128, 123),
            ("larger_extension_candidate", 74725, 8, 8, 128, 247),
        ];
        let mut reports = vec![];
        for (name, constraints, extension, random, queries, field_bits) in cases {
            let costs = checked_cost(extension, random, queries).unwrap();
            let batched = num_batched_openings(
                WIDTH,
                true,
                0,
                false,
                8,
                extension,
                OpeningShape::hiding(random),
            );
            assert!(batched > 90000);
            let fri = FriRegime {
                log_blowup: 3,
                num_queries: queries,
                log_final_poly_len: 0,
                max_log_arity: 1,
                commit_pow_bits: 0,
                query_pow_bits: 0,
            };
            let air = StarkAirParams {
                num_constraints: constraints,
                max_constraint_degree: 4,
                num_quotient_chunks: 8,
                max_combo: 2,
            };
            let shape = InstanceShape {
                log_trace_length: 14,
                modulus_bits: field_bits,
                collision_resistance: 256,
                num_batched_functions: batched,
            };
            let report = proven_security_report(&fri, &air, &shape, &[], &GrindingSites::NONE);
            let selected_bits = report.security_bits();
            assert!(selected_bits.is_finite() && selected_bits > 0.0);
            let (_, binding) = report.binding();
            reports.push(serde_json::json!({"name":name,"constraints":constraints,"challenge_field_bits_floor":field_bits,
                "batched_opening_functions":batched,"costs":costs,"library_classical_rbr_bits":selected_bits,
                "binding_term":binding.label,"report":report}));
        }
        assert_eq!(
            reports[1]["costs"]["all_field_bytes"].as_u64(),
            Some(27796045824)
        );
        assert_eq!(
            reports[1]["batched_opening_functions"].as_u64(),
            Some(94196)
        );
        assert!(reports[3]["costs"]["all_field_bytes"].as_u64().unwrap() > 27796045824);
        let invalid = [
            (8, 4, 64),
            (4, 4, 0),
            (4, 4, 4096),
            (8, 8, usize::MAX),
            (4, usize::MAX, 64),
            (0, 4, 64),
        ];
        for (extension, random, queries) in invalid {
            assert!(checked_cost(extension, random, queries).is_none());
        }
        let record = serde_json::json!({"format":"kova.conditional-proof-profile.v1",
            "scope":"Retained library classical RBR model only, no selected protocol security level",
            "height":HEIGHT,"width":WIDTH,"stored_degree_bits":14,"base_modulus":2013265921u32,
            "grinding_bits":0,"hash_collision_assumption_classical_bits":256,"reports":reports,
            "invalid_profile_controls":6,"parameter_selection":false,"quantum_security_established":false,
            "knowledge_soundness_established":false,"signature_trace_allocations":0,"backend_proofs":0});
        record
    }

    #[test]
    fn retained_model_matches_reference_record() {
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/report.json")).unwrap();
        let actual = report_data();
        for (left, right) in actual["reports"]
            .as_array()
            .unwrap()
            .iter()
            .zip(expected["reports"].as_array().unwrap())
        {
            for name in [
                "name",
                "constraints",
                "challenge_field_bits_floor",
                "batched_opening_functions",
                "costs",
                "binding_term",
            ] {
                assert_eq!(left[name], right[name]);
            }
            assert!(
                (left["library_classical_rbr_bits"].as_f64().unwrap()
                    - right["library_classical_rbr_bits"].as_f64().unwrap())
                .abs()
                    < 1e-10
            );
            for regime in ["udr", "ldr"] {
                let left = left["report"][regime]["terms"].as_array().unwrap();
                let right = right["report"][regime]["terms"].as_array().unwrap();
                assert_eq!(left.len(), right.len());
                for (left, right) in left.iter().zip(right) {
                    assert_eq!(left["label"], right["label"]);
                    assert!(
                        (left["bits"].as_f64().unwrap() - right["bits"].as_f64().unwrap()).abs()
                            < 1e-10
                    );
                }
            }
        }
        assert!(!actual["parameter_selection"].as_bool().unwrap());
        assert!(!actual["quantum_security_established"].as_bool().unwrap());
        assert!(!actual["knowledge_soundness_established"].as_bool().unwrap());
    }

    #[test]
    #[ignore = "Separate finite model source review and external resource admission"]
    fn retained_classical_reports_and_resource_controls() {
        assert_eq!(
            std::env::var("KOVA_SECURITY_PROFILE_GATE").as_deref(),
            Ok("reviewed-external-resource-admission")
        );
        let record = report_data();
        let data = serde_json::to_vec_pretty(&record).unwrap();
        assert!(data.len() < 65536);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("results/report.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(&data).unwrap();
        println!(
            "conditional_reports=4 invalid_profile_controls=6 signature_trace_allocations=0 backend_proofs=0"
        );
    }
}
