use super::*;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, check_all_constraints};
use p3_matrix::dense::RowMajorMatrix;
use serde_json::Value;

struct Harness;
impl<F> BaseAir<F> for Harness {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        6
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for Harness {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let values = eval_use_hint(builder, local);
        let public = builder.public_values().to_vec();
        for (byte, expected) in public[..4].iter().copied().enumerate() {
            let start = byte * 8;
            let value = if start < 23 {
                packed::<AB>(&local[start..(start + 8).min(23)])
            } else {
                AB::Expr::ZERO
            };
            builder.assert_eq(expected, value);
        }
        builder.assert_eq(values.hint, public[4]);
        builder.assert_eq(values.output, public[5]);
    }
}

fn bits(row: &mut [BabyBear], start: usize, value: i64, count: usize) {
    let word = value as u64;
    for bit in 0..count {
        row[start + bit] = BabyBear::from_bool((word >> bit) & 1 != 0);
    }
}

fn row_for_input(input: u32, hint: u8) -> Vec<BabyBear> {
    let r = i64::from(input);
    let shifted = r + i64::from(GAMMA2) - 1;
    let n = shifted / i64::from(ALPHA);
    let u = shifted % i64::from(ALPHA);
    let edge = i64::from(n == 16);
    let high = n % 16;
    let low = u - i64::from(GAMMA2) + 1 - edge;
    let positive = i64::from(low > 0);
    let sign_slack = if positive == 1 {
        u - i64::from(GAMMA2) - edge
    } else {
        i64::from(GAMMA2) + edge - 1 - u
    };
    let raw = high + i64::from(hint == 1) * (2 * positive - 1);
    let borrow = i64::from(raw < 0);
    let overflow = i64::from(raw > 15);
    let output = raw + 16 * (borrow - overflow);
    let mut row = vec![BabyBear::ZERO; WIDTH];
    for (offset, value, count) in [
        (R, r, 23),
        (R_COMPLEMENT, i64::from(MODULUS) - 1 - r, 23),
        (N, n, 5),
        (N_COMPLEMENT, 16 - n, 5),
        (U, u, 19),
        (U_COMPLEMENT, i64::from(ALPHA) - 1 - u, 19),
        (HIGH, high, 4),
        (OUTPUT, output, 4),
        (SIGN_SLACK, sign_slack, 18),
    ] {
        bits(&mut row, offset, value, count);
    }
    row[EDGE] = BabyBear::from_bool(edge == 1);
    row[POSITIVE] = BabyBear::from_bool(positive == 1);
    row[HINT] = BabyBear::from_u8(hint);
    row[BORROW] = BabyBear::from_bool(borrow == 1);
    row[OVERFLOW] = BabyBear::from_bool(overflow == 1);
    row
}

fn public(input: u32, hint: u8, output: u8) -> Vec<BabyBear> {
    input
        .to_le_bytes()
        .into_iter()
        .chain([hint, output])
        .map(BabyBear::from_u8)
        .collect()
}

fn check(row: Vec<BabyBear>, input: u32, hint: u8, output: u8) -> p3_air::ConstraintReport {
    let trace = RowMajorMatrix::new(row.repeat(2), WIDTH);
    check_all_constraints(&Harness, &trace, &public(input, hint, output), Some(32))
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

#[test]
fn exact_bit_layout_and_symbolic_degree_are_conservative() {
    assert_eq!(WIDTH, 125);
    let layout = p3_air::symbolic::AirLayout {
        main_width: WIDTH,
        num_public_values: 6,
        ..Default::default()
    };
    assert_eq!(
        p3_air::symbolic::get_max_constraint_degree::<BabyBear, _>(&Harness, layout, 2),
        2
    );
}

#[test]
fn every_rounding_sign_and_wrap_boundary_matches_independent_reference_air() {
    let data = parse(include_str!(
        "../../../../research/coefficient-constraints/boundary_vectors.json"
    ));
    for case in data["cases"].as_array().unwrap() {
        let input = case["r"].as_u64().unwrap() as u32;
        let hint = case["hint"].as_u64().unwrap() as u8;
        let output = case["expected"]["output"].as_u64().unwrap() as u8;
        assert!(
            check(row_for_input(input, hint), input, hint, output).is_ok(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn genuine_signature_reconstruction_coefficients_match_independent_reference_air() {
    let data = parse(include_str!(
        "../../../../research/coefficient-constraints/signature_vectors.json"
    ));
    assert_eq!(data["cases"].as_array().unwrap().len(), 10240);
    for case in data["cases"].as_array().unwrap() {
        let input = case["r"].as_u64().unwrap() as u32;
        let hint = case["hint"].as_u64().unwrap() as u8;
        let output = case["expected"]["output"].as_u64().unwrap() as u8;
        assert!(
            check(row_for_input(input, hint), input, hint, output).is_ok(),
            "{}",
            case["source"]
        );
    }
}

#[test]
fn wrong_diagnostics_and_public_integer_field_aliases_fail_actual_air() {
    let data = parse(include_str!(
        "../../../../research/coefficient-constraints/invalid_diagnostics.json"
    ));
    for case in data["cases"].as_array().unwrap() {
        let input = case["r"].as_u64().unwrap() as u32;
        let hint = case["hint"].as_u64().unwrap() as u8;
        let output = case["output"].as_u64().unwrap() as u8;
        assert!(
            !check(row_for_input(input, hint), input, hint, output).is_ok(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn quotient_model_matches_independent_fips_decomposition_for_every_canonical_residue() {
    for r in 0..MODULUS {
        let mut low = i64::from(r % ALPHA);
        if low > i64::from(GAMMA2) {
            low -= i64::from(ALPHA);
        }
        let high = if i64::from(r) - low == i64::from(MODULUS - 1) {
            low -= 1;
            0
        } else {
            (i64::from(r) - low) / i64::from(ALPHA)
        };
        let n = i64::from((r + GAMMA2 - 1) / ALPHA);
        let u = i64::from((r + GAMMA2 - 1) % ALPHA);
        let edge = i64::from(n == 16);
        assert_eq!(high, n - 16 * edge);
        assert_eq!(low, u - i64::from(GAMMA2) + 1 - edge);
        let pos = i64::from(u >= i64::from(GAMMA2) + edge);
        assert_eq!(pos == 1, low > 0);
        for hint in 0..=1 {
            let expected = if hint == 0 {
                high
            } else {
                (high + if low > 0 { 1 } else { -1 }).rem_euclid(16)
            };
            let raw = high + hint * (2 * pos - 1);
            let actual = raw + 16 * (i64::from(raw < 0) - i64::from(raw > 15));
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn causal_tie_edge_sign_wrap_and_bit_alias_faults_fail_actual_air() {
    let mut cases: Vec<(&str, Vec<BabyBear>, u32, u8, u8)> = Vec::new();
    let mut row = row_for_input(0, 1);
    row[POSITIVE] = BabyBear::ONE;
    row[SIGN_SLACK..BORROW].fill(BabyBear::ZERO);
    row[BORROW] = BabyBear::ZERO;
    bits(&mut row, OUTPUT, 1, 4);
    cases.push((
        "zero_low_treated_positive_with_matching_wrong_output",
        row,
        0,
        1,
        1,
    ));

    let mut row = row_for_input(GAMMA2, 1);
    row[POSITIVE] = BabyBear::ZERO;
    row[SIGN_SLACK..BORROW].fill(BabyBear::ZERO);
    row[BORROW] = BabyBear::ONE;
    bits(&mut row, OUTPUT, 15, 4);
    cases.push(("positive_tie_treated_nonpositive", row, GAMMA2, 1, 15));

    for input in [MODULUS - GAMMA2, MODULUS - 1] {
        let mut row = row_for_input(input, 1);
        row[EDGE] = BabyBear::ZERO;
        let u = (input + GAMMA2 - 1) % ALPHA;
        bits(&mut row, SIGN_SLACK, i64::from(GAMMA2 - 1 - u), 18);
        cases.push(("q_minus_one_region_without_edge", row, input, 1, 15));
    }
    let mut row = row_for_input(0, 0);
    row[BORROW] = BabyBear::ONE;
    row[OVERFLOW] = BabyBear::ONE;
    cases.push(("both_wrap_flags_preserve_scalar_equation", row, 0, 0, 0));

    let mut row = row_for_input(0, 1);
    row[BORROW] = BabyBear::ZERO;
    bits(&mut row, OUTPUT, 0, 4);
    cases.push(("missing_borrow_with_canonical_wrong_output", row, 0, 1, 0));

    let input = 15 * ALPHA + 1;
    let mut row = row_for_input(input, 1);
    row[OVERFLOW] = BabyBear::ZERO;
    bits(&mut row, OUTPUT, 15, 4);
    cases.push((
        "missing_overflow_with_canonical_wrong_output",
        row,
        input,
        1,
        15,
    ));

    let mut row = row_for_input(ALPHA, 0);
    bits(&mut row, HIGH, 0, 4);
    bits(&mut row, OUTPUT, 0, 4);
    cases.push(("wrong_high_with_matching_wrong_output", row, ALPHA, 0, 0));

    let input = GAMMA2 + 1;
    let mut row = row_for_input(input, 1);
    bits(&mut row, N, 0, 5);
    bits(&mut row, N_COMPLEMENT, 16, 5);
    bits(&mut row, U, i64::from(ALPHA), 19);
    bits(&mut row, U_COMPLEMENT, -1, 19);
    bits(&mut row, HIGH, 0, 4);
    row[POSITIVE] = BabyBear::ONE;
    bits(&mut row, SIGN_SLACK, i64::from(GAMMA2), 18);
    row[BORROW] = BabyBear::ZERO;
    row[OVERFLOW] = BabyBear::ZERO;
    bits(&mut row, OUTPUT, 1, 4);
    cases.push((
        "unbounded_remainder_preserves_rounding_equation",
        row,
        input,
        1,
        1,
    ));

    for offset in [
        R,
        R_COMPLEMENT,
        N,
        N_COMPLEMENT,
        U,
        U_COMPLEMENT,
        HIGH,
        OUTPUT,
        SIGN_SLACK,
    ] {
        let mut row = row_for_input(0, 1);
        row[offset] += BabyBear::from_u8(2);
        row[offset + 1] -= BabyBear::ONE;
        cases.push(("nonboolean_bits_preserve_every_scalar_pack", row, 0, 1, 15));
    }
    let mut row = row_for_input(MODULUS - 1, 1);
    bits(&mut row, N, 17, 5);
    bits(&mut row, HIGH, 1, 4);
    bits(&mut row, N_COMPLEMENT, -1, 5);
    cases.push((
        "five_bit_n_is_not_a_bound_of_sixteen",
        row,
        MODULUS - 1,
        1,
        15,
    ));

    for (name, row, input, hint, output) in cases {
        let report = check(row, input, hint, output);
        assert!(!report.is_ok(), "{name}");
        println!(
            "{}",
            serde_json::json!({"fault":name,"failures":report.failures.iter().take(4).map(|f|[f.row,f.constraint]).collect::<Vec<_>>()})
        );
    }
}
