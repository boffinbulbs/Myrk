use super::*;
use p3_air::{Air, AirBuilder, BaseAir};
use serde_json::Value;

pub(super) fn data() -> &'static Value {
    static DATA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../research/reconstructed-row/vectors.json"
            ))
            .unwrap(),
        )
        .unwrap()
    })
}
pub(super) fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}
pub(super) fn from_input(input: &Value) -> Witness {
    Witness::from_inputs(
        bytes(input["rho_hex"].as_str().unwrap()),
        core::array::from_fn(|c| {
            core::array::from_fn(|i| input["zhat"][c][i].as_u64().unwrap() as u32)
        }),
        core::array::from_fn(|i| input["t1"][i].as_u64().unwrap() as u16),
        core::array::from_fn(|i| input["chat"][i].as_u64().unwrap() as u32),
        core::array::from_fn(|i| input["hint"][i].as_u64().unwrap() as u8),
    )
}
pub(super) fn fixture(case: &Value) -> (Witness, Statement) {
    (
        from_input(&case["input"]),
        Statement::new(case["input"]["row"].as_u64().unwrap() as u8, [0x71; 64]).unwrap(),
    )
}
pub(super) fn value(row: &[BabyBear], start: usize, count: usize) -> u32 {
    (0..count)
        .map(|bit| row[start + bit].as_canonical_u32() << bit)
        .sum()
}
pub(super) fn count(row: &[BabyBear], lane: usize) -> usize {
    row[COUNT + lane * 257..COUNT + (lane + 1) * 257]
        .iter()
        .position(|v| *v == BabyBear::ONE)
        .unwrap()
}
fn bank(t: &RowMajorMatrix<BabyBear>, at: usize, start: usize, expected: &Value) {
    let row = t.row_slice(at).unwrap();
    for (i, v) in expected.as_array().unwrap().iter().enumerate() {
        assert_eq!(
            row[start + i].as_canonical_u32(),
            v.as_u64().unwrap() as u32,
            "bank row{at} cell{i}"
        );
    }
}
fn product(row: &[BabyBear], lane: usize, x: u32, y: u32, k: u32, z: u32, carries: [i64; 2]) {
    for (i, expected) in [x, y, k, z].iter().enumerate() {
        assert_eq!(
            value(row, PRODUCTS + lane * mul::WIDTH + i * 23, 23),
            *expected
        );
    }
    assert_eq!(
        i64::from(value(row, PRODUCTS + lane * mul::WIDTH + mul::CARRY0, 13)) - 2,
        carries[0]
    );
    assert_eq!(
        i64::from(value(row, PRODUCTS + lane * mul::WIDTH + mul::CARRY1, 14)) - 4096,
        carries[1]
    );
}
pub(super) fn compare_case(t: &RowMajorMatrix<BabyBear>, case: &Value) {
    for (column, model) in case["matrix_columns"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        bank(t, column * 42, ACCUMULATOR, &model["accumulator_before"]);
        bank(
            t,
            (column + 1) * 42,
            ACCUMULATOR,
            &model["accumulator_after"],
        );
        if let Some(events) = model["events"].as_array() {
            for (event, m) in events.iter().enumerate() {
                let at = column * 42 + event / 8;
                let lane = event % 8;
                let row = t.row_slice(at).unwrap();
                assert_eq!(
                    count(&row, lane),
                    m["count_before"].as_u64().unwrap() as usize
                );
                assert_eq!(
                    count(&row, lane + 1),
                    m["count_after"].as_u64().unwrap() as usize
                );
                assert_eq!(
                    value(&row, CURSOR + lane * 10, 10),
                    m["cursor_before"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    value(&row, CURSOR + (lane + 1) * 10, 10),
                    m["cursor_after"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    value(&row, CANDIDATE + lane * 24, 24),
                    m["candidate24"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    value(&row, SLACK + lane * 23, 23),
                    m["compare_slack"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    row[TAKE + lane],
                    BabyBear::from_bool(m["take"].as_bool().unwrap())
                );
                product(
                    &row,
                    lane,
                    m["mul_x"].as_u64().unwrap() as u32,
                    m["mul_y"].as_u64().unwrap() as u32,
                    m["mul_quotient"].as_u64().unwrap() as u32,
                    m["product"].as_u64().unwrap() as u32,
                    [
                        m["mul_carry0"].as_i64().unwrap(),
                        m["mul_carry1"].as_i64().unwrap(),
                    ],
                );
                assert_eq!(
                    value(&row, WRITES + lane * 2 * 46, 23),
                    m["selected_old"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    value(&row, WRITES + (lane * 2 + 1) * 46, 23),
                    m["new"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    row[FLAGS + lane * 2].as_canonical_u32(),
                    m["add_carry"].as_u64().unwrap() as u32
                );
            }
        }
    }
    for load in case["t1_load_windows"].as_array().unwrap() {
        let at = load["physical_row"].as_u64().unwrap() as usize;
        let row = t.row_slice(at).unwrap();
        assert_eq!(
            value(&row, T1_BITS, 8),
            u32::from(bytes::<10>(load["bytes_hex"].as_str().unwrap())[0])
        );
        for lane in 0..8 {
            assert_eq!(
                value(&row, T1_BITS + lane * 10, 10),
                load["decoded"][lane].as_u64().unwrap() as u32
            );
        }
    }
    bank(t, 32, WORK, &case["t1_shifted"]);
    bank(t, 294, WORK, &case["t1_forward"]["input"]);
    bank(t, 422, WORK, &case["t1_forward"]["output"]);
    bank(t, 294, ACCUMULATOR, &case["matrix_sum"]);
    bank(t, 454, ACCUMULATOR, &case["subtraction_output"]);
    bank(t, 454, ACCUMULATOR, &case["inverse"]["input"]);
    bank(
        t,
        582,
        ACCUMULATOR,
        &case["inverse"]["raw_butterfly_output"],
    );
    bank(t, 614, ACCUMULATOR, &case["inverse"]["output"]);
    for (mode, begin, storage) in [("t1_forward", 294, WORK), ("inverse", 454, ACCUMULATOR)] {
        for (stage, expected) in case[mode]["stages"].as_array().unwrap().iter().enumerate() {
            let at = begin + 16 * stage;
            bank(t, at, storage, expected);
        }
        for op in case[mode]["operations"].as_array().unwrap() {
            let at = op["physical_row"].as_u64().unwrap() as usize;
            let lane = op["lane"].as_u64().unwrap() as usize;
            let row = t.row_slice(at).unwrap();
            product(
                &row,
                lane,
                op["mul_x"].as_u64().unwrap() as u32,
                op["mul_y"].as_u64().unwrap() as u32,
                op["mul_quotient"].as_u64().unwrap() as u32,
                op["mul_result"].as_u64().unwrap() as u32,
                [
                    op["carry0"].as_i64().unwrap(),
                    op["carry1"].as_i64().unwrap(),
                ],
            );
            if op["kind"] == "normalization" {
                assert_eq!(
                    value(&row, WRITES + lane * 46, 23),
                    op["output_left"].as_u64().unwrap() as u32
                );
            } else {
                assert_eq!(
                    value(&row, WRITES + lane * 2 * 46, 23),
                    op["output_left"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    value(&row, WRITES + (lane * 2 + 1) * 46, 23),
                    op["output_right"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    row[FLAGS + lane * 2].as_canonical_u32(),
                    op["add_carry"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    row[FLAGS + lane * 2 + 1].as_canonical_u32(),
                    op["sub_borrow"].as_u64().unwrap() as u32
                );
            }
        }
    }
    for m in case["challenge_products_subtractions"].as_array().unwrap() {
        let at = m["physical_row"].as_u64().unwrap() as usize;
        let lane = m["lane"].as_u64().unwrap() as usize;
        let row = t.row_slice(at).unwrap();
        product(
            &row,
            lane,
            m["chat_read"].as_u64().unwrap() as u32,
            m["t1hat_read"].as_u64().unwrap() as u32,
            m["quotient"].as_u64().unwrap() as u32,
            m["product"].as_u64().unwrap() as u32,
            [m["carry0"].as_i64().unwrap(), m["carry1"].as_i64().unwrap()],
        );
        assert_eq!(
            value(&row, WRITES + lane * 2 * 46, 23),
            m["accumulator"].as_u64().unwrap() as u32
        );
        assert_eq!(
            value(&row, WRITES + (lane * 2 + 1) * 46, 23),
            m["reduced"].as_u64().unwrap() as u32
        );
        assert_eq!(
            row[FLAGS + lane * 2].as_canonical_u32(),
            m["borrow"].as_u64().unwrap() as u32
        );
    }
    for m in case["hints"].as_array().unwrap() {
        let row = t
            .row_slice(m["physical_row"].as_u64().unwrap() as usize)
            .unwrap();
        let start = USE_HINT + m["lane"].as_u64().unwrap() as usize * hints::WIDTH;
        for (offset, bits, field) in [
            (hints::R, 23, "r"),
            (hints::N, 5, "n"),
            (hints::U, 19, "u"),
            (hints::HIGH, 4, "high"),
            (hints::OUTPUT, 4, "output"),
            (hints::SIGN_SLACK, 18, "sign_slack"),
        ] {
            assert_eq!(
                value(&row, start + offset, bits),
                m[field].as_u64().unwrap() as u32
            );
        }
        for (offset, field) in [
            (hints::HINT, "hint_read"),
            (hints::EDGE, "edge"),
            (hints::POSITIVE, "positive"),
            (hints::BORROW, "borrow"),
            (hints::OVERFLOW, "overflow"),
        ] {
            assert_eq!(
                row[start + offset].as_canonical_u32(),
                m[field].as_u64().unwrap() as u32
            );
        }
    }
    for m in case["packing"].as_array().unwrap() {
        let row = t
            .row_slice(m["write_available_row"].as_u64().unwrap() as usize)
            .unwrap();
        assert_eq!(
            row[W1 + m["byte"].as_u64().unwrap() as usize].as_canonical_u32(),
            m["packed"].as_u64().unwrap() as u32
        );
    }
    let expected = bytes::<128>(case["packed_w1_hex"].as_str().unwrap());
    for at in [646, 1023] {
        let row = t.row_slice(at).unwrap();
        for (i, b) in expected.iter().enumerate() {
            assert_eq!(row[W1 + i], BabyBear::from_u8(*b));
        }
    }
}
#[test]
fn eight_independent_rows_match_all_real_arithmetic_and_private_output_journals() {
    assert_eq!(data()["cases"].as_array().unwrap().len(), 8);
    for case in data()["cases"].as_array().unwrap() {
        let (w, s) = fixture(case);
        let t = trace(&w, &s).unwrap();
        assert!(check(&t, &s), "{}", case["name"]);
        compare_case(&t, case);
    }
}
pub(super) struct WithoutHash;
impl<F> BaseAir<F> for WithoutHash {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for WithoutHash {
    fn eval(&self, b: &mut AB) {
        keccak::eval(b);
        air::eval_state(b);
        row_hash::eval_lifetime(b);
        control::eval(b);
        arithmetic::eval(&ReconstructedRowAir::default(), b);
    }
}
#[test]
fn all_last_candidate_lanes_use_old_xof_and_actual_c8_before_the_next_reset() {
    let b: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../research/reconstructed-row/injected_boundaries.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let baseline = &data()["cases"][0];
    let (w, s) = fixture(baseline);
    let expansions: Vec<_> = (0..7).map(|c| build::expansion(&w, &s, c)).collect();
    for case in b["supported"].as_array().unwrap() {
        assert_eq!(case["seed_preimage_claim"], false);
        let mut streams = core::array::from_fn(|c| expansions[c].1);
        streams[0] = bytes(case["stream_hex"].as_str().unwrap());
        let t = build::trace_with_columns(
            &w,
            &s,
            expansions.iter().map(|v| v.0.clone()).collect(),
            streams,
            false,
        )
        .unwrap();
        let lane = case["completion_lane"].as_u64().unwrap() as usize;
        let old = t.row_slice(41).unwrap();
        let next = t.row_slice(42).unwrap();
        assert_eq!(count(&old, 0), 255 - lane);
        assert_eq!(count(&old, 8), 256);
        assert_eq!(count(&next, 0), 0);
        assert_eq!(value(&next, CURSOR, 10), 0);
        for byte in 0..1008 {
            assert_eq!(old[XOF + byte], BabyBear::from_u8(streams[0][byte]));
            assert_eq!(next[XOF + byte], BabyBear::from_u8(streams[1][byte]));
        }
        assert!(
            check_all_constraints(&WithoutHash, &t, &public_values(&s), Some(8)).is_ok(),
            "late lane{lane}"
        );
        assert!(!check(&t, &s));
        compare_case(&t, case);
    }
    for case in b["unsupported"].as_array().unwrap() {
        let mut streams = core::array::from_fn(|c| expansions[c].1);
        streams[0] = bytes(case["stream_hex"].as_str().unwrap());
        assert_eq!(
            build::trace_with_columns(
                &w,
                &s,
                expansions.iter().map(|v| v.0.clone()).collect(),
                streams,
                false
            )
            .err(),
            Some(Error::UnsupportedCapacity)
        );
        let t = build::trace_with_columns(
            &w,
            &s,
            expansions.iter().map(|v| v.0.clone()).collect(),
            streams,
            true,
        )
        .unwrap();
        assert!(!check_all_constraints(&WithoutHash, &t, &public_values(&s), Some(1)).is_ok());
    }
}
