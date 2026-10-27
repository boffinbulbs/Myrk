use super::*;
use crate::mul::MODULUS;
use p3_air::{Air, BaseAir, WindowAccess, check_all_constraints};
use p3_matrix::dense::RowMajorMatrix;
use serde_json::Value;

const WIDTH: usize = 40 + Z_AUX_WIDTH;
struct Harness {
    z: bool,
}
impl<F> BaseAir<F> for Harness {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        if self.z { 13 } else { 29 }
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for Harness {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let public = builder.public_values().to_vec();
        for byte in 0..5 {
            builder.assert_eq(public[byte], packed::<AB>(&local[byte * 8..(byte + 1) * 8]));
        }
        if self.z {
            let normal = decode_z_pair(builder, &local[..40], &local[40..]);
            for (index, value) in normal.into_iter().enumerate() {
                let output = 5 + index * 4;
                for byte in 0..4 {
                    let offset = byte * 8;
                    let expected = if offset < 23 {
                        let start = 40 + NORMAL + index * 23 + offset;
                        packed::<AB>(&local[start..start + (23 - offset).min(8)])
                    } else {
                        AB::Expr::ZERO
                    };
                    builder.assert_eq(public[output + byte], expected);
                }
                let expected = (0..4).rev().fold(AB::Expr::ZERO, |acc, byte| {
                    let value: AB::Expr = public[output + byte].into();
                    acc * BabyBear::from_u32(256) + value
                });
                builder.assert_eq(value, expected);
            }
        } else {
            let values = decode_t1(builder, &local[..40]);
            let scaled = scaled_t1(builder, &local[..40]);
            for (index, value) in values.into_iter().enumerate() {
                let start = index * 10;
                builder.assert_eq(
                    public[5 + index * 2],
                    packed::<AB>(&local[start..start + 8]),
                );
                builder.assert_eq(
                    public[6 + index * 2],
                    packed::<AB>(&local[start + 8..start + 10]),
                );
                let low: AB::Expr = public[5 + index * 2].into();
                let high: AB::Expr = public[6 + index * 2].into();
                builder.assert_eq(value.clone(), low + high * BabyBear::from_u32(256));
                let output = 13 + index * 4;
                builder.assert_zero(public[output]);
                builder.assert_eq(
                    public[output + 1],
                    packed::<AB>(&local[start..start + 3]) * BabyBear::from_u32(32),
                );
                builder.assert_eq(
                    public[output + 2],
                    packed::<AB>(&local[start + 3..start + 10]),
                );
                builder.assert_zero(public[output + 3]);
                builder.assert_eq(scaled[index].clone(), value * BabyBear::from_u32(8192));
            }
            for value in &local[40..] {
                builder.assert_zero(*value);
            }
        }
    }
}

fn set_bits(row: &mut [BabyBear], offset: usize, value: i64, count: usize) {
    for bit in 0..count {
        row[offset + bit] = BabyBear::from_bool((value as u64 >> bit) & 1 != 0);
    }
}
fn raw_bytes(case: &Value) -> [u8; 5] {
    let text = case["bytes_hex"].as_str().unwrap();
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}
fn fixture(case: &Value, z: bool) -> (Vec<BabyBear>, Vec<BabyBear>) {
    let raw = raw_bytes(case);
    let mut row = vec![BabyBear::ZERO; WIDTH];
    for (byte, value) in raw.into_iter().enumerate() {
        set_bits(&mut row, byte * 8, i64::from(value), 8);
    }
    let mut public = raw.to_vec();
    if z {
        for index in 0..2 {
            let d = case["encoded"][index].as_i64().unwrap();
            let normal = case["normal"][index].as_u64().unwrap() as u32;
            for (offset, value, count) in [
                (LOWER + index * 20, d - 121, 20),
                (UPPER + index * 20, 1_048_455 - d, 20),
                (NORMAL + index * 23, i64::from(normal), 23),
                (
                    COMPLEMENTS + index * 23,
                    i64::from(MODULUS - 1 - normal),
                    23,
                ),
                (NEGATIVE + index, i64::from(d > 524_288), 1),
            ] {
                set_bits(&mut row, 40 + offset, value, count);
            }
            public.extend(normal.to_le_bytes());
        }
    } else {
        for value in case["decoded"].as_array().unwrap() {
            public.extend((value.as_u64().unwrap() as u16).to_le_bytes());
        }
        for value in case["scaled"].as_array().unwrap() {
            public.extend((value.as_u64().unwrap() as u32).to_le_bytes());
        }
    }
    (row, public.into_iter().map(BabyBear::from_u8).collect())
}
fn check(row: &[BabyBear], public: &[BabyBear], z: bool) -> bool {
    check_all_constraints(
        &Harness { z },
        &RowMajorMatrix::new(row.repeat(2), WIDTH),
        public,
        Some(32),
    )
    .is_ok()
}
fn data() -> Value {
    serde_json::from_str(include_str!(
        "../../../../research/coefficient-constraints/packing_vectors.json"
    ))
    .unwrap()
}

#[test]
fn genuine_key_and_signature_windows_match_independent_decoding() {
    let data = data();
    assert_eq!(data["t1"].as_array().unwrap().len(), 2602);
    assert_eq!(data["z"].as_array().unwrap().len(), 4624);
    for (name, z) in [("t1", false), ("z", true)] {
        for case in data[name].as_array().unwrap() {
            let (row, public) = fixture(case, z);
            assert_eq!(
                check(&row, &public, z),
                !z || case["accepted"].as_bool().unwrap(),
                "{case}"
            );
        }
    }
}

#[test]
fn detached_results_and_nonboolean_packing_aliases_fail_actual_constraints() {
    let data = data();
    for (name, z) in [("t1", false), ("z", true)] {
        let case = &data[name][0];
        let (row, public) = fixture(case, z);
        assert!(check(&row, &public, z));
        for index in 0..40 {
            let mut changed = row.clone();
            changed[index] = BabyBear::from_u32(2);
            assert!(!check(&changed, &public, z));
        }
        for index in 0..public.len() {
            let mut changed = public.clone();
            changed[index] += BabyBear::ONE;
            assert!(!check(&row, &changed, z));
        }
        if z {
            for index in 40..WIDTH {
                let mut changed = row.clone();
                changed[index] = BabyBear::from_u32(2);
                assert!(!check(&changed, &public, z));
            }
        }
    }
}

#[test]
fn coefficient_windows_have_derived_degree_two() {
    for z in [false, true] {
        let air = Harness { z };
        let layout = p3_air::symbolic::AirLayout {
            main_width: WIDTH,
            num_public_values: <Harness as BaseAir<BabyBear>>::num_public_values(&air),
            ..Default::default()
        };
        assert_eq!(
            p3_air::symbolic::get_max_constraint_degree::<BabyBear, _>(&air, layout, 2),
            2
        );
    }
}

#[test]
fn byte_distinct_public_prime_aliases_fail_result_bindings() {
    let data = data();
    for (name, z, base, count) in [("t1", false, 13, 4), ("z", true, 5, 2)] {
        let case = &data[name][0];
        let (row, public) = fixture(case, z);
        for index in 0..count {
            let start = base + index * 4;
            let mut changed = public.clone();
            let value = if z {
                case["normal"][index].as_u64().unwrap() as u32
            } else {
                case["scaled"][index].as_u64().unwrap() as u32
            };
            for (byte, value) in (value + 2_013_265_921)
                .to_le_bytes()
                .into_iter()
                .enumerate()
            {
                changed[start + byte] = BabyBear::from_u8(value);
            }
            assert!(!check(&row, &changed, z));
        }
    }
}
