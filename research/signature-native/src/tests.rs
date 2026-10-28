//! Native source tests. Wide and symbolic allocations require external limits.
use super::*;
use layout::*;
use p3_air::{check_all_constraints, Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use serde_json::Value;
use thorum_core::Amount;
use thorum_crypto_lab::{SealedNote, KEM_CIPHERTEXT_BYTES};
use thorum_relation_lab::PaymentOutput;

fn gate(kind: &str) {
    assert_eq!(
        std::env::var(kind).as_deref(),
        Ok("reviewed-external-resource-admission"),
        "External admission and actual limits must precede test selection"
    );
}
#[test]
#[ignore = "Requires explicit external resource admission for static inspection"]
fn shape_schedule_and_private_routes() {
    gate("THORUM_PRIVATE_NTT_STATIC_GATE");
    assert_eq!((HEIGHT, WIDTH, PUBLIC_VALUES), (8192, 44678, 196));
    assert_eq!(HEIGHT * WIDTH * 4, 1_464_008_704);
    assert_eq!(ntt::END, 3522);
    assert!(ntt::operation(449).is_none());
    assert_eq!(ntt::operation(3521), Some((15, ntt::Op::Output(31))));
    assert!(ntt::operation(3522).is_none());
    for i in 0..256 {
        assert_eq!(ntt::source(7, i), (CHALLENGE + i, 1));
        assert_eq!(ntt::source(15, i), (T1 + 7 * 256 + i, 8192));
    }
}
fn read_json(name: &str) -> Value {
    use std::io::Read;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../signature-ownership")
        .join(name);
    let source = std::fs::File::open(path).unwrap();
    assert!(source.metadata().unwrap().is_file());
    let mut raw = Vec::new();
    source
        .take(9 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .unwrap();
    assert!(raw.len() <= 9 * 1024 * 1024);
    serde_json::from_slice(&raw).unwrap()
}
fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}
fn by_id<'a>(items: &'a Value, id: &str) -> &'a Value {
    items
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == id)
        .unwrap()
}
fn transaction() -> PaymentStatement {
    PaymentStatement {
        chain_id: core::array::from_fn(|i| i as u8),
        protocol_version: 7,
        validation_tag: [0x33; 32],
        anchor: [0x44; 64],
        input_nullifiers: vec![[0x50; 64], [0x51; 64]],
        outputs: (0..2)
            .map(|i| PaymentOutput {
                commitment: [0x60 + i; 64],
                envelope: SealedNote {
                    kem_ciphertext: vec![0x70 + i; KEM_CIPHERTEXT_BYTES],
                    nonce: [0x80 + i; 12],
                    ciphertext: vec![0x90 + i; 32],
                },
            })
            .collect(),
        native_fee: Amount::from_atomic(5),
    }
}
fn fixture(raw: &Value, reference: &Value) -> Witness {
    Witness::from_sources(
        bytes(by_id(&raw["keys"], "A")["public_key_hex"].as_str().unwrap()),
        bytes(
            by_id(&raw["signatures"], "A0")["signature_hex"]
                .as_str()
                .unwrap(),
        ),
        bytes(reference["notes"]["N_A"]["opening_hex"].as_str().unwrap()),
    )
}
fn power(mut x: u64, mut n: u32) -> u64 {
    let q = u64::from(MODULUS);
    let mut out = 1;
    while n != 0 {
        if n & 1 != 0 {
            out = out * x % q;
        }
        x = x * x % q;
        n >>= 1;
    }
    out
}
// Direct Horner evaluation at odd roots. No stage, twiddle or butterfly helper.
fn direct(input: [u32; 256]) -> [u32; 256] {
    core::array::from_fn(|i| {
        let mut index = i;
        let mut reverse = 0;
        for _ in 0..8 {
            reverse = 2 * reverse + index % 2;
            index /= 2;
        }
        let root = power(1753, (2 * reverse + 1) as u32);
        input
            .iter()
            .rev()
            .fold(0u64, |a, v| (a * root + u64::from(*v)) % u64::from(MODULUS)) as u32
    })
}
fn expected_input(stage: &Value, t: usize) -> [u32; 256] {
    core::array::from_fn(|i| match t {
        0..=6 => stage["z_signed"][t][i]
            .as_i64()
            .unwrap()
            .rem_euclid(i64::from(MODULUS)) as u32,
        7 => stage["challenge_signed"][i]
            .as_i64()
            .unwrap()
            .rem_euclid(i64::from(MODULUS)) as u32,
        _ => 8192 * stage["t1"][t - 8][i].as_u64().unwrap() as u32,
    })
}
struct ProductsOnly;
impl<F> BaseAir<F> for ProductsOnly {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        196
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for ProductsOnly {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let local = main.current_slice();
        for slot in 0..8 {
            mul::eval_mul(
                b,
                &local[NTT_PRODUCTS + slot * mul::WIDTH..NTT_PRODUCTS + (slot + 1) * mul::WIDTH],
            );
        }
    }
}
fn integer_product(x: u32, y: u32, dst: &mut [BabyBear]) {
    let q = u64::from(MODULUS);
    let p = u64::from(x) * u64::from(y);
    let k = (p / q) as u32;
    let z = (p % q) as u32;
    for (i, v) in [x, y, k, z].into_iter().enumerate() {
        build::bits(dst, 23 * i, v, 23);
        build::bits(dst, mul::COMPLEMENTS + 23 * i, MODULUS - 1 - v, 23);
    }
    let low = |v: u32| i64::from(v % 4096);
    let high = |v: u32| i64::from(v / 4096);
    let c0 = (low(x) * low(y) - low(k) - low(z)) / 4096;
    let c1 = (low(x) * high(y) + high(x) * low(y) - 2046 * low(k) - high(k) - high(z) + c0) / 4096;
    build::bits(dst, mul::CARRY0, (c0 + 2) as u32, 13);
    build::bits(dst, mul::CARRY1, (c1 + 4096) as u32, 14);
}
fn valid(t: &RowMajorMatrix<BabyBear>, public: &[BabyBear]) -> bool {
    check_all_constraints(&PrivateForwardNttAir, t, public, Some(1)).is_ok()
}

#[test]
#[ignore = "Requires external native limits and one wide trace"]
fn sixteen_direct_source_transforms_and_locally_exact_crosswires() {
    gate("THORUM_PRIVATE_NTT_NATIVE_GATE");
    let raw = read_json("raw-fixture.json");
    let reference = read_json("reference-fixture.json");
    let stage = &by_id(&reference["signature_records"], "A0")["fixed_target_stages"];
    let witness = fixture(&raw, &reference);
    let tx = transaction();
    let public = Statement::from_transaction(&tx).unwrap().public_values();
    let mut trace = build_private_forward_ntts(&witness, &tx).unwrap();
    assert_eq!((trace.height(), trace.width()), (8192, 44678));
    assert!(valid(&trace, &public));
    for t in 0..16 {
        let input = expected_input(stage, t);
        let expected = direct(input);
        let final_row = trace.row_slice(HEIGHT - 1).unwrap();
        for i in 0..256 {
            assert_eq!(
                final_row[NTT_OUTPUT + 256 * t + i].as_canonical_u32(),
                expected[i]
            );
        }
    }
    // Exact alternative products satisfy the integer equations, but their x/y
    // operands cannot detach from the private clock selected scratch reads.
    let arithmetic_row = ntt::START + 32;
    let at = arithmetic_row * WIDTH + NTT_PRODUCTS;
    let saved = trace.values[at..at + mul::WIDTH].to_vec();
    let read_bits = |bits: &[BabyBear]| {
        bits.iter()
            .enumerate()
            .map(|(i, v)| v.as_canonical_u32() << i)
            .sum::<u32>()
    };
    let x = read_bits(&saved[..23]);
    let y = read_bits(&saved[23..46]);
    for (wrong_x, wrong_y) in [((x + 1) % MODULUS, y), (x, (y + 1) % MODULUS)] {
        integer_product(wrong_x, wrong_y, &mut trace.values[at..at + mul::WIDTH]);
        assert!(check_all_constraints(&ProductsOnly, &trace, &public, Some(1)).is_ok());
        assert!(!valid(&trace, &public));
        trace.values[at..at + mul::WIDTH].copy_from_slice(&saved);
    }
    // Source initialization, output producers, dropped writes and last row holds.
    // Canonical alternative writes keep all Boolean/complement equations valid.
    for row in [ntt::START, ntt::START + 160] {
        let at = row * WIDTH + NTT_WRITES;
        let saved = trace.values[at..at + 46].to_vec();
        let value = read_bits(&saved[..23]);
        ntt::encode_write((value + 1) % MODULUS, &mut trace.values[at..at + 46]);
        assert!(check_all_constraints(&ProductsOnly, &trace, &public, Some(1)).is_ok());
        assert!(!valid(&trace, &public));
        trace.values[at..at + 46].copy_from_slice(&saved);
    }
    for (row, column) in [
        (arithmetic_row + 1, NTT_SCRATCH),
        (ntt::END, NTT_OUTPUT + 4095),
        (HEIGHT - 1, NTT_OUTPUT + 4095),
        (HEIGHT - 1, NTT_SCRATCH + 255),
    ] {
        let at = row * WIDTH + column;
        let value = trace.values[at];
        trace.values[at] += BabyBear::ONE;
        assert!(check_all_constraints(&ProductsOnly, &trace, &public, Some(1)).is_ok());
        assert!(!valid(&trace, &public));
        trace.values[at] = value;
    }
    // A23bit q value with an arbitrary complement cannot pass canonical writes.
    let at = (ntt::START + 159) * WIDTH + NTT_WRITES;
    let saved = trace.values[at..at + 46].to_vec();
    build::bits(&mut trace.values[at..at + 46], 0, MODULUS, 23);
    build::bits(&mut trace.values[at..at + 46], 23, 0, 23);
    assert!(!valid(&trace, &public));
    trace.values[at..at + 46].copy_from_slice(&saved);
    assert!(valid(&trace, &public));
}

#[test]
#[ignore = "Requires external symbolic memory limits, no trace"]
fn actual_symbolic_shape_and_degree() {
    gate("THORUM_PRIVATE_NTT_SYMBOLIC_GATE");
    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    let air = PrivateForwardNttAir;
    let shape = AirLayout::from_air::<BabyBear>(&air);
    assert_eq!((shape.main_width, shape.num_public_values), (44678, 196));
    assert_eq!(
        (shape.preprocessed_width, shape.num_periodic_columns),
        (0, 0)
    );
    let (constraint_count, degree) = {
        let constraints = get_symbolic_constraints::<BabyBear, _>(&air, shape);
        let count = constraints.len();
        let degree = constraints
            .iter()
            .map(|value| value.degree_multiple())
            .max()
            .unwrap_or(0);
        drop(constraints);
        (count, degree)
    };
    assert!(constraint_count > 0);
    assert!(degree > 0);
    println!("Actual private forward NTT symbolic constraints_per_row {constraint_count}, degree {degree}; collection dropped. No backend result.");
}
