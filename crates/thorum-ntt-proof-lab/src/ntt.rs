use crate::{Mode, Statement, Witness, mul};

pub const ROOT: u32 = 1753;
pub const INVERSE_256: u32 = 8_347_681;

fn power(mut x: u64, mut e: u32) -> u32 {
    let q = u64::from(mul::MODULUS);
    let mut result = 1;
    while e != 0 {
        if e & 1 != 0 {
            result = result * x % q;
        }
        x = x * x % q;
        e >>= 1;
    }
    result as u32
}
pub(crate) fn zetas() -> [u32; 256] {
    core::array::from_fn(|k| {
        if k == 0 {
            0
        } else {
            power(u64::from(ROOT), (k as u8).reverse_bits() as u32)
        }
    })
}
pub(crate) fn butterflies(mode: Mode, stage: usize) -> Vec<(usize, usize, u32)> {
    assert!(stage < 8);
    let length = match mode {
        Mode::Forward => 128 >> stage,
        Mode::Inverse => 1 << stage,
    };
    let z = zetas();
    let mut result = Vec::with_capacity(128);
    for group in 0..128 / length {
        let k = match mode {
            Mode::Forward => (1 << stage) + group,
            Mode::Inverse => (256 >> stage) - 1 - group,
        };
        let twiddle = match mode {
            Mode::Forward => z[k],
            Mode::Inverse => mul::MODULUS - z[k],
        };
        for j in 0..length {
            let left = group * 2 * length + j;
            result.push((left, left + length, twiddle));
        }
    }
    result
}

#[derive(Clone, Copy)]
pub(crate) struct Product {
    pub values: [u32; 4],
    pub carry0: i32,
    pub carry1: i32,
}
pub(crate) fn product(x: u32, y: u32) -> Product {
    let p = u64::from(x) * u64::from(y);
    let k = (p / u64::from(mul::MODULUS)) as u32;
    let z = (p % u64::from(mul::MODULUS)) as u32;
    let low = |v: u32| i64::from(v & 4095);
    let high = |v: u32| i64::from(v >> 12);
    let c0 = (low(x) * low(y) - low(k) - low(z)) / 4096;
    let c1 = (low(x) * high(y) + high(x) * low(y) - 2046 * low(k) - high(k) - high(z) + c0) / 4096;
    Product {
        values: [x, y, k, z],
        carry0: c0 as i32,
        carry1: c1 as i32,
    }
}
pub(crate) struct Row {
    pub polynomial: [u32; 256],
    pub products: [Product; 128],
    pub carries: [[bool; 2]; 128],
}
pub(crate) fn empty_row(polynomial: [u32; 256]) -> Row {
    Row {
        polynomial,
        products: [product(0, 0); 128],
        carries: [[false; 2]; 128],
    }
}
pub(crate) fn rows(witness: &Witness, statement: &Statement) -> Vec<Row> {
    rows_for_input(witness.input, statement.mode)
}
pub(crate) fn rows_for_input(input: [u32; 256], mode: Mode) -> Vec<Row> {
    let mut current = input;
    let mut rows = Vec::new();
    for stage in 0..8 {
        let mut row = empty_row(current);
        let mut next = current;
        for (slot, (left, right, twiddle)) in butterflies(mode, stage).into_iter().enumerate() {
            let a = current[left];
            let b = current[right];
            match mode {
                Mode::Forward => {
                    let p = product(twiddle, b);
                    let t = p.values[3];
                    let sum = a + t;
                    let add = sum >= mul::MODULUS;
                    let borrow = a < t;
                    next[left] = sum - if add { mul::MODULUS } else { 0 };
                    next[right] = (u64::from(a) + if borrow { u64::from(mul::MODULUS) } else { 0 }
                        - u64::from(t)) as u32;
                    row.products[slot] = p;
                    row.carries[slot] = [add, borrow];
                }
                Mode::Inverse => {
                    let sum = a + b;
                    let add = sum >= mul::MODULUS;
                    let borrow = a < b;
                    let difference = (u64::from(a)
                        + if borrow { u64::from(mul::MODULUS) } else { 0 }
                        - u64::from(b)) as u32;
                    let p = product(twiddle, difference);
                    next[left] = sum - if add { mul::MODULUS } else { 0 };
                    next[right] = p.values[3];
                    row.products[slot] = p;
                    row.carries[slot] = [add, borrow];
                }
            }
        }
        rows.push(row);
        current = next;
    }
    if mode == Mode::Inverse {
        for half in 0..2 {
            let mut row = empty_row(current);
            for slot in 0..128 {
                let index = half * 128 + slot;
                let p = product(INVERSE_256, current[index]);
                row.products[slot] = p;
                current[index] = p.values[3];
            }
            rows.push(row);
        }
    }
    rows.push(empty_row(current));
    rows
}
