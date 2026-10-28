use crate::reconstructed_row::{Mode, mul};

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
