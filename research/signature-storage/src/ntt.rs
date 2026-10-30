//! Sixteen forward transforms and eight source connected inverse transforms.
//! Compact radix4096 arithmetic is adapted from Thorum MIT sources.
//! No child AIR, independent clock, public polynomial or free inverse input is used.
use crate::{full_program as fp, layout::*, mul, program};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

pub const START: usize = 450;
pub const TRANSFORMS: usize = 16;
pub const ROWS_PER_TRANSFORM: usize = 192;
pub const END: usize = START + TRANSFORMS * ROWS_PER_TRANSFORM;
const _: [(); 1] = [(); (START >= program::INITIAL_END && END < HEIGHT) as usize];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Op {
    Initialize(usize),
    Butterfly { layer: usize, chunk: usize },
    Output(usize),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InverseOp {
    Initialize(usize),
    Butterfly { layer: usize, chunk: usize },
    Normalize(usize),
    Output(usize),
}
pub(crate) fn inverse_operation(row: usize) -> Option<(usize, InverseOp)> {
    if !(fp::INVERSE_START..fp::INVERSE_END).contains(&row) {
        return None;
    }
    let offset = row - fp::INVERSE_START;
    let pc = offset % 224;
    Some((
        offset / 224,
        match pc {
            0..=31 => InverseOp::Initialize(pc),
            32..=159 => InverseOp::Butterfly {
                layer: (pc - 32) / 16,
                chunk: (pc - 32) % 16,
            },
            160..=191 => InverseOp::Normalize(pc - 160),
            _ => InverseOp::Output(pc - 192),
        },
    ))
}

pub(crate) fn operation(row: usize) -> Option<(usize, Op)> {
    if !(START..END).contains(&row) {
        return None;
    }
    let offset = row - START;
    let t = offset / ROWS_PER_TRANSFORM;
    let pc = offset % ROWS_PER_TRANSFORM;
    Some((
        t,
        match pc {
            0..=31 => Op::Initialize(pc),
            32..=159 => Op::Butterfly {
                layer: (pc - 32) / 16,
                chunk: (pc - 32) % 16,
            },
            _ => Op::Output(pc - 160),
        },
    ))
}

fn power(mut x: u64, mut n: u32) -> u32 {
    let mut out = 1u64;
    while n != 0 {
        if n & 1 != 0 {
            out = out * x % u64::from(mul::MODULUS);
        }
        x = x * x % u64::from(mul::MODULUS);
        n >>= 1;
    }
    out as u32
}

/// Normal residue twiddles, not Montgomery or signed BabyBear values.
pub(crate) fn butterfly(layer: usize, ordinal: usize) -> (usize, usize, u32) {
    assert!(layer < 8 && ordinal < 128);
    let length = 128 >> layer;
    let group = ordinal / length;
    let left = 2 * group * length + ordinal % length;
    let k = (1usize << layer) + group;
    let zeta = power(1753, (k as u8).reverse_bits() as u32);
    (left, left + length, zeta)
}
pub(crate) fn inverse_butterfly(layer: usize, ordinal: usize) -> (usize, usize, u32) {
    assert!(layer < 8 && ordinal < 128);
    let length = 1 << layer;
    let group = ordinal / length;
    let left = 2 * group * length + ordinal % length;
    let k = (256usize >> layer) - 1 - group;
    (
        left,
        left + length,
        mul::MODULUS - power(1753, (k as u8).reverse_bits() as u32),
    )
}

/// Each source is already canonical and is held before START.
pub(crate) fn source(t: usize, index: usize) -> (usize, u32) {
    assert!(t < TRANSFORMS && index < 256);
    match t {
        0..=6 => (Z_VALUES + 256 * t + index, 1),
        7 => (CHALLENGE + index, 1),
        _ => (T1 + 256 * (t - 8) + index, 8192),
    }
}

fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, bit| acc.double() + *bit)
}

pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    for bit in &local[NTT_WRITES..NTT_FLAGS] {
        builder.assert_bool(*bit);
    }
    let writes: [AB::Expr; 16] = core::array::from_fn(|slot| {
        let start = NTT_WRITES + slot * 46;
        packed::<AB>(&local[start..start + 23])
    });
    for (slot, value) in writes.iter().enumerate() {
        let start = NTT_WRITES + slot * 46 + 23;
        builder.assert_eq(
            value.clone() + packed::<AB>(&local[start..start + 23]),
            BabyBear::from_u32(mul::MODULUS - 1),
        );
    }
    let products: [[AB::Expr; 4]; 8] = core::array::from_fn(|slot| {
        mul::eval_mul(
            builder,
            &local[NTT_PRODUCTS + slot * mul::WIDTH..NTT_PRODUCTS + (slot + 1) * mul::WIDTH],
        )
    });
    for flag in &local[NTT_FLAGS..FORWARD_WIDTH] {
        builder.assert_bool(*flag);
    }

    // Every scratch coordinate has exactly one initialization and eight
    // butterfly producers per transform. All other transitions hold it.
    for index in 0..256 {
        builder
            .when_first_row()
            .assert_zero(local[NTT_SCRATCH + index]);
        let mut change = AB::Expr::ZERO;
        for t in 0..TRANSFORMS {
            let start = START + t * ROWS_PER_TRANSFORM;
            change += program::at::<AB>(local, start + index / 8)
                * (writes[index % 8].clone() - local[NTT_SCRATCH + index]);
            for layer in 0..8 {
                let length = 128 >> layer;
                let group = index / (2 * length);
                let ordinal = group * length + index % length;
                let side = usize::from(index % (2 * length) >= length);
                let slot = 2 * (ordinal % 8) + side;
                let pc = start + 32 + layer * 16 + ordinal / 8;
                change += program::at::<AB>(local, pc)
                    * (writes[slot].clone() - local[NTT_SCRATCH + index]);
            }
        }
        for i in 0..8 {
            let start = fp::INVERSE_START + 224 * i;
            change += program::at::<AB>(local, start + index / 8)
                * (writes[index % 8].clone() - local[NTT_SCRATCH + index]);
            for layer in 0..8 {
                let length = 1 << layer;
                let group = index / (2 * length);
                let ordinal = group * length + index % length;
                let side = usize::from(index % (2 * length) >= length);
                let slot = 2 * (ordinal % 8) + side;
                change += program::at::<AB>(local, start + 32 + 16 * layer + ordinal / 8)
                    * (writes[slot].clone() - local[NTT_SCRATCH + index]);
            }
            change += program::at::<AB>(local, start + 160 + index / 8)
                * (writes[index % 8].clone() - local[NTT_SCRATCH + index]);
        }
        builder.when_transition().assert_eq(
            next[NTT_SCRATCH + index],
            local[NTT_SCRATCH + index].into() + change,
        );
    }
    // A physical output has one update equation across its fixed owners.
    // Each selected value still comes from the actual canonical NTT write.
    for bank in 0..9 {
        for index in 0..256 {
            let column = NTT_OUTPUT + 256 * bank + index;
            builder.when_first_row().assert_zero(local[column]);
            let mut change = AB::Expr::ZERO;
            for (t, physical) in OUTPUT_BANKS.iter().enumerate() {
                if *physical == bank {
                    let start = START + t * ROWS_PER_TRANSFORM;
                    let selected = program::at::<AB>(local, start + 160 + index / 8);
                    change += selected * (writes[index % 8].clone() - local[column]);
                }
            }
            builder
                .when_transition()
                .assert_eq(next[column], local[column].into() + change);
        }
    }

    // Multiplex actual private reads into the integer products without a
    // second clock or a phase gated free operand. Dormant x and y are zero.
    for slot in 0..8 {
        let mut x = AB::Expr::ZERO;
        let mut y = AB::Expr::ZERO;
        for t in 0..TRANSFORMS {
            for layer in 0..8 {
                for chunk in 0..16 {
                    let (_, right, twiddle) = butterfly(layer, 8 * chunk + slot);
                    let pc = START + t * ROWS_PER_TRANSFORM + 32 + 16 * layer + chunk;
                    let selected = program::at::<AB>(local, pc);
                    x += selected.clone() * BabyBear::from_u32(twiddle);
                    y += selected * local[NTT_SCRATCH + right];
                }
            }
        }
        for i in 0..8 {
            let start = fp::INVERSE_START + 224 * i;
            for layer in 0..8 {
                for chunk in 0..16 {
                    let (left, right, twiddle) = inverse_butterfly(layer, 8 * chunk + slot);
                    let selected = program::at::<AB>(local, start + 32 + 16 * layer + chunk);
                    x += selected.clone() * BabyBear::from_u32(twiddle);
                    y += selected
                        * (local[NTT_SCRATCH + left] - local[NTT_SCRATCH + right]
                            + local[NTT_FLAGS + 2 * slot + 1] * BabyBear::from_u32(mul::MODULUS));
                }
            }
            for group in 0..32 {
                let selected = program::at::<AB>(local, start + 160 + group);
                x += selected.clone() * BabyBear::from_u32(8_347_681);
                y += selected * local[NTT_SCRATCH + 8 * group + slot];
            }
        }
        builder.assert_eq(products[slot][0].clone(), x);
        builder.assert_eq(products[slot][1].clone(), y);
    }

    // The complete factor clock selects at most one actual operation row.
    // Every write is its selected producer, with zero for an absent slot or
    // dormant row. Actual operands, modular gadgets and state holds above
    // remain in this same relation.
    let mut expected: [AB::Expr; 16] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut butterfly_phase = AB::Expr::ZERO;
    for row in START..END {
        let (t, op) = operation(row).unwrap();
        let selected = program::at::<AB>(local, row);
        match op {
            Op::Initialize(group) => {
                for (slot, value) in expected.iter_mut().take(8).enumerate() {
                    let (column, factor) = source(t, group * 8 + slot);
                    *value += selected.clone() * local[column] * BabyBear::from_u32(factor);
                }
            }
            Op::Output(group) => {
                for (slot, value) in expected.iter_mut().take(8).enumerate() {
                    *value += selected.clone() * local[NTT_SCRATCH + group * 8 + slot];
                }
            }
            Op::Butterfly { layer, chunk } => {
                butterfly_phase += selected.clone();
                for slot in 0..8 {
                    let (left, _, _) = butterfly(layer, 8 * chunk + slot);
                    let a: AB::Expr = local[NTT_SCRATCH + left].into();
                    expected[2 * slot] += selected.clone()
                        * (a.clone() + products[slot][3].clone()
                            - local[NTT_FLAGS + 2 * slot] * BabyBear::from_u32(mul::MODULUS));
                    expected[2 * slot + 1] += selected.clone()
                        * (a - products[slot][3].clone()
                            + local[NTT_FLAGS + 2 * slot + 1] * BabyBear::from_u32(mul::MODULUS));
                }
            }
        }
    }
    for row in fp::INVERSE_START..fp::INVERSE_END {
        let (i, op) = inverse_operation(row).unwrap();
        let selected = program::at::<AB>(local, row);
        match op {
            InverseOp::Initialize(group) => {
                for (slot, value) in expected.iter_mut().take(8).enumerate() {
                    *value += selected.clone() * local[ACCUMULATOR + 256 * i + 8 * group + slot];
                }
            }
            InverseOp::Output(group) => {
                for (slot, value) in expected.iter_mut().take(8).enumerate() {
                    *value += selected.clone() * local[NTT_SCRATCH + 8 * group + slot];
                }
            }
            InverseOp::Normalize(_) => {
                for (slot, value) in expected.iter_mut().take(8).enumerate() {
                    *value += selected.clone() * products[slot][3].clone();
                }
            }
            InverseOp::Butterfly { layer, chunk } => {
                butterfly_phase += selected.clone();
                for slot in 0..8 {
                    let (left, right, _) = inverse_butterfly(layer, 8 * chunk + slot);
                    expected[2 * slot] += selected.clone()
                        * (local[NTT_SCRATCH + left] + local[NTT_SCRATCH + right]
                            - local[NTT_FLAGS + 2 * slot] * BabyBear::from_u32(mul::MODULUS));
                    expected[2 * slot + 1] += selected.clone() * products[slot][3].clone();
                }
            }
        }
    }
    for (write, value) in writes.into_iter().zip(expected) {
        builder.assert_eq(write, value);
    }
    for flag in &local[NTT_FLAGS..FORWARD_WIDTH] {
        builder.assert_zero((AB::Expr::ONE - butterfly_phase.clone()) * *flag);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Product {
    pub(crate) values: [u32; 4],
    pub(crate) carry0: i32,
    pub(crate) carry1: i32,
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
pub(crate) fn encode_product(p: Product, row: &mut [BabyBear]) {
    for (i, value) in p.values.into_iter().enumerate() {
        crate::build::bits(row, mul::VALUES + 23 * i, value, 23);
        crate::build::bits(row, mul::COMPLEMENTS + 23 * i, mul::MODULUS - 1 - value, 23);
    }
    crate::build::bits(row, mul::CARRY0, (p.carry0 + 2) as u32, 13);
    crate::build::bits(row, mul::CARRY1, (p.carry1 + 4096) as u32, 14);
}
pub(crate) fn encode_write(value: u32, row: &mut [BabyBear]) {
    crate::build::bits(row, 0, value, 23);
    crate::build::bits(row, 23, mul::MODULUS - 1 - value, 23);
}

/// An in place pass over the same wide trace. No caller polynomial is accepted.
pub(crate) fn fill(values: &mut [BabyBear]) {
    assert_eq!(values.len(), HEIGHT * WIDTH);
    let mut bank = [0u32; 256];
    let mut outputs = [0u32; 9 * 256];
    for (row_index, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        for (i, value) in bank.iter().enumerate() {
            row[NTT_SCRATCH + i] = BabyBear::from_u32(*value);
        }
        for (i, value) in outputs.iter().enumerate() {
            row[NTT_OUTPUT + i] = BabyBear::from_u32(*value);
        }
        let mut writes = [0u32; 16];
        let mut products = [product(0, 0); 8];
        let mut flags = [[false; 2]; 8];
        if let Some((t, op)) = operation(row_index) {
            match op {
                Op::Initialize(group) => {
                    for slot in 0..8 {
                        let (column, factor) = source(t, group * 8 + slot);
                        writes[slot] = row[column].as_canonical_u32() * factor;
                        bank[group * 8 + slot] = writes[slot];
                    }
                }
                Op::Output(group) => {
                    for slot in 0..8 {
                        writes[slot] = bank[group * 8 + slot];
                        outputs[256 * OUTPUT_BANKS[t] + group * 8 + slot] = writes[slot];
                    }
                }
                Op::Butterfly { layer, chunk } => {
                    for slot in 0..8 {
                        let (left, right, twiddle) = butterfly(layer, 8 * chunk + slot);
                        let a = bank[left];
                        products[slot] = product(twiddle, bank[right]);
                        let b = products[slot].values[3];
                        let add = a + b >= mul::MODULUS;
                        let borrow = a < b;
                        flags[slot] = [add, borrow];
                        writes[2 * slot] = a + b - if add { mul::MODULUS } else { 0 };
                        writes[2 * slot + 1] = (u64::from(a)
                            + if borrow { u64::from(mul::MODULUS) } else { 0 }
                            - u64::from(b)) as u32;
                        bank[left] = writes[2 * slot];
                        bank[right] = writes[2 * slot + 1];
                    }
                }
            }
        }
        for slot in 0..8 {
            encode_product(
                products[slot],
                &mut row[NTT_PRODUCTS + slot * mul::WIDTH..NTT_PRODUCTS + (slot + 1) * mul::WIDTH],
            );
            row[NTT_FLAGS + 2 * slot] = BabyBear::from_bool(flags[slot][0]);
            row[NTT_FLAGS + 2 * slot + 1] = BabyBear::from_bool(flags[slot][1]);
        }
        for slot in 0..16 {
            encode_write(
                writes[slot],
                &mut row[NTT_WRITES + slot * 46..NTT_WRITES + (slot + 1) * 46],
            );
        }
    }
}
pub(crate) fn fill_inverse(values: &mut [BabyBear]) {
    // Seed from the actual held forward terminal state. Partial initialization
    // preserves every coordinate not yet reloaded, including slot boundaries.
    let initial = &values[fp::INVERSE_START * WIDTH..(fp::INVERSE_START + 1) * WIDTH];
    let mut bank: [u32; 256] =
        core::array::from_fn(|k| initial[NTT_SCRATCH + k].as_canonical_u32());
    for at in fp::INVERSE_START..HEIGHT {
        let row = &mut values[at * WIDTH..(at + 1) * WIDTH];
        for (k, v) in bank.iter().enumerate() {
            row[NTT_SCRATCH + k] = BabyBear::from_u32(*v);
        }
        let mut writes = [0u32; 16];
        let mut products = [product(0, 0); 8];
        let mut flags = [false; 16];
        if let Some((i, op)) = inverse_operation(at) {
            match op {
                InverseOp::Initialize(g) => {
                    for s in 0..8 {
                        writes[s] = row[ACCUMULATOR + 256 * i + 8 * g + s].as_canonical_u32();
                        bank[8 * g + s] = writes[s];
                    }
                }
                InverseOp::Output(g) => {
                    for s in 0..8 {
                        writes[s] = bank[8 * g + s];
                    }
                }
                InverseOp::Normalize(g) => {
                    for s in 0..8 {
                        products[s] = product(8_347_681, bank[8 * g + s]);
                        writes[s] = products[s].values[3];
                        bank[8 * g + s] = writes[s];
                    }
                }
                InverseOp::Butterfly { layer, chunk } => {
                    for s in 0..8 {
                        let (left, right, twiddle) = inverse_butterfly(layer, 8 * chunk + s);
                        let (a, b) = (bank[left], bank[right]);
                        let add = a + b >= mul::MODULUS;
                        let borrow = a < b;
                        let difference = (u64::from(a)
                            + if borrow { u64::from(mul::MODULUS) } else { 0 }
                            - u64::from(b)) as u32;
                        products[s] = product(twiddle, difference);
                        flags[2 * s] = add;
                        flags[2 * s + 1] = borrow;
                        writes[2 * s] = a + b - if add { mul::MODULUS } else { 0 };
                        writes[2 * s + 1] = products[s].values[3];
                        bank[left] = writes[2 * s];
                        bank[right] = writes[2 * s + 1];
                    }
                }
            }
        }
        for s in 0..8 {
            encode_product(
                products[s],
                &mut row[NTT_PRODUCTS + s * mul::WIDTH..NTT_PRODUCTS + (s + 1) * mul::WIDTH],
            );
        }
        for s in 0..16 {
            encode_write(
                writes[s],
                &mut row[NTT_WRITES + 46 * s..NTT_WRITES + 46 * (s + 1)],
            );
            row[NTT_FLAGS + s] = BabyBear::from_bool(flags[s]);
        }
    }
}
