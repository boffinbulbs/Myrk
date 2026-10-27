use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use super::{Mode, Statement, Witness, mul, ntt};

pub const HEIGHT: usize = 256;
pub const PAD: usize = 224;
pub const BANK: usize = PAD + 1;
pub const PRODUCTS: usize = BANK + 256;
pub const WRITES: usize = PRODUCTS + 8 * mul::WIDTH;
pub const FLAGS: usize = WRITES + 16 * 46;
pub const WIDTH: usize = FLAGS + 16;
pub const PUBLIC_VALUES: usize = 2113;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Initialize(usize),
    Butterfly { layer: usize, chunk: usize },
    Normalize(usize),
    Output(usize),
}

#[derive(Clone)]
pub(crate) struct Instruction {
    pub kind: Kind,
    pub destinations: [Option<usize>; 16],
    pub butterflies: Vec<(usize, usize, u32)>,
}

pub(crate) fn program(mode: Mode) -> Vec<Instruction> {
    let mut result = Vec::new();
    for group in 0..32 {
        result.push(Instruction {
            kind: Kind::Initialize(group),
            destinations: core::array::from_fn(|slot| (slot < 8).then_some(group * 8 + slot)),
            butterflies: Vec::new(),
        });
    }
    for layer in 0..8 {
        let all = ntt::butterflies(mode, layer);
        for chunk in 0..16 {
            let butterflies = all[chunk * 8..(chunk + 1) * 8].to_vec();
            result.push(Instruction {
                kind: Kind::Butterfly { layer, chunk },
                destinations: core::array::from_fn(|slot| {
                    let tuple = butterflies[slot / 2];
                    Some(if slot % 2 == 0 { tuple.0 } else { tuple.1 })
                }),
                butterflies,
            });
        }
    }
    if mode == Mode::Inverse {
        for group in 0..32 {
            result.push(Instruction {
                kind: Kind::Normalize(group),
                destinations: core::array::from_fn(|slot| (slot < 8).then_some(group * 8 + slot)),
                butterflies: Vec::new(),
            });
        }
    }
    for group in 0..32 {
        result.push(Instruction {
            kind: Kind::Output(group),
            destinations: [None; 16],
            butterflies: Vec::new(),
        });
    }
    assert_eq!(result.len(), if mode == Mode::Forward { 192 } else { 224 });
    result
}

pub struct NttAir {
    mode: Mode,
    instructions: Vec<Instruction>,
    routes: [Vec<(usize, usize)>; 256],
}

impl NttAir {
    pub fn new(statement: &Statement) -> Self {
        let instructions = program(statement.mode);
        let mut routes: [Vec<(usize, usize)>; 256] = core::array::from_fn(|_| Vec::new());
        for (pc, instruction) in instructions.iter().enumerate() {
            for (slot, destination) in instruction.destinations.iter().enumerate() {
                if let Some(index) = destination {
                    routes[*index].push((pc, slot));
                }
            }
        }
        Self {
            mode: statement.mode,
            instructions,
            routes,
        }
    }
}

impl<F> BaseAir<F> for NttAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |acc, value| acc.double() + *value)
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for NttAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let public = builder.public_values().to_vec();
        let instructions = &self.instructions;
        let active = instructions.len();
        builder.assert_eq(public[0], BabyBear::from_u8(self.mode as u8));
        let mut selector_sum = AB::Expr::ZERO;
        for pc in 0..=PAD {
            builder.assert_bool(local[pc]);
            selector_sum += local[pc].into();
            builder
                .when_first_row()
                .assert_eq(local[pc], BabyBear::from_bool(pc == 0));
            let predecessor: AB::Expr = if pc == PAD {
                local[PAD].into() + local[active - 1]
            } else if pc > 0 && pc < active {
                local[pc - 1].into()
            } else {
                AB::Expr::ZERO
            };
            builder.when_transition().assert_eq(next[pc], predecessor);
            if (active..PAD).contains(&pc) {
                builder.assert_zero(local[pc]);
            }
        }
        builder.assert_one(selector_sum);
        builder.when_last_row().assert_one(local[PAD]);
        for coefficient in &local[BANK..PRODUCTS] {
            builder.when_first_row().assert_zero(*coefficient);
        }

        // A canonical write window is sufficient with zero initialization and
        // exact holds for every nonwritten bank cell. It is not a free range hint.
        for bit in &local[WRITES..FLAGS] {
            builder.assert_bool(*bit);
        }
        let writes: [AB::Expr; 16] = core::array::from_fn(|slot| {
            let start = WRITES + slot * 46;
            packed::<AB>(&local[start..start + 23])
        });
        for (slot, value) in writes.iter().enumerate() {
            let start = WRITES + slot * 46 + 23;
            builder.assert_eq(
                value.clone() + packed::<AB>(&local[start..start + 23]),
                BabyBear::from_u32(mul::MODULUS - 1),
            );
        }
        let products: Vec<_> = (0..8)
            .map(|slot| {
                mul::eval_mul(
                    builder,
                    &local[PRODUCTS + slot * mul::WIDTH..PRODUCTS + (slot + 1) * mul::WIDTH],
                )
            })
            .collect();
        for flag in &local[FLAGS..WIDTH] {
            builder.assert_bool(*flag);
        }

        // Selectors form one fixed program. These updates include every bank
        // cell, including untouched butterfly and normalization coefficients.
        for index in 0..256 {
            let mut change = AB::Expr::ZERO;
            for &(pc, slot) in &self.routes[index] {
                change += local[pc] * (writes[slot].clone() - local[BANK + index]);
            }
            builder
                .when_transition()
                .assert_eq(next[BANK + index], local[BANK + index].into() + change);
        }

        // Algebraic multiplexing avoids another phase gate around a register
        // read. x and y become zero on every nonarithmetic instruction.
        for (slot, product) in products.iter().enumerate() {
            let mut x = AB::Expr::ZERO;
            let mut y = AB::Expr::ZERO;
            for (pc, instruction) in instructions.iter().enumerate() {
                match instruction.kind {
                    Kind::Butterfly { .. } => {
                        let (left, right, twiddle) = instruction.butterflies[slot];
                        x += local[pc] * BabyBear::from_u32(twiddle);
                        y += match self.mode {
                            Mode::Forward => local[pc] * local[BANK + right],
                            Mode::Inverse => {
                                local[pc]
                                    * (local[BANK + left] - local[BANK + right]
                                        + local[FLAGS + slot * 2 + 1]
                                            * BabyBear::from_u32(mul::MODULUS))
                            }
                        };
                    }
                    Kind::Normalize(group) => {
                        x += local[pc] * BabyBear::from_u32(ntt::INVERSE_256);
                        y += local[pc] * local[BANK + group * 8 + slot];
                    }
                    _ => {}
                }
            }
            builder.assert_eq(product[0].clone(), x);
            builder.assert_eq(product[1].clone(), y);
        }

        for (pc, instruction) in instructions.iter().enumerate() {
            let selector = local[pc];
            match instruction.kind {
                Kind::Initialize(group) | Kind::Output(group) => {
                    let output = matches!(instruction.kind, Kind::Output(_));
                    for (slot, value) in writes.iter().enumerate().take(8) {
                        let index = group * 8 + slot;
                        if output {
                            builder
                                .when(selector)
                                .assert_eq(value.clone(), local[BANK + index]);
                        }
                        for byte in 0..4 {
                            let start = WRITES + slot * 46 + byte * 8;
                            let encoded = if byte < 3 {
                                packed::<AB>(&local[start..start + if byte == 2 { 7 } else { 8 }])
                            } else {
                                AB::Expr::ZERO
                            };
                            let public_index = (if output { 1025 } else { 1 }) + index * 4 + byte;
                            builder
                                .when(selector)
                                .assert_eq(public[public_index], encoded);
                        }
                    }
                    for value in &writes[8..] {
                        builder.when(selector).assert_zero(value.clone());
                    }
                }
                Kind::Butterfly { .. } => {
                    for (slot, product) in products.iter().enumerate() {
                        let (left, right, _) = instruction.butterflies[slot];
                        let a: AB::Expr = local[BANK + left].into();
                        let b: AB::Expr = local[BANK + right].into();
                        let add = local[FLAGS + slot * 2];
                        let borrow = local[FLAGS + slot * 2 + 1];
                        match self.mode {
                            Mode::Forward => {
                                builder.when(selector).assert_eq(
                                    writes[slot * 2].clone(),
                                    a.clone() + product[3].clone()
                                        - add * BabyBear::from_u32(mul::MODULUS),
                                );
                                builder.when(selector).assert_eq(
                                    writes[slot * 2 + 1].clone(),
                                    a - product[3].clone()
                                        + borrow * BabyBear::from_u32(mul::MODULUS),
                                );
                            }
                            Mode::Inverse => {
                                builder.when(selector).assert_eq(
                                    writes[slot * 2].clone(),
                                    a + b - add * BabyBear::from_u32(mul::MODULUS),
                                );
                                builder
                                    .when(selector)
                                    .assert_eq(writes[slot * 2 + 1].clone(), product[3].clone());
                            }
                        }
                    }
                }
                Kind::Normalize(_) => {
                    for slot in 0..8 {
                        builder
                            .when(selector)
                            .assert_eq(writes[slot].clone(), products[slot][3].clone());
                    }
                    for value in &writes[8..] {
                        builder.when(selector).assert_zero(value.clone());
                    }
                }
            }
            if !matches!(instruction.kind, Kind::Butterfly { .. }) {
                for flag in &local[FLAGS..WIDTH] {
                    builder.when(selector).assert_zero(*flag);
                }
            }
        }
        for value in &writes {
            builder.when(local[PAD]).assert_zero(value.clone());
        }
        for flag in &local[FLAGS..WIDTH] {
            builder.when(local[PAD]).assert_zero(*flag);
        }
    }
}

pub(crate) fn encode_product(product: &ntt::Product, output: &mut [BabyBear]) {
    let mut bits = |start, value: u32, count| {
        for bit in 0..count {
            output[start + bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
        }
    };
    for (index, value) in product.values.into_iter().enumerate() {
        bits(index * 23, value, 23);
        bits(
            mul::COMPLEMENTS + index * 23,
            (mul::MODULUS - 1).wrapping_sub(value),
            23,
        );
    }
    bits(mul::CARRY0, product.carry0.wrapping_add(2) as u32, 13);
    bits(mul::CARRY1, product.carry1.wrapping_add(4096) as u32, 14);
}

pub(crate) fn encode_write(value: u32, output: &mut [BabyBear]) {
    for bit in 0..23 {
        output[bit] = BabyBear::from_bool((value >> bit) & 1 != 0);
        output[23 + bit] =
            BabyBear::from_bool(((mul::MODULUS - 1).wrapping_sub(value) >> bit) & 1 != 0);
    }
}

pub(crate) fn trace_for_input(input: [u32; 256], mode: Mode) -> RowMajorMatrix<BabyBear> {
    let instructions = program(mode);
    let mut bank = [0u32; 256];
    let mut values = vec![BabyBear::ZERO; WIDTH * HEIGHT];
    for (row_index, row) in values.chunks_exact_mut(WIDTH).enumerate() {
        row[if row_index < instructions.len() {
            row_index
        } else {
            PAD
        }] = BabyBear::ONE;
        for (index, value) in bank.iter().enumerate() {
            row[BANK + index] = BabyBear::from_u32(*value);
        }
        let mut writes = [0u32; 16];
        let mut products = [ntt::product(0, 0); 8];
        let mut flags = [[false; 2]; 8];
        if let Some(instruction) = instructions.get(row_index) {
            match instruction.kind {
                Kind::Initialize(group) => {
                    writes[..8].copy_from_slice(&input[group * 8..(group + 1) * 8])
                }
                Kind::Output(group) => {
                    writes[..8].copy_from_slice(&bank[group * 8..(group + 1) * 8])
                }
                Kind::Normalize(group) => {
                    for slot in 0..8 {
                        products[slot] = ntt::product(ntt::INVERSE_256, bank[group * 8 + slot]);
                        writes[slot] = products[slot].values[3];
                    }
                }
                Kind::Butterfly { .. } => {
                    for slot in 0..8 {
                        let (left, right, twiddle) = instruction.butterflies[slot];
                        let (a, b) = (bank[left], bank[right]);
                        match mode {
                            Mode::Forward => {
                                products[slot] = ntt::product(twiddle, b);
                                let t = products[slot].values[3];
                                let add = a + t >= mul::MODULUS;
                                let borrow = a < t;
                                flags[slot] = [add, borrow];
                                writes[slot * 2] = a + t - if add { mul::MODULUS } else { 0 };
                                writes[slot * 2 + 1] = (u64::from(a)
                                    + if borrow { u64::from(mul::MODULUS) } else { 0 }
                                    - u64::from(t))
                                    as u32;
                            }
                            Mode::Inverse => {
                                let add = a + b >= mul::MODULUS;
                                let borrow = a < b;
                                let difference = (u64::from(a)
                                    + if borrow { u64::from(mul::MODULUS) } else { 0 }
                                    - u64::from(b))
                                    as u32;
                                products[slot] = ntt::product(twiddle, difference);
                                flags[slot] = [add, borrow];
                                writes[slot * 2] = a + b - if add { mul::MODULUS } else { 0 };
                                writes[slot * 2 + 1] = products[slot].values[3];
                            }
                        }
                    }
                }
            }
            for (slot, destination) in instruction.destinations.iter().enumerate() {
                if let Some(index) = destination {
                    bank[*index] = writes[slot];
                }
            }
        }
        for slot in 0..8 {
            encode_product(
                &products[slot],
                &mut row[PRODUCTS + slot * mul::WIDTH..PRODUCTS + (slot + 1) * mul::WIDTH],
            );
            row[FLAGS + slot * 2] = BabyBear::from_bool(flags[slot][0]);
            row[FLAGS + slot * 2 + 1] = BabyBear::from_bool(flags[slot][1]);
        }
        for slot in 0..16 {
            encode_write(
                writes[slot],
                &mut row[WRITES + slot * 46..WRITES + (slot + 1) * 46],
            );
        }
    }
    RowMajorMatrix::new(values, WIDTH)
}

pub fn trace(witness: &Witness, statement: &Statement) -> RowMajorMatrix<BabyBear> {
    trace_for_input(witness.input, statement.mode)
}

pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    core::iter::once(BabyBear::from_u8(statement.mode as u8))
        .chain(
            statement
                .input
                .iter()
                .chain(&statement.output)
                .flat_map(|v| v.to_le_bytes().map(BabyBear::from_u8)),
        )
        .chain(statement.context.map(BabyBear::from_u8))
        .collect()
}
