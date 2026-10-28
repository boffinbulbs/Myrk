use crate::reconstructed_row::{Statement, arithmetic, control, keccak, program, row_hash};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub const HEIGHT: usize = 1024;
pub const CLOCK: usize = 4 * p3_keccak_air::NUM_KECCAK_COLS;
pub const MESSAGE: usize = CLOCK + HEIGHT;
pub const OUTPUT: usize = MESSAGE + 168 * 8;
pub const RHO: usize = OUTPUT + 168 * 8;
pub const XOF: usize = RHO + 32;
pub const ZHAT: usize = XOF + 1008;
pub const T1: usize = ZHAT + 7 * 256;
pub const CHAT: usize = T1 + 256;
pub const HINTS: usize = CHAT + 256;
pub const ACCUMULATOR: usize = HINTS + 256;
pub const WORK: usize = ACCUMULATOR + 256;
pub const W1: usize = WORK + 256;
pub const COUNT: usize = W1 + 128;
pub const CURSOR: usize = COUNT + 9 * 257;
pub const CANDIDATE: usize = CURSOR + 9 * 10;
pub const SLACK: usize = CANDIDATE + 8 * 24;
pub const TAKE: usize = SLACK + 8 * 23;
pub const PRODUCTS: usize = TAKE + 8;
pub const WRITES: usize = PRODUCTS + 8 * crate::reconstructed_row::mul::WIDTH;
pub const FLAGS: usize = WRITES + 16 * 46;
pub const T1_BITS: usize = FLAGS + 16;
pub const USE_HINT: usize = T1_BITS + 80;
pub const ROW_BITS: usize = USE_HINT + 8 * crate::reconstructed_row::hints::WIDTH;
pub const WIDTH: usize = ROW_BITS + 3;
pub const PUBLIC_VALUES: usize = 65;

pub struct ReconstructedRowAir {
    pub(crate) instructions: Vec<program::Instruction>,
    pub(crate) a_routes: [Vec<(usize, usize)>; 256],
    pub(crate) w_routes: [Vec<(usize, usize)>; 256],
}
impl Default for ReconstructedRowAir {
    fn default() -> Self {
        let instructions = program::instructions();
        let mut a_routes: [Vec<(usize, usize)>; 256] = core::array::from_fn(|_| Vec::new());
        let mut w_routes: [Vec<(usize, usize)>; 256] = core::array::from_fn(|_| Vec::new());
        for (pc, instruction) in instructions.iter().enumerate() {
            for slot in 0..16 {
                if let Some(index) = instruction.a_destinations[slot] {
                    a_routes[index].push((pc, slot));
                }
                if let Some(index) = instruction.w_destinations[slot] {
                    w_routes[index].push((pc, slot));
                }
            }
        }
        Self {
            instructions,
            a_routes,
            w_routes,
        }
    }
}
impl<F> BaseAir<F> for ReconstructedRowAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}
pub(crate) fn packed<AB: AirBuilder>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .rev()
        .fold(AB::Expr::ZERO, |a, v| a.double() + *v)
}
pub(crate) fn sum_clock<AB: AirBuilder>(
    row: &[AB::Var],
    indices: impl Iterator<Item = usize>,
) -> AB::Expr {
    indices.map(|i| row[CLOCK + i].into()).sum()
}
pub(crate) fn reset<AB: AirBuilder>(row: &[AB::Var]) -> AB::Expr {
    sum_clock::<AB>(row, (0..6).map(|c| c * 42 + 41))
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for ReconstructedRowAir {
    fn eval(&self, builder: &mut AB) {
        keccak::eval(builder);
        eval_state(builder);
        row_hash::eval(builder);
        control::eval(builder);
        arithmetic::eval(self, builder);
    }
}
pub(crate) fn eval_state<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    let public = builder.public_values().to_vec();
    let mut total = AB::Expr::ZERO;
    for pc in 0..HEIGHT {
        let p = local[CLOCK + pc];
        builder.assert_bool(p);
        total += p.into();
        builder
            .when_first_row()
            .assert_eq(p, BabyBear::from_bool(pc == 0));
        let predecessor: AB::Expr = if pc > 0 {
            local[CLOCK + pc - 1].into()
        } else {
            AB::Expr::ZERO
        };
        builder
            .when_transition()
            .assert_eq(next[CLOCK + pc], predecessor);
    }
    builder.assert_one(total);
    builder
        .when_last_row()
        .assert_one(local[CLOCK + HEIGHT - 1]);
    for bit in &local[ROW_BITS..WIDTH] {
        builder.assert_bool(*bit);
    }
    builder.assert_eq(packed::<AB>(&local[ROW_BITS..WIDTH]), public[0]);
    for column in RHO..XOF {
        builder
            .when_transition()
            .assert_eq(next[column], local[column]);
    }
    for column in ZHAT..ACCUMULATOR {
        builder
            .when_transition()
            .assert_eq(next[column], local[column]);
    }
    for hint in &local[HINTS..ACCUMULATOR] {
        builder.assert_bool(*hint);
    }
    for value in &local[ACCUMULATOR..COUNT] {
        builder.when_first_row().assert_zero(*value);
    }
}
pub fn public_values(statement: &Statement) -> Vec<BabyBear> {
    core::iter::once(statement.row)
        .chain(statement.context)
        .map(BabyBear::from_u8)
        .collect()
}
