//! Temporal output storage model. No transform, signature or proof backend.
#![forbid(unsafe_code)]

#[path = "../../signature-scheduling/src/clock.rs"]
pub mod clock;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

pub const HEIGHT: usize = 8192;
pub const WIDTH: usize = 274;
const SOURCE: usize = 192;
const DEDICATED: usize = SOURCE + 32;
const SHARED: usize = DEDICATED + 32;
pub const BANKS: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 8, 6];

/// Representative coordinates are the first and last actual output groups.
pub const fn write_row(logical: usize, coordinate: usize) -> usize {
    610 + 192 * logical + 31 * coordinate
}

/// Conservative reads include every potential matrix sampler iteration.
pub fn read_windows(logical: usize) -> Vec<(usize, usize)> {
    match logical {
        0..=6 => (0..8)
            .map(|i| {
                let start = 642 + 48 * (8 * logical + i);
                (start + 6, start + 48)
            })
            .collect(),
        7 => vec![(3330, 3586)],
        8..=15 => {
            let start = 3330 + 32 * (logical - 8);
            vec![(start, start + 32)]
        }
        _ => panic!("logical output outside fixed schedule"),
    }
}

/// The unsafe map exists only as a negative layout control.
pub struct LifetimeAir {
    unsafe_overlap_control: bool,
}
impl LifetimeAir {
    pub const fn candidate() -> Self {
        Self {
            unsafe_overlap_control: false,
        }
    }
    pub const fn overlap_control() -> Self {
        Self {
            unsafe_overlap_control: true,
        }
    }
    fn bank(&self, logical: usize) -> usize {
        if self.unsafe_overlap_control && logical == 14 {
            6
        } else {
            BANKS[logical]
        }
    }
}
impl<F> BaseAir<F> for LifetimeAir {
    fn width(&self) -> usize {
        WIDTH
    }
}
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for LifetimeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        clock::eval(builder, local, next, 0, 64, 128);
        for index in 0..32 {
            builder
                .when_transition()
                .assert_eq(next[SOURCE + index], local[SOURCE + index]);
        }
        for logical in 0..16 {
            let active: AB::Expr = read_windows(logical)
                .iter()
                .map(|&(from, to)| clock::interval::<AB>(local, 0, 64, 128, from, to))
                .sum();
            for coordinate in 0..2 {
                let source = local[SOURCE + 2 * logical + coordinate];
                let dedicated = DEDICATED + 2 * logical + coordinate;
                let shared = SHARED + 2 * self.bank(logical) + coordinate;
                let selected = clock::at::<AB>(local, 0, 64, 128, write_row(logical, coordinate));
                builder.when_first_row().assert_zero(local[dedicated]);
                builder.when_transition().assert_eq(
                    next[dedicated],
                    local[dedicated].into() + selected * (source - local[dedicated]),
                );
                builder.assert_zero(active.clone() * (local[dedicated] - source));
                builder.assert_zero(active.clone() * (local[shared] - local[dedicated]));
            }
        }
        // A physical cell has one aggregate producer update and one hold rule.
        for bank in 0..9 {
            for coordinate in 0..2 {
                let column = SHARED + 2 * bank + coordinate;
                builder.when_first_row().assert_zero(local[column]);
                let mut delta = AB::Expr::ZERO;
                for logical in 0..16 {
                    if self.bank(logical) == bank {
                        let selected =
                            clock::at::<AB>(local, 0, 64, 128, write_row(logical, coordinate));
                        delta +=
                            selected * (local[SOURCE + 2 * logical + coordinate] - local[column]);
                    }
                }
                builder
                    .when_transition()
                    .assert_eq(next[column], local[column].into() + delta);
            }
        }
    }
}

#[cfg(test)]
mod tests;
