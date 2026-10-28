use crate::reconstructed_row::{Mode, ntt};
pub const HEIGHT: usize = 1024;
pub const MATRIX_END: usize = 294;
pub const FORWARD_END: usize = 422;
pub const POINT_END: usize = 454;
pub const INVERSE_END: usize = 582;
pub const NORMALIZE_END: usize = 614;
pub const HINT_END: usize = 646;

#[derive(Clone, Copy)]
pub enum Kind {
    Matrix { column: usize, local: usize },
    Forward,
    Point(usize),
    Inverse,
    Normalize(usize),
    Hint(usize),
    Pad,
}
#[derive(Clone)]
pub struct Instruction {
    pub kind: Kind,
    pub butterflies: Vec<(usize, usize, u32)>,
    pub a_destinations: [Option<usize>; 16],
    pub w_destinations: [Option<usize>; 16],
}
pub fn instructions() -> Vec<Instruction> {
    (0..HEIGHT)
        .map(|row| {
            let mut result = Instruction {
                kind: Kind::Pad,
                butterflies: Vec::new(),
                a_destinations: [None; 16],
                w_destinations: [None; 16],
            };
            if row < MATRIX_END {
                result.kind = Kind::Matrix {
                    column: row / 42,
                    local: row % 42,
                };
            } else if row < FORWARD_END {
                let step = row - MATRIX_END;
                result.kind = Kind::Forward;
                result.butterflies = ntt::butterflies(Mode::Forward, step / 16)
                    [step % 16 * 8..(step % 16 + 1) * 8]
                    .to_vec();
                result.w_destinations = core::array::from_fn(|slot| {
                    Some(if slot % 2 == 0 {
                        result.butterflies[slot / 2].0
                    } else {
                        result.butterflies[slot / 2].1
                    })
                });
            } else if row < POINT_END {
                let group = row - FORWARD_END;
                result.kind = Kind::Point(group);
                result.a_destinations =
                    core::array::from_fn(|slot| (slot % 2 == 1).then_some(group * 8 + slot / 2));
            } else if row < INVERSE_END {
                let step = row - POINT_END;
                result.kind = Kind::Inverse;
                result.butterflies = ntt::butterflies(Mode::Inverse, step / 16)
                    [step % 16 * 8..(step % 16 + 1) * 8]
                    .to_vec();
                result.a_destinations = core::array::from_fn(|slot| {
                    Some(if slot % 2 == 0 {
                        result.butterflies[slot / 2].0
                    } else {
                        result.butterflies[slot / 2].1
                    })
                });
            } else if row < NORMALIZE_END {
                let group = row - INVERSE_END;
                result.kind = Kind::Normalize(group);
                result.a_destinations =
                    core::array::from_fn(|slot| (slot < 8).then_some(group * 8 + slot));
            } else if row < HINT_END {
                result.kind = Kind::Hint(row - NORMALIZE_END);
            }
            result
        })
        .collect()
}
