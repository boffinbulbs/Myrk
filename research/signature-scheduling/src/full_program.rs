//! One verifier fixed schedule on the retained master clock.
use crate::{layout::*, sources};
use p3_air::AirBuilder;

pub const MATRIX_START: usize = 642;
pub const MATRIX_WINDOW: usize = 48;
pub const MATRIX_END: usize = MATRIX_START + 56 * MATRIX_WINDOW;
pub const POINT_START: usize = MATRIX_END;
pub const POINT_END: usize = POINT_START + 8 * 32;
pub const INVERSE_START: usize = 3522;
pub const INVERSE_END: usize = INVERSE_START + 8 * 224;
pub const FINAL_START: usize = 5316;
pub const FINAL_END: usize = FINAL_START + 9 * 6;
const _: [(); 47058] = [(); WIDTH];
const _: [(); 1] = [(); (FINAL_END < HEIGHT && FINAL_START >= INVERSE_END) as usize];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hash {
    Initial(usize),
    Matrix {
        row: usize,
        column: usize,
        block: usize,
    },
    Final(usize),
    Dummy,
}
#[derive(Clone, Copy)]
pub(crate) enum Byte {
    Initial(sources::Source),
    Fixed(u8),
    Rho(usize),
    Mu(usize),
    W1(usize),
}
pub(crate) fn matrix(row: usize) -> Option<(usize, usize, usize)> {
    if !(MATRIX_START..MATRIX_END).contains(&row) {
        return None;
    }
    let offset = row - MATRIX_START;
    let stream = offset / MATRIX_WINDOW;
    Some((stream % 8, stream / 8, offset % MATRIX_WINDOW))
}
pub(crate) fn matrix_start(i: usize, j: usize) -> usize {
    assert!(i < 8 && j < 7);
    MATRIX_START + MATRIX_WINDOW * (8 * j + i)
}
pub(crate) fn point(row: usize) -> Option<(usize, usize)> {
    if !(POINT_START..POINT_END).contains(&row) {
        return None;
    }
    let offset = row - POINT_START;
    Some((offset / 32, offset % 32))
}
pub(crate) fn hash(row: usize) -> Hash {
    assert!(row < HEIGHT);
    if row < crate::program::SOURCE_END {
        return Hash::Initial(row / 6);
    }
    if let Some((i, j, local)) = matrix(row) {
        if local < 36 {
            return Hash::Matrix {
                row: i,
                column: j,
                block: local / 6,
            };
        }
    }
    if (FINAL_START..FINAL_END).contains(&row) {
        return Hash::Final((row - FINAL_START) / 6);
    }
    Hash::Dummy
}
pub(crate) fn rate(hash: Hash) -> usize {
    match hash {
        Hash::Initial(p) => crate::program::hash(p).unwrap().rate,
        Hash::Matrix { .. } => 168,
        Hash::Final(_) => 136,
        Hash::Dummy => 0,
    }
}
pub(crate) fn message(hash: Hash, byte: usize) -> Byte {
    assert!(byte < 168);
    match hash {
        Hash::Initial(p) => Byte::Initial(sources::message_source(p, byte)),
        Hash::Matrix {
            row,
            column,
            block: 0,
        } => match byte {
            0..=31 => Byte::Rho(byte),
            32 => Byte::Fixed(column as u8),
            33 => Byte::Fixed(row as u8),
            34 => Byte::Fixed(31),
            167 => Byte::Fixed(128),
            _ => Byte::Fixed(0),
        },
        Hash::Final(block) => {
            if byte >= 136 {
                return Byte::Fixed(0);
            }
            let offset = block * 136 + byte;
            match offset {
                0..=63 => Byte::Mu(offset),
                64..=1087 => Byte::W1(offset - 64),
                1088 => Byte::Fixed(31),
                1223 => Byte::Fixed(128),
                _ => Byte::Fixed(0),
            }
        }
        _ => Byte::Fixed(0),
    }
}
pub(crate) fn fresh(hash: Hash) -> bool {
    match hash {
        Hash::Initial(p) => crate::program::hash(p).unwrap().block == 0,
        Hash::Matrix { block, .. } => block == 0,
        Hash::Final(block) => block == 0,
        Hash::Dummy => true,
    }
}
pub(crate) fn continuation(hash: Hash) -> Option<usize> {
    match hash {
        Hash::Initial(p) => {
            let h = crate::program::hash(p).unwrap();
            (h.block + 1 < h.blocks).then_some(h.rate)
        }
        Hash::Matrix { block, .. } if block < 5 => Some(168),
        Hash::Final(block) if block < 8 => Some(136),
        _ => None,
    }
}
pub(crate) fn sample_selector<AB: AirBuilder>(row: &[AB::Var], i: usize, j: usize) -> AB::Expr {
    crate::program::range::<AB>(row, matrix_start(i, j) + 6, matrix_start(i, j) + 48)
}
pub(crate) fn point_selector<AB: AirBuilder>(row: &[AB::Var], i: usize, g: usize) -> AB::Expr {
    crate::program::at::<AB>(row, POINT_START + 32 * i + g)
}
