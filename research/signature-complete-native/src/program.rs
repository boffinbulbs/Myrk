//! Fixed global source schedule. Later row programs are not implemented yet.
use crate::layout::{CLOCK, HEIGHT};
use p3_air::AirBuilder;

pub const SOURCE_PERMUTATIONS: usize = 69;
pub const SOURCE_END: usize = 414;
pub const SAMPLE_START: usize = 12;
pub const SAMPLE_END: usize = 276;
pub const DECODE_END: usize = 448;
pub const INITIAL_END: usize = 450;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Challenge,
    Owner,
    Tr,
    Mu,
    Note,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hash {
    pub kind: Kind,
    pub block: usize,
    pub rate: usize,
    pub blocks: usize,
}
pub fn hash(permutation: usize) -> Option<Hash> {
    let (kind, block, rate, blocks) = match permutation {
        0..=1 => (Kind::Challenge, permutation, 136, 2),
        2..=38 => (Kind::Owner, permutation - 2, 72, 37),
        39..=58 => (Kind::Tr, permutation - 39, 136, 20),
        59..=61 => (Kind::Mu, permutation - 59, 136, 3),
        62..=68 => (Kind::Note, permutation - 62, 72, 7),
        _ => return None,
    };
    Some(Hash {
        kind,
        block,
        rate,
        blocks,
    })
}
pub(crate) fn at<AB: AirBuilder>(row: &[AB::Var], pc: usize) -> AB::Expr {
    assert!(pc < HEIGHT);
    row[CLOCK + pc].into()
}
pub(crate) fn range<AB: AirBuilder>(row: &[AB::Var], from: usize, to: usize) -> AB::Expr {
    assert!(from <= to && to <= HEIGHT);
    row[CLOCK + from..CLOCK + to]
        .iter()
        .copied()
        .map(Into::into)
        .sum()
}
pub(crate) fn hash_selector<AB: AirBuilder>(row: &[AB::Var], permutation: usize) -> AB::Expr {
    range::<AB>(row, permutation * 6, permutation * 6 + 6)
}
