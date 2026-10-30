//! Unchanged bounded helper on an independent literal witness and short row.
use crate::{layout::*, packed, Witness};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
pub(crate) const PROBES: [usize; 21] = [
    0, 1, 63, 64, 74, 75, 233, 234, 235, 255, 256, 413, 414, 447, 448, 5315, 5316, 5368, 5369,
    5370, 8191,
];
#[derive(Debug)]
pub(crate) enum ReferenceError {
    Sequence,
    Exhausted,
}
pub(crate) struct PortReference {
    witness: Witness,
    row: Vec<BabyBear>,
    next: usize,
    last: Option<usize>,
}
impl PortReference {
    pub(crate) fn new(witness: Witness) -> Self {
        Self {
            witness,
            row: vec![BabyBear::ZERO; MESSAGE],
            next: 0,
            last: None,
        }
    }
    pub(crate) fn prepared(&self) -> usize {
        self.next
    }
    pub(crate) fn pristine(&self) -> bool {
        self.next == 0 && self.last.is_none() && self.row.iter().all(|v| *v == BabyBear::ZERO)
    }
    pub(crate) fn prepare(&mut self, at: usize) -> Result<(), ReferenceError> {
        if self.next == PROBES.len() {
            return Err(ReferenceError::Exhausted);
        }
        if PROBES[self.next] != at {
            return Err(ReferenceError::Sequence);
        }
        self.row.fill(BabyBear::ZERO);
        self.row[CLOCK + at % CLOCK_LOW] = BabyBear::ONE;
        self.row[CLOCK + CLOCK_LOW + at / CLOCK_LOW] = BabyBear::ONE;
        packed::fill(&mut self.row, at, &self.witness);
        self.last = Some(at);
        self.next += 1;
        Ok(())
    }
    pub(crate) fn row(&self, at: usize) -> &[BabyBear] {
        assert_eq!(self.last, Some(at));
        &self.row
    }
}
