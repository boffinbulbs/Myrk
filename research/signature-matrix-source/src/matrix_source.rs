//! Private fixed matrix overlay after the actual forward source prefix.
use super::{
    decoder_state::DecodeError,
    forward_source::{ForwardSource, ForwardSourceError},
    hash_source::Generation,
    initial_source::InitialError,
    matrix_overlay::{MatrixGeneration, MatrixOverlay},
};
use crate::{full_program as fp, layout::*, BoundInputs};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
pub(crate) fn hash_row(at: usize) -> bool {
    fp::matrix(at).is_some_and(|(_, _, local)| local < 36)
}
pub(crate) fn owned(at: usize, column: usize) -> bool {
    (MATRIX_XOF..MATRIX_XOF + 1008).contains(&column)
        || (hash_row(at) && (column < CLOCK || (MESSAGE..RHO).contains(&column)))
}
#[derive(Debug)]
pub(crate) enum MatrixSourceError {
    RowShape,
    Exhausted,
    Incomplete,
}
pub(crate) struct MatrixSource<'a> {
    forward: ForwardSource<'a>,
    overlay: MatrixOverlay,
    next_row: usize,
    baseline: Vec<BabyBear>,
    preserved: usize,
}
impl<'a> MatrixSource<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Result<Self, DecodeError> {
        let forward = ForwardSource::new(inputs)?;
        Ok(Self {
            forward,
            overlay: MatrixOverlay::new(),
            next_row: 0,
            baseline: vec![BabyBear::ZERO; WIDTH],
            preserved: 0,
        })
    }
    pub(crate) fn initial_generation(&self) -> Generation {
        self.forward.generation()
    }
    pub(crate) fn matrix_generation(&self) -> MatrixGeneration {
        self.overlay.generation()
    }
    pub(crate) fn preserved(&self) -> usize {
        self.preserved
    }
    pub(crate) fn forward_preserved(&self) -> usize {
        self.forward.preservation_positions()
    }
    pub(crate) fn initial_preserved(&self) -> usize {
        self.forward.initial_preservation_positions()
    }
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, MatrixSourceError> {
        if row.len() != WIDTH {
            return Err(MatrixSourceError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(MatrixSourceError::Exhausted);
        }
        let at = self.next_row;
        assert_eq!(self.forward.emit_next(row).unwrap(), at);
        self.baseline.copy_from_slice(row);
        assert_eq!(self.overlay.emit_next(row).unwrap(), at);
        for (column, (actual, before)) in row.iter().zip(&self.baseline).enumerate() {
            if !owned(at, column) {
                assert_eq!(
                    actual, before,
                    "matrix changed source at row {at}, column {column}"
                );
                self.preserved += 1;
            }
        }
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), MatrixSourceError> {
        if self.next_row != HEIGHT {
            return Err(MatrixSourceError::Incomplete);
        }
        match self.forward.finish() {
            Ok(()) => {}
            Err(ForwardSourceError::Initial(InitialError::Sample(reason))) => {
                panic!("initial source completion: {reason:?}")
            }
            Err(e) => panic!("forward source completion: {e:?}"),
        }
        self.overlay
            .finish()
            .expect("synchronized matrix overlay completion");
        Ok(())
    }
}
