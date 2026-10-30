//! Fixed initial source and forward ordering within one nominal owner.
use super::{
    decoder_state::DecodeError,
    forward_state::ForwardState,
    hash_source::Generation,
    initial_source::{InitialError, InitialSource},
};
use crate::{layout::*, BoundInputs};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
#[derive(Debug)]
pub(crate) enum ForwardSourceError {
    RowShape,
    Exhausted,
    Incomplete,
    Initial(InitialError),
}
pub(crate) struct ForwardSource<'a> {
    initial: InitialSource<'a>,
    forward: ForwardState,
    next_row: usize,
    protected: Vec<BabyBear>,
    preservation_positions: usize,
}
impl<'a> ForwardSource<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Result<Self, DecodeError> {
        let initial = InitialSource::new(inputs)?;
        Ok(Self {
            initial,
            forward: ForwardState::new(),
            next_row: 0,
            protected: vec![BabyBear::ZERO; NTT_OUTPUT],
            preservation_positions: 0,
        })
    }
    pub(crate) fn generation(&self) -> Generation {
        self.initial.generation()
    }
    pub(crate) fn preservation_positions(&self) -> usize {
        self.preservation_positions
    }
    pub(crate) fn initial_preservation_positions(&self) -> usize {
        self.initial.preservation_positions()
    }
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, ForwardSourceError> {
        if row.len() != WIDTH {
            return Err(ForwardSourceError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(ForwardSourceError::Exhausted);
        }
        let at = self.next_row;
        assert_eq!(self.initial.emit_next(row).unwrap(), at);
        self.protected.copy_from_slice(&row[..NTT_OUTPUT]);
        let activity = row[ACTIVE_CHALLENGE];
        assert_eq!(self.forward.emit_next(row).unwrap(), at);
        if let Some(column) = row[..NTT_OUTPUT]
            .iter()
            .zip(&self.protected)
            .position(|(a, b)| a != b)
        {
            panic!("forward changed source at row {at}, column {column}");
        }
        assert_eq!(row[ACTIVE_CHALLENGE], activity);
        self.preservation_positions += NTT_OUTPUT + 1;
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), ForwardSourceError> {
        if self.next_row != HEIGHT {
            return Err(ForwardSourceError::Incomplete);
        }
        self.initial.finish().map_err(ForwardSourceError::Initial)?;
        self.forward
            .finish()
            .expect("complete synchronized forward cursor");
        Ok(())
    }
}
