//! Private fixed ordering for initial hashing, decoding and sampling.
use super::{
    decoder_state::{DecodeError, DecodeState},
    hash_source::{Generation, SourceHashState},
    sample_state::{SampleError, SampleState},
};
use crate::{layout::*, program, BoundInputs};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

#[derive(Debug)]
pub(crate) enum InitialError {
    RowShape,
    Exhausted,
    Sample(SampleError),
}

pub(crate) struct InitialSource<'a> {
    hash: SourceHashState<'a>,
    decoder: DecodeState<'a>,
    sampler: SampleState,
    next_row: usize,
    protected: Vec<BabyBear>,
    preservation_positions: usize,
}
impl<'a> InitialSource<'a> {
    pub(crate) fn new(inputs: &'a BoundInputs) -> Result<Self, DecodeError> {
        // Actual encoding checks precede construction buffers and hash work.
        let decoder = DecodeState::new(inputs)?;
        Ok(Self {
            hash: SourceHashState::new(inputs),
            decoder,
            sampler: SampleState::new(),
            next_row: 0,
            protected: vec![BabyBear::ZERO; SIGN_BITS],
            preservation_positions: 0,
        })
    }
    pub(crate) fn generation(&self) -> Generation {
        self.hash.generation()
    }
    pub(crate) fn preservation_positions(&self) -> usize {
        self.preservation_positions
    }
    pub(crate) fn emit_next(&mut self, row: &mut [BabyBear]) -> Result<usize, InitialError> {
        if row.len() != WIDTH {
            return Err(InitialError::RowShape);
        }
        if self.next_row == HEIGHT {
            return Err(InitialError::Exhausted);
        }
        let at = self.next_row;
        assert_eq!(self.hash.emit_next(row).unwrap(), at);
        assert_eq!(self.decoder.emit_next(row).unwrap(), at);
        // Diagnostic preservation storage is bounded to one prefix per row.
        self.protected.copy_from_slice(&row[..SIGN_BITS]);
        assert_eq!(self.sampler.emit_next(row).unwrap(), at);
        row[ACTIVE_CHALLENGE] =
            BabyBear::from_bool((program::SAMPLE_START..program::SAMPLE_END).contains(&at))
                * (BabyBear::ONE - row[COUNT + 60]);
        if let Some(column) = row[..SIGN_BITS]
            .iter()
            .zip(&self.protected)
            .position(|(a, b)| a != b)
        {
            panic!("sampler changed protected field at row {at}, column {column}");
        }
        self.preservation_positions += SIGN_BITS;
        self.next_row += 1;
        Ok(at)
    }
    pub(crate) fn finish(&self) -> Result<(), InitialError> {
        self.sampler.finish().map_err(InitialError::Sample)
    }
}
