//! Bounded original loop oracle with independently saved synthetic XOF bytes.
use crate::{layout::*, program};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

const PREFIX_ROWS: usize = 277;
pub(crate) struct SampleReference {
    prefix: Option<Vec<BabyBear>>,
    terminal: Vec<BabyBear>,
}
impl SampleReference {
    pub(crate) fn new(xof: &[u8; 272]) -> Self {
        let mut prefix = vec![BabyBear::ZERO; PREFIX_ROWS * WIDTH];
        for (at, row) in prefix.chunks_exact_mut(WIDTH).enumerate() {
            for (i, &value) in xof.iter().enumerate() {
                let ready = if i < 136 { 6 } else { 12 };
                if at >= ready {
                    row[CHALLENGE_XOF + i] = BabyBear::from_u8(value);
                }
            }
        }
        // The original loop checks accepted == 60 after these actual rows.
        super::sample::fill(&mut prefix);
        let last = (PREFIX_ROWS - 1) * WIDTH;
        let terminal = prefix[last + SIGN_BITS..last + INITIAL_WIDTH].to_vec();
        Self {
            prefix: Some(prefix),
            terminal,
        }
    }
    pub(crate) fn band(&mut self, at: usize) -> &[BabyBear] {
        if at < PREFIX_ROWS {
            &self.prefix.as_ref().unwrap()[at * WIDTH + SIGN_BITS..at * WIDTH + INITIAL_WIDTH]
        } else {
            // No later access retains the large prefix allocation.
            drop(self.prefix.take());
            &self.terminal
        }
    }
    pub(crate) fn prefix_live(&self) -> bool {
        self.prefix.is_some()
    }
    pub(crate) fn activity(expected: &[BabyBear], at: usize) -> BabyBear {
        BabyBear::from_bool((program::SAMPLE_START..program::SAMPLE_END).contains(&at))
            * (BabyBear::ONE - expected[COUNT + 60 - SIGN_BITS])
    }
}
