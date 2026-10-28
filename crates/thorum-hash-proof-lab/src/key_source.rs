//! Two fixed private key sources with constrained hashes, decoding and reuse.
//! This segment is not a signature verifier or spending authorization.

mod air;
mod hash;
pub(super) mod keccak;
mod packing;
mod proof;
#[cfg(test)]
mod tests;

pub const KEY_BYTES: usize = 2592;

pub struct Witness {
    keys: [[u8; KEY_BYTES]; 2],
}
impl Witness {
    pub fn from_keys(keys: [[u8; KEY_BYTES]; 2]) -> Self {
        Self { keys }
    }
}

#[derive(Clone, Copy)]
pub struct Statement {
    context: [u8; 64],
}
impl Statement {
    pub fn new(context: [u8; 64]) -> Self {
        Self { context }
    }
}

pub use crate::Error;
pub use proof::{MAX_PROOF_BYTES, PROFILE, prove_key_slots, verify_key_slots};
