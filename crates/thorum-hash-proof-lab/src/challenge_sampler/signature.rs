//! Same private signature canonicality and bounded challenge constraints.
//! This diagnostic relation does not establish signature validity or permission.

#![forbid(unsafe_code)]

use super::air as challenge;
pub use super::{CAPACITY, Error, MODULUS, Statement};
mod air;
mod hash;
mod packing;
mod proof;
pub use proof::{MAX_PROOF_BYTES, PROFILE, prove_signature_challenge, verify_signature_challenge};
#[cfg(test)]
mod tests;

pub struct Witness {
    seed: [u8; 64],
    signature_tail: [u8; 4563],
}
impl Witness {
    pub fn from_signature(signature: [u8; 4627]) -> Self {
        Self {
            seed: signature[..64].try_into().unwrap(),
            signature_tail: signature[64..].try_into().unwrap(),
        }
    }
}
