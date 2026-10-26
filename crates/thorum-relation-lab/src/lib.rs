//! Transparent local witness checks for synthetic relation research.
//!
//! This crate consumes private openings, authorization evidence and sender
//! encryption randomness directly. It does not implement a proof system, a
//! private ledger, recipient anonymity, consensus, persistence or networking.
//! Authenticated anchors, spent sets and snapshot parameters are caller inputs.
//! The output sender currently knows the nullifier secret and can predict a
//! later spend nullifier. No sender unlinkability or anonymous recipient claim
//! follows from this laboratory construction.

#![forbid(unsafe_code)]

mod error;
mod merkle;
mod note;
mod payment;
mod stake;

pub use error::RelationError;
pub use merkle::{merkle_leaf, merkle_parent, MerklePath, MAX_MERKLE_DEPTH};
pub use note::{key_binding, BondPolicy, NoteOpening, NoteParameters, NotePolicy, NullifierSecret};
pub use payment::{
    check_payment, output_encryption_context, InputWitness, OutputWitness, PaymentContext,
    PaymentOutput, PaymentStatement, PaymentWitness, MAX_PAYMENT_ITEMS,
};
pub use stake::{
    check_stake_eligibility, BondWitness, StakeClaim, StakeContext, StakeStatement, MAX_STAKE_BONDS,
};

use sha3::{Digest, Sha3_512};

pub type ChainId = [u8; 32];
pub type AssetId = [u8; 32];
pub type Digest64 = [u8; 64];
pub const NATIVE_ASSET_ID: AssetId = [0; 32];
pub const FORMAT_VERSION: u16 = 1;
pub const MAX_STATEMENT_BYTES: usize = 64 * 1024;

pub(crate) fn frame(output: &mut Vec<u8>, field: &[u8]) {
    // Callers use fixed fields or bounded statement and envelope encodings.
    output.extend_from_slice(&(field.len() as u32).to_be_bytes());
    output.extend_from_slice(field);
}

pub(crate) fn statement_frame(output: &mut Vec<u8>, field: &[u8]) -> Result<(), RelationError> {
    let next = output
        .len()
        .checked_add(4)
        .and_then(|len| len.checked_add(field.len()))
        .ok_or(RelationError::LimitExceeded)?;
    if next > MAX_STATEMENT_BYTES {
        return Err(RelationError::LimitExceeded);
    }
    frame(output, field);
    Ok(())
}

pub(crate) fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> Digest64 {
    let mut hash = Sha3_512::new();
    hash.update((domain.len() as u32).to_be_bytes());
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u32).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

pub(crate) fn short_tag(digest: &Digest64) -> [u8; 32] {
    let mut tag = [0; 32];
    tag.copy_from_slice(&digest[..32]);
    tag
}
