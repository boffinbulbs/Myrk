//! Fixed small relation source prover with the original transcript and verifier.
//! The diagnostic profile is separate from the private payment relation.
#![deny(unsafe_code)]
extern crate alloc;
#[cfg(feature = "diagnostics")]
include!("laboratory.rs");
