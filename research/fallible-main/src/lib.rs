//! Actual fallible source consumption into a bounded main commitment.
//! Main-only observation is terminal and never returned as a proof.
#![deny(unsafe_code)]
extern crate alloc;
#[cfg(feature = "diagnostics")]
include!("laboratory.rs");
