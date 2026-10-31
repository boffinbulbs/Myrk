//! Owned committed quotient construction for the fixed research relation.
//! The diagnostic feature uses public synthetic inputs and produces no proof.
#![deny(unsafe_code)]
extern crate alloc;
#[cfg(feature = "diagnostics")]
include!("laboratory.rs");
