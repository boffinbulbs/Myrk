//! Actual private opening preflight and shared consumption controls.
//! The fixed synthetic prefix never constructs a complete proof.
#![deny(unsafe_code)]
extern crate alloc;
#[cfg(feature = "diagnostics")]
include!("laboratory.rs");
