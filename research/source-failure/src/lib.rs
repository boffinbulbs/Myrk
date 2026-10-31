//! Fixed source failure experiments under the original proving lifecycle.
//! These cases exercise real file failures, not verifier rejection.
#![deny(unsafe_code)]
extern crate alloc;
#[cfg(feature = "diagnostics")]
include!("laboratory.rs");
