//! Whole physical domain preflight around the retained opening protocol.
#![deny(unsafe_code)]
extern crate alloc;
#[cfg(all(feature = "diagnostics", debug_assertions))]
compile_error!("Opening domain diagnostics require the retained release profile");
#[cfg(all(feature = "diagnostics", not(debug_assertions)))]
include!("laboratory.rs");
