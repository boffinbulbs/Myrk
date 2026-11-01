//! Producer raw trace-domain admission with retained owned source operations.
#![deny(unsafe_code)]
extern crate alloc;
#[cfg(all(feature = "diagnostics", debug_assertions))]
compile_error!("Trace domain diagnostics require the retained release profile");
#[cfg(all(feature = "diagnostics", not(debug_assertions)))]
include!("laboratory.rs");
