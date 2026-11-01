//! Fallible raw source integration into the retained owned proving context.
//! Native diagnostics select storage failures before the proving protocol.
#![deny(unsafe_code)]
extern crate alloc;
#[cfg(feature = "diagnostics")]
include!("laboratory.rs");
