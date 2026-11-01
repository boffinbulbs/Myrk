//! Bounded public synthetic snapshot storage. No ledger or proof acceptance.
#![forbid(unsafe_code)]
#[cfg(all(feature = "diagnostics", debug_assertions))]
compile_error!("Journal diagnostics require the retained release profile");
#[cfg(all(feature = "diagnostics", not(debug_assertions)))]
mod journal;
#[cfg(all(feature = "diagnostics", not(debug_assertions)))]
pub use journal::*;
