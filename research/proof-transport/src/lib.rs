//! Bounded decoding diagnostics for the retained synthetic source proof.
#![forbid(unsafe_code)]
#[cfg(feature = "diagnostics")]
mod codec;
#[cfg(feature = "diagnostics")]
mod diagnostics;
#[cfg(feature = "diagnostics")]
mod transport;
#[cfg(feature = "diagnostics")]
pub use diagnostics::fixed_transport_diagnostic;
