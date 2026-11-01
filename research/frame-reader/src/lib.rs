//! Header admission before payload reservation for the retained small proof codec.
#![forbid(unsafe_code)]
#[cfg(feature = "diagnostics")]
#[path = "../../proof-transport/src/codec.rs"]
#[allow(
    dead_code,
    reason = "The retained borrowed frame entry is not selected here"
)]
mod codec;
#[cfg(feature = "diagnostics")]
mod diagnostics;
#[cfg(feature = "diagnostics")]
mod reader;
#[cfg(feature = "diagnostics")]
#[path = "../../proof-transport/src/transport.rs"]
#[allow(
    dead_code,
    reason = "The retained borrowed frame entry is not selected here"
)]
mod transport;
#[cfg(feature = "diagnostics")]
pub use diagnostics::fixed_reader_diagnostic;
