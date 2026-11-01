#![forbid(unsafe_code)]

#[cfg(feature = "diagnostics")]
pub mod bytes;

#[cfg(all(test, feature = "diagnostics"))]
mod tests;
