//! Finite metadata analysis of the retained AIR. No proof or witness verifier.
#![forbid(unsafe_code)]
#[cfg(feature = "diagnostics")]
pub mod metadata;
#[cfg(feature = "diagnostics")]
use kova_signature_overlay::{PackedSignatureOwnerAir, layout};
