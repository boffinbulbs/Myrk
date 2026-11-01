//! Prospective numeric research. No history, reward or ledger authorization.
#![forbid(unsafe_code)]

#[cfg(feature = "diagnostics")]
mod retained_table {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/thorum-core/src/table.rs"
    ));
}

#[cfg(feature = "diagnostics")]
pub mod accounting;
