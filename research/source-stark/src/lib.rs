//! Fixed owned quartic computation prover. Research parameter class only.
#![deny(unsafe_code)]
extern crate alloc;
mod composite;
pub mod context;
mod owned_pcs;
#[cfg(not(debug_assertions))]
mod owned_prover;
pub use composite::{Error as StorageError, Phase, Snapshot};
pub use context::{Context, OwnedConfig, OwnedError};
#[path = "../../storage-pcs/backend/src/config.rs"]
mod config;
mod hiding_pcs;
#[path = "../../storage-pcs/backend/src/pcs_transcript.rs"]
mod pcs_transcript;
#[path = "../../storage-pcs/backend/src/periodic.rs"]
mod periodic;
#[path = "../../storage-pcs/backend/src/proof.rs"]
mod proof;
#[path = "../../storage-pcs/backend/src/prover.rs"]
pub mod prover;
// The frozen module also contains the unused dense convenience entry types.
#[allow(dead_code)]
#[path = "../../source-commitment/src/source.rs"]
mod source;
#[allow(unsafe_code)]
#[path = "../../storage-pcs/backend/src/storage.rs"]
pub mod storage;
#[path = "../../storage-pcs/backend/src/transcript.rs"]
mod transcript;
#[path = "../../storage-pcs/backend/src/two_adic_pcs.rs"]
mod two_adic_pcs;
#[path = "../../storage-pcs/backend/src/verifier.rs"]
pub mod verifier;
pub use config::*;
pub use hiding_pcs::*;
pub use pcs_transcript::{
    PcsProverTranscript, PcsShape, PcsTranscriptFailure, PcsVerifierTranscript,
};
pub use periodic::*;
pub use proof::*;
pub use transcript::{FriShape, ProverTranscript, TranscriptFailure, VerifierTranscript};
pub use two_adic_pcs::*;
