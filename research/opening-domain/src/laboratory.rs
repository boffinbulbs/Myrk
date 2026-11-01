mod composite;
pub mod context;
mod diagnostics;
#[allow(dead_code, reason = "Retained observer has operations outside domain refusal controls")]
mod diagnostics_setup;
mod domain;
#[path = "../../fallible-source/src/extension.rs"]
mod extension;
#[cfg(not(debug_assertions))]
mod owned_pcs;
#[cfg(not(debug_assertions))]
mod owned_prover;
#[path = "../../quotient-source/src/quotient_kernel.rs"]
mod quotient_kernel;
pub use composite::{Error as StorageError, Phase, Snapshot};
pub use context::{Context, OwnedConfig, OwnedError, OwnedProof, ProvingResult};
pub use domain::{DomainError, OpeningChecked, OpeningProverError, OpeningVerifyError};
#[path = "../../storage-pcs/backend/src/config.rs"]
mod config;
#[allow(dead_code, reason = "Retained generic entries include unselected diagnostic paths")]
mod hiding_pcs;
#[path = "../../storage-pcs/backend/src/pcs_transcript.rs"]
mod pcs_transcript;
#[path = "../../storage-pcs/backend/src/periodic.rs"]
mod periodic;
#[path = "../../storage-pcs/backend/src/proof.rs"]
mod proof;
#[path = "../../storage-pcs/backend/src/prover.rs"]
pub mod prover;
#[allow(dead_code)]
#[path = "../../fallible-source/src/source.rs"]
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
pub use pcs_transcript::{PcsProverTranscript, PcsShape, PcsTranscriptFailure, PcsVerifierTranscript};
pub use periodic::*;
pub use proof::*;
pub use transcript::{FriShape, ProverTranscript, TranscriptFailure, VerifierTranscript};
pub use two_adic_pcs::*;
pub use diagnostics::fixed_domain_controls;
