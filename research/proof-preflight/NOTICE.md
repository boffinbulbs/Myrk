# Source provenance

This adapter compiles the retained kova-storage-fri 0.5.0 source under new nominal Rust types. The original backend is an adaptation of p3-fri 0.8.0 from Plonky3 revision a21e3ed42905040ad49c519e402f018381c12d0c, path fri. Original copyright is retained in LICENSE-MIT. Imported backend code remains available under its original MIT OR Apache-2.0 terms. New adapter, preflight, test and documentation code uses the repository MIT license.

The frozen adaptation and its original attribution remain in ../storage-pcs/NOTICE.md. Its upstream identities, original package metadata, README, changelog and source changes are retained under ../storage-pcs/backend. This adapter does not change those files or the earlier proof records.

Nine original modules are imported by source path. The original hiding_pcs.rs is included inside a local module so a pure method can call its existing private masking checker. The new method and resource planning code do not replace the checker arithmetic, prover, transcript, proof structure, verifier, entropy flow or single opening state. Recompiling those definitions creates different nominal Rust types. Serialized proof compatibility has not been tested for this adapter.

Tests reuse the exact hash framing and quartic AIR source from ../storage-pcs/tests/common. The real hash and MMCS types satisfy the selected extension interfaces. Fixed test seeds and counted generators exercise preflight behavior only. These tests do not establish production seeding, hiding MMCS security or a complete proof profile. Source and dependency identities are retained in provenance.json and Cargo.lock.
