# Source provenance

The flat preparation layout and ordinary matrix policy interface follow the retained storage experiment in ../storage-pcs/tests/common/store.rs and ../storage-pcs/backend/src/storage.rs. The new owned preparation policy, failure states and controls use the repository MIT license. Original source and test records remain unchanged.

The MatrixStore and RowSource identities come from kova-proof-preflight, which compiles retained backend definitions under its own nominal Rust types. The checked file decoder comes from kova-storage-matrix. Their original source attribution and license notices remain at those directories. No verifier, transcript, proof format or cryptographic acceptance algorithm is replaced here.

Source and dependency identities are recorded in provenance.json and Cargo.lock. Deterministic public test seeds establish reproducibility only. This policy is a preparation laboratory and is not production secret storage.
