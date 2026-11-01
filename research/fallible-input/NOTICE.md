# Source provenance

This component derives its preparation owner, checked matrix adapter, resource bounds and cleanup state machine from `research/source-preparation/src/lib.rs` at revision `0912fe8e52eec70888207dfc0e978327fe7b13ae`. The original laboratory remains unchanged. The derivative adds deferred infallible and fallible raw ingestion through one internal writer. It does not select or execute the original preparation tests.

The diagnostic uses twelve saved canonical field literals from `research/storage-matrix/src/tests.rs` at the same revision. Expected bytes and fields are independent of the candidate writer. The external Windows guard is retained unchanged from `research/signature-overlay-native/run_guarded_windows.ps1`.

The component uses the retained Plonky3 0.8.0 interfaces and field implementation, with their original MIT or Apache 2.0 attribution. `provenance.json` records the precise source, manifest, lock, feature and license closure. Root and package MIT licenses remain in place. No upstream authorship is reassigned.
