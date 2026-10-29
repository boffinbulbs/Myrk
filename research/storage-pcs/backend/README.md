# Stored FRI backend

This source adaptation of p3-fri 0.8.0 changes committed input matrix representation, ordinary LDE construction and domain borrowing interfaces for a finite synthetic experiment. Dense construction and storage remain the default policy. A file policy can construct actual columns without allocating a complete dense LDE. Masks, row order and transcript operations retain their original algorithms.

The original source revision is a21e3ed42905040ad49c519e402f018381c12d0c, path fri. Original source identities are in upstream-source-sha256.json. The source delta is source-changes.patch. Original package metadata, README and changelog are retained with the upstream prefix. LICENSE-MIT and LICENSE-APACHE retain the original notices and terms.

Proof, verifier, transcript, configuration and periodic source remain byte identical. The separate retained registry implementation is the test verifier and dense reference. The selected integration harness is described in [the laboratory record](../README.md). Original upstream unit test source is preserved, but this package does not select that complete suite.

The storage policy is an experimental interface. It does not establish immutable secret storage, streamed construction, full payment privacy or a quantum security level.
