# Source derivation

The transport preflight and shape checks derive from the repository's MIT licensed conservation laboratory. This laboratory retains its two MiB byte limit and adds matching delimiters, a borrowed experimental envelope and canonical serialization comparison without a second encoded vector. The envelope is not a production wire format.

Typed decoding uses the actual Plonky3 0.8.0 `Proof` type and the retained `kova-proof-preflight` hiding PCS and FRI proof structures. The source prover observer delegates its commitment and multiproof associated types to the original MMCS. Type aliases here use that underlying MMCS without constructing it. Leaf, node and transcript hash implementations are imported unchanged from `research/storage-pcs/tests/common/hash.rs`. No prover or verifier configuration is constructed.

The fixture is the previously generated synthetic source prover proof, copied byte for byte. Its original producer and healthy verifier are not rerun. Decoding that fixture establishes encoding and shape scope only. The deliberately altered commitment that still decodes is not verified.

Original backend derivation is Plonky3 0.8.0 at revision `a21e3ed42905040ad49c519e402f018381c12d0c`. Existing MIT and Apache 2.0 notices remain with that source. Local additions retain the repository MIT license. Exact source, fixture, feature and dependency identities accompany the validation record.
