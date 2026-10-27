# Sparse challenge reference record

These public synthetic and retained official fixtures exercise one bounded ML-DSA-87 challenge sampler. They are diagnostic data without production transaction authority. Source provenance and original notices remain in the existing [cryptographic inventory](../crypto/README.md) and [signature research](../signatures/README.md).

The [constraint specification](../../docs/challenge-sampling.md) defines the same seed, full SHAKE256 continuation, index comparison, accepted count, sign consumption, read before replacement, final polynomial and transport boundaries. The [profile](profile.json) records fixed dimensions. [Source hashes](source_record.json) identify the exact retained inputs and independent reference implementations.

Reproduction uses the standard Python library:

```text
python research/challenge-sampling/reference_vectors.py
python research/challenge-sampling/reference_vectors.py --check
python research/challenge-sampling/profile_check.py
```

`vectors.json` contains six genuine seed cases, 12 full sponge states, 288 round states and 267 injected streams. Genuine XOF output matches the manual sponge, `hashlib` and the separate complete signature verifier. Dictionary and array based finite samplers agree on every coefficient, consumption cursor and capacity classification. Public data match the earlier separately retained sampler corpus.

The injected corpus includes all 256 final candidate indices, repeated occupied indices, $j=i$, positive and negative signs, ignored high header bits, exact comparison boundaries and both supported and unsupported capacity edges. An injected byte stream does not assert a known SHAKE preimage. Correct challenge sampling is independent of whether its source signature is valid.

`hash_vectors.csv` gives all 64 bytes and eight words for each independently computed leaf, node and transcript domain. It checks the exact framing and full SHA3-512 digest. The source change guard pins reviewed code, profile and corpus counts. It is not a correctness, privacy or security proof.

Component validation runs are:

```text
cargo test -p thorum-hash-proof-lab challenge_sampler --locked --offline -- --test-threads=1
cargo test -p thorum-hash-proof-lab challenge_sampler --release --locked --offline -- --test-threads=1
```

The release suite constructs false proofs through the actual backend without witness prechecks and requires direct verification rejection. Repeated honest proofs test fresh commitment randomness. The external interface independently checks expected coefficients, context and constructor rejection. Large local proof jobs run serially.

Analytical payloads are 13512704 bytes for raw fields, 27041792 bytes after hiding expansion and 216334336 bytes for the main LDE. They exclude other allocations and provide no measured performance or full signature feasibility claim. No runtime or hardware benchmark is published by this record.
