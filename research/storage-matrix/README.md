# Checked storage matrix

This standalone experiment implements bounded synthetic field storage through the retained `p3-matrix` 0.8.0 interface. It is the first storage interface step toward a complete hiding prover with reduced resident memory. It does not construct a PCS commitment, FRI proof or private payment proof.

## Interface and ownership

The matrix supports at most 4096 rows and 12 columns of canonical BabyBear values. Each field value occupies four little endian bytes. Files must have the exact declared length. Dimensions and windows are checked before reads. Noncanonical field words are rejected rather than reduced modulo the field order.

Clones share one read only descriptor protected by a mutex. Every returned row owns its elements, so later reads cannot overwrite a previously returned window. Poisoned cursor state is an error. A path replacement after opening cannot redirect the existing descriptor, but canonical modification of the opened file is not authenticated by this adapter.

The safe `try_row` and `try_window` interfaces return typed errors. The upstream matrix interface cannot return storage errors. Its required `unsafe fn row_unchecked` declaration therefore has one explicit lint exception, while its entire body uses checked safe operations. There are no local unsafe blocks, raw pointers or memory maps. Trait access raises a typed `StorageAccessFailure` on error. That abort is distinct from cryptographic proof rejection.

## Resource boundary

For height H, width W and a requested window of length L,

$$
0 < H \le 4096, \qquad 0 < W \le 12, \qquad 0 \le L \le W.
$$

The file contains exactly 4HW bytes. The reader allocates 4L bytes of input and an owned field row, rather than materializing H rows. This is a local accessor bound, not a full prover memory bound. Upstream default methods can still materialize matrices, and their complete call paths require separate review.

All fixtures are synthetic. The largest test file contains 196608 bytes. This implementation does not establish production file confidentiality, immutable storage, secure erasure or protection against hostile filesystem mutation during opening. No real witness or wallet data belongs in this experiment.

## Validation

Tests exercise independent integer words, retained trait access, owned row lifetimes, concurrent clone reads, malformed dimensions, incorrect file lengths, noncanonical words, truncation and poisoned locks. A canonical modification control demonstrates that the accessor alone does not authenticate file contents.

Unix specific tests cover symbolic link rejection and descriptor retention after path replacement. Those cases are not reported as Windows executions.

```text
cargo test --manifest-path research/storage-matrix/Cargo.toml --locked --offline -- --test-threads=1
cargo clippy --manifest-path research/storage-matrix/Cargo.toml --all-targets --locked --offline -- -D warnings
```

The next gate connects storage to actual main trace commitments, quotient evaluation, the separate randomization polynomial and FRI openings. Commitment and mask randomness, transcript order, single use opening state and the unchanged verifier must remain intact. A successful row test cannot replace that proof.

## Sources

The matrix trait comes from the retained Plonky3 0.8.0 release. Its [`Matrix` interface](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/matrix/src/lib.rs) defines the accessor contract. The local adapter is original Kova source under the project MIT license. Upstream packages retain their original MIT or Apache 2.0 licensing and notices in the repository dependency inventory.
