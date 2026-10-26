# Conservation proof evidence

The isolated [proof laboratory](../../docs/proof-lab.md) proves checked integer conservation with private amount bits and a public fee and context. It uses a pinned hiding STARK configuration. The four amounts have no binding to ledger notes, assets, ownership, membership, nullifiers, authorization or encrypted delivery. A valid proof therefore does not authorize a payment.

For private amounts $a_0,a_1,b_0,b_1$ and public fee $f$, the relation is

$$
a_0+a_1=b_0+b_1+f,\qquad
0\le a_0+a_1\le 2^{64}-1,\qquad
0\le b_0+b_1+f\le 2^{64}-1.
$$

All individual values are unsigned 64 bit integers. Bit and carry constraints establish integer equality rather than equality modulo the proof field. The complete [feasibility gates](../../docs/proof-feasibility.md) for private payments and confidential stake remain open.

## Independent reference artifacts

| Artifact | Content |
|---|---|
| [Conservation cases](conservation_vectors.csv) | Thirteen exact integer cases, including modulus aliasing and overflow rejection |
| [Trace fixture](trace_vector.csv) | All 256 rows of a synthetic amount and carry trace |
| [Public values](public_values.csv) | Sixty four fee bits followed by 64 context bytes |
| [Hash fixtures](hash_vectors.csv) | Complete framed preimages, SHA3-512 bytes and little endian digest words |
| [Reference generator](reference_vectors.py) | Python integer arithmetic and standard library hashing, independent of the Rust proof backend |
| [Feature guard](profile_check.py) | Resolved dependency version and serial feature checks |

The trace and amounts in these fixtures are deliberately public synthetic data. They are not serialized private proof witnesses. Rust unit tests compare the actual AIR trace, public inputs, hash adapters and constraint verdicts with these retained fixtures. Backend proof tests separately generate proofs and invoke verification without the witness.

The dependency source review, original license texts, archive checksums and dated advisory lookup are retained in the workspace [dependency inventory](../crypto/dependency-inventory.json). A dependency advisory lookup and passing tests do not establish cryptographic security.

## Reproduction

From the repository root:

```text
cargo fetch --locked
cargo test -p thorum-proof-lab --locked --offline
cargo test -p thorum-proof-lab --release --locked --offline
python research/proofs/reference_vectors.py --check
python research/proofs/profile_check.py
```

The release test suite bypasses the wrapper's local constraint checks for deliberately false traces and checks rejection by the real verifier. Debug builds retain upstream constraint assertions and therefore cannot exercise that same proving path. The serial feature guard rejects feature unification that would enable an unreviewed parallel configuration. It does not replace source review after any dependency change.

The measurement example runs actual proving and verification on two synthetic witness classes with the same public fee and context:

```text
cargo run --release -p thorum-proof-lab --example conservation_measure --locked --offline
```

CSV output contains sample indices, public experiment class labels, operation durations and encoded proof sizes. A retained measurement run requires its own source revision, source and executable hashes, compiler, hardware and operating system record. Timing and proof size observations do not establish witness indistinguishability, constant time behavior or a quantum security level.
