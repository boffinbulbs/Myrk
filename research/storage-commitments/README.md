# Storage backed salted commitments

This finite experiment connects the [checked storage matrix](../storage-matrix/README.md) to the retained Plonky3 0.8.0 salted Merkle commitment. The actual upstream commitment and verification implementations are used without modification. No PCS, FRI, STARK, signature or payment proving interface is supplied.

## Evaluated boundary

The commitment accepts the storage matrix through the generic matrix interface and retains that same matrix in its prover data. The ordinary verifier receives the commitment, dimensions, row index, opened values, salts and authentication path. It does not receive a storage adapter or a host acceptance callback.

For equal synthetic inputs and continuing RNG state, memory backed and storage backed operations must produce identical roots, serialized single openings and serialized pruned multiproofs. An opening decoded through the retained proof type must verify against the same root.

| Case | Matrix dimensions, height by width |
|---|---|
| 1 | 8 by 1 |
| 2 | 16 by 4 |
| 3 | 256 by 8 |
| 4 | 64 by 4, 256 by 8, 64 by 1, in that insertion order |

The tree has binary compression, cap height zero, full SHA3 512 digests and sixteen BabyBear salt fields per row. These are isolated experiment domains. They do not change any retained chain or proof profile. Each synthetic seed consists of the case identifier repeated 32 times. The actual input MMCS is cloned once before its first commitment, exercising its retained seed fork operation. These published seeds and salts are reproducibility data, not production entropy.

## Independent reference

Field entries are canonical integers modulo q = 2013265921. For case a, matrix m, row r and column c, the public synthetic value is

$$
x_{a,m,r,c} = (1009a + 65537m + 97r + 13c + 17rc) \bmod q.
$$

The Rust fixture exporter records the actual salt rows and roots in [salts.json](fixtures/salts.json). The independent [Python reference](reference.py) reconstructs every synthetic value, frames field and digest words explicitly and rebuilds each binary tree. Shorter matrices are injected at their corresponding tree level. It checks all four roots against the retained implementation and produces [reference.json](fixtures/reference.json). Separate framing vectors cover leaf and node hashing.

The Rust checks reproduce all 664 salt rows and all four independent roots from the fixed seeds. Python checks reject altered roots, salts, matrix order, dimensions and noncanonical integer encodings. No RNG implementation is copied into the independent reference.

## Rejection and failure behavior

The retained verifier rejects changed values, salts, sibling digests, indices, widths and a compensating row extension plus salt truncation. Mixed height rows use the global index shifted to the corresponding matrix height. Mutated multiproof values are rejected through the actual multiproof verifier.

After commitment, a canonical change to a queried file value produces an opening that fails against the original root. The previously returned original opening remains valid. This is a commitment binding check for the queried data, not a complete file integrity monitor.

Noncanonical words and file truncation abort opening through the matrix adapter's typed storage failure. They are not reported as cryptographic proof rejections. Continuing commitments consume continuing salts, and a cloned MMCS forks its RNG rather than reusing the same sequence.

## Resource and privacy scope

The largest individual synthetic field file contains 8192 bytes. The mixed batch contains 9472 field bytes in total. Salt matrices, authentication digests and hashing scratch buffers remain resident upstream. The experiment measures neither full prover memory nor end to end payment performance.

Only public synthetic data is used. There is no polynomial masking, trace relation, quotient computation, randomization polynomial or FRI opening here. Real witness storage confidentiality, immutable leases, complete hiding proofs, soundness and quantum security remain separate requirements. A salted root and successful row openings do not establish those properties.

## Reproduction

```text
cargo test --manifest-path research/storage-commitments/Cargo.toml --locked --offline -- --test-threads=1
cargo clippy --manifest-path research/storage-commitments/Cargo.toml --all-targets --locked --offline -- -D warnings
python research/storage-commitments/reference.py --check
python -m unittest discover -s research/storage-commitments -p test_reference.py -v
```

The ignored fixture exporter runs only with an explicit new output path in `KOVA_SYNTHETIC_SALT_OUTPUT`. It refuses to overwrite an existing file. Ordinary validation checks the retained fixtures and does not regenerate them.

## Sources and next integration gate

The retained [salted MMCS](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/merkle-tree/src/hiding_mmcs.rs) and [matrix interface](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/matrix/src/lib.rs) define the upstream contracts. Local code uses the project MIT license. Original dependency licenses remain in the repository inventory.

The next gate connects storage to actual LDE data, quotient evaluation, coupled quotient masks, the separate randomization polynomial and FRI queries. The same commitments, randomness, transcript order and single use opening state must reach the unchanged verifier. The dense PCS and FRI input types still require a separately reviewed storage adaptation.
