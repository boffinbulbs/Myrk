# Stored polynomial proofs

This laboratory connects checked field storage and column construction to a complete small hiding STARK. Main trace randomization writes its actual prepared rows directly to storage. Main, coupled quotient and separate randomization commitments use actual column construction. The stored prover produces the same serialized proof as the retained dense prover, and that proof is checked by the unmodified retained verifier. The experiment uses a synthetic quartic relation. It is separate from private signature and payment integration.

## Relation and profile

For each row r, the trace contains a_r and b_r over the field with modulus 2013265921. The constraints are

$$
b_r = a_r^4, \qquad a_{r+1} = a_r + 1, \qquad a_0 = 5, \qquad a_{255} = 260.
$$

The increment applies to every nonterminal row. The fourth power relation applies to all rows. The retained symbolic builder reports an actual maximum constraint degree of four. An independent Python integer reference covers all 256 rows.

| Parameter | Value |
| :--- | :--- |
| Raw trace | 256 rows, two columns |
| Challenge extension | Degree four |
| Main trace after masking | 512 rows, six columns |
| LDE blowup | Eight |
| FRI queries | 64 |
| Hidden codeword columns | Four |
| Salt columns | Sixteen |
| Folding arity | Two |
| Grinding | Zero |
| Test entropy | Fixed public synthetic seeds |

These settings identify an interoperability experiment. They do not select deployment security parameters or establish a quantum security level.

## Storage and polynomial evaluation

For raw height N, raw width W and k random codeword columns, the main input preparation follows the retained append and reshape operation. Each even prepared row contains W raw fields followed by k random fields. The next W+k random fields form the following odd row. The continuing mask generator samples exactly

$$
N(W+2k)
$$

field elements. The file policy writes these rows directly without a widened dense input bank. Independent flat append and reshape indices check placement against actual field samples, and continued generator output matches the retained dense preparation. All matrices in a batch are prepared before any LDE commitment. Hiding budget refusal precedes every mask draw and file creation.

The retained prover computes its actual main trace, coupled quotient masks and separate randomization polynomial. Construction hooks receive the actual prepared inputs, configured DFT, supplied shift and any already coupled mask coefficients. The default policy retains dense construction. The finite file policy extends at most four columns per tile and writes exact contiguous spans within each physical output row. It neither samples randomness nor generates substitute polynomial values.

For a committed column f_c, physical row r represents

$$
E_{r,c} = f_c(g\omega^{\operatorname{rev}(r)}).
$$

A prefix of a matrix in this order represents the corresponding smaller subgroup. Polynomial opening preparation reads that prefix without another permutation. Quotient evaluation applies the retained bit reversal view to obtain the requested domain order and removes the hidden columns. Alternate domains retain the original coefficient reconstruction and evaluation calculation.

For prepared height N, output height L and tile width t at most four, ordinary construction uses an explicit input tile of Nt fields and output tile of Lt fields. The checked RowSource interface supplies exactly the requested column window. It has no whole row fallback, cache or validity callback. Dense and file sources retain the same bounds semantics. Quotient construction adds a padded coefficient tile of Lt fields. Prepared quotient inputs and coupled masks remain in memory.

$$
\text{explicit tile field lengths} = Nt + Lt, \qquad \text{dense output fields} = LW.
$$

The complete test covers six main columns, 64 quotient columns and eight separate randomization columns in twenty forward DFT batches and sixteen inverse batches. The largest explicit input tile is 2048 fields and output tile is 16384 fields or 65536 bytes. Encoding scratch is sixteen bytes. The implementation does not build a complete dense output across all columns when its width exceeds the tile. A matrix narrower than four columns fits in one tile. DFT workspace, vector overlap, allocator behavior and remaining prover buffers are separate from these lengths.

Actual source windows number 6144 and contain 23552 fields in total. Output writes number 81920 and contain the same 319488 output fields as earlier versions. The prior scalar construction made one source window and one output write per corresponding field. These are observed source operation counters, not measured physical disk operations or a runtime speedup. The [resource model](resources/README.md) distinguishes these costs from native proof feasibility.

## Coupled quotient construction

The actual quotient is split into the same subdomains and order as the retained PCS. Its random columns and masks come from one shared preparation path with the original draw order. For subdomain shift s_i and chunk height h, the normalized vanishing polynomial and selector constant are

$$
Z_i(X) = (X/s_i)^h - 1, \qquad c_i = \left(\prod_{j\ne i} Z_j(s_i)\right)^{-1}.
$$

The final mask polynomial is derived from the earlier masks rather than independently sampled. Coefficient by coefficient,

$$
R_{d-1} = -\sum_{i=0}^{d-2}(c_i/c_{d-1})R_i, \qquad \sum_{i=0}^{d-1} c_i R_i = 0.
$$

Let g be the field generator and a_i = g/s_i. The retained inverse coset DFT produces a coefficient column A_i. For mask coefficient R_i[k], the construction applies

$$
\mu_{i,k} = g^k R_i[k], \qquad A'_i[k] = A_i[k]-\mu_{i,k}, \qquad A'_i[h+k] = a_i^h\mu_{i,k}.
$$

The high coefficients begin at zero. After padding, the actual forward DFT and bit reversal produce the committed column. The coset scaling and mask scaling remain separate. Independent integer references check both scales and the normalized coupling constants.

The complete uni-STARK path uses the local commit_quotient override to construct and commit these stored columns. The legacy get_quotient_ldes interface still returns dense matrices for compatibility and shares the same entropy preparation. Neither interface supplies an acceptance decision to a ledger.

| Commitment phase | Stored matrices | Field bytes |
| :--- | :--- | ---: |
| Main trace | One matrix of 4096 by six | 98304 |
| Quotient | Eight matrices of 4096 by eight | 1048576 |
| Separate randomization polynomial | One matrix of 4096 by eight | 131072 |
| Total | Ten files | 1277952 |

The main prepared source is a separate 512 by six file occupying 12288 bytes. Its preparation samples 2560 field elements. This file remains counted until the owning construction directory is released. Total field storage for the complete case is eleven files and 1290240 bytes. File creation, writer closure and descriptor ownership precede source exposure. A failed write aborts construction and does not rewind the mask generator.

The test policy admits at most sixteen files, 4096 rows, twelve columns and two MiB of total source and committed field data. File descriptors and directory ownership remain live through borrowed evaluation views and opening queries. A storage decoding failure aborts evaluation through a typed failure. It is distinct from rejection of an invalid proof.

The policy does not prevent external file modification. Data is public synthetic material. Immutable storage and secret data handling require further work. Main prepared rows and all ten committed LDEs use storage construction. The raw trace, separate randomization polynomial input, prepared quotient chunks, coupled mask arrays, salts, tree layers, quotient scratch, reduction vectors and FRI folds still use memory. This experiment establishes this finite construction path and complete opening compatibility. It does not establish a general full prover memory bound or lower total peak memory.

## Verification evidence

1. Every tested domain row agrees with the unmodified retained PCS, including an alternate shifted domain.
2. The complete honest stored proof deserializes to the retained proof type and passes its ordinary verifier. All 596650 serialized bytes equal the unmodified dense prover output under identical fixed seeds.
3. Changed public data, trace claims, quotient claims, randomization claims, input query values and hidden codeword openings are rejected.
4. A false quartic cell is sent through the actual release prover without a host validity precheck. It produces a proof that the unchanged verifier rejects.
5. Four independent Python polynomial domains check every physical output field, including a distinct shift, no blowup and a partial final tile. Both default and stored construction match them.
6. Injected failures before and inside ordinary and quotient tile writes leave no completed matrix or partial file. Invalid dimensions and shifts are refused. A cloned matrix retains its descriptor after the creator and original matrix are dropped.
7. Two independent quotient coefficient domains check coset and mask scaling. Actual mask preparation satisfies four independently computed normalized selector constants, and its commitment matches the retained dense PCS.
8. A valid trace with a deliberately corrupted final mask reaches the real release prover and produces a proof rejected by the unchanged verifier.
9. Two independent main preparation layouts check raw and random field placement, scalar draw counts and generator continuation. A mixed width batch matches the retained commitment and preserves preparation order. A refused batch creates no files and consumes no entropy.
10. Sources whose whole row, scalar access and dense materialization fail still extend through exact windows. Short windows refuse construction and allow a later valid retry. An injected main input write failure removes the partial source without rolling back consumed randomness.
11. Noncanonical or truncated prepared source reads retain the typed storage abort and remove the unfinished output. The construction mutex becomes poisoned during that abort and refuses later writes. It does not return replacement fields or claim cryptographic rejection.

The complete proof includes actual trace, quotient and randomization commitments, polynomial openings and FRI queries. It is not a bundle of independently accepted component proofs. The test does not establish a complete signature, ownership or payment relation.

Local proof runs use verified Windows process and job commit ceilings of 256 MiB, a sixty second timeout and a finite file allowance. The current source and measured results are retained in [validation.json](validation.json). The [versioned records](records/README.md) preserve earlier construction and measurements at exact source revisions.

The [Windows execution guard](run_guarded_windows.ps1) accepts the built test executable and an exact test selection. It installs and reads back both commit limits before resuming the child process. Local result files are excluded from version control.

## Reproduction

Run from the repository root with Rust 1.94.1. Ordinary tests do not invoke the three explicit complete proof tests.

```text
python research/storage-pcs/reference.py --check
python research/storage-pcs/stream_reference.py --check
python research/storage-pcs/quotient_reference.py --check
python research/storage-pcs/preparation_reference.py --check
cargo fmt --manifest-path research/storage-pcs/Cargo.toml --all -- --check
cargo test --manifest-path research/storage-pcs/Cargo.toml --locked --release --test integration -- --test-threads=1
cargo test --manifest-path research/storage-pcs/Cargo.toml --locked --release --test integration -- --ignored --test-threads=1
cargo clippy --manifest-path research/storage-pcs/Cargo.toml -p kova-storage-fri --lib --locked -- -D warnings -A clippy::nonminimal_bool
cargo clippy --manifest-path research/storage-pcs/Cargo.toml -p kova-storage-pcs-experiment --test integration --locked -- -D warnings -A clippy::nonminimal_bool
```

The named lint exception preserves an existing retained boolean expression in the hiding budget verifier. The test guard attributes preserve explicit release mode checks. The selected harness is not the complete upstream test suite.

## Source provenance

[The adapted backend](backend/README.md) retains the original MIT and Apache notices and a per file source inventory. The original registry sources, earlier measured experiments and production source remain unchanged. The adaptation changes committed input representation and borrowing interfaces. Its proof schema, transcript modules and verifier source remain unchanged.
