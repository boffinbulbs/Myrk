# Stored polynomial proofs

This laboratory connects checked field storage to a complete small hiding STARK. The stored prover produces the same serialized proof as the retained dense prover, and that proof is checked by the unmodified retained verifier. The experiment uses a synthetic quartic relation. It is separate from private signature and payment integration.

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

The retained prover computes its actual main trace, coupled quotient masks and separate randomization polynomial. A storage policy consumes each exact dense LDE in its existing physical row order. It neither samples randomness nor generates substitute polynomial values.

For a committed column f_c, physical row r represents

$$
E_{r,c} = f_c(g\omega^{\operatorname{rev}(r)}).
$$

A prefix of a matrix in this order represents the corresponding smaller subgroup. Polynomial opening preparation reads that prefix without another permutation. Quotient evaluation applies the retained bit reversal view to obtain the requested domain order and removes the hidden columns. Alternate domains retain the original coefficient reconstruction and evaluation calculation.

| Commitment phase | Stored matrices | Field bytes |
| :--- | :--- | ---: |
| Main trace | One matrix of 4096 by six | 98304 |
| Quotient | Eight matrices of 4096 by eight | 1048576 |
| Separate randomization polynomial | One matrix of 4096 by eight | 131072 |
| Total | Ten files | 1277952 |

The test policy admits at most sixteen files, 4096 rows, twelve columns and two MiB of field data. File descriptors and directory ownership remain live through borrowed evaluation views and opening queries. A storage decoding failure aborts evaluation through a typed failure. It is distinct from rejection of an invalid proof.

The policy does not prevent external file modification. Data is public synthetic material. Immutable storage and secret data handling require further work. Dense LDE construction, salts, tree layers, quotient scratch, reduction vectors and FRI folds still use memory. This experiment establishes complete opening compatibility rather than streaming construction or a general memory reduction.

## Verification evidence

1. Every tested domain row agrees with the unmodified retained PCS, including an alternate shifted domain.
2. The complete honest stored proof deserializes to the retained proof type and passes its ordinary verifier. All 596650 serialized bytes equal the unmodified dense prover output under identical fixed seeds.
3. Changed public data, trace claims, quotient claims, randomization claims, input query values and hidden codeword openings are rejected.
4. A false quartic cell is sent through the actual release prover without a host validity precheck. It produces a proof that the unchanged verifier rejects.

The complete proof includes actual trace, quotient and randomization commitments, polynomial openings and FRI queries. It is not a bundle of independently accepted component proofs. The test does not establish a complete signature, ownership or payment relation.

Local proof runs use verified Windows process and job commit ceilings of 256 MiB, a sixty second timeout and a finite file allowance. The first run stopped at an underestimated one MiB file allowance before completing a proof. The revised allowance follows the exact ten file calculation above. The source and measured results are retained in [validation.json](validation.json).

The [Windows execution guard](run_guarded_windows.ps1) accepts the built test executable and an exact test selection. It installs and reads back both commit limits before resuming the child process. Local result files are excluded from version control.

## Reproduction

Run from the repository root with Rust 1.94.1. Ordinary tests do not invoke the two explicit complete proof tests.

```text
python research/storage-pcs/reference.py --check
cargo fmt --manifest-path research/storage-pcs/Cargo.toml --all -- --check
cargo test --manifest-path research/storage-pcs/Cargo.toml --locked --release --test integration -- --test-threads=1
cargo test --manifest-path research/storage-pcs/Cargo.toml --locked --release --test integration -- --ignored --test-threads=1
cargo clippy --manifest-path research/storage-pcs/Cargo.toml -p kova-storage-fri --lib --locked -- -D warnings -A clippy::nonminimal_bool
cargo clippy --manifest-path research/storage-pcs/Cargo.toml -p kova-storage-pcs-experiment --test integration --locked -- -D warnings -A clippy::nonminimal_bool
```

The named lint exception preserves an existing retained boolean expression in the hiding budget verifier. The test guard attributes preserve explicit release mode checks. The selected harness is not the complete upstream test suite.

## Source provenance

[The adapted backend](backend/README.md) retains the original MIT and Apache notices and a per file source inventory. The original registry sources, earlier measured experiments and production source remain unchanged. The adaptation changes committed input representation and borrowing interfaces. Its proof schema, transcript modules and verifier source remain unchanged.
