# Consistent virtual padding constraints

This separate native test checks the two virtual padding bytes in the last signature word and the last note word. It imports the actual complete packed signature and ownership AIR unchanged. The test changes the held word and all matching read ports consistently, so source word equality remains valid while the selected padding rule must reject.

## Causal alteration

Each held word represents three bytes:

$$w=b_0+2^8b_1+2^{16}b_2.$$

The partial signature and note tails have one real byte and require $b_1=b_2=0$. Each control makes one of the following changes on every row:

$$w'=w+2^{8j},\qquad b_j'=1,\qquad j\in\{1,2\}.$$

The real low byte stays unchanged. Held words still match their next row, all bits remain Boolean, and the selected word equality remains satisfied. The other padding byte and all real consumer bytes are preserved. Exactly the targeted zero padding constraint should fail. Every altered word stays below $2^{24}$ and the base field prime, so no modular alias or carry changes the real byte.

| Control | Held column | Original word | Altered word |
| --- | ---: | ---: | ---: |
| Signature offset 1 | 13,130 | 46 | 302 |
| Signature offset 2 | 13,130 | 46 | 65,582 |
| Note offset 1 | 13,270 | 0 | 256 |
| Note offset 2 | 13,270 | 0 | 65,536 |

The fixture is B0 with verification key B, signature B0, transaction T0 and note N_B. Exact canonical transaction and 196 authorization values are checked, alongside five independent byte comparisons covering 288 bytes. Fixture reading remains typed and bounded.

## Complete frame coverage

Both tail words are selected on every physical row. Each negative pass evaluates the unchanged complete AIR on all 8,192 real global current and next row pairs, including the final to first wrap. It retains the actual first, last and transition selectors. A checker that stopped at the first failure would not establish this coverage.

Each frame must have exactly one failure at an independently predicted padding index. Every other equation in that frame must pass. The debug builder and its failure vector are dropped before the next frame. Unexpected diagnostics are bounded and synchronized before stopping. Successful records contain aggregate counts and fixed size port histograms rather than a list of every row's failures.

Tail ranks come from independent fixed source word unions and the retained scalar certificate's total word runs. The actual two tail port getters are compared over every row once. The 25 fully fixed note words are not used as the complete set of words touched by fixed note bytes. That set includes mixed words. The source rank projection is metadata checking, separate from actual constraint evaluation.

The fixed source ledger identifies 33 padding eligible ports. If $P$ is that set, the selected word equality has index

$$E(p)=6127+p+2\,|\{t\in P:t<p\}|.$$

Padding offset $j$ must fail at $E(p)+j$. These expectations come from the frozen source, rather than the observed failure index. The symbolic count of 69,242 assertions is a previously measured source property. Negative passes count actual frame evaluations and do not invent a per-frame assertion counter.

## Implementation status

The actual guarded run passed once on Windows 11 with a Core i9-13900H and Rust 1.94.1. The baseline and all four restorations passed complete native scans. Each of the four consistent padding alterations produced exactly one expected padding failure on every global frame, with no hold, Boolean, selected word equality or downstream consumer failures. All 32,768 negative frame evaluations reached the unchanged complete AIR.

| Actual result | Record |
| --- | ---: |
| Complete constructed traces | 1 |
| Maximum live complete traces | 1 |
| Positive full scans | 5 |
| Negative all-frame passes | 4 |
| Negative frame evaluations | 32,768 |
| Total frame evaluations | 73,728 |
| Independent byte comparisons | 5 across 288 bytes |
| Peak process commit bytes | 1,419,476,992 |
| Peak aggregate commit bytes | 1,420,767,232 |
| Backend proofs | 0 |

The observed test duration was 486.94 seconds, including rank comparisons, construction, reference checks, all negative frames and restored scans. This is not proof generation time or payment latency. Exact aggregate observations and histograms are retained in fixtures-observations.jsonl. The five positive reports record the actual 69,242 assertion count. Negative passes record eval calls and failures rather than an unavailable per-frame assertion counter.

The copied native guard installed and read back 2 GiB process and aggregate commit limits before child execution, required at least 5 GiB freshly available memory and enforced the selected 1,200 second deadline. No timeout, output violation or guard termination occurred. All frozen source, fixture, dependency and executable identities matched after execution. The resource record is retained in validation.json.

Release compilation and strict selected lint checks also pass. CI checks the saved evidence and compiles the ignored target without automatically repeating this large allocation. Fresh execution requires separate resource admission. A failed admission or partial pass preserves its evidence and stops, without a larger limit or unchanged retry.

These native controls remain distinct from a hiding proof, exhaustive equivalence, ledger eligibility, membership, unspent state, conservation and encrypted delivery. They introduce no public owner or input commitment linking shortcut. The full payment and security composition requirements remain separate work.

## Derivation

The bounded fixture reader, canonical transaction mapper, direct byte checks and global frame approach derive from research/signature-packed-native/tests/native.rs at revision d04516b6635d79c76d57887568719f7708203d49. The original relation, independent fixtures, source inventory and their attribution remain unchanged. The source uses the repository MIT license, copied unchanged here. Registry identities remain pinned in Cargo.lock.

## Reproduction

```text
python research/signature-packed-padding/static_check.py
cargo fetch --manifest-path research/signature-packed-padding/Cargo.toml --locked
cargo fmt --manifest-path research/signature-packed-padding/Cargo.toml --all -- --check
cargo test --manifest-path research/signature-packed-padding/Cargo.toml --release --locked --offline --test padding --no-run --jobs 1
cargo clippy --manifest-path research/signature-packed-padding/Cargo.toml --release --test padding --locked --offline -- -D warnings
```

After separate resource admission, set `KOVA_PACKED_PADDING_GATE=reviewed-external-resource-admission` and select only:

```text
cargo test --manifest-path research/signature-packed-padding/Cargo.toml --release --locked --offline --test padding --jobs 1 -- --ignored --exact four_consistent_virtual_padding_controls --test-threads=1
python research/signature-packed-padding/static_check.py --check-results
```

The static checker validates identities, fixed source rank histograms and saved expectations without executing the AIR or initializing its cache. The optional `--registry-root` argument checks actual retained Cargo registry files. The copied Windows guard can enforce the recorded external limits around the exact compiled executable. Result files are exclusive and preserve existing evidence.
