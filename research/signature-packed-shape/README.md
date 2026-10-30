# Complete packed signature constraint shape

This separate test target inspects the complete [packed signature and note ownership relation](../signature-packed/README.md). It leaves the retained source unchanged. The default feature configuration keeps the full native constructor disabled.

The harness invokes the actual symbolic AIR builder once. It records the emitted assertion count, cached maximum degree and a bounded degree histogram. The observed result is written before its expectations are checked. No signature trace, native constructor or proof is executed.

## Source accounting

The retained relation emitted 71,141 assertions per row. Removing 7,637 byte holds and adding 2,547 word holds, 3,000 Boolean constraints and 125 selected word equalities gives

$$71,141-7,637+2,547+3,000+125=69,176.$$

Each port that can address a partial tail contributes two further zero padding assertions. At most 125 ports qualify, giving the independently derived range $69,176\leq C\leq69,426$. Consumer rewrites expand expressions while preserving their assertion calls. Degree four remains the expectation for the complete relation.

The symbolic builder uses two rows of variable descriptors. Its arithmetic expressions share reference counted child nodes. The returned root vector briefly overlaps the builder's root vector. This mechanism has different memory costs from a dense trace. Reduced column count does not establish reduced symbolic memory.

## Measured result

The actual single complete collection emitted 69,242 assertions with maximum degree four. Subtracting the source base count accounts for 66 additional padding assertions. The observed degree histogram is retained in fixtures-symbolic.json.

| Quantity | Actual record |
| --- | ---: |
| Main columns | 43,176 |
| Public values | 196 |
| Assertions per row | 69,242 |
| Maximum degree | 4 |
| Symbolic collections | 1 |
| Native traces | 0 |
| Backend proofs | 0 |
| Peak process commit bytes | 404,402,176 |
| Peak aggregate commit bytes | 405,688,320 |

The guarded release test passed once on Windows 11 with a Core i9-13900H and Rust 1.94.1. The observed test duration was 0.51 seconds. This measures symbolic collection and its test harness, not payment latency or proof generation. The source dependencies, executable identity and guard summary are retained in provenance.json and validation.json. The source and executable identities matched after execution.

Rust release compilation and strict selected Clippy checks also pass. The exact test is ignored by default and requires an acknowledgement environment variable. Native equivalence and backend proofs remain separate gates. Symbolic shape establishes neither satisfiability nor completeness of authorization, privacy or post quantum security.

The copied Windows guard enforces a 120 second deadline, 512 MiB process and aggregate commit limits, and at least 2 GiB freshly available memory. A failed admission or capped execution preserves its result and stops. It does not authorize a larger limit or a full trace.

Source uses the repository MIT license. The relation is imported unchanged from the retained laboratory. Its source origins and upstream notices continue to apply. Exact registry versions and checksums remain in Cargo.lock.

## Reproduction

```text
python research/signature-packed-shape/static_check.py
cargo fetch --manifest-path research/signature-packed-shape/Cargo.toml --locked
cargo fmt --manifest-path research/signature-packed-shape/Cargo.toml --all -- --check
cargo clippy --manifest-path research/signature-packed-shape/Cargo.toml --release --test shape --locked --offline -- -D warnings
```

After separate resource admission, set `KOVA_PACKED_SYMBOLIC_GATE=reviewed-external-resource-admission` and select only:

```text
cargo test --manifest-path research/signature-packed-shape/Cargo.toml --release --locked --offline --test shape --jobs 1 -- --ignored --exact complete_packed_symbolic_shape --test-threads=1
python research/signature-packed-shape/static_check.py --check-results
```

The static checker verifies identities and recorded arithmetic without evaluating the AIR. The optional `--registry-root` argument also checks the retained source files against an actual Cargo registry directory. Results are written exclusively. An existing result is preserved rather than replaced. The copied Windows guard can enforce the recorded limits around the exact compiled test executable.
