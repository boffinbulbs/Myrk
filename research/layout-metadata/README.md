# Bounded complete AIR metadata

This laboratory derives assertion degrees from the actual [complete signature overlay](../signature-overlay/README.md) without retaining a symbolic expression graph. It invokes the unchanged AIR, including all four Keccak windows, source bindings, arithmetic modes, transform, matrix and hint equations. It checks metadata rather than witness satisfaction. No proof backend or payment verifier is instantiated.

## Representation and ordering

An expression contains an optional known field constant, an unknown polynomial degree, a borrowed budget authority and deferred literal work. Main row variables have degree one. Public variables have degree zero but remain unknown. First and last row selectors have cached degree one, while the two adic transition selector has cached degree zero. Periodic, Circle, preprocessing, permutation and extension relations are outside this fixed diagnostic's supported scope.

For unknown operands, addition and subtraction retain the maximum input degree and multiplication adds degrees. Actual constant arithmetic is preserved. A known zero annihilates a product, while an unknown expression $x-x$ retains its original symbolic degree. Thus

$$
d(x-x)=d(x),\qquad d(0x)=0,\qquad d(ux)=d(x)\quad\text{for unknown public }u.
$$

These are cached symbolic metadata rules. They are not claims about a polynomial's minimal degree after algebraic simplification.

The source assertion order is preserved. For $m$ assertions, original assertion $j$ has coefficient $\alpha^{m-1-j}$ in the retained Horner folding order. This base field relation records degrees in that order. It does not reorder assertions by bank, mode or degree. A control checks the nonmonotone sequence `[0, 2, 1, 4]` and the actual selector methods.

One variable bank supplies both main rows and public variables. `RowWindow` borrows its slices, so `main()` does not clone the bank. The implementation stores no expression children, witness rows, committed data or supplied validity verdict.

## Bounds and measured result

The fixed entry has height 8,192, width 42,178 and 196 unknown public variables. It permits at most 80,000 assertion records, degree seven and 20,000,000 attached metadata charges. Shape checks precede full variable allocation and AIR evaluation. Allocation errors, crossed authorities, overflow and exhausted limits refuse the result with a sticky first cause.

The charge counter measures metadata operations attached to the current authority. Literal work without an authority is deferred until attachment. Reusing a copied detached expression can charge that work again. Discarded detached work and field arithmetic outside the metadata type are not counted. The counter is neither every process instruction nor an I/O or proving budget. The external deadline remains necessary.

| Recorded quantity | Result |
|---|---:|
| Actual complete AIR evaluations | 1 |
| Assertion records | 71,623 |
| Maximum recorded degree | 4 |
| Degree histogram, zero through seven | `[72, 3295, 46690, 20884, 682, 0, 0, 0]` |
| Attached metadata charges | 3,975,662 |
| Variable entries and observed capacity | 84,552 |
| Bytes per expression metadata entry | 40 |
| Requested variable payload bytes | 3,382,080 |
| Assertion record capacity | 80,000 |
| Independent metadata control groups | 24 |
| Symbolic graph collections, witness frames and proofs | 0 |

The counts and histogram agree with the unchanged [earlier symbolic record](../signature-overlay/results/symbolic.json). Its producer was not repeated. Fixed literal controls cover constants, unknown cancellation, public variables, selector degrees, deferred work, arithmetic overflow, crossed owners, first cause preservation, assertion capacity, unsupported shapes and ordered records. Allocation failure was not forced.

The sole native test completed in 0.05 seconds on the retained Windows research host with Rust 1.94.1. The unchanged external guard enforced separate 512 MiB process and aggregate job limits, at least 2 GiB freshly available memory and a 120 second deadline. It observed 5,210,112 process private commit bytes, 6,516,736 aggregate job commit bytes and 9,773,056 working bytes. Requested vector payloads, observed capacities and process peaks are separate quantities.

The previous symbolic graph run recorded 405,774,336 process commit bytes for its own scope. This separate metadata result avoids retaining that graph. It does not lower the complete proof's retained matrix, salt, digest or query contents. Neither measurement is a full proving memory bound.

Strict default and diagnostic Clippy checks and explicit test preparation passed under their original external limits. No native retry was used. The [validation](validation.json) and [provenance](provenance.json) bind the successful result, source, dependency features and executable identity.

## Reproduction

```text
python -I -S research/layout-metadata/static_check.py
cargo fetch --manifest-path research/layout-metadata/Cargo.toml --locked
cargo clippy --manifest-path research/layout-metadata/Cargo.toml --release --lib --locked --offline --jobs 1 -- -D warnings
cargo clippy --manifest-path research/layout-metadata/Cargo.toml --release --features diagnostics --lib --test metadata --locked --offline --jobs 1 -- -D warnings
cargo test --manifest-path research/layout-metadata/Cargo.toml --release --features diagnostics --test metadata --locked --offline --no-run --jobs 1
```

The static command checks saved evidence without running the AIR. The ignored native test requires its own external admission and a new exclusive output location. The [Windows guard](run_guarded_windows.ps1) retains the original limits. CI compiles the ignored target and checks the saved record rather than repeating the native evaluation.

## Integration boundary

This is a separate nominal diagnostic. The original signature overlay sources, manifests and evidence remain unchanged. The imported relation has neither diagnostics nor native execution enabled by this crate. The default library executes no metadata pass.

The original full signature still fails `RawWidth` above eight before symbolic construction. Stored matrix, public value and quotient kernel bounds remain separate. This helper is not integrated into a proving planner and cannot authorize a wider proof. The conditional 22,115,516,416 main LDE field bytes, source adapter monomorphism, real commitment and query construction, security composition and private payment witness joins remain unresolved. See the [complete instance and security obligations](../overlay-composition/instance-security.md).
