# Owned matrix sampling and accumulation

This experiment consumes the actual current squeeze bank and forward transform outputs from one owned signature source. A private accumulator follows the matrix hash prefix on the same row and global position. Saved coefficients and products enter only the reference and independent comparisons.

## Eight sequential decisions

Each sampling row exposes nine count and byte cursor states around eight decisions. For an active slot with count k below256, the current three bytes form a24-bit candidate. The lower23 bits determine acceptance modulo the signature modulus.

$$
q=8380417,\quad a=\operatorname{LE}_{24}(x)\mathbin{\&}(2^{23}-1),\quad
t=[a<q],\quad k'=k+t,\quad c'=c+3.
$$

An accepted coefficient multiplies the actual physical Z transform operand and updates its selected accumulator modulo q. A rejected active slot still uses that operand with a zero multiplier. After count256, slots stop consuming bytes and use canonical neutral encodings. The full accumulator is exposed before current decisions update its private next state.

The assigned mask is `[33804,41143)` plus eight activity fields `[43168,43176)`. Reused rows clear sparse flags and then encode all fields, including neutral products and writes with their required complements and carry offsets. Activity derives from each emitted pre-decision count and the fixed sampling phase.

## Completion and point correction

Every stream requires256 accepted coefficients at local row47. Count and cursor reset only for the55 nonfinal streams. The final completed count and cursor remain held through the point and idle phases. This differs from the upstream squeeze bank, which resets after every stream.

Point correction reads the actual challenge and scaled T1 transform banks:

$$
u_{i,k}=A_{i,k}-\widehat c_k\,\widehat{T1}_{i,k}\pmod q.
$$

The implementation preserves modular subtraction and borrow encoding, physical bank lifetimes and pre-state visibility. Point rows overlap the later inverse schedule. Their completed vectors become available separately, rather than behind a global completion barrier.

## Reference and failure boundary

The reference explicitly adapts the original matrix row body to independent state and a one-row destination. Matrix phases populate only the current Z operand bank. Point phases populate only challenge and the current T1 bank. It never loads all logical vectors into aliased physical banks. Existing independent coefficient, product, after-state and point vectors supplement shared helper equations. They are selected as literals without regenerating arithmetic or cryptographic references.

A capacity shortage is a typed construction class failure. Upstream row work may already have advanced, so the composite and kernel become terminal and refuse reuse or completion. No rollback is promised. The fixed failure diagnostic deliberately replaces first-stream source-row XOF bytes after the real prefix. That injected row is not a genuine hash-derived input or a valid emitted AIR row. It tests terminal failure propagation, not signature rejection, AIR rejection or proof soundness.

## Recorded execution

One explicit integration test passed on Windows with Rust 1.94.1, producing 157 synced observations across serial main and failure scopes. All 8,192 main rows matched the bounded reference. Independent comparisons covered 14,336 accepted coefficients and their products and after values, seven rejected events, 56 completed streams and 2,048 point products. The walk observed 1,007 point borrows and 6,190 matrix carries. Eight comparator corruptions were detected and restored.

The fixed source-row fault reached a typed shortage at row 689 with zero accepted coefficients and cursor 1,008. Upstream had emitted 690 rows while the outer source retained 689 successful rows. Both source and kernel refused further emission and completion without writes. This confirms the stated terminal construction failure path. It does not claim a genuine bad-capacity seed or proof rejection.

Generation counters total 482 calls, including 406 for the main source and 76 for the fault prefix. The pinned generator implies 964 internal round trace computations. The schedule implies 16 complete main forwards, one complete and one partial fault forward. These internal counts are source inferences. The arithmetic reference performs no hash or transform, and independent fixtures are not regenerated. Normal public transaction preprocessing remains outside generator counts.

The external guard enforced 512 MiB process and aggregate limits, a 120 second deadline and at least 2 GiB immediately available. Actual kernel peaks were 4,579,328 process private commit bytes and 5,865,472 aggregate commit bytes. Available memory before launch was 11,209,523,200 bytes. There was no timeout, output limit or guard termination. These are component construction measurements.

## Remaining integration

The scope covers matrix rejection sampling, accumulation and point construction. Inverse state, hints, final hashing, complete clock and ports, hiding proofs and private ledger integration remain unfinished. The full constructor retains its default execution refusal. Actual proof planning stops at its retained resource class before later checks. No validated security profile or private payment authority follows from these source controls.

## Reproduction

`static_check.py` verifies saved source identities, dependency features, selected literals and recorded results. It does not rerun arithmetic, hashing, the native diagnostic or proofs. CI compiles the explicit integration target without repeating the finite local execution.

```text
python -I -S research/signature-accumulator-source/static_check.py
cargo test --locked --release --manifest-path research/signature-accumulator-source/Cargo.toml --features accumulator-controls --test accumulator --no-run
```

The native target requires separately reviewed fresh process and aggregate resource admission. Source origins, extraction changes and MIT licenses are preserved.
