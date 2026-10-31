# Committed quotient construction

This laboratory connects the retained main commitment to fallible quotient evaluation and an owned canonical output file. The relation is the fixed synthetic Quartic computation with 256 rows, two trace columns and public endpoints 5 and 260. It tests proof infrastructure needed for a larger private ledger.

For the actual committed evaluation matrix $L$, the commitment and batching challenge follow

$$
C=\operatorname{MMCS}(L),\qquad \alpha=\mathcal{T}(C,p).
$$

The quotient reads the same main prover data returned with $C$. Callers cannot supply an independent matrix, commitment root or challenge. Its logical view is

$$
V[r,c]=L[\operatorname{rev}_{11}(r),c],\quad 0\le r<2048,\quad 0\le c<2.
$$

The physical matrix has 4096 rows and six columns. Its 2048-row prefix supplies the quotient coset. Four random codeword columns remain outside the view. The next trace row at a quotient point has logical index $(r+8)\bmod 2048$.

For $N=256$, $x=31\omega_{2048}^r$ and the original emitted constraints $C_j$, evaluation preserves the upstream relation

$$
Q(x)=\frac{\sum_{j=0}^{m-1}\alpha^{m-1-j}C_j(V(x),V(\omega_Nx),p)}{x^N-1}.
$$

The actual upstream constraint folder performs the fold. Extension values use the ascending basis of $\mathbb{F}_p[u]/(u^4-11)$, with $p=2013265921$. Each completed row writes four canonical little endian field coefficients directly to the owned sink. The evaluator keeps packed row windows and bounded selector arrays. It does not return a whole quotient vector.

The owner reserves 13 field files and 1325056 field bytes before construction. A single writer advances MainCommitted to QuotientEvaluating and then QuotientReady. Sealing requires 2048 ordered rows, synchronization, closing the writer and reopening a checked descriptor. Errors close subsequent reads across the owner. Cleanup removes only files created by that attempt and preserves failed reservations.

The diagnostic compares all 4096 visible fields with the original fast view, captures all 8192 quotient coefficients and records commitment, transform, opening and randomness effects. An independent integer implementation compares the captured coefficients using the actual transcript challenge. Its nine fixed mutations examine stride, wrap, alpha ordering, basis, reduction polynomial, selectors and column/index mapping. Both comparisons share the same captured main evaluations. They do not independently reconstruct the LDE or verify its root.

Nine additional storage cases use ten isolated owner fixtures. They cover writer exclusion, row shape/order, incomplete completion, unowned files, unfinished drop, a missing descriptor, short-file reopen and foreign-owner/noncanonical reads. Those fixtures perform no commitment. Actual panic unwinding, lock poisoning, operating-system write/sync failures and orphan cleanup need separate controls.

## Reproduction

The default build leaves diagnostics disabled. The selected feature uses fixed public synthetic data. It has no wallet input or transaction admission interface.

```powershell
cargo clippy --release --features diagnostics --lib --test construction --locked --offline -- -D warnings
cargo test --release --features diagnostics --test construction --no-run --locked --offline --jobs 1
```

Run the printed test executable through [the Windows guard](run_guarded_windows.ps1) with ExpectedTests 1, arguments `--test-threads=1`, a fresh output prefix and a 120-second limit. The guard requires 2 GiB of free physical memory and installs 512 MiB process and aggregate memory limits before execution. Existing result files are preserved through create_new refusal.

After a successful native capture, preparation and independent comparison are separate steps.

```powershell
python -I -S compare.py prepare
python -I -S compare.py run
python -I -S static_check.py --check-results
```

The comparison process uses the same external memory and time guard. Preparation hashes the captured payload and records its actual commitment and source manifest. The receipt identity is a provenance identifier, without independent root authentication. Synthetic capture and reference input files remain local and are excluded from Git.

## Verified results

One guarded Windows x86_64 run on an Intel Core i9-13900H completed the selected diagnostic in 0.16 seconds. This is component construction time, without a proof. Rust 1.94.1 and Python 3.14.5 were used.

| Check | Saved result |
|---|---|
| Actual committed main view | All 4,096 visible fields match the retained fast view |
| Independent quotient arithmetic | All 8,192 coefficients match across 2,048 rows |
| Arithmetic identities | Seven pass |
| Mutation controls | All nine separate, with missing wrap detected on the final eight rows |
| Protocol effects | One main commitment, two main extension tile calls, zero openings and zero proofs |
| Native peak process and job commit | 2,994,176 and 4,288,512 bytes |
| Reference peak process and job commit | 14,598,144 and 15,888,384 bytes |

These are diagnostic observations under the recorded profile. They are not performance measurements of the full private signature prover. [Saved validation](validation.json), [construction effects](results/measurement.json) and [independent comparison](results/reference-report.json) retain the exact scope.

## Scope

QuotientReady means completed evaluation data. Construction stops before coupled quotient masking, quotient commitment, auxiliary commitment and opening. The complete private signature relation remains outside this small storage class. These results establish neither a complete payment proof nor network finality, privacy, post quantum security or a production release.

Original notices, source differences and pinned identities are retained in [NOTICE.md](NOTICE.md) and [provenance.json](provenance.json).
