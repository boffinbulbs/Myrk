# Live source failure closure

This laboratory checks two real filesystem failures during the small source proving lifecycle. A truncated canonical quotient source returns its original typed access error. An auxiliary output collision records its original error before the infallible storage interface unwinds. Both failures close the same committed data across retained descriptor aliases.

The experiment extends the [uninterrupted source prover](../source-prover/README.md). It generates no completed proof and calls no verifier. These controls test storage and transcript failure boundaries rather than cryptographic proof rejection.

## Failure invariants

Let $S$ denote the owner state and $e_\star$ its first recorded failure. Every later failure observation must preserve

$$
S=\mathrm{Failed},\qquad
e_\star=\operatorname{FirstError}(e_0,e_1,\ldots),\qquad
\operatorname{Read}(\ell)=\mathrm{Err}
$$

for each retained lease $\ell$ of that owner. An error must not create ProofProduced, reopen a source or reset private randomness. Releasing the active writer claim after its descriptor closes does not reopen the failed owner.

The normal public proving entry selects no fault. A crate private diagnostic selector chooses two fixed actions at real stage boundaries. It accepts no path, witness predicate, field value, commitment root, challenge or proof verdict.

| Case | Physical action | Actual failure | Last completed commitment |
|---|---|---|---|
| Quotient source length | Truncate the same owned sealed source from 32,768 to 4 bytes | Typed Access(Length) return | Main |
| Auxiliary output collision | Create a diagnostic sentinel at the planned auxiliary file | Io(AlreadyExists) followed by the original storage unwind | Quotient |

The first case retains the actual descriptor established by canonical sealing. The checked reader tests descriptor length before reading fields. The original quotient mapper has already sampled its masks when that access fails. Its error returns through the live transcript abort path without restoring entropy or manufacturing a field value.

The second case retains the original auxiliary sampler and transform. The real exclusive output creation fails against the sentinel. The owner records AlreadyExists before the infallible MatrixStore interface raises its typed panic payload. The outer diagnostic catches that actual unwind. The common attempt and step cleanup retain the first cause.

The inherited pending writer cleanup left its active writer flag set after closing the descriptor. This successor clears the claim after recording failure and before either cleanup branch. The phase remains Failed, and original unlink authority remains unchanged. The selected collision exercises the uncreated output branch. Orphan removal failure remains a source inspected branch.

## Recorded results

One guarded release test passed on 31 October 2026 with Rust 1.94.1 on an Intel Core i9-13900H running Windows x86_64.

| Observation | Truncated source | Auxiliary collision |
|---|---:|---:|
| Main MMCS commitments | 1 | 1 |
| Quotient MMCS commitments | 0 | 1 |
| Coset LDE wrapper entries | 2 | 3 |
| Coupled coset inverse and forward entries | 0 and 0 | 8 and 8 |
| Refused actual lease aliases | 2 | 2 |
| Openings, verifier calls and completed proofs | 0 | 0 |
| Reserved field roles | 13 | 13 |
| Reserved field bytes | 1,325,056 | 1,325,056 |

Both cases evaluate the real 2,048 row quotient kernel and seal its 8,192 canonical coefficients. The first source access fails before any quotient transform or commitment. The second completes those operations and the original auxiliary extension before its output collision. Each case refuses reentry without another protocol operation and leaves the resource anchor untouched.

The sentinel survives the storage failure because the owner never created it and never acquired permission to remove it. The diagnostic checks the fixed parent path, file kind, length and bounded exact body, then explicitly removes its own sentinel. This isolated fixture does not establish protection against an adversary replacing filesystem paths concurrently.

## Resources and evidence

The original external guard installed 512 MiB process and aggregate job limits, required at least 2 GiB free physical memory and imposed a 120 second deadline. Peak process commit was 4,698,112 bytes and aggregate job commit 5,992,448 bytes. The test harness reported 0.47 seconds. This single diagnostic duration is not a throughput benchmark or a general prover bound.

The existing sixteen file and 2 MiB field storage class is unchanged. The report is bounded to 16 KiB and written exclusively with synchronization. Transform counters describe wrapper entries. RNG fingerprints cover directly delivered streams and exclude separately journaled seeded forks.

The [measurement](results/measurement.json), [validation record](validation.json), [source manifest](provenance.json) and [original notices](NOTICE.md) identify the exact tested scope. The prior successful source proof belongs to its earlier source snapshot. No new successful proof or actual private opening is selected here.

## Build and reproduce

The default library excludes diagnostics. Saved evidence validation and compilation do not repeat the filesystem faults or invoke a prover.

```sh
python -I -S research/source-failure/static_check.py --check-results
cargo clippy --manifest-path research/source-failure/Cargo.toml --release --lib --locked --offline -- -D warnings
cargo clippy --manifest-path research/source-failure/Cargo.toml --release --features diagnostics --lib --test failures --locked --offline -- -D warnings
cargo test --manifest-path research/source-failure/Cargo.toml --release --features diagnostics --test failures --locked --offline --no-run --jobs 1
```

A fresh execution uses [the unchanged Windows guard](run_guarded_windows.ps1), the compiled release unwind binary, one test thread and the exact test name `live_source_failures_preserve_first_cause_and_close_leases`. Fixed output paths cannot overwrite an earlier record. Exact source, executable, effects and fresh resource admission precede execution. CI validates saved evidence, formatting, lints and compilation without replaying the native fault cases.

Private opening consumption, complete signature proof resources, hiding and quantum security composition, same witness private payments and network integration retain separate milestones.
