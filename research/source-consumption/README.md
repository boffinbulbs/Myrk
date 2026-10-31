# Private opening authority

This laboratory exercises two actual refused opening calls against committed private data. A point budget refusal leaves private opening authority unused. Two individually valid requests sharing cloned authority consume it and reach the original repeated opening guard. In both cases, caller failure closes the same owner and its committed leases.

The experiment extends the [source prover](../source-prover/README.md) with the corrected [failure owner](../source-failure/README.md). Its normal prover remains compiled and unselected. No inner opening, verifier call or completed proof is selected here.

## Budget and consumption

Let $N_m$ be the mask height, $q$ the query count, $d$ the extension degree and $o$ the number of supplied opening points. The retained hiding implementation requires

$$
N_m\geq 2(q+do).
$$

The actual committed main matrix has 4,096 rows and six columns. Its original blowup and masking rules give $N_m=256$. The fixed profile has $q=64$ and $d=4$. Seventeen supplied points require $2(64+4\cdot17)=264$, so the original preflight returns HidingBudgetExceeded before consuming a private flag. Repeated points count toward that conservative budget.

Cloned private prover data shares the original atomic opening flag. After all preflight checks pass, the opening implementation consumes each requested flag before delegating to inner opening. Two requests referencing the same authority therefore encounter the original already opened guard on the second request.

| Actual call | Preflight | Shared flags afterward | Caller first cause |
|---|---|---|---|
| One request with seventeen points | Original budget refusal | false and false | Typed HidingBudgetExceeded |
| Two requests with one point each | Both pass | true and true | Actual original unwind |

The diagnostic calls the real Pcs::open. It neither writes the flags directly nor supplies a verdict. The duplicate case checks the actual original panic message. The budget case retains the exact original error fields: mask height 256, query count 64, point count 17 and extension degree 4.

Caller closure is independent of unused private authority. With $S$ the owner state and $\ell$ any retained committed lease, both outcomes require

$$
S=\mathrm{Failed},\qquad
\operatorname{Read}(\ell)=\mathrm{Err},\qquad
e_{\mathrm{first}}=e_{\mathrm{actual}}.
$$

The common step records the actual typed cause or caught unwind before the attempt is destroyed. Both actual lease aliases refuse access. Reentry leaves protocol counters unchanged and preserves the first cause. A false private flag cannot reopen a failed owner.

## Recorded scope

One guarded release test passed on 1 November 2026 with Rust 1.94.1 on an Intel Core i9-13900H running Windows x86_64.

| Observation per case | Budget refusal | Shared requests |
|---|---:|---:|
| Actual main commitments | 1 | 1 |
| Actual Pcs::open calls | 1 | 1 |
| Main matrix inspections | 2 | 3 |
| Coset LDE wrapper entries | 2 | 2 |
| Refused actual lease aliases | 2 | 2 |
| Inner openings, verifier calls and completed proofs | 0 | 0 |
| Reserved field roles and bytes | 13 and 1,325,056 | 13 and 1,325,056 |

Both cases observe equal next extension samples on public challenger clones before and after the call. That finite observation is supplemented by inspection of the original preflight and consumption code, which calls no challenger before these exits. It does not assert arbitrary challenger state equivalence. No StarkProverTranscript is created by this prefix, and no aborted prefix is resumed.

## Resources and evidence

Private data cloning copies the dense 4,096 by sixteen salt matrix and digest vectors. The salt fields alone occupy $4096\cdot16\cdot4=262144$ bytes per clone. Stored descriptors, owner identity and private opening flags remain shared. Cloning samples no fresh entropy. The PCS, configuration, MMCS and RNG are not cloned or reset by the diagnostic. The observer records one existing MMCS clone during each fresh setup.

The unchanged external guard installed 512 MiB process and aggregate job limits, required 2 GiB free physical memory and imposed a 120 second deadline. Peak process commit was 2,654,208 bytes and aggregate job commit 3,944,448 bytes. The harness reported 0.14 seconds. This single duration is a diagnostic observation, not a general performance bound.

The sixteen file and 2 MiB field storage class remains unchanged. The report is exclusive, synchronized and bounded to 16 KiB. Each case records 10,948 directly observed mask bytes and 279,800 salt bytes including the initial 32 byte fork seed. Separately journaled seeded forks remain outside those delivered stream fingerprints.

The [measurement](results/measurement.json), [validation record](validation.json), [source manifest](provenance.json) and [notices](NOTICE.md) bind the tested source and scope. Complete signature proof resources, hiding and quantum security composition and same witness private payments retain separate milestones.

## Build and reproduce

The default library excludes diagnostics. Saved evidence validation and compilation do not execute opening controls or a prover.

```sh
python -I -S research/source-consumption/static_check.py --check-results
cargo clippy --manifest-path research/source-consumption/Cargo.toml --release --lib --locked --offline -- -D warnings
cargo clippy --manifest-path research/source-consumption/Cargo.toml --release --features diagnostics --lib --test opening --locked --offline -- -D warnings
cargo test --manifest-path research/source-consumption/Cargo.toml --release --features diagnostics --test opening --locked --offline --no-run --jobs 1
```

A fresh execution uses the [unchanged Windows guard](run_guarded_windows.ps1), the compiled release unwind binary, one test thread and the exact name `actual_private_opening_preflight_and_shared_consumption`. Fixed outputs cannot overwrite a previous record. Exact source, executable, effects and fresh resource admission precede execution. CI checks saved evidence, formatting, lints and compilation without replaying the native controls.
