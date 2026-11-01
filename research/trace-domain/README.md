# Producer raw trace-domain admission

This nominal source prover refuses an out-of-domain challenge on the original trace domain before opening values are computed. It uses the actual sampled challenge and admitted raw domain. The retained physical LDE preflight remains separate. Historical source snapshots are unchanged.

## Admission and lifetime

For the current raw subgroup $H$ of size $n$, the original normalized vanishing polynomial is

$$Z_H(z)=z^n-1.$$

The private [guard](src/trace_admission.rs) returns `RawTracePoint { trace_height }` when this value is zero. It uses the original domain operation rather than a caller supplied verdict. Zero is outside this subgroup and passes this raw-domain criterion. The trace generator preserves $H$, so rejecting $z\in H$ also covers its next-row translate.

The [producer](src/owned_prover.rs) calls the guard immediately after the original `ood_phase` sample and grinding-witness normalization. The call precedes `begin_opening`, opening interpolation and private flag consumption. Main, quotient and auxiliary commitments and their entropy already exist at this point. Refusal neither restores that entropy nor samples another challenge.

The typed cause enters `OwnedError::Storage` and the actual owner's `OpeningDomain` cause. The existing stage error branch aborts the same original transcript. `Step` records the cause before attempt destruction, so the subsequent unwind marker does not replace it. A failed prefix is terminal. It supplies no partial proof or reusable opening authority.

The retained [physical-domain wrapper](src/domain.rs) independently rejects points on committed LDE cosets before denominator inversion. The raw trace subgroup and physical generator coset are different domains. Raw-domain admission alone is not opening acceptance.

The [nominal root](src/laboratory.rs) imports the latest composite owner, source, extension, owned PCS, hiding adapter and observer at their actual paths. The source family instantiates together with the new domain and context types. Its original writer busy correction, shared private flags, normalized domains and method forwarding remain intact. Construction moves the PCS rather than cloning or resetting its configuration or RNG.

## Recorded finite controls

One native diagnostic passed six canonical literal cases. The raw subgroup points one, minus one and the retained order-256 generator reject. Zero, the full field generator and the retained order-512 generator pass the raw criterion. These results do not replace the physical-domain checks.

One genuine fallible 256 by 2 source reaches original owned preparation, tiled extension and retained hiding MMCS. The direct diagnostic derives its raw domain from the same PCS and calls the actual shared guard at the explicit public point one. It checks the real typed cause, unused private flags and unchanged observer counts across the guard. Actual prover data are dropped. The terminal owner records the domain cause and a retained alias refuses reads. A failed reentry initializes its producer zero times. Shared read closure is not an independent OS descriptor closure probe.

The diagnostic records one main commitment, two observed tile LDE calls, one borrowed matrix inspection, 10,948 parent mask bytes and 279,800 parent salt bytes. The original constructor salt fork and one original MMCS clone remain included. The separate anchor construction has its own original fork. Parent journals do not observe every child RNG stream. One context construction retains two original tiny Quartic planner inferences. This is not a complete overlay symbolic evaluation.

The native test does **not** run the live post-auxiliary OOD sample and transcript-abort path. That actual producer call site is connected and compiled. A direct known-point guard control is not evidence that the unchanged sampler naturally generated that point. No sampling override, supplied root or alpha, manual flag setter, prover data clone or host validity callback is used.

No successful opening, quotient or auxiliary construction, proving transcript, complete proof or cryptographic verifier is selected by the native diagnostic. The complete producer remains a separate compiled capability. No healthy predecessor proof, decoder, verifier or earlier reference was replayed.

The [validation record](validation.json) preserves the actual 512 MiB limits on both process and aggregate job commit, a fresh 2 GiB availability requirement and a 120 second deadline. Native private commit was 1,675,264 bytes and aggregate job commit was 2,961,408 bytes. The harness reported one passing test in 0.07 seconds. These measurements describe the direct diagnostic, not complete proving performance or wide feasibility.

## Build and evidence

The dependency graph retains 66 nodes and 62 registry packages with identical versions, features and licenses. No parallel feature or new dependency is selected. Strict diagnostic and default library checks and test compilation passed. The source-format preparation was syntax-only. The [source record](provenance.json) preserves the concrete derivation and imported context.

```text
cargo clippy --manifest-path research/trace-domain/Cargo.toml --release --features diagnostics --lib --locked --offline --jobs 1 -- -D warnings
cargo clippy --manifest-path research/trace-domain/Cargo.toml --release --no-default-features --lib --locked --offline --jobs 1 -- -D warnings
cargo test --manifest-path research/trace-domain/Cargo.toml --release --features diagnostics --test admission --no-run --locked --offline --jobs 1
python -I -S research/trace-domain/static_check.py
```

The default feature set executes no diagnostic. Diagnostic builds require the retained release profile. A new native run requires separate source and executable review, the unchanged [external guard](run_guarded_windows.ps1), fresh memory admission and `KOVA_TRACE_DOMAIN_GATE=reviewed-external-resource-admission`. Use the exact compiled executable with `--ignored --exact actual_trace_domain_controls --test-threads=1 --nocapture`. Result creation is exclusive. Reproduction requires a newly reviewed snapshot and result destination. The static checker reads saved evidence without native execution.

## Capability boundary

This is a producer privacy admission in the retained small source class. It is not a repository-wide network policy, full signature proof or payment acceptance API. The original width, storage, public-value and quotient limits remain unchanged. The complete signature is still refused by its existing admission classes.

The [conditional joint observation argument](../joint-observation/README.md) and [auxiliary isolation argument](../joint-hiding/README.md) remain ideal oracle statements with explicit challenge, degree and mask assumptions. Actual failure probabilities, Fiat Shamir compilation, salts, hashes, repeated fresh proofs, concurrency, knowledge and quantum applicability need complete composition. Private payment requirements, hidden inputs and the same witness across authorization, nullifier, conservation, encrypted delivery and atomic ledger consumption remain intact.
