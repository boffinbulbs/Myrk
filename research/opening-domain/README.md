# Physical domain admission for opening arguments

This laboratory adds a typed domain preflight to the retained polynomial commitment scheme. The checked owned context uses it before opening private data. It also runs before the checked verifier replays claimed evaluations. The original source snapshots remain unchanged.

The implementation prevents a requested point on a committed evaluation domain from reaching full-domain denominator inversion. It supplies one hypothesis of the [conditional batching correspondence](../overlay-composition/challenge-batching.md). It is not a complete soundness, hiding or private payment proof.

## Domain and ordering

The retained two-adic PCS evaluates every physical LDE on

$$D_h=g\langle\omega_h\rangle,\qquad |D_h|=2^h,$$

with the original base field generator $g$. For a requested extension point $z$,

$$z\in D_h\quad\Longleftrightarrow\quad z^{2^h}=g^{2^h}.$$

The exponent uses the actual physical matrix height. The original trace, prepared trace and quotient reconstruction domains are different objects. Logical input shifts and bit reversal do not change this physical set. Since $2^h$ divides the base field multiplicative order, the polynomial already splits there and has no additional extension roots.

The prover reads matrix metadata from actual retained MMCS data. The verifier derives physical height with checked arithmetic from the claimed domain and retained blowup. Non-power-of-two heights, overflow, field two-adicity violations, empty shapes and in-domain points return typed causes. The metadata traversal allocates a temporary vector of borrowed matrix references. It copies no matrix fields or prover data.

`OpeningChecked` runs this admission before all four opening and verification entry points, including preprocessing. A pass delegates the actual retained operation. All auxiliary, quotient, preprocessing, evaluation view and periodic table methods retain their original implementation. The private geometry trait has only the retained hiding and non-hiding implementations. It accepts no validity callback or supplied proof verdict.

The owned context moves the PCS into the wrapper and configuration. The configuration's original `Clone` bound remains a type requirement. Constructing the context invokes no new PCS or configuration clone. Original private opening flags, salt generation and transcript objects remain in the retained data. Typed domain causes reach the outer failure owner before attempt destruction. Successful proof construction still precedes `ProofProduced`.

## Recorded finite validation

One ignored native diagnostic passed in 0.08 seconds. This timing describes the diagnostic, not a proving benchmark. The unchanged external guard installed 512 MiB limits on both process and aggregate job commit, required 2 GiB freshly available memory and enforced a 120 second deadline. Observed private commit was 1,703,936 bytes and aggregate job commit was 2,998,272 bytes. The [record](validation.json), [source identities](provenance.json) and [native result](results/native-v1.json) preserve the execution scope.

1. Nine literal and metadata cases cover the canonical generator and its negative, zero, one, a non-base extension element, mixed matrix heights, a three-row matrix, checked overflow and a height beyond base field two-adicity. The large metadata case constructs no corresponding LDE.
2. One genuine fallible 256 by 2 source reaches original owned preparation, tiled extension and main MMCS commitment. An actual checked `Pcs::open` request returns `PointInDomain` before consuming its private flag. The live challenger is unchanged.
3. Two subsequent valid requests borrow that same original prover data. They reach the original shared-opening guard. Its actual unwind consumes the original authority and occurs before inner opening. No prover data clone or manual flag setter is used. Challenger comparisons sample disposable clones of public state.
4. The terminal caller preserves the earlier typed domain cause before dropping the attempt. A retained matrix alias refuses further reads. This is shared read closure, not an independent OS descriptor closure probe.
5. Four checked verifier calls cover hiding and non-hiding PCS and preprocessing routes. They use a typed object decoded from the saved small proof and refuse the unsafe domain before query sampling or original cryptographic verification. They do not replay that proof's producer or healthy verifier.

The diagnostic records one main commitment, six metadata inspections, 10,948 mask bytes and 279,800 parent salt bytes. The main setup's original MMCS clone and constructor salt fork remain included. Parent journals do not claim to observe every child RNG stream. The owner retains its original thirteen roles and 1,325,056 byte reservation. Three additional constructor setups retain their own original salt forks. All setup and decoding allocations are included in process accounting.

The original shared guard prints a caught panic message. That event is separate from the normal typed domain refusal. No successful inner opening, FRI execution, quotient or auxiliary construction, proving transcript driver, complete proof or cryptographic verification is selected. No partial diagnostic prefix can resume.

Five compiler preparations were recorded. The first diagnostics attempt exposed a trait import and ambiguous call. The second exposed an unused copied accessor. The corrected strict diagnostics build, strict default build and test compilation passed under the same limits. No resource or profile limit was increased. The resolved graph has 66 nodes and 62 registry packages with unchanged dependency declarations and no parallel feature.

## Build and evidence inspection

The package is standalone. Its default feature set contains no diagnostic execution. The diagnostic feature requires the retained release profile.

```text
cargo clippy --manifest-path research/opening-domain/Cargo.toml --release --features diagnostics --lib --locked --offline --jobs 1 -- -D warnings
cargo test --manifest-path research/opening-domain/Cargo.toml --release --features diagnostics --test admission --no-run --locked --offline --jobs 1
python -I -S research/opening-domain/static_check.py
```

The Python command checks recorded evidence and source identities without running native controls. A new native run requires separate source and executable review, the unchanged [external guard](run_guarded_windows.ps1), a fresh memory check and `KOVA_OPENING_DOMAIN_GATE=reviewed-external-resource-admission`. Use the exact executable produced by the selected test compilation with `--ignored --exact actual_opening_domain_controls --test-threads=1 --nocapture`. Result creation is exclusive. Reproduction requires a separately reviewed source snapshot and result destination.

## Capability boundary

The checked nominal context is connected to the complete small owned prover, but that complete prover is not executed here. Safe cryptographic verification remains delegated and is not retested by these refusal controls. Original retained types and other laboratory snapshots are not changed. This is not a repository-wide network acceptance policy.

The complete signature remains refused by its original width and resource classes. These small validation peaks do not admit its projected retained LDE, query contents or full proof. Complete batching, DEEP, hiding, repeated observation, hash, multiround Fiat Shamir and knowledge composition remain unresolved. Input commitments remain hidden and private payments remain the default requirement. No payment or ledger acceptance capability is supplied.
