# Bounded native paired monetary accounting

This isolated safe Rust 1.94.1 component implements numeric accounting for the prospective [paired 60 second profile](../../docs/monetary-paired60.md). The default library is empty. The `diagnostics` feature enables a std-only module with no registry dependencies. The actual frozen reward table is included as constants from the unchanged monetary core. No original core accounting, tests or earlier reference producer is executed.

All public amounts, totals, budgets and issuance results are explicitly `Unverified`. Numeric consistency authenticates no height ordering, branch, reward duty, ownership, destination, restored state or commit permission. This is a research component, not an accepting ledger or activated monetary profile.

## Actual operations

1. Nominal subsidy uses the new 43800 block periods and ordered `10*floor(S/20)`, `S-first` pair. Genesis is zero and maximum unsigned height is handled without an increment or doubling. The old 120 second reference and all its data remain unchanged.
2. Each numeric quote clips the current nominal amount to `cap-issued` before applying the four allocation floors. Every remainder belongs to the miner. The caller-supplied earned amount is checked against the current stake budget, without authenticating duty evidence.
3. Issuance recomputes that quote, performs checked amount operations, constructs the next totals and result, then assigns once. A failed operation leaves its original numeric totals unchanged. An earlier quote is never an issuance input.
4. Burn checks current outstanding value and assigns only after successful arithmetic. It increases completed burns without reopening issuance capacity. Issuance and burn are separate numeric operations. Calling both is not an atomic database transaction.
5. The uncapped nominal prefix uses checked `u128` arithmetic and at most 240 table entries. The saved maximum-height prefix has 89 bits. Individual amounts use checked `u64` addition and subtraction. The module performs no I/O or explicit heap allocation.

The [MIT notice](licenses/Kova-MIT) preserves original attribution. The [source record](provenance.json) pins the actual included constants, dependencies, source and [independent saved reference](../monetary-paired60/README.md). Toolchain intrinsics may internally use unsafe code. Source inspection is not a toolchain audit or a security theorem.

## Recorded native validation

One ignored release diagnostic passed under actual Windows 512 MiB process and 512 MiB aggregate job limits, fresh 2 GiB availability, 120 seconds and job flags 8960 read back before launch. It reported 0.00 seconds, 1302528 bytes of peak process private commitment, 2199552 bytes of peak job commitment and 5808128 bytes of peak working set. All 2955 frozen source/runtime/linker/build inputs were verified afterward. This small measurement admits no complete private proof.

| Executed scope | Count |
|---|---:|
| Saved period pairs | 240 |
| Nominal phase boundary comparisons | 960 |
| Real two-height capped accounting pairs | 960 |
| Earned amount and completed burn cases | 18 |
| Real typed numeric refusals | 16 |
| Saved wide prefixes | 9 |
| Saved new-profile transitions | 3 |
| Manual nominal / pair / allocation anchors | 13 / 7 / 6 |

The caps cover full old amounts and both sides of the first-half boundary for every period. Independent component vectors and fixed rounding deltas check the actual state transitions. Failure controls cover invalid restored totals, excess earned atoms, overburn, arithmetic overflow/underflow, stale quotes, wrong-phase earning bounds and unchanged originals. Genesis, tail, maximum unsigned amounts and burned-cap behavior are also checked. These are numeric tests, not authenticated replay, branch or recovery tests.

The saved near-cap difference is preserved: with 100 atoms remaining and zero earned stake, two new opportunities issue 80 then 16 and leave four. The old single opportunity's saved comparison issues 80 and leaves twenty. No old-profile issuance is passed through the new API. The saved final cap transition at new height 167804683 also matches the independent reference.

Six guarded preparations passed: bounded test-data transcription, offline metadata, formatting, default compilation, strict diagnostic compilation and the release test build. The helper copied actual stored numbers into a 41306 byte test fixture and computed no expected monetary result. No old producer, model, core test, native arithmetic suite, proof, healthy verifier or journal control was replayed. The [validation](validation.json) and [native capture](results/native.txt) retain exact outcomes.

## Remaining boundaries

Recorded evidence can be inspected without running the native arithmetic:

```text
pwsh -NoProfile -File research/monetary-paired60-native/static_check.ps1
```

The native test is ignored and requires a separately reviewed finite release scope with actual external limits. CI and the job layout are unchanged. No cryptographic work, RNG, keys, signatures, private source owner, opening flag, prover, verifier, ledger, signer or network instance is imported or executed.

Production genesis, authenticated profile registry, live activation and any migration remain absent. Reward origin and 10080 block maturity, initial checkpoint finality, normal bond conservation, blocked stake bootstrap and distinct treasury authorities are unchanged. The developer retirement still needs a later consensus change.

Complete private authorization and parser feasibility remain the next architectural gate. A numeric accounting result cannot supply same-witness ownership, a valid proof, authenticated history, confidential stake, durable signing or atomic ledger acceptance. Payments and hidden input commitments remain private by default across the complete roadmap.
