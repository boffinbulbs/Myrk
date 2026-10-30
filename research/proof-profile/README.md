# Conditional proof profiles

This laboratory computes the retained library's classical round by round soundness model for the complete native signature shape. It includes the actual width of batched openings, hiding columns and quotient chunks. It also records their conditional storage cost. No scenario is selected as a protocol parameter set.

The evaluated relation has height 8192, width 47058 and degree four. Routing changes reduce its constraint count from 181221 to 74725. At the current comparison settings, both receive the same overall calculator output because the opening batch term binds first.

These are the costs of one authorization relation. A complete multi input payment also requires the private ledger constraints and authenticated shared witnesses.

| Scenario | Extension | Random columns | Queries | Classical model bits | Binding term | Field files in bytes |
| :--- | ---: | ---: | ---: | ---: | :--- | ---: |
| Before routing | 4 | 4 | 64 | 79.6394 | Batch combination | 27796045824 |
| Current comparison | 4 | 4 | 64 | 79.6394 | Batch combination | 27796045824 |
| More queries | 4 | 4 | 128 | 89.4766 | Batch combination | 27796045824 |
| Larger extension candidate | 8 | 8 | 128 | 190.6667 | Low degree test | 27836153856 |

These are outputs of the pinned classical model, not attack costs, quantum security levels or certification of this custom protocol. The extension eight candidate has not been exercised through a prover. Increasing query count alone does not remove the field and batching terms. Fewer constraints do not automatically strengthen the binding term.

## Concrete shape

With $W$ main columns, $r$ random columns, $e$ extension coefficients and eight quotient chunks, the opening batch contains

$$
k=2(W+r)+8(e+r)+(e+r).
$$

The two main openings account for local and next state. The final term accounts for the randomization polynomial. This gives 94196 functions for the extension four comparison and 94276 for the larger candidate. Passing one function to the calculator would omit the actual batching cost.

The prime is $p=2013265921$. Field bit inputs are conservative integer floors of $\log_2(p^e)$, giving 123 and 247. No unenforced grinding is credited. The 256 bit collision input is a declared classical assumption for full SHA3-512 framing. It is not converted into a quantum claim.

The retained hiding implementation requires

$$
r\ge e,\qquad N\ge2(q+et),
$$

where $q$ is query count and $t$ the number of opening points. The comparison uses $t=2$ and $N=8192$. A larger extension therefore carries more random columns and larger auxiliary commitment widths. Those costs remain in the table. All scenarios exceed current full signature storage and shape allowances.

## Verification boundary

The [captured report](fixtures/report.json) retains every labeled library term and both proximity regimes. One ordinary Rust regression compares the complete calculation against that record. Four Python tests independently check cardinality floors, mask budgets, batched widths, field byte arithmetic, query payload, unique regime AIR composition and DEEP terms, and report aggregation. They also reject a false batch width, altered storage arithmetic and unsupported security flags. They do not independently validate the entire FRI or proximity theorem.

The separately guarded export computes four bounded model scenarios and six invalid profile controls. Its [validation record](validation.json) pins source and executable identities, dependency boundaries and installed external limits. It allocates no symbolic AIR, signature trace, polynomial commitment or proof. Existing native and proof budgets are unchanged.

## Research assumptions

The library's model names are calculator regimes. Applying a theorem to the complete system also requires matching the actual transcript, commitment encoding, query model and relation. Round by round soundness, knowledge extraction and the quantum random oracle transformation remain distinct obligations. [Fiat Shamir security of FRI](https://eprint.iacr.org/2023/1071), [soundness notions for interactive oracle proofs](https://eprint.iacr.org/2023/1256).

Finite code proximity bounds must be distinguished from optimistic capacity assumptions. The analysis retains the library's named regimes and records their assumptions rather than treating a query count as a complete security level. [Distances of random words](https://eprint.iacr.org/2025/2010), [quantitative Reed Solomon bounds](https://eprint.iacr.org/2026/2056), [DEEP ALI parameter analysis](https://eprint.iacr.org/2024/1553).

The larger candidate's classical output does not establish a quantum target or a private payment proof. The [proof feasibility record](../../docs/proof-feasibility.md) and [resource model](../signature-scheduling/README.md) retain the remaining composition and implementation gates.

## Reproduction

```text
python research/proof-profile/static_check.py
python research/proof-profile/reference.py
python -m unittest discover -s research/proof-profile -p test_reference.py -v
cargo fmt --manifest-path research/proof-profile/Cargo.toml --all -- --check
cargo test --manifest-path research/proof-profile/Cargo.toml --release --locked --lib -- --test-threads=1
cargo clippy --manifest-path research/proof-profile/Cargo.toml --release --all-targets --locked -- -D warnings
```

The ignored exporter requires a separate finite source and resource admission. Set `KOVA_SECURITY_PROFILE_GATE` to `reviewed-external-resource-admission` and select only `tests::retained_classical_reports_and_resource_controls` through the Windows guard with `ExpectedTests 1` and `TimeoutSeconds 120`. The guard installs and reads back 512 MiB process and aggregate limits and requires 2 GiB free physical memory before resume. Generated results refuse overwrites.
