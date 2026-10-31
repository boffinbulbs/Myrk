# Eight domain mask normalization

This laboratory checks the exact eight domain normalization and final coupled mask bank used by the owned quotient commitment source. An original backend helper and a separate integer implementation agree on all domain shifts, normalizers and 2,048 final coordinates. No commitment or proof is generated in this diagnostic.

## Relation

The quotient domain has 2,048 points over the field of order

$$p=2013265921.$$

It splits into eight cosets of size 256. The ordered first points are defined by the retained subgroup generator.

$$a_i=31\omega_{2048}^i,\qquad 0\leq i<8.$$

The backend uses normalized vanishing polynomials. Their normalization is part of the relation.

$$Z_j(x)=(x/a_j)^{256}-1,\qquad
c_i=\left(\prod_{j\ne i}Z_j(a_i)\right)^{-1}.$$

The first seven banks contain 256 rows and eight columns. The final bank begins at zero and receives the actual retained update order.

$$t_{7,k}=-\sum_{i=0}^{6}\frac{c_i}{c_7}t_{i,k},\qquad
\sum_{i=0}^{7}c_i t_{i,k}=0,\quad0\leq k<2048.$$

The private helper is used by both the source adapter and this diagnostic. It receives no expected result or acceptance callback. The diagnostic replaces entropy with an explicit public input recipe for arithmetic comparison. This recipe is not available as a production randomness option.

For ordinary coordinates the public bank is `11 + 23i + 9r + 17c` modulo p. Each first coordinate is zero and each last coordinate is p minus one. These fourteen edge inputs are included in the same full bank calculation.

## Verified scope

One guarded native diagnostic captures the actual eight domains, original get_zp_cis result and coupled helper output. A separately guarded Python reference reconstructs the banks with integer arithmetic. It imports no candidate field or normalization code. It shares the explicit input recipe and pinned subgroup root.

| Observation | Result |
|---|---|
| Ordered domain shifts |All 8 equal|
| Original normalizers |All 8 equal to the independent reference|
| Final bank coordinates |All 2,048 equal|
| Cancellation residuals |All 2,048 zero|
| Coupled coordinate updates |14,336 in the successful helper call|
| Shape refusals |Two before any update|
| Preserved input fields per refusal |16,384|
| Preserved first bank fields after success |14,336|

The two shape controls use incorrect multiplier and bank lengths. The helper refuses each before modifying any coordinate. These are native source helper refusals, separate from a verifier rejecting a proof.

The independent arithmetic controls record actual differences.

| Mutation | Differing entries |
|---|---:|
| Reversed reported domain order |8 domain entries|
| Monic replacement of normalized vanishing |8 normalizers|
| Final coupling with monic normalizers |2,047 coordinates|
| Incorrect final sign |2,047 coordinates|
| Omitted masks for added random columns |1,024 coordinates|
| Zero final bank |2,047 coordinates|

Equal size normalized subcosets have equal normalizers. Reordering those normalizers or removing a common factor can therefore preserve the final coupling. Those cases are not claimed as separated mutations. Domain order is checked as ordered metadata, with its own comparison.

## Resources and provenance

Both selected runs passed on 31 October 2026 using Rust 1.94.1 and CPython 3.14.5 on an Intel Core i9-13900H running Windows. Each run had an external 512 MiB process and aggregate job ceiling, at least 2 GiB free physical memory and a 120 second deadline. Native peak process commit was 1,306,624 bytes and job commit 2,383,872 bytes. Reference peaks were 13,328,384 and 14,622,720 bytes respectively. The native test duration rounded below the test timer's display resolution.

The synthetic capture is 22,778 bytes within the 64 KiB class. Reports are limited to 16 KiB. Exclusive writes and source, executable, interpreter and input identities are recorded separately from arithmetic outcomes. The original 16 file and 2 MiB commitment storage class is unchanged and no commitment owner is instantiated here.

No PCS, owner, RNG, DFT, MMCS, opening, verifier or proof constructor is called by the selected diagnostic. This absence follows source inspection rather than counters from constructed protocol objects. The complete earlier commitment diagnostic remains unselected. These measurements do not establish a general prover memory bound or a security level.

## Reproduction

The default library excludes diagnostics. The saved result can be checked without repeating either admitted execution.

```sh
python -I -S research/mask-normalization/static_check.py --check-results
cargo clippy --manifest-path research/mask-normalization/Cargo.toml --release --lib --locked --offline -- -D warnings
cargo clippy --manifest-path research/mask-normalization/Cargo.toml --release --features diagnostics --lib --test normalization --locked --offline -- -D warnings
cargo test --manifest-path research/mask-normalization/Cargo.toml --release --features diagnostics --test normalization --locked --offline --no-run --jobs 1
```

The unchanged Windows guard runs the compiled normalization test under external limits. Its fixed outputs cannot be overwritten. The capture preparation command verifies the actual native guard and executable before creating the reference input. The reference run requires all equalities, zero residuals and six positive mutation distances before writing its report.

This gate supplies arithmetic evidence for subsequent uninterrupted transcript integration. Auxiliary commitment, the original batched opening, complete hiding proof resources and same witness private payment composition remain separate milestones. The [owned quotient commitment](../quotient-mask/README.md) records the preceding full commitment comparison for its exact source revision.
