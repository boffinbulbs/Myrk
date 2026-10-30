# Owned hint reconstruction

This component connects actual normalized inverse coefficients and decoded signature hints to the private W1 reconstruction bank. One source owner supplies the current row. Saved inputs and intermediate values enter only the reference and independent comparisons.

## Reconstruction relation

For q = 8380417, alpha = 523776 and gamma2 = 261888, the retained encoder derives

$$
n=\left\lfloor\frac{r+\gamma_2-1}{\alpha}\right\rfloor,\qquad
u=(r+\gamma_2-1)\bmod\alpha.
$$

The high component is n modulo 16. The signed low component is u minus gamma2 plus one, with the modulus edge correction. A set hint adjusts the high component by one according to the strict sign of low, modulo 16. Bounded carries, complements, sign slack and wrap flags retain the original integer encoding. Low remains a signed expression, rather than a canonical field residue.

## Same row inputs and delayed bytes

At each inverse output tile, the candidate reads eight current scratch coefficients and their actual held decoder flags. It receives no external inverse vector, hint vector or packed result. Other rows use the canonical zero input and zero hint encoding for all eight gadgets. Clearing the gadgets without encoding would lose required nonzero complements.

The assigned mask is `[41143,43167)`, containing eight hint gadgets and 1,024 packed bytes. Every row first exposes the old packed bank. An output tile then updates four private bytes, placing the even coefficient in the low nibble. Those bytes first appear on the next row.

The first update is visible at row 3715. Each completed row contributes 128 bytes. The full bank is visible at row 5314, after its final producer and before the later final hash schedule. The bank remains held through row 8191. Inverse scratch, forward banks, activity and all other source fields are preserved.

## Reference boundary

The bounded reference explicitly adapts the original encoder and row loop to independent state and one row of storage. Only the current output tile receives saved inverse coefficients and hints. It never copies candidate state or runs an inverse reference to obtain its inputs.

The reference shares the retained encoding equations. Ten saved step fields, including signed low, and saved packed bytes provide separate comparisons. Active branch observations remain distinct from dormant zero encodings. A fixed dataset does not establish every edge or wrap branch.

## Recorded execution

One explicit integration test passed on Windows with Rust 1.94.1, producing 46 synced observations across 8,192 rows. Comparisons covered 2,048 active gadgets, their 20,480 saved step fields and input/complement encodings, plus 63,488 canonical dormant gadgets. All 1,024 packed bytes were checked on every row, giving 8,388,608 independent visibility comparisons. Seven comparator corruptions were detected and restored.

The active cases contained 1,022 positive and 1,026 nonpositive low components, 46 set hints, 73 modulus edge cases and one output borrow. No active zero-low tie or output overflow occurred in this dataset. Dormant zeros do not supply those missing active cases.

The source preserved 337,117,184 fields outside its mask. Generation counters report 70 initial and 336 matrix calls. The pinned source implies 812 internal round traces, 16 candidate forwards, eight candidate inverses and 65,536 logical hint encodings per candidate and reference side. These internal counts are source inferences. The reference performs no hash or transform oracle call. Normal public transaction preprocessing remains outside generator counts.

The external guard enforced 512 MiB process and aggregate limits, a 120 second deadline and at least 2 GiB immediately available. Actual kernel peaks were 4,399,104 process private commit bytes and 5,689,344 aggregate commit bytes. Available memory before launch was 11,044,487,168 bytes. There was no timeout, output limit or guard termination. These are component construction measurements.

## Implementation scope

The source and explicit diagnostic compile under the default and selected feature profiles. Final hashing and challenge equality, complete clock and ports, hiding proofs and private ledger integration remain unfinished. Default complete construction and actual proof resource class refusals remain in place. No validated full security profile follows from source construction.

`static_check.py` checks source identities, dependency scope, saved literal aliases and recorded observations. It does not rerun decomposition, packing arithmetic, transforms or proofs. Original extraction changes and MIT attribution are retained. CI compiles the explicit diagnostic without repeating its finite local execution.

```text
python -I -S research/signature-hint-source/static_check.py
cargo test --locked --release --manifest-path research/signature-hint-source/Cargo.toml --features hint-controls --test hint --no-run
```

Any further native attempt needs a fresh reviewed process and aggregate resource admission.
