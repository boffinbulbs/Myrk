# Owned inverse construction

This component extends the same signature source through eight inverse transforms. The candidate reads actual accumulator tiles and the held forward scratch from its current row. Saved stage vectors enter only the independent reference and comparisons.

## State and timing

For inverse index i, the start is S_i = 3522 + 224 i. Its schedule has 32 initializer rows, 128 butterfly rows, 32 normalization rows and 32 output rows. The private bank is seeded once from actual held forward scratch at row 3522, before clearing the assigned fields.

Each row exposes the bank before its current operation updates private state. Initializers replace eight coordinates at a time. The remaining coordinates retain the preceding bank, including across transform boundaries. No complete free inverse input is supplied to the candidate.

For q = 8380417 and an inverse twiddle zeta, each butterfly computes

$$
a' = a+b \pmod q,\qquad b' = \zeta(a-b) \pmod q.
$$

Normalization multiplies each coordinate by 8347681, the inverse of 256 modulo q. Integer multiplication, addition and subtraction retain the original carry, borrow, complement and offset encodings. Dormant gadgets are canonically encoded.

## Overlap and preservation

The new mask is `[30100,32796)` only from row 3522 onward. All nine forward output banks remain unchanged while point rows 6 and 7 are still active. Inverse initializers read corrected accumulator coordinates at their actual readiness time. They do not wait behind an artificial global barrier.

Output rows expose values through NTT_WRITES without overwriting forward banks. After row 5313, the final normalized scratch remains held through row 8191. Unused products, writes and flags retain canonical neutral encodings throughout that tail.

## Reference boundary

The bounded reference explicitly adapts the original inverse row body to independent state and one row of storage. Its seed comes from the saved T1_7 forward output. Only the current initializer tile populates its accumulator inputs. Candidate state never seeds the reference.

Eight retained inverse records contain eleven snapshots each: input, eight layer endpoints, the first normalization half and complete normalization. These saved mathematical references supplement shared helper equations. The reference itself executes eight adapted inverse bodies. Calling no generic transform oracle does not make that inverse work zero.

Comparator corruptions measure equality sensitivity. Source construction controls do not establish AIR rejection, proof soundness or private payment authorization. Upstream capacity errors retain typed terminal propagation. The closed earlier fault diagnostic is not repeated by this component.

## Recorded execution

One explicit integration test passed on Windows with Rust 1.94.1, producing 123 synced observations across one 8,192 row source walk. All eight inverses matched the bounded original body reference. Independent comparisons covered 88 stage snapshots, 65,536 partial initializer coordinates, 2,048 initializer values, 2,048 normalization values, 2,048 output values and 512 held tail coordinates. Six comparator corruptions were detected and restored. The walk observed 4,060 addition carries and 4,094 subtraction borrows.

The source preserved 341,107,472 fields outside the temporal mask, including forward banks during 64 overlapping point rows. Generation counters report 70 initial and 336 matrix calls. The pinned generator implies 812 internal round trace computations. The schedule implies 16 candidate forwards, eight candidate inverses and eight adapted reference inverses. These internal work counts are source inferences. The reference performs no hash generation or standalone old transform oracle call. Normal public transaction preprocessing remains outside generator counts.

The external guard enforced 512 MiB process and aggregate limits, a 120 second deadline and at least 2 GiB immediately available. Actual kernel peaks were 4,771,840 process private commit bytes and 6,057,984 aggregate commit bytes. Available memory before launch was 11,147,468,800 bytes. There was no timeout, output limit or guard termination. These are component construction measurements.

## Implementation scope

The cohesive source and explicit diagnostic compile under the default and selected feature profiles. Hints, W1, final challenge equality, complete clock and ports, hiding proofs and private ledger integration remain unfinished. Default complete construction and actual proof resource class refusals remain in place. Full security profile validation remains open.

`static_check.py` checks saved identities, dependency scope, literal aliases and recorded observations without rerunning arithmetic, transforms or proofs. CI compiles the explicit diagnostic without repeating its finite local execution. Original extraction changes and MIT attribution are retained.

```text
python -I -S research/signature-inverse-source/static_check.py
cargo test --locked --release --manifest-path research/signature-inverse-source/Cargo.toml --features inverse-controls --test inverse --no-run
```

Any further native attempt needs a fresh reviewed process and aggregate resource admission.
