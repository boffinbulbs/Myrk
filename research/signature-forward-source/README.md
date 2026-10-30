# Owned forward transform construction

This experiment joins forward signature arithmetic to the actual current source row. One local witness and immutable canonical transaction feed initial hashing, decoding, sampling and then private forward state. Reference polynomials never enter the candidate constructor.

## State and timing

The forward state holds one 256 coefficient scratch bank and nine physical output banks. It exposes current registers before applying each scheduled operation.

$$
r_t=450+192t,\qquad
(x,y)\longmapsto\bigl(x+\zeta y,\ x-\zeta y\bigr)\pmod q,
\qquad q=8380417.
$$

Each transform uses 32 initialization rows, 128 butterfly rows and 32 output rows. Its complete output is first visible at row 642+192t. Initialization reads actual decoded Z, actual sampled challenge or actual T1 with the retained factor 8192. Partial initialization preserves coordinates not yet overwritten. Dormant multiplication and write witnesses retain their canonical complement and carry encodings.

The assigned interval `[27796,32796)` contains 5,000 fields. Scratch and output values use canonical residues modulo q. Other source fields and the separate sampling activity cell are preserved. The physical output map is `[0,1,2,3,4,5,6,7,0,1,2,3,4,5,8,6]`. Nine banks preserve overlapping consumers, including the lifetime of Z6 while the later T1 output is produced.

## Bounded reference

The retained full forward pass requires a full height destination. The reference here is an explicit adaptation of its original row body to a reusable 32 row window. Separate reference scratch, outputs and global position persist across windows. The complete extraction and reference changes are recorded in the two patch files. This is an adapted source oracle, not an invocation of the unchanged full writer on a prefix.

Only reference input fields receive existing synthetic literals. Sixteen forward records are selected by exact kind and mode from a larger record list containing interleaved inverse transforms. Saved inputs, nine states per transform and first visible outputs supplement the shared arithmetic oracle. Actual source values and encoded initialization writes are checked separately. No historical producer, new transform reference or scalar hash is used to prepare these literals.

The diagnostic executes 16 candidate forward computations and 16 adapted reference forward computations. These 32 computations belong to the new construction comparison. The independent saved goldens are not regenerated. The source hash cursor remains separate from these transform counts.

## Recorded execution

One explicit integration test passed on Windows with Rust 1.94.1, producing 175 synced observations. All 8,192 candidate rows matched 256 adapted reference windows. Independent checks covered 4,096 initialization coordinates and their encoded writes, 144 stage checkpoints with 36,864 coefficients, and 16 first visible outputs with 4,096 coefficients. Six comparator corruptions were detected and restored. Shape, sequence, early completion and exhaustion controls passed.

The external guard enforced 512 MiB limits for both the process and aggregate job, a 120 second deadline and at least 2 GiB immediately available. Actual kernel peaks were 9,510,912 process private commit bytes and 10,801,152 aggregate commit bytes. Available memory before launch was 11,476,844,544 bytes. The process exited successfully without timeout, output limit or guard termination.

The candidate hash cursor completed 70 generator calls and held at most one logical hash trace. The reference generated no hash trace. The pinned generator implies 140 internal round trace computations. The completed global schedule implies 16 forward computations for each of the two state machines. These schedule and internal counts are source inferences, separate from observed row, checkpoint and kernel resource counters.

## Remaining integration

The scope is the forward pass and its held tail before inverse overlays. Matrix work overlaps the forward interval in the complete schedule. Its actual source hashing, sampling and accumulation must later interleave on the same global rows. The current initial hash tail remains provisional. Inverse initialization, hint processing, final hashing and complete clock and port construction remain unfinished.

The full constructor retains its default execution refusal. Actual proof planning stops at its retained resource class refusal before later checks. Source comparisons and comparator calibrations do not establish AIR rejection, a complete hiding proof, private payment authority or a validated security profile.

## Reproduction

`static_check.py` checks saved source identities, dependency features, literal selection and recorded results. It performs no transform, hash reference, sampler or proof. CI compiles the explicit integration target without replaying the finite local execution.

```text
python -I -S research/signature-forward-source/static_check.py
cargo test --locked --release --manifest-path research/signature-forward-source/Cargo.toml --features forward-controls --test forward --no-run
```

Native execution requires a separately reviewed fresh admission under the retained external process and aggregate limits. Original source provenance and MIT licenses are preserved.
