# Owned sampling source composition

This experiment connects initial hash construction, decoding and private challenge sampling over one owned witness and immutable canonical transaction. The source owner fixes that order on the same mutable row. The sampler reads only the actual current row XOF emitted by the hash cursor. Saved XOF bytes enter the reference oracle only.

## Construction

Let the current sampling state be positive and negative coefficient registers, accepted count a and byte cursor u. The initial values are zero registers, a = 0 and u = 8. Each row exposes the current state before its update. For active sampling rows, r₀ = 12 and r₁ = 276 define the source window below. The candidate byte j is read only within that window while a < 60.

$$
i = 196 + a,\qquad j = \operatorname{XOF}[8+r-r_0],\qquad
\operatorname{take} = [a<60]\,[r_0\le r<r_1]\,[j\le i].
$$

An active candidate increments u. A taken candidate also increments a, copies the previous coefficient at j to i and assigns the selected sign at j. Capturing the previous coefficient before either assignment preserves the case j = i. Negative coefficients have the canonical value q − 1 = 8380416, embedded in the proof field. They are not the negative unit of that field.

The sampler clears and owns 1,185 fields in `[26611,27796)`. A separate activity cell at column 43167 uses the current row count. Hash and decoding columns remain unchanged by sampling. The diagnostic keeps one bounded prefix snapshot to check this preservation. That storage is a comparison instrument, not a verifier or permission to accept a transaction.

## Reference and controls

The unchanged original sampler loop runs once on a zeroed 277 row prefix populated from an already saved independent synthetic XOF with its actual visibility schedule. It asserts completion at 60 coefficients. Every sampler column and the separate activity cell are compared. On the reference access at row 277 the large prefix is released, leaving only the terminal 1,185 fields. Independent retained signed coefficients, cursor and rejected byte positions supplement this original loop comparison.

The candidate uses one real hash cursor and the same local decoding cursor. It never receives a supplied challenge polynomial or reference XOF buffer. The fixed diagnostic checks every actual source XOF row against the saved schedule, destination refusals before writes, early completion refusal, terminal state, exhaustion and five comparator corruptions with restoration. Comparator controls establish diagnostic sensitivity. They are not AIR rejection tests.

The fixtures contain public synthetic sources only. Source identities, nominal type changes, the sampler extraction diff and dependency features are recorded alongside the measurements. Hash and decoding source files remain at their pinned origins. A new nominal owner does not convert or expose an older opaque object.

## Recorded execution

One explicit integration test passed with 22 synced observations on Windows with Rust 1.94.1. All 8,192 composed rows matched the sampler oracle and source XOF schedule. There were 70 candidate events, 60 takes and ten rejections. The terminal state first appeared at row 82 and remained stable through the final row. Five comparator corruptions were detected and restored. Shape, early completion and exhaustion controls passed.

The fixed walk contained no same index alias event. Its assignment order is preserved by source comparison, while isolated alias execution remains outside this result. The original reference loop ran once. The candidate generated 70 logical hash blocks, with no reference hash generation or new scalar hash calculation. The pinned generator implies 140 internal round trace computations. That last count is inferred from source rather than separately instrumented.

The external guard enforced 512 MiB limits for both the process and aggregate job, with a 120 second deadline and at least 2 GiB immediately available before launch. Actual kernel peaks were 49,987,584 process private commit bytes and 51,286,016 aggregate commit bytes. Available memory before launch was 11,110,301,696 bytes. There was no timeout, output limit or guard termination. These are component diagnostic measurements.

## Remaining integration

The source composition covers initial hashing, decoding and sampling. Complete chronological construction, transform and matrix overlap, final hash replacement, clock and port columns, hiding proof composition and ledger integration remain unfinished. The full constructor retains its default execution refusal. The real proof planner stops at its retained resource class refusal before later checks. A complete security profile remains unvalidated. This diagnostic establishes neither a complete private signature proof nor a usable private payment network.

The reference prefix occupies 47,839,008 raw field bytes. Its retained terminal band occupies 4,740 bytes. Actual process and aggregate peaks are recorded in `validation.json`. These source sizes do not predict a complete proof footprint.

## Reproduction

`static_check.py` checks recorded source identities, dependency scope, literal reference selection and results without running a sampler, hash reference or proof. CI compiles the explicit integration target without replaying its finite execution.

```text
python -I -S research/signature-sample-source/static_check.py
cargo test --locked --release --manifest-path research/signature-sample-source/Cargo.toml --features sample-controls --test sample --no-run
```

The integration executable requires separate fresh resource admission and the retained external Windows guard. Its diagnostic target is one test with one thread. Existing source provenance and MIT licenses remain applicable.
