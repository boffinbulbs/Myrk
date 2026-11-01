# Streamed signature overlay validation

This laboratory constructs a complete native witness for the shared arithmetic signature relation from one owned synthetic verification key, signature, hidden note and canonical transaction. All 8,192 genuine global frames satisfy the actual complete AIR. Twelve altered frames reject, and all twelve restorations pass. Independent saved literals match 27,648 observed transform, hint and packed result values.

The witness and rows are available to this local native checker. Node verification without those private values requires a hiding proof. This native laboratory provides no payment acceptance API or proof verifier.

## Owned source and complete relation

Let $w=(\mathrm{vk},\sigma,n)$ be the immutable private source tuple and $A(T)$ the canonical public authorization statement. The ordered source cursor produces row $r_t$ from its current private computation state. Validation imposes the complete relation

$$F\bigl(r_t,r_{(t+1)\bmod8192},A(T),[t=0],[t=8191],[t\ne8191]\bigr)=0.$$

The last three arguments are the actual first, last and transition selectors. The final frame borrows the saved genuine row zero. Every frame calls the unchanged complete [overlay AIR](../signature-overlay/src/air.rs), including clock, private word routing, four Keccak windows, source sponge, canonical decoding, sampling, transforms, matrix reconstruction, inverse hints, note ownership, authorization and final signature equality. No reconstructed subset or host signature verdict replaces these equations.

Three rolling full width rows replace a complete trace allocation. Seven bounded pipeline preservation buffers and one initial source prefix remain separate. Original logical hash caches retain their own bounded lifetimes. A fresh marker fills each destination row before emission, so an unwritten field cannot silently inherit a zero witness.

## Shared bank ownership

| Writer | Physical fields it may change |
| --- | --- |
| Forward transform | Original transform fields and the discontiguous shared bank |
| Inverse transform | Scratch, writes, flags and shared bank from the actual inverse start |
| Inverse hints | W1 state on every row, shared bank only on inverse output rows |
| Final source ports | Original clock and private words and ports, plus two late mode fields |

Every wrapper checks fields outside its actual ownership against the upstream row. The forward wrapper checks all nonowned fields. Hint ownership depends on the actual physical row, so dormant hint encoding cannot erase an active product. Canonical idle cells and the 688 field hint suffix remain constrained by the complete AIR. Matrix products retain their separate workspace and all nine transform output banks remain present.

The cursor executes the original source order once: hashing, decoding, challenge sampling, forward transforms, matrix hashing and accumulation, inverse transforms, hints, final hashing and private ports. Partial inverse reloads, result visibility and W1 state before each update retain their original timing. The default full constructor remains refused before preflight or trace allocation.

## Independent observations and rejection controls

| Saved reference boundary | Compared values |
| --- | ---: |
| Forward transform endpoints | 4,096 |
| Normalized inverse coefficients | 2,048 |
| Hint step fields | 20,480 |
| Final packed W1 bytes | 1,024 |

Expected values are existing independent synthetic reference literals. The diagnostic regenerates no reference computation or signature. It also checks the exact canonical transaction bytes and 196 authorization fields before constructing rows.

The twelve controls cover idle data, same note ownership, suppressed product mode, simultaneous modes, product and inverse result bits, suppressed hint mode, hint input encoding, hint suffix, final signature bytes, transaction context and the last clock boundary. Ownership, context and final signature changes keep the borrowed held words and current source port consistent. Each rejects at its expected consumer equation. Three arithmetic bit controls record their actual rejection indices without assuming a predetermined index. Every altered field is restored before continued source generation.

These controls are local frame counterfactuals. They do not construct globally consistent forged witnesses or invalid cryptographic proofs. The full finite failure list is checked. Exporting up to eight indices per failure record changes logging only.

## Recorded scope

| Quantity | Result |
| --- | ---: |
| Rows and columns | 8,192 by 42,178 |
| Public values | 196 |
| Complete baseline frames | 8,192 |
| Negative and restored frames | 12 each |
| Actual complete AIR calls | 8,216 |
| Product, hint and idle rows | 3,328, 256 and 4,608 |
| Candidate logical hash constructions | 415 |
| Complete trace allocations | 0 |
| Symbolic collections and backend proofs | 0 |

One externally bounded Windows run passed in 56.86 diagnostic seconds on a Core i9-13900H with Rust 1.94.1. Peak process commit was 7,974,912 bytes and aggregate job commit was 9,261,056 bytes. Separate 512 MiB limits, at least 2 GiB available memory and a 120 second deadline applied. This is complete native checking time for the named synthetic fixture, not proof generation time or network payment latency.

The [measurement](results/measurement.json), [validation](validation.json) and [source provenance](provenance.json) preserve scope, actual rejection indices, independent fixture identities and resource observations. The earlier [symbolic result](../signature-overlay/results/symbolic.json) establishes 71,623 assertions and degree four for the imported complete relation. It is not recollected by this native run.

## Reproduction and proof boundary

```text
python -I -S research/signature-overlay-native/static_check.py
cargo fetch --manifest-path research/signature-overlay-native/Cargo.toml --locked
cargo clippy --manifest-path research/signature-overlay-native/Cargo.toml --release --lib --locked --offline -- -D warnings
cargo clippy --manifest-path research/signature-overlay-native/Cargo.toml --release --features diagnostics --lib --test stream --locked --offline -- -D warnings
cargo test --manifest-path research/signature-overlay-native/Cargo.toml --release --features diagnostics --test stream --locked --offline --no-run --jobs 1
```

The ignored native test requires an exact external acknowledgement, a separate resource admission and exclusive new journal output. CI compiles its target and checks source and saved evidence without replaying the native walk. A failed or interrupted walk is not a partial successful validation.

Native satisfaction of one synthetic owner is distinct from universal soundness and a hiding signature proof. The full signature remains outside the retained proof resource class. Composed proof security, same witness payment constraints, encrypted recipient data and authenticated private ledger admission remain unfinished. Hidden input commitments, stable nullifiers and private payments remain requirements of that integration.
