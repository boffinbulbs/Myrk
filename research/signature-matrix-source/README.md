# Owned matrix hash and squeeze construction

This experiment joins matrix expansion to the same owned signature source and canonical transaction. A private overlay follows actual initial hashing, decoding, sampling and forward transforms on each current row. It reads the held RHO bank directly. Saved stream bytes enter only the reference and independent comparisons.

## Matrix expansion

For coordinates i and j, the first rate block frames the same witness seed with column j and row i. Six real Keccak permutations carry the complete internal state. Subsequent blocks absorb zero rate bytes rather than restarting the seed.

$$
S_0=0,\qquad S_{b+1}=f(S_b\oplus M_b),\qquad
X_b=\operatorname{rate}_{168}(S_{b+1}),\qquad 0\le b<6.
$$

Here M₀ is the retained seed and domain padding block. Each rate block is zero extended to the 200 byte state width before XOR. Later M_b are zero. The overlay uses the original schedule and encoders. It replaces only Keccak columns `[0,10532)` and message/output columns `[16271,18959)` during the six active permutations of a stream. Other source fields, forward outputs and activity remain unchanged.

## Current and next bank state

Each stream occupies 48 physical rows. Its six permutations use the first 36 rows, followed by twelve inherited dummy rows. The 1,008 byte bank is emitted before updates. A terminal physical row latches its 168 OUTPUT bytes into the next bank state.

$$
V_{\ell,b}=[\ell\ge6(b+1)],\qquad
B_{\ell}[168b:168(b+1)]=V_{\ell,b}\,X_b,\qquad 0\le\ell<48.
$$

The first chunk appears at local row 6, and the complete bank appears at row 36. Row 47 still exposes that complete stream. Reset follows its emission, so the next stream begins with a zero bank. The final genuine matrix hash row is 3317, the final stream row is 3329, and row 3330 exposes zero. Current bank timing cannot be replaced by immediate consumption of a just generated chunk.

## Reference boundaries

The reference explicitly adapts the original matrix permutation and bank passes to a six row destination with carried global position. It releases its temporary logical permutation before candidate generation. It is not an unchanged invocation of the global writer on a short prefix.

The retained synthetic corpus provides all 56 complete streams. Records are selected by coordinates and reordered from saved row order to actual construction order. Terminal chunks and every current bank are checked against those literals. Intermediate round fields are checked against the shared original body adaptation. No independent intermediate round-state goldens are available in that corpus.

The candidate retains its initial dummy cache and can hold a second logical cache during matrix blocks. One cache per cursor does not imply one aggregate cache. The reference destination and transient generator storage are additional allocations. Source identities, two adaptation patches and kernel measurements record this boundary.

## Recorded execution

One explicit integration test passed on Windows with Rust 1.94.1, producing 692 synced observations. All 8,192 composed rows matched the bounded reference within the assigned mask. Independent comparisons covered 56,448 terminal squeeze bytes, 8,257,536 current bank positions and 10,752 actual RHO byte positions. Seven comparator corruptions were detected and restored. Destination, sequence, completion and exhaustion controls passed.

Observed generation counters report 70 initial calls, 336 candidate matrix calls and 336 reference calls. The pinned generator implies 1,484 internal round trace computations across those 742 calls. The completed schedule also implies 16 candidate forward computations, with no reference forward computation. These inferred internal counts remain separate from observed counters. Independent stream goldens were not regenerated, and the capacity preflight was not called. Normal public transaction preprocessing remains outside the trace generator count.

The external guard enforced 512 MiB process and aggregate limits, a 120 second deadline and at least 2 GiB immediately available before launch. Actual kernel peaks were 4,288,512 process private commit bytes and 5,591,040 aggregate commit bytes. Available memory before launch was 11,103,739,904 bytes. There was no timeout, output limit or guard termination. These are component construction measurements.

## Integration boundary

This slice constructs matrix hashes and squeeze banks. Matrix rejection sampling, accumulation, point subtraction, inverse state, hint processing, final hashing and complete clock and port construction remain unfinished. Their actual overlap with the forward schedule is preserved for subsequent integration. Historical six-block support metadata is not a new capacity verdict.

The complete constructor retains its default execution refusal. Actual proof planning stops at its retained resource class before later checks. Source comparisons and comparator calibration do not establish a complete hiding proof, private payment authority, AIR rejection or a validated security profile.

## Reproduction

`static_check.py` checks saved source identities, dependency features, literal selection and recorded results. It does not regenerate matrix streams, run the native diagnostic or construct a proof. CI compiles the explicit integration target without replaying its finite execution.

```text
python -I -S research/signature-matrix-source/static_check.py
cargo test --locked --release --manifest-path research/signature-matrix-source/Cargo.toml --features matrix-controls --test matrix --no-run
```

Native execution requires a separately reviewed fresh admission under the retained external process and aggregate limits. Original source provenance and MIT licenses are preserved.
