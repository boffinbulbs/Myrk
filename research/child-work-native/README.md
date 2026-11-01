# Bounded native child work arithmetic

This isolated Rust 1.94.1 component implements the numeric [prospective child work policy](../../docs/child-work-policy.md). The default library is empty. The `diagnostics` feature enables safe fixed-size target, work score and timestamp arithmetic without external dependencies. Every public context and result remains explicitly `Unverified`. Numeric checks authenticate no predecessor, branch, clock, policy, private payment or block.

## Arithmetic and ownership

1. A positive target has four little endian `u64` limbs. A product or work score has five. ASERT uses a signed `i128` numerator, truncation toward zero, a Euclidean whole/fraction split and the exact integer polynomial. The polynomial uses `u128` intermediates. No float, compact target round trip, host bigint or data-sized allocation occurs.
2. Target multiplication retains up to 273 bits. Bit length checks clamp before any large shift. Actual left shifts are at most 255 one-bit operations. Right shifts are bounded by the product size. Carry, borrow, underflow and 320 bit accumulation overflow use explicit checks.
3. Work is exactly `floor(2^256/(T+1))`. The denominator can have 257 bits. Binary division uses exactly 257 iterations with fixed arrays. Numeric score comparison supplies no branch compatibility or finality check.
4. The public expected-target method fixes the prospective spacing at 60 seconds. Candidate time, candidate target and parent bits are absent. The original 600 second spacing is private comparison scope. The context checks numeric initial/limit order, the height-zero genesis time and successor height exhaustion. Its caller-owned fields are not authenticated history.
5. Timestamp classification requires the exact `min(11,height)` predecessor count, uses a stack insertion sort and strict upper median, and distinguishes missing clock or future quarantine from numeric eligibility. UTC addition uses a wider integer. No actual clock is read.

The algorithm is attributed to Mark Lundeberg and the Bitcoin Cash Node contributors. Original MIT notices are retained in [licenses](licenses/). The [source record](provenance.json) links the exact primary revision and independent prior [integer reference](../child-work-policy/README.md). Source inspection is not a toolchain audit or a PoW security theorem.

## Recorded validation

One guarded release diagnostic passed. It computed all 66 saved targets from the separate integer reference, including 18 independent primary literals, without running their producer. Thirty-one cases also passed through the public fixed-spacing context. The test includes real zero/over-limit/time-range/spacing/height/window refusals, a 273 bit product literal, full target endian round trips and a 319 bit maximum work sum.

| Actual scope | Count |
|---|---:|
| Saved target calculations | 66 |
| Public numeric context calculations | 31 |
| Complete right-shift amounts | 322 |
| Individual shifted bit comparisons | 103040 |
| Independent work literals | 8 |
| Exact Mersenne-denominator work divisions | 256 |
| Startup median windows, checked at equality and above | 11 |

Additional source-counted groups cover carry and borrow across every limb boundary, checked overflow with unchanged originals, a full-width multiplication identity, outlier/duplicate times, missing UTC, the 7200 second boundary and maximum unsigned time. These are numeric controls. No authenticated history splice, fork switch or reorganization is tested.

Actual Windows limits were 512 MiB process commitment and 512 MiB aggregate job commitment, fresh 2 GiB availability and 120 seconds, with job flags 8960 read back before launch. The test reported 0.00 seconds, 1302528 bytes peak process private commitment, 2187264 bytes peak job commitment and 5783552 bytes peak working set. All 2958 frozen source/runtime/linker/build inputs were verified afterward. This small measurement admits no wide private proof.

Eight guarded preparations preceded the native run. Seven passed. The first strict compilation failed on a constant release-assertion lint. A const-block correction passed fresh formatting and strict checks before the release test build. The exact failed record is retained. No arithmetic native attempt failed or was replayed. The [validation record](validation.json) preserves all preparation outcomes and the native executable identity.

The [test fixture](src/saved_cases.rs) is a bounded transcription of the immutable 19194 byte reference record. The helper copied actual numeric strings into 66 tuples and calculated no expected target. The native implementation computes the results. Neither the original C++ tests nor a prior Python model, proof, healthy verifier, witness walk or journal test was run.

## Use and remaining gates

The ignored release test requires a separate reviewed finite execution and actual external limits. Ordinary compilation does not run it. Recorded evidence can be checked without executing its arithmetic:

```text
pwsh -NoProfile -File research/child-work-native/static_check.ps1
```

No CI or job layout change is included. This component imports no hash, Equihash, RNG, keys, signing, encryption, proof, PCS, MMCS, challenger, private opening authority, ledger or network implementation.

Production genesis, initial/easiest targets, authenticated policy registry, clock source and history remain unselected. The retained executable monetary reference still uses 120 seconds. A versioned 60 second monetary transition must specify exact integer subsidies, periods, allocations and cap behavior. Reward maturity remains 10080 blocks. Initial checkpoint finality, conserved bonds and the blocked stake bootstrap are unchanged.

Full private proof and parser feasibility, same-header auxiliary binding, confidential stake, durable signer state, atomic authenticated ledger and network gates remain required. Payments and hidden input commitments remain private by default. This research component is not a working blockchain or an authorization API.
