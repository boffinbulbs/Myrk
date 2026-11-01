# Bounded parent header work selection

This source review selects a narrow next implementation target: an exact header work predicate with fixed Equihash `(200,9)`, canonical header framing and a validator supplied expected target. It implements no verifier yet. It does not select complete auxiliary work, parent chain validation, bootstrap activation, a mining service or a running Kova node.

## Source correspondence

The reviewed official [librustzcash snapshot](https://github.com/zcash/librustzcash/tree/a551fac8a233f54799ca1920ef78ef098cfda929/components/equihash) declares `equihash` 0.3.0. It is a pinned source snapshot, not a claimed byte match to a published crate artifact. Its [entry](https://github.com/zcash/librustzcash/blob/a551fac8a233f54799ca1920ef78ef098cfda929/components/equihash/src/verify.rs) decodes packed indices, computes the actual personalized BLAKE2b leaves and recursively checks collisions, ordering, distinct indices and the zero root. The solver is separately gated and is excluded from this selection.

The independent client [Zebra snapshot](https://github.com/ZcashFoundation/zebra/tree/f72dc18766be63574f17510ee35e61ff2abfe2ae) supplies the header serialization, hash and target comparison references, plus a saved mainnet genesis block fixture. The fixture is source data, not a newly verified Kova result. Both upstreams retain MIT and Apache-2.0 notices. Source bodies and fixtures are captured for inspection outside this package. No upstream code is imported or compiled by this increment.

The protocol source served on 1 November 2026 identifies version `v2026.7.0-399-gff594d [NU6.3]`, dated 30 October. Sections 5.4.1.11 and 7.6 through 7.7 distinguish solution validity from the whole-header difficulty filter. Its header carries a 32 byte nonce and a minimally encoded 1344 byte solution. The block version rule uses signed comparison with four as a lower bound, rather than requiring exactly four. See the [publisher specification](https://zips.z.cash/protocol/protocol.pdf).

The protocol text was inspected through the web reader. Its screenshot interface returned references without displayable images, and direct PDF capture failed before download. No raw PDF identity or visual formula verification is claimed. The exact source paths, independent implementation correspondence and remaining review boundary are recorded in [source-record.json](source-record.json). Unresolved numerical policy is not transcribed from flattened formulas.

## Selected byte and policy boundary

The proposed component borrows one exact 1487 byte header. It accepts no arbitrary Equihash parameters, caller hash or supplied validity result.

| Slice | Selected meaning |
|---|---|
| Bytes 0 through 107 | Exact serialized fields before the nonce |
| Bytes 108 through 139 | Actual 32 byte nonce |
| Bytes 140 through 142 | Exact minimal solution length prefix `fd4005` |
| Bytes 143 through 1486 | Actual 1344 byte packed solution |
| Whole header | Input to the actual double SHA-256 difficulty hash |

Header version is interpreted as signed little endian. The expected raw `nBits` belongs to the verification context and must match the header. Target decoding must reject negative, zero and nonzero overflow values. The actual digest comparison uses the source's little endian integer interpretation. A displayed reversed hash must not become the comparison operand.

This component will not derive expected difficulty from a peer's claim or from the header being checked. In a future node, that context must come from authenticated preceding history and the active rules. In a standalone diagnostic it is an explicit fixture policy, not authenticated history. No production difficulty adjustment, timestamp policy, parent upgrade activation, work accumulation or fork choice is selected.

The remaining nominal assembly must choose exact dependency artifacts and features before compilation. The source candidate excludes solver and C++ compilation, arbitrary parameter profiles and unrelated node dependencies. It must retain actual cryptographic checks and error causes, rather than replacing them with a callback or cached Boolean.

## Contents and construction costs

The fixed solution encodes 512 indices of 21 bits each. The retained decoder creates a 2048 byte expanded cursor buffer and returns 512 logical `u32` indices. Its current reservation expression requests capacity for **2048 `u32` elements**, or 8192 bytes. Logical contents and requested capacity therefore differ. This is source arithmetic, not observed allocation or a measured process peak.

A complete recursive tree has 512 leaves and 511 joins. Each leaf selects 25 bytes from a 50 byte personalized BLAKE2b digest and expands collision chunks for the retained comparison. Parent construction owns hash and index vectors and can grow a moved index allocation. Recursion, simultaneous child ownership, allocator transients, hash state, library/runtime costs and the input buffer require separate accounting before native selection. No solver workspace or full node is needed to verify a saved solution.

The saved independent block text contains 1692 decoded bytes. Its first 1487 bytes are the prospective header fixture. Its version, `nBits` and length-prefix literals are `04000000`, `ffff071f` and `fd4005`. Inspecting those literals is not solution validation or a difficulty check. An independently anchored expected header hash remains required before a test may claim matching known block identity. The candidate must not generate its own expected result and call that an independent vector.

## Remaining finite validation selection

No formatter, compiler, model, reference evaluator or native verifier has run for this component. No test or runtime admission follows from this source review. Required controls include exact valid header work, truncated and trailing bytes, nonminimal or wrong length framing, signed version boundaries, unexpected target policy, target sign/zero/overflow and endian boundaries, changed nonce or other hashed fields, altered solution bits, duplicate indices and incorrect subtree ordering. Controls must identify the actual rejection layer. The smaller upstream `(96,5)` negative vectors are not evidence that the fixed `(200,9)` wrapper rejects every corresponding mutation.

The complete dependency, license, feature, source, fixture and executable closure must be frozen before a fresh finite native request. Existing process and aggregate job limits remain unchanged. This work does not reopen earlier proof, model or journal tests.

## Auxiliary work and bootstrap boundary

A valid header work predicate does not authenticate a child commitment. Full auxiliary work must bind the intended child and network through the applicable parent transaction and authentication commitments. [ZIP 244](https://zips.z.cash/zip-0244) distinguishes transaction identity from authentication data. Its complete applicable commitment construction remains outside this selected component. [ZIP 301](https://zips.z.cash/zip-0301) specifies miner/pool transport rather than consensus proof validity.

Header work also does not prove valid child private state, canonical parent history, external broadcast, external winning receipts or stake eligibility. A genesis fixture is not a Kova genesis configuration. No standalone result may be accepted as an activation certificate.

The [confidential stake bootstrap dependency](../../docs/confidential-stake.md#first-activation-and-the-bootstrap-dependency) remains blocked pending complete work evidence, private eligible principal and an explicit activation construction. Payments remain private by default, with the same hidden owner, input, authorization, stable nullifier, conservation, encrypted delivery and atomic ledger requirements. The [full proof feasibility boundary](../overlay-composition/transport-feasibility.md), consensus and recovery gates are unchanged.
