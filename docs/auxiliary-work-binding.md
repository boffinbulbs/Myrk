# Auxiliary work and child candidate binding

This specification connects the [fixed header work component](../research/header-work/README.md) to the transaction and authorization commitments required by [mining](mining.md). It implements no auxiliary verifier, child block encoder, mining service or activation rule. The construction decision below selects a carrier location and a bounded witness proposal. The [preseal job specification](preseal-job.md) now fixes its outer framing and commitment candidate. Execution remains blocked by the missing actual class encodings and supported resource profile, independent complete binding fixture and remaining decoder source closure.

## Versioned parent comparison

The source comparison uses Zcash mainnet's historical NU5 interval, heights `1687104 <= h < 2726400`, branch ID `0xc2d6d0b4`, transaction version five and version group ID `0x26a7270a`. This is an explicit historical compatibility profile, not a selected current production parent profile. Its source and digest fixtures are pinned in the [source record](../research/auxiliary-binding/source-record.json).

The retained sources also include later v6 and Ironwood paths. The existence of a supported v5 encoding does not authorize treating every subsequent network upgrade as NU5. A future active profile must derive network, height, branch and commitment rules from its own authenticated context. A peer's height or transaction branch field cannot select that context. Unsupported parent profiles refuse rather than falling back to genesis or a reserved header field.

The header byte layout remains the fixed 1487 byte format. Its transaction root is at bytes `36..68`, its block commitment at `68..100`, and its compact difficulty field at `104..108`. All root bytes below use serialized internal order. Display reversal is not part of tree hashing.

## One carrier and two commitments

The selected carrier location is the miner data in the **single null-prevout input of a v5 coinbase transaction**. Its canonical height prefix must match the expected parent height and the applicable coinbase expiry rule. The proposed restricted script is exactly:

```text
canonical_height_push || 0x45 || "KOVA" || 0x01 || job_commitment[64]
```

The marker, version and commitment occupy 69 payload bytes. `0x45` is their direct push length. With a height prefix of at most six bytes, this script occupies at most 76 bytes, within the original 2 through 100 byte coinbase script bound. These are byte counts, not an executed parser result. This restricted candidate includes no additional miner suffix or alternate placement. A later pool integration needing other data must select a new unambiguous carrier grammar. Raw substring search, a second marker, a different push form or an ignored suffix is insufficient.

This location deliberately requires the authorization commitment. In the actual [v5 digest source](https://github.com/zcash/librustzcash/blob/a551fac8a233f54799ca1920ef78ef098cfda929/zcash_primitives/src/transaction/txid.rs), the transparent transaction effect digest covers prevouts, sequences and outputs. It excludes `scriptSig`. The transparent authorization digest covers every complete serialized input script, including its CompactSize framing. A change to the proposed miner record can therefore preserve the transaction ID while changing the authorization digest. Checking only transaction inclusion would leave the selected carrier unbound.

For the same canonical raw carrier bytes `C`, the eventual verifier must recompute both

$$T=\operatorname{TxId}_{v5}(C),\qquad A=\operatorname{AuthDigest}_{v5}(C).$$

It must not accept either digest from a caller or combine the effect digest of one parsed object with the authorization digest of another. Counts, conditional fields, scripts, amounts and every included shielded effect and authorization field must follow the exact selected format. A structurally decoded parent transaction is not thereby cryptographically valid. Parent signatures, shielded proofs, subsidy and funding rules remain distinct from this commitment calculation.

The [ZIP 244 source](https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/zips/zip-0244.rst) defines ordered transaction and authorization trees. They share transaction position but use different hashes and padding. The actual [Zebra construction](https://github.com/ZcashFoundation/zebra/blob/f72dc18766be63574f17510ee35e61ff2abfe2ae/zebra-chain/src/block/merkle.rs) duplicates the last odd transaction node, while the authorization tree pads its leaf level to a power of two with zero leaves. Authorization internal nodes use personalized BLAKE2b-256 with `ZcashAuthDatHash`. Transaction internal nodes use SHA256d.

The candidate fixes the carrier position to zero. Both branches must have the same admitted depth and use that position. There is no caller-controlled index. Every sibling is consumed in bottom-to-top order. Branch lengths, trailing siblings, root substitution and display-order confusion must reject. A branch cannot establish the complete transaction count, global duplicate absence or validity of other transactions. In particular, the transaction tree has known duplicate-list ambiguity. These missing properties must not become inferred bootstrap or parent-history rights.

Let the independently recomputed roots be `R_tx` and `R_auth`. Require `R_tx` to equal the transaction root of the very same header whose work is checked. For the NU5 commitment structure, also recompute

$$B=\operatorname{BLAKE2b256}_{\texttt{ZcashBlockCommit}}
  (M_{\rm previous}\parallel R_{\rm auth}\parallel 0^{32})$$

and compare `B` with that header's block commitment. The [actual constructor](https://github.com/ZcashFoundation/zebra/blob/f72dc18766be63574f17510ee35e61ff2abfe2ae/zebra-chain/src/block/commitment.rs) hashes all 96 input bytes. Omitting the terminator or substituting another active structure is a different predicate.

`M_previous` can be an opened component of the header commitment without being trusted as valid history. Recomputing the outer hash authenticates its inclusion as a value, not the correctness of its MMR contents. Any claim about parent history or expected parent difficulty needs the separate actual history verification or verifier-owned authenticated state. The [ZIP 221 source](https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/zips/zip-0221.rst) does not supply a generally established security theorem for this project's parent-history use. No FlyClient theorem or confirmation depth is selected here.

## Child effect, authorization and work lifetime

The existing `PaymentStatement` encoder binds a payment's public effect and encrypted delivery bytes. Its authorization mapping produces 196 bytes for that relation. It is not a child block encoder. A caller-supplied payment digest, state root or collection of component results cannot substitute for one canonical block job.

The required job construction has this acyclic order:

1. Derive the exact child effects and expected private proof statements from the current authenticated Kova context.
2. Construct and verify the actual bounded authorization data. Its statements bind effects and prior context, without referring to the bytes of their own proofs or the eventual work seal.
3. Freeze one canonical preseal job containing the child network, active rules and resource identity, predecessor and ordering context, expected child target, effect binding, actual public authorization binding, recovery data binding and treasury policy binding.
4. Compute the 64 byte job commitment from those actual canonical bytes under the [specified outer framing and domain](preseal-job.md), then place it in the parent carrier. The inner class encodings and supported actual proof mapping remain required. No shorter replacement authorization primitive is introduced.
5. Construct the parent transaction and both header roots, then perform work over that actual header. The auxiliary witness and its work hash are excluded from the preseal job so the construction does not hash itself.
6. A receiving validator recomputes the job commitment from its actual child data, checks the complete auxiliary binding and separately verifies every child proof, state, policy, availability and consensus condition. It never adopts a job commitment supplied by the auxiliary witness as the expected value.

A different public proof for the same child effect changes the preseal authorization binding and requires matching work. It does not rename a consumed note. Commit-time state checks still prevent double consumption and duplicate issuance. The [atomic state contract](private-transition-state.md) applies after cryptographic and work validation, with snapshot recheck and a coherent branch transition. No work receipt overrides those checks.

The miner record exposes only the proposed job commitment. It must not carry private input commitments, paths, amounts, creation versions, keys or signature intermediates. The child statement and its authorized viewing controls retain their separate visibility requirements. Commitment hiding, binding, repeated observation and hash security still need composition review.

## Separate work targets

Let `T_child` be derived from authenticated Kova predecessor state. A child share requires an actual valid fixed-parameter solution and `SHA256d(header) <= T_child`. Whether that same share wins the parent network is a distinct comparison with its authenticated expected `T_parent`, together with the parent's other validity rules.

The existing [header diagnostic](../research/header-work/src/header.rs) matches one expected raw parent `nBits` and uses its expanded value as the comparison target. That interface intentionally couples two facts for its saved fixture. It cannot be relabeled as a general auxiliary-share predicate: using the parent's harder target can exclude legitimate child-only shares, while using the child target as the expected raw parent field changes the parent template requirement. Reading an untrusted header's bits back into `ExpectedWork` would evade its policy boundary.

A future cohesive successor must keep expected raw parent header policy, the child threshold and any parent-win assertion distinct. No such successor is implemented by this document, and the existing fixture verifier remains unchanged. Removing the expected-bits check, resetting a profile or supplying a host verdict is not an integration fix. Ordinary Kova validators are not silently required to run a parent full node. A claimed external canonical history or winning receipt needs its own evidence path.

## Proposed bounded witness contents

The following is a diagnostic grammar proposal, not an implemented or activated wire format. Its profile ID must equal an expected supported context before allocation or hashing. The 32 KiB carrier and depth 20 caps admit no private proving class.

| Field | Contents |
|---|---:|
| Expected historical binding profile identifier | 4 bytes |
| Exact parent header | 1487 bytes |
| Carrier length, unsigned big endian | 4 bytes |
| Exact canonical v5 coinbase carrier | At most 32768 bytes |
| Common branch depth `d` | 1 byte, `0 <= d <= 20` |
| Transaction siblings at fixed index zero | `32d` bytes |
| Authorization siblings at fixed index zero | `32d` bytes |
| Previous-history component opened in the outer commitment | 32 bytes |

The maximum payload contents are `4 + 1487 + 4 + 32768 + 1 + 64*20 + 32 = 35576` bytes. An upstream frame, request accounting and deadline policy are additional. This count is not serialized transport implemented by the existing proof reader, a measured allocation, a simultaneous peak or a new runtime admission.

Carrier admission must bound counts and all conditional byte ranges before owning decoded vectors. It needs exact minimal CompactSize encodings, checked arithmetic, complete-consumption and canonical roundtrip checks against the actual parent serializer. A 32 KiB slice alone does not bound every temporary allocation of an arbitrary decoder. Borrowed raw bytes, owned parsed objects, script copies, digest states, branch buffers, source descriptors and caller-owned child data need separate accounting. The required complete child proof remains subject to its existing feasibility refusal, irrespective of this smaller auxiliary envelope.

## Independent evidence and decision

The retained [primary digest vectors](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/test-vectors/json/zip_0244.json) contain ten raw v5 transactions with independently saved transaction and authorization digests. The generator uses NU5 branch `0xc2d6d0b4`. Its shielded proof bytes are synthetic, so these are digest references, not ten valid mined transactions or complete parent witnesses. The generator was inspected, not imported or executed.

The separately captured [mainnet block 1687106](https://github.com/ZcashFoundation/zebra/blob/f72dc18766be63574f17510ee35e61ff2abfe2ae/zebra-test/src/vectors/block-main-1-687-106.txt) contains 9117 decoded bytes. It supplies actual historical parent-format data. Only byte framing has been inspected in this increment. No header work, tree, digest, proof or history check has run on it. It contains no demonstrated Kova job record. The earlier genesis positive is not evidence for a v5 authorization tree.

The architectural decision is to retain the coinbase-script carrier and same-position dual-root construction as the candidate, and **refuse execution or activation until its remaining inputs are concrete**:

1. The outer canonical child preseal framing, public authorization binding and domain are now specified. Actual supported effect, proof and recovery encoders and an authenticated context must still exist before deriving the expected 64 byte record from a real child candidate.
2. The selected v5 carrier decoder, complete shielded conditional serialization paths, constants, dependencies and licenses require full nominal assembly review. Captured source does not itself admit a build.
3. An independent full tuple of carrier bytes, both branches, history component, header and expected job statement is required. Digest vectors and unrelated header success cannot be joined into a fabricated positive. A newly mined tuple cannot be obtained by editing a saved header's transaction data without changing its work input.
4. The two-target successor and the exact parent-template policy must be selected before an auxiliary-share implementation can forward actual work checks.
5. Complete private authorization, confidential eligible stake, bootstrap trust, denominator and certificate construction, durable signer state, atomic ledger and network gates remain unresolved. This binding proposal cannot activate them.

These are specific missing constructions, not proof that the parent format is incompatible. No solver, live parent RPC, external submission, source generator or old native test is run to manufacture the missing tuple.

## Required future controls

These scenarios are specifications, not executed tests of a new verifier.

| Mutation or condition | Required boundary |
|---|---|
| Different child network, predecessor, rules, target, effect, proof or delivery | Recomputed expected job differs |
| Correct work with another carrier or copied record | Actual effect and authorization leaves must both bind |
| Change only coinbase miner script while preserving its effect digest | Authorization path must reject |
| Pair effect and authorization digests from different raw objects | Refuse the mixed carrier |
| Nonminimal height or record push, duplicate marker or trailing script data | Refuse carrier grammar |
| Wrong transaction version, group, branch or claimed parent height | Refuse selected profile |
| Nonminimal length, excessive count, truncated conditional field or trailing carrier data | Refuse before unbounded decoding |
| Reverse sibling bytes, levels or positions, omit a sibling or extend one branch | Refuse exact tree binding |
| Replace null authorization padding with transaction-style duplication | Refuse actual authorization root |
| Use roots, history component or terminator from another header or epoch | Refuse exact commitment composition |
| Assert transaction count, duplicate absence or canonical history from one inclusion branch | Grant no such authority |
| Valid child-only share whose hash exceeds `T_parent` | Keep child and parent outcomes distinct |
| Supply header-selected expected bits or replay a success token | Refuse policy substitution |
| Mutate fixed-parameter solution or header after binding | Run actual work verification against the changed exact bytes |
| Replay a valid witness against stale child state or consumed reward rights | Atomic current-state recheck prevents a second effect |
| Invalid child private proof, missing payload or unsupported bootstrap certificate | Remain unaccepted despite valid parent binding |

The source identities and limits document source inspection only. No compiler, model, native witness, crypto verifier, proof producer or network service executes for this increment. Payments remain private by default and the complete launch gates and later roadmap deferrals remain unchanged.
