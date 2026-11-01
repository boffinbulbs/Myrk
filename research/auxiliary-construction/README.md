# Restricted auxiliary construction

The construction decision is a transparent coinbase carrier with both transaction and authorization paths into one actual work header. The comparison format is historical NU5. A general shielded transaction decoder is excluded from this candidate. Nonzero shielded counts must refuse before their payloads are decoded. The complete predicate remains unimplemented because authenticated expected context, a complete independent work fixture and the selected nominal dependency closure are missing.

This resolves the decoder direction and the complete binding schedule from the [auxiliary contract](../../docs/auxiliary-work-binding.md). It adds no accepting work, payment, state or network API. The [implemented public job bytes](../preseal-bytes/README.md) remain unverified data. Existing header and proof snapshots are unchanged.

The restriction applies to the public parent coinbase carrier. Child payments retain their private proof requirements. Their input commitments, amounts, creation versions, paths, keys and signature intermediates never enter the carrier.

## Exact comparison profile

1. The parent format is the historical mainnet NU5 comparison interval `1687104 <= h < 2726400`, transaction version five, group `0x26a7270a` and branch `0xc2d6d0b4`. This is not a selected current live parent profile. Parent height, branch and template policy must come from expected context, rather than from the carrier's claims.
2. The restricted transaction has exactly one transparent input with a null prevout. Its sequence is `0xffffffff`. Its lock time is zero and its expiry height equals the expected parent height. These are explicit restrictions of this construction, not a claim that every parent coinbase uses this subset.
3. Its script is exactly the canonical height push followed by `45 || KOVA || 01 || JobID64`. The `45` and `01` are single hexadecimal bytes. There is no alternate push, suffix or second marker. Every height in the comparison interval needs exactly three positive little endian height bytes. Thus the height prefix is `03 || u24le(h)`, the complete script is exactly 74 bytes and its minimal CompactSize length is `4a`. The earlier 76 byte bound covers a broader height range and is conservative for this interval.
4. There are between one and 64 transparent outputs. Each script is at most 4096 bytes. The complete carrier is at most 32768 bytes. Output values must use the original canonical nonnegative monetary range. The retained `TxOut::read` delegates that range to `Zatoshis::from_nonnegative_i64_le_bytes`. Its defining value module still needs exact source and dependency selection before implementation. No guessed range or unchecked cast replaces it.
5. Sapling spend count, Sapling output count and Orchard action count must each be the minimal one byte zero encoding. The parser stops at the first nonzero count. It does not skip a claimed payload to look for a later zero, parse shielded proofs or erase a nonempty bundle. No Sprout field occurs in v5. Complete consumption is mandatory.
6. The four byte discriminator in the proposed auxiliary envelope must resolve through the expected supported descriptor. The job contains the full parent binding descriptor identity. Neither representation authenticates its own registry mapping. No production descriptor encoding or live activation is selected here.

The original [v5 reader and writer](https://github.com/zcash/librustzcash/blob/a551fac8a233f54799ca1920ef78ef098cfda929/zcash_primitives/src/transaction/mod.rs) read the transparent bundle before the Sapling and Orchard bundles. [ZIP 225](https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/zips/zip-0225.rst) fixes their conditional field order. Requiring all three counts to be zero removes every conditional shielded payload from this restricted grammar. It does not establish validity of an arbitrary transaction accepted by the general decoder.

The [transparent input and output source](https://github.com/zcash/librustzcash/blob/a551fac8a233f54799ca1920ef78ef098cfda929/zcash_transparent/src/bundle.rs) defines coinbase form as one null-prevout input. Its coinbase builder uses the maximum sequence value. [Zebra's height parser](https://github.com/ZcashFoundation/zebra/blob/f72dc18766be63574f17510ee35e61ff2abfe2ae/zebra-chain/src/transparent/serialize.rs) checks canonical height encoding by re-encoding the candidate. These are original source rules and explicit restrictions. No parser or fixture has executed for this decision.

## Admission and lifetime

The future predicate must consume two immutable byte sources: the actual complete public child job `J` and the actual auxiliary witness `W`. It also requires verifier-owned expected context. The current byte component cannot supply that authority.

| Expected value | Required origin | Current boundary |
|---|---|---|
| Child network, predecessor, rules, class and resource descriptors | Current authenticated child snapshot and supported registry | Unimplemented |
| Child threshold and timestamp policy | Actual preceding child work state under a selected rule | No child difficulty rule is selected |
| Parent profile, height, raw template bits and applicable header policy | A selected expected parent policy with an explicit history evidence contract | Unimplemented |
| Treasury policy and recovery obligations | Authenticated child state and actual class encoders | Unimplemented |
| Expected job commitment | Recomputed from the actual matched complete job bytes | Byte hashing exists for public synthetic jobs only |

An opened history component is not a replacement for either chain's authenticated expected context. Requiring every ordinary validator to run a parent full node would change the [operator contract](../../docs/mining.md). No such requirement is introduced. A compact history or external policy evidence path would need its own actual verification and trust analysis.

The complete selected schedule is:

1. Admit envelope size, expected descriptor, exact 1487 byte header, carrier length and common branch depth before payload ownership or expensive work. Bounds on a borrowed slice do not bound upstream allocation, blocking reads or network admission.
2. Parse and canonically compare the actual job. Match every expected context field, target and actual treasury policy. Resolve supported inner classes. Missing authentication or unsupported classes refuse. A caller's matching label cannot satisfy this step.
3. Validate the restricted carrier in one bounded scan. Check canonical CompactSize values, exact input and script, output limits, all three zero counts and complete consumption. Keep borrowed ranges for the header, prevout, sequence, complete script and contiguous serialized output body. No vector of outputs is required by the proposed algorithm.
4. Recompute `JobID` from actual immutable `J`, using the specified SHA3-512 framing. Compare it with the exact 64 bytes in the admitted script. Never accept the script value as the expected job. Local publication generation and the work seal stay outside `J`.
5. Recompute both carrier digests using the exact schedule below. Both consume ranges admitted from the same carrier. A named serialized wrapper, cached digest or successful parse cannot replace this calculation.
6. Fold both paths at fixed index zero, consuming all siblings from the leaf toward the root. Match the transaction root and the derived outer authorization commitment against the same header. Do not compare roots from one object with work from another.
7. Match the expected raw parent template bits. Perform actual fixed `(200,9)` Equihash validation and actual whole-header SHA256d. Apply the child threshold and classify a separate parent-target comparison if that result is requested.
8. Return only the scope actually checked. Work binding supplies no child proof validity, current spending permission, authenticated history, finality, stake eligibility or parent settlement. A later accepting kernel must perform all real private and state checks and atomically recheck current generation and lineage.

This is a source construction plan, not an executed call graph. A successor must forward actual hash and Equihash operations through one cohesive assembly. Calling the old parent-target predicate and then checking a child threshold would reject valid child-only shares. Replacing its expected bits with child bits or peer header bits would discard its policy boundary. The old [header source](../header-work/src/header.rs) remains frozen.

## Carrier digest correspondence

Let `B_P(x)` mean BLAKE2b with **32 byte output** and exact 16 byte personalization `P`. This differs from truncating a BLAKE2b-512 digest. Let `c` be the four raw little endian branch bytes, `O` the admitted serialized outputs concatenated without their count, and `S` the complete admitted script.

The exact effect schedule for this restricted carrier is:

```text
Hh = B_ZTxIdHeadersHash(actual first 20 carrier bytes)
Hp = B_ZTxIdPrevoutHash(actual 36-byte null prevout)
Hs = B_ZTxIdSequencHash(actual 4-byte sequence)
Ho = B_ZTxIdOutputsHash(actual O)
Ht = B_ZTxIdTranspaHash(Hp || Hs || Ho)
Hz = B_ZTxIdSaplingHash(empty)
Hr = B_ZTxIdOrchardHash(empty)
TxId = B_(ASCII ZcashTxHash_ || c)(Hh || Ht || Hz || Hr)
```

The exact authorization schedule is:

```text
At = B_ZTxAuthTransHash(CompactSize(len(S)) || actual S)
Az = B_ZTxAuthSapliHash(empty)
Ar = B_ZTxAuthOrchaHash(empty)
AuthDigest = B_(ASCII ZTxAuthHash_ || c)(At || Az || Ar)
```

These are eight and four BLAKE2b-256 invocations respectively. Counts are source schedule incidence, not measured hash calls or an execution admission. The [original digest implementation](https://github.com/zcash/librustzcash/blob/a551fac8a233f54799ca1920ef78ef098cfda929/zcash_primitives/src/transaction/txid.rs) and [ZIP 244](https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/zips/zip-0244.rst) give the exact personalizations, branch order and empty-bundle rules. The absence of a bundle does not mean replacing its digest with 32 zero bytes.

Input count, output count and script bytes are not added to the TxId input list above. Script bytes and their CompactSize framing enter the authorization digest. Counts and framing are still checked by parsing. They cannot be ignored merely because their roles differ in the two digest trees.

For index zero, every branch step places the running value on the left:

```text
T_0 = TxId
A_0 = AuthDigest
T_(i+1) = SHA256d(T_i || actual tx_sibling_i)
A_(i+1) = B_ZcashAuthDatHash(A_i || actual auth_sibling_i)
Outer = B_ZcashBlockCommit(actual history_component || A_d || zero32)
```

Require `T_d` to equal raw header bytes `36..68` and `Outer` to equal raw header bytes `68..100`. Wire order is used throughout. RPC display reversal is not an input transformation. The whole work header includes both fields.

The [original transaction tree](https://github.com/ZcashFoundation/zebra/blob/f72dc18766be63574f17510ee35e61ff2abfe2ae/zebra-chain/src/block/merkle.rs) duplicates odd transaction nodes. Its authorization tree pads the leaves with zero hashes. A path is not a declaration of padding: every supplied sibling is consumed. The two branches authenticate inclusion at the selected position under hash assumptions. They do not authenticate global transaction count, duplicate exclusion or validity of the rest of a parent block. The [outer constructor](https://github.com/ZcashFoundation/zebra/blob/f72dc18766be63574f17510ee35e61ff2abfe2ae/zebra-chain/src/block/commitment.rs) includes all 96 bytes, including the terminator.

## Separate thresholds and errors

Expected raw parent bits, expanded parent target and child target have separate roles. The parent bits must match the selected expected policy. The child target must match both authenticated child state and `J`. Neither is derived from an untrusted field merely because it is present.

After actual solution validation, let `w` be the unsigned little endian whole-header SHA256d value. Child work requires `w <= T_child`, including equality. A requested numeric parent classification is `w <= T_parent`. No ordering between the two thresholds is assumed by these comparisons. A numeric parent classification still proves no external broadcast, acceptance, canonical history or receipt.

Typed refusal stages must distinguish context and profile, bounded framing, canonical carrier, unsupported shielded counts, job mismatch, transaction path, authorization path, raw template policy, original Equihash error and insufficient child work. A first actual cause must survive any real enclosing owner cleanup. No failure is manufactured from a later panic, and no incomplete check is labelled a complete binding verdict. The borrowed calculation itself introduces no file lease or proving attempt. Existing private prover ownership and opening flags are unaffected.

The current general `Transaction::read` derives v5 branch identity from wire bytes. That parser is not the expected parent branch policy. Likewise, a serialized transaction wrapper is not sufficient resource or consensus authority. These observations specify the required caller boundary. They are not claims of an upstream vulnerability or an executed attack.

## Resource ledger

For output script lengths `k_i`, let `cs(k_i)` be their minimal CompactSize prefix length. The selected output count is at most 64, so its own count prefix is one byte. In the historical interval the restricted carrier size is exactly

```text
20 header + 1 input count + 36 prevout + 1 script length
+ 74 script + 4 sequence + 1 output count + 3 zero counts
+ sum(8 + cs(k_i) + k_i)
= 140 + sum(8 + cs(k_i) + k_i).
```

The 32768 total bound applies in addition to the count and per-script limits. Allowing 64 output descriptors does not admit 64 maximum scripts simultaneously. Output monetary range checks, checked accumulated lengths and complete consumption remain separate.

| Contents or operations | Source limit or schedule | Status |
|---|---:|---|
| Complete auxiliary witness | `1528 + carrier_bytes + 64d <= 35576` bytes | Proposed grammar |
| Both sibling arrays combined | `64d <= 1280` bytes | Included in auxiliary contents |
| Actual public synthetic job | At most 51130 bytes | Separate tested byte class |
| Joint job and auxiliary contents | At most 86706 bytes under those two laboratory limits | Sum of contents, not peak memory |
| Output descriptors | Two scans and borrowed ranges can avoid an owned output vector | Unimplemented algorithm |
| BLAKE2b-256 outside Equihash | `13+d <= 33` invocations | Includes carrier, auth branch and outer hash |
| SHA-256 outside Equihash | `2(d+1) <= 42` invocations | Both calls per SHA256d counted |
| Job SHA3-512 | One invocation for the actual complete job | Record IDs need not be recomputed for this binding |
| Equihash | One actual fixed-parameter invocation | Internal BLAKE2b-50 and recursive vectors remain separate |

Caller-owned vectors, digest states, recursive Equihash vectors, script copies, source descriptors, canonical comparison, allocator transients and upstream transport must be accounted independently before execution. No byte sum establishes simultaneous process memory or serialized private proof size. A borrowed two-scan design does not remove the owner's job or witness bytes. No new Cargo root, dependency graph, compiler or runtime class is selected by this ledger.

## Evidence and architectural refusal

There is no complete independent tuple containing actual child job bytes, the matching carrier record, both paths, history component and the same solved header. The saved public digest vectors contain synthetic shielded proof bytes. The historical block is not demonstrated to contain the selected Kova record. The healthy genesis work result belongs to a different format and cannot fill this gap. Changing a mined script changes the authorization root and work header even when its v5 TxId stays unchanged.

Execution of the complete binding candidate is therefore refused until all of the following are concrete:

1. A verifier-owned expected context, including a derived child threshold and a parent template policy compatible with ordinary validator roles. A peer-provided expected bits value is not that construction.
2. Exact supported descriptor and inner public effect, proof and recovery encoders for a real child candidate. The synthetic byte component does not activate them. The full private proof resource refusal remains unchanged.
3. A complete independent tuple with valid work under the exact selected profile. No solver, edited mined header or join of unrelated component successes is selected to manufacture one.
4. A cohesive nominal source assembly with actual bounded parsing, monetary range semantics, all hash dependencies, features, licenses, original work calls and truthful errors. Full original shielded decoder imports are excluded from the restricted design. Its unused conditional import closure is not claimed compiled or audited.
5. A finite fresh resource and adversarial plan covering the whole candidate, followed by actual source, artifact, runtime, executable and fixture identity freezes. Source counts and old successful diagnostics grant no execution permission.

Required future controls include every nonminimal CompactSize form, wrong version/group/branch/height, second input, nonnull prevout, suffix or marker alternative, each nonzero shielded count before payload decoding, output and total bounds, monetary range edges, association substitution, same TxId with changed script authorization, branch order and depth, reversed display bytes, missing outer terminator, child-only versus parent-winning thresholds and actual original solution errors. These are requirements, not executed tests.

The next independent launch requirement is the missing derivation of the child threshold and timestamp policy from actual preceding work state. That decision must retain separate monetary timing profiles, authenticated lineage and explicit genesis and bootstrap boundaries. It cannot supply missing private authorization, confidentiality, consensus, signer recovery or network activation. Private payments remain the default throughout the full roadmap and agreed later deferrals.

The [source record](source-record.json) pins the retained source and exact scope. This increment executes no compiler, parser, protocol digest calculator, model, solver, prover, verifier, signer or network service. Only source identity, document target and whitespace checks are performed.
