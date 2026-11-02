# Encoded oracle and query correspondence

## Implementation status

This is a source review and conditional mathematical construction. It follows the actual encoded message, mask, original commitment, first fold, later folds, queried cosets and terminal consumer in one prospective word proof backend. Kova has no selected complete private cash program, backend, proving profile, execution class or practical recipient policy from this review.

The [masked oracle opening](masked-oracle-opening.md) fixes the preceding relation batching, mask interpolation and combined polynomial. The [private trace relation](private-trace-oracles.md) fixes the original word packing. The [integer word correspondence](integer-word-correspondence.md) retains the actual operation predicates. Their assumptions remain necessary. This review identifies the additional encoding and authenticated query correspondence required to connect them.

## Primary source and coverage

The source is the historical revision `6e75a2d1d2e716578ae3ccb62806413fb1615176` of [binius-zk/binius64](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). Current upstream HEAD was not verified. Three directory metadata reads resolved nine complete bodies before acquisition. All twelve requests completed once. Their selection is closed.

| Actual body | RAW bytes | Inspected role |
|---|---:|---|
| `crates/iop/src/fri/batch.rs` | 12,699 | Original oracle openings, batch contraction and queried coset checks |
| `crates/iop/src/fri/common.rs` | 41,622 | Dimensions, early and later batches, lifting and parameter selection |
| `crates/iop/src/fri/fold.rs` | 8,617 | Additive butterfly and verifier commitment schedule |
| `crates/iop/src/fri/mod.rs` | 1,867 | Actual module declarations and exports |
| `crates/iop/src/fri/verify.rs` | 10,302 | Query sampling, fold checks and terminal consumer |
| `crates/iop-prover/src/fri/encode.rs` | 8,382 | Original message and mask assembly and encoder call |
| `crates/iop-prover/src/fri/fold.rs` | 24,115 | Matched first fold, later folds and retained commitment data |
| `crates/iop-prover/src/fri/mod.rs` | 193 | Actual producer module declarations |
| `crates/iop-prover/src/fri/query.rs` | 7,878 | Matched original and later query openings |

All nine whole bodies and their embedded tests were read as data. No test or example was executed. The separate producer `tests.rs`, verifier `error.rs` and `size_estimation.rs` were not selected. The selected bodies total 115,675 RAW bytes. Their computed Git blobs match both returned primary SHAs and separately resolved directory metadata. The [source record](encoded-oracle-sources.json) preserves exact identities and prior context pins.

Original MIT and Apache notices remain unchanged. Metadata is connector returned JSON. These comparisons do not establish complete Git tree, installed artifact, target feature, dependency license, field, toolchain or hardware equivalence. No upstream implementation or dependency is imported into Kova.

## Dimensions and actual encoded input

Let the common reduced Reed Solomon dimension be `D`, inverse rate logarithm be `r`, and input oracle `i` have lift `ell_i`, early batch logarithm `e_i` and later batch logarithm `b_i`. The actual code specification uses

```text
own dimension       d_i = D - ell_i
within batch        a_i = e_i + b_i
committed input log d_i + a_i
encoded length      2^(d_i + a_i + r)
first folded length 2^(D + r)
```

The matched producer checks the input codeword count, `ell_i <= D` and each codeword's exact logarithmic length. Its original commitment handle is carried with that codeword into the query producer. These checks are distinct from an authenticated network parser and from verification of an arbitrary peer supplied parameter object.

For a masked original message of length `2^n`, `encode_masked` constructs a field buffer of logarithmic length `n+1`. At this call site its scalar sequence is the complete message followed by the complete mask. When the pair fits inside one packed field, it fills that field from message values followed by mask values. Otherwise it extends a vector with all packed message values and then all packed mask values. The source also asserts the masked batch size is one.

It then calls `encode_interleaved`, which constructs the oracle's own Reed Solomon code from the common basis prefix and invokes `ReedSolomonCode::encode_batch` with the actual NTT. That called implementation is outside this selection. Consequently the precise map from the concatenated input buffer to the interleaved committed leaves remains an explicit source obligation. A comment naming interleaving does not determine the input basis, transpose, normalization or low coordinate convention.

The required encoder equation must be derived from that actual body and its NTT. With an explicitly defined scalar permutation `J` and encoding operator `E`, it must establish the same original values at the same leaves, for example

```text
C_i[2*j]   = E(message_i)[j]
C_i[2*j+1] = E(mask_i)[j]
```

when that is the actual leaf convention. The equation is a required correspondence, not a result established by this review. An alternative actual ordering must be propagated consistently through the first fold, original openings and combined message placement. No encoding mismatch or accepted bad proof is demonstrated here.

The mask comes from the actual parallel random field generator seeded through the producer's RNG path. Packed lane count, low dimension handling, field sampling distribution, independent streams and entropy delivery require their called implementations. An equal mask buffer length alone does not establish uniform independent masks.

## First fold and lift correspondence

Let `u = ceil(log2(number of original oracles))`. The first fold challenge slice is ordered

```text
[ early challenges ++ u outer challenges ++ later challenges ]
```

Both producer and verifier give oracle `i` the suffix of length `e_i` of the early group followed by the suffix of length `b_i` of the later group. Its own fold excludes the outer group. The outer group supplies its equality tensor coefficient `s_i`. Nonexistent oracle indices in the power of two outer tensor contribute no actual oracle.

The parameter selection makes a masked oracle purely early with batch size one. Its early challenge is the shared mask interpolation challenge. An unmasked oracle has a flexible purely later batch. This preserves the preceding protocol order in which mask interpolation precedes outer oracle batching and the later standard variables. The same gamma symbol must not merge unrelated lookup and mask challenges.

For the actual opened leaf chunk, let `q_i` be the equality tensor of that oracle's own challenge slice. The producer computes an inner product per original chunk and places its contiguous lifted copies. Conditional on the actual field buffer and equality tensor order, its combined codeword is exactly

```text
F[j] = sum_i s_i * < C_i.chunk(j >> ell_i), q_i >.
```

The verifier opens the same original commitment at translated index `j >> ell_i`, folds its returned chunk with the same own challenges and combines with the same outer tensor. This gives equality of the two finite computations under the same commitment, leaf shape, scalar order and source identity assumptions.

The producer initializes the combined buffer by writing every slot from the first oracle and then adds the remaining oracle contributions. For an original codeword of the checked length, the source dimensions give

```text
2^(D+r) / 2^ell_i = 2^(d_i+r)
                 = number of original chunks after within batch folding.
```

This establishes the specific equal chunk count used by its spare capacity loop, conditional on the actual chunk API and checked arithmetic. It is not a general audit of unsafe vectors, Rayon, allocation, packed fields or unchecked shifts. Later iterations must satisfy the same full length equation.

The repeated codeword entries correspond to a particular encoded domain lift. Connecting them to the preceding combined message polynomial requires the actual Reed Solomon basis and NTT identity. The Phase A all high coordinate zero padding and Phase B lift only zero padding with repetition remain separate constructions. Repetition of encoded entries does not by itself prove either identity for the original message coordinates.

## Later additive folds

For one actual additive butterfly pair `(a,b)` and its source twiddle `t`, the selected scalar fold computes, in characteristic two,

```text
v = b + a
u = a + t*v
fold_gamma(a,b) = (1-gamma)*u + gamma*v.
```

The pair transform is invertible: `a = u + t*v` and `b = a + v`. Thus it preserves the pair's information before the evaluation step. Evaluation at one sampled gamma is a projection. It is not an invertible recovery of both original values and does not give a deterministic converse from one successful fold check.

The verifier's channel implementation builds twiddles from the actual domain subspace basis and uses `subset_sum` on the chunk index. It expands low offsets and folds successively by the supplied challenges. The scalar producer fold obtains twiddles through its NTT and calls the selected `fold_chunk`. Agreement requires equality of those two domain and twiddle constructions, including neighbor order, layer, shifted chunk index and challenge order. The actual NTT and domain implementation remain outside this selection.

At each scheduled commitment boundary the producer folds the prior codeword, stores that prior codeword with its actual commitment and coset arity, and commits the new folded codeword. The leaf size of each commitment is the next fold's coset size. For the last commitment it is determined by the remaining final challenges. The matched verifier schedules commitment receipt from its own parameters and requires all scheduled rounds to complete.

The producer buffers challenges until a commitment boundary instead of materializing every intermediate fold. Its finalization returns the remaining terminal codeword and clears the buffered final challenges. The verifier applies those final challenges to the received terminal codeword. Source finalization therefore must be read with the terminal check, rather than treated as an unchecked acceptance of a claimed final value.

## Actual query and terminal checks

The matched query paths have the following order.

1. After the fold commitments, both sides sample all `q` word query indices before opening data. The source retains duplicate indices. It does not deduplicate the field values by replacing the query sequence with a set.
2. Original commitments are opened in actual commitment order. A lifted oracle translates each query by right shifting `ell_i`, so distinct common domain queries can also produce the same original leaf index.
3. The verifier computes original chunk folds and their outer weighted sum. The next oracle receives cosets indexed by each query's high bits and checks its low selected entry equals that prior claimed value before folding the coset.
4. Query indices shift by each fold arity. The producer and verifier use the same resulting coset coordinates and the retained commitment for that round.
5. The producer sends the final committed vector in full. The verifier checks every reduced query claim against its actual selected terminal entry.
6. The verifier folds every terminal coset with the remaining challenges and asserts all resulting values equal the first. The returned value is consumed by the preceding BaseFold terminal equality.

This is an actual terminal consumer in the selected source. Complete authentication of those values still requires the actual Merkle channel and tree implementation, including root identity, leaf framing, salt interpretation, canonical field decoding, count bounds, index bounds and complete opening verification. The interface names `recv_openings` and `recv_committed_vector` do not establish those properties or byte EOF.

The actual query verifier calls `sample_bits`, `select` and `subset_sum` on its channel. Earlier word reduction bodies using only field operations do not resolve these calls. The wrapped symbolic channel's dummy `WordZERO` therefore requires a precise publicness and specialization argument for this real path. The argument must identify which word queries and authentication checks are deliberately performed by the actual native verifier, which values enter the symbolic outer equations, and why the fixed compiled shape is unchanged for all genuine public query values. No dummy zero index may stand in for an unchecked peer chosen leaf.

## Both correspondence directions

The forward map starts from the same original hidden word assignment and field packing. It derives the exact message and independent mask, actual encoded codeword, original commitment, own chunk folds, lifted outer sum, scheduled later codewords and matching query data. Under the explicit encoding, field, domain, buffer, channel and transcript assumptions above, the selected local arithmetic computations agree and the complete terminal consumer checks the same value. This conditional map does not establish that every recipient can be encrypted within a feasible complete program.

The converse requires a complete valid opening relation, not one honest producer trace. It must bind every claimed original and folded value to the verifier's actual commitments and fixed program. It must establish the actual code proximity and fold tests under their exact hypotheses, preserve both private lookup openings and original coefficient bitness, consume expected public wiring, verify the outer proof, and run the single combined opening and complete parser. Random batching and fold projections require a soundness argument. None has a deterministic inverse solely from the displayed linear identities.

Even a complete committed coefficient correspondence would still need the same source operation predicates, word compiler, private input authorization, native asset conservation, same opening encrypted delivery and atomic authenticated state. Matching public statements cannot identify independently existential private assignments.

## Joint privacy and simultaneous resources

For fixed query indices and independent fixed challenge values, the source identifies a finite linear map from original message and mask coefficients to opened field values, folded values and mask inner products. The preceding criterion `A*delta in image(B)` can then be applied to a complete map `A*message+B*mask`. This review has not constructed that complete map because the actual encoding, full query channels, joint field representation and all disclosures remain open. Hash commitments and adaptive Fiat Shamir dependencies also lie outside that restricted fixed linear view.

Actual query locations can repeat. Lift translation can add further duplicate leaves. The resource and privacy analysis must retain their multiplicities, per commitment coset lengths, terminal entries, authentication data, masks and shared challenges. Mask size, an invertible butterfly or a source query count supplies no joint hiding or quantum security theorem.

At masked encoding the caller's original message, the newly generated mask, temporary concatenated input and encoded output can overlap. Exact allocation and release depend on the encoder and allocator. In the first fold the original committed codewords and their trees remain retained for later queries while a new `2^(D+r)` scalar buffer is written and committed. Later rounds retain prior codewords and commitments while allocating their successor. Parallel fold scratch and retained buffer pool capacity are additional lifetimes.

These are source ownership obligations, not measured peak memory or proof bytes. The parameter search prices queried cosets, Merkle proof estimates and terminal field contents. Its `min_concave` helper stops after the first strict increase and assumes the objective's stated shape. Neither a strategy name nor upstream tests prove global optimality for every shape, complete parser cost, simultaneous memory, or a Kova security profile.

The query count helper's own documentation limits its intended error calculation to the query phase. Folding, batching, denominators, hash binding, transcript conversion, quantum queries and knowledge require separate actual hypotheses. The source's 96 bit configuration and test tables are not an achieved Kova security level. No test table or benchmark was executed here.

Current raw, owner, stored, kernel, proof transport and aggregate resource limits remain unchanged. No complete feasible private class is admitted. Host packing, buffer reuse and fewer explicit intermediate folds do not remove retained codewords, trees, queries, entropy or full wire contents.

## Minimum missing construction

The next complete source and mathematical construction must establish the original message and mask encoding orientation against actual `ReedSolomonCode::encode_batch`, its NTT, domain basis and field representation. It must connect that exact map to the selected first fold, matched scalar and channel twiddles, lift identity and terminal repetition check. Proper nominal source resolution is required before any further bounded source selection.

It must then resolve the actual Merkle producer and verifier channels, their `Word` query routes, authenticated leaves and terminal vector, full consumption and bounded canonical parser. This is directly necessary for the converse and for the actual joint query exposure map. A new small native evaluator or cipher prefix would not provide this missing construction.

Complete bare lookup, product and batched sumcheck, denominator exceptions, field generator, word lowering, dependency feature and license graph, entropy, hash and transcript obligations remain. The same hidden private payment program and practical recipient completion or refusal policy remain unselected. The [whole encrypted output relation](whole-encryption-completion.md) and [common private witness](private-witness-join.md) continue to define those exact associations.

No new program, compiler, proof, parser, ledger, execution admission, root dependency or proving class is supplied by this review. All original consensus, confidential bootstrap, reward origin maturity, checkpoint finality, consumed bonds, durable signing, recovery and independent network gates remain in the [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md).
