# Proof entropy source and complete view certificates

## Construction status

This source and conditional mathematical review traces the retained wrapped proof entry's randomness ownership and defines a complete source criterion for its visible view. It extends the [visible history criterion](visible-history-source-privacy.md), [outer witness padding](outer-witness-padding.md) and [shared word source map](shared-word-source-map.md) reviews.

No complete private cash program, entropy model, simulator, backend, parser, profile or execution class is adopted. No random generator, helper, model, witness, proof or upstream program was executed. The result identifies actual source boundaries and the minimum construction still missing.

## Retained source

The source remains [binius-zk/binius64 at `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). The [source record](proof-entropy-source-sources.json) identifies the retained entry, wrapper, outer packer, BaseFold and encoder bodies. Existing whole body reviews and selected actual contexts are reused. No new acquisition or failed request retry was performed.

The actual external generator implementation, seed source, field samplers, packed samplers, parallel random helper and dependency feature closure remain outside this inspected boundary. A generic randomness trait is not evidence for their distribution, seed length, independence or freshness.

## Actual wrapped entry lineage

The inspected `ZKProver::prove` borrows its input witness and receives a caller supplied `CryptoRng` argument as mutable state. That argument may itself borrow an underlying generator. Its order is significant:

1. It creates one BaseFold channel using a mutable borrow of that caller generator. The channel stores its own `StdRng::from_rng` result.
2. It passes the same caller generator to wrapper construction for transcript keys and precommit blinding.
3. It runs the inner proof through the wrapped channel. This call does not receive the caller generator as a separate argument.
4. It moves the remaining caller generator into wrapper completion, which invokes the outer `IOPProver::prove` on the existing BaseFold channel.

The last step does not call the outer standalone prover entry or seed a second BaseFold channel on this wrapped path. The inspected replay channel reads the same stored keys and events. Those recorded values are not fresh entropy. Complete witness generator and hint effects remain outside this local statement.

The input witness's own generation source is not supplied by this entry. Random note fields, sender secrets or prospective word shares inside that witness need their actual independent source and semantic representation proof. The proof entry's caller generator does not randomize the already supplied original inner trace merely by existing elsewhere in the call graph.

## Parent stream calls and stored masks

Wrapper construction draws `n_precommit` field keys from the caller generator. It then packs and blinds the precommit segment using that same generator. The precommit oracle is sent through the existing BaseFold channel, whose encoder mask comes from the channel's internal generator.

For a segment, the packer copies its original scalar prefix, honestly fills unused tail capacity with zero, draws each free dummy scalar, then draws two scalars `A,B` per dummy multiplication constraint and writes `C=A*B`. The third product coordinate is derived. Copies of keys into packed buffers or the replay witness are the same random values, not additional random coordinates.

After inner verification replay, the outer `IOPProver::prove` checks witness segment lengths. It then samples the entire packed mask polynomial buffer through `P::random` on the caller generator. Only afterward does it pack and blind the private segment through that same generator. It sends the private oracle followed by the mask oracle through the existing BaseFold channel.

The whole mask buffer is sampled. The active mask polynomial's restricted coefficient use does not imply that other sampled buffer cells are zero.

These are logical sampler calls. They do not establish primitive random byte counts or independent uniform field samples. The parent generator and its seeded child have a common lineage. Distinct objects and API names do not prove statistically independent streams.

The inspected BaseFold channel retains each original oracle's mask and codeword for its queued relations. Completion destructures its generator away and passes the existing masks and committed data to the combined opening routine. It does not accept a fresh RNG argument. Multiple relations, inner products, folds and terminal values must therefore be analyzed against their actual reused source values. Other effects in called tree, hash or transcript dependencies still require source closure.

## Parallel mask generation boundary

The actual masked encoder invokes

```text
par_rand::<StdRng, _, _>(packed_len, &mut rng, P::random)
```

It then forms the same message and mask concatenation used by the interleaved encoder. This is not an inspected simple loop of independent scalar draws. The `par_rand`, `StdRng`, seeding, field, packed lane and parallel child schedule implementations remain unreviewed here.

Consequently no exact seed byte count, primitive entropy count, independent child stream theorem or complete deterministic seed to proof function is established. Repeated and concurrent proofs also need the actual parent ownership, child derivation, draw positions, lifecycle and refusal record. No repeated generator state, mask reuse across proofs or actual random generator failure was demonstrated.

A finite seeded generator's many outputs do not automatically become mutually independent ideal field primitives. An ideal randomness model needs its explicit hypotheses and the applicable connection to the actual generator.

Transcript challenges follow the actual challenger and field decoding route. They are not automatically fresh independent private mask entropy. The original witness and lookup source, all commitments, claims, masks, rounds and openings still need one joint source model.

## Conditional finite uniform source theorem

Suppose a proposed complete construction supplies actual total deterministic source maps

```text
Phi_i : Omega -> complete permitted visible record and terminal status,
```

for an explicitly justified comparison of executions. Assume `Omega` is the same actual nonempty finite primitive source for both executions and is uniform, with `M=|Omega|`.

These are extra hypotheses. The inspected caller and sampler traits do not establish them. Actual termination, bounded effects and observed errors must be proved or supplied by a real admitted mechanism. An unknown computation cannot be totalized by inventing a successful or refusing implementation.

Let `n_i(v)` count the source points producing visible record `v`. Then the output probability is `n_i(v)/M`, and

```text
TV(Phi_0(Omega),Phi_1(Omega))
  = (1/(2*M))*sum_v |n_0(v)-n_1(v)|
  = 1-(1/M)*sum_v min(n_0(v),n_1(v)).
```

Perfect equality of these specified output laws holds exactly when every output fiber has the same cardinality.

There is then a permutation `T` of `Omega` satisfying `Phi_0(s)=Phi_1(T(s))` for every source point: pair the two equally sized fibers for each output. Conversely, such a permutation gives equal fiber counts.

More generally, every permutation can match at most `sum_v min(n_0(v),n_1(v))` source points. Pairing that many within each output fiber and pairing the remaining source points arbitrarily attains the bound. The minimum mismatch fraction over all permutations is therefore exactly the displayed total variation distance.

This is a certificate for the entire selected record and terminal status. Matching one oracle, one mask projection or one final triple is insufficient. No such actual `Phi`, primitive source or matching permutation is instantiated here.

## Nonuniform sources and computational limits

For a nonuniform primitive source, fiber probability is the sum of the actual source weights in that fiber. Counts alone are insufficient. General probability couplings may be required. Equal output masses need not admit a deterministic source permutation preserving each atom's weight.

The finite fiber matching argument gives no efficient or online algorithm for finding a matching source point. It is not an efficient simulator, a required condition for every computational privacy notion, or a ROM or QROM theorem. It authorizes no prover reset, seed search, resampling, prefix retry, forced matching roots or collision oracle.

Same statement witness comparisons may be vacuous for a unique witness and do not define the complete payment privacy game. Binding, soundness, proximity, knowledge and the actual cryptographic assumptions remain separate. No security score follows from a seed space cardinality or source count.

The actual source maps must retain genuine observed refusal, partial proof and timeout mass where implemented. Selecting only successful runs changes their laws. Some outer segment errors occur after earlier seeding, key generation, precommit and inner proof activity. The inspected route therefore does not establish an atomic operation consuming no randomness on every failure. Panics, assertions and prospective proof dump or grinding effects require their actual finite effects and confidentiality treatment before execution. No such execution was admitted by this review.

## Derived product coordinates

For a genuine field, translating the primitive pair by fixed values gives

```text
A' = A+dA
B' = B+dB
C' = A'*B' = C+A*dB+B*dA+dA*dB.
```

Fixed translations preserve the ideal uniform primitive pair law. A separately proved global measure preserving bijection could also do so. Shifts depending on `A,B` or an entropy dependent history do not automatically preserve that law.

The product coordinate must change by the displayed equation. It cannot be translated as a third independent random field coordinate. Every other source value, original constraint, root, claim, query, fold and terminal status would still need the actual complete source correspondence. The equation alone constructs no joint proof hiding map.

## Whole private cash decision

The completed local result is the actual retained proof entry's parent and child randomness boundary and a conditional complete source certificate. The actual primitive source and full witness to visible view function remain unestablished. The bare lookup constructor and full original cash lowering remain missing.

The required construction must join one actual original private cash program and representation to all same source trace, lookup indices and `Y`, both lookup relations, clear claims, masks, rounds, raw queries, folds, terminal values, outer proof and repeated or concurrent views. It needs both semantic directions, the expected native verifier and combined opening, canonical bounded parsing and finalization, complete resources, supported recipient completion or refusal and the applicable joint privacy and proof security arguments.

The [same private witness](private-witness-join.md), [whole encrypted output](whole-encryption-completion.md), [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) gates remain. Current limits, original primitives, authenticated atomic state, confidential bootstrap, independent nodes, private scanning and encrypted recovery are unchanged. Backend adoption remains refused pending the complete construction.
