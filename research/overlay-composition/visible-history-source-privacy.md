# Visible history and common source privacy

## Construction status

This source and conditional mathematical review gives an exact criterion for a joint visible history and a designated disclosed value. Histories may depend on the witness and the same mask randomness. It extends the [shared word source map](shared-word-source-map.md), [original codeword privacy](original-codeword-privacy.md) and [private lookup compensation](private-lookup-compensation.md) reviews.

The criterion applies to complete selected outcome laws. No complete private payment program, hiding representation, simulator, backend, profile, parser or execution class is adopted. No model, helper, witness, proof or cryptographic operation was executed.

## Retained source boundary

The source remains [binius-zk/binius64 at `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). The [source record](visible-history-source-privacy-sources.json) identifies the retained encoder, native channel, query, wrapper and lookup contexts. No new primary request or capture was performed. The earlier failed source selection remains closed without retry or alternate acquisition.

The retained native Merkle channel reads roots as observed messages and openings as decommitment advice. It reads each requested raw leaf, checks its opening and returns all its scalars. The FRI caller translates indices by each original oracle's lift and receives the raw coset before folding it. Original oracles are visited in commitment order, and the query sequence is sampled before opening them.

Decommitment advice is visible to the verifier even though that route does not observe it into the Fiat Shamir state. It belongs to the privacy view.

Under the earlier actual encoder, field, bit reversal, packed buffer and NTT hypotheses, a masked original leaf contains separately identifiable original message and encoder mask components. For an original lookup message `Y`, the original component is a vector of queried `E(Y)` values. The encoder mask has zero coefficient in that projected component.

This projection is not the whole coefficient vector `Y` and is not a finite query witness extractor. The actual honest lookup constructor, weights, private randomness and denominator source are still unacquired. Its factorization through original semantic values cannot be asserted from the verifier wrapper or the notation used below.

## Actual public record

Fix an explicitly justified privacy comparison between two allowed executions, such as original witnesses `w_0,w_1` for the same actual public statement. Let an actual extracted public record be `(H,Z)`.

`Z` is the separately designated visible value or vector. `H` contains the other selected visible history components. It may contain adaptive earlier or later values and can have arbitrary witness dependent distributions. It must contain no hidden constructor coins merely to make a formula deterministic.

For a queried original oracle projection, the actual public data needed to interpret it can include the expected program, statement, options, dimensions, oracle identity, encoder and lift layout, looker challenges, query tuple with duplicates and translations, relevant roots and messages. The actual source must establish which data is available and sufficient. A latent private table is not an observed `Z`.

Use a finite or countable canonical history and output alphabet. Additional timing or resource observations remain part of a larger view when present. Every genuine observed refusal or timeout outcome must retain its probability mass. An unproved nonterminating computation cannot be converted into an invented refusal outcome. Success only postselection is a different experiment and cannot establish privacy of the full attempt.

## General conditional law

Let the actual normalized history laws be `p_0(h),p_1(h)`. Let

```text
K_i(z|h) = Pr[Z=z | H=h, execution i].
```

At histories with `p_i(h)=0`, choose any normalized kernel. Its value there does not change that execution's joint law.

For countable normalized distributions, total variation distance is one minus their overlapping mass. Therefore the exact joint distance is

```text
TV(joint_0,joint_1)
  = 1-sum_(h,z) min(p_0(h)*K_0(z|h),p_1(h)*K_1(z|h)).
```

This equation includes arbitrary dependence of the visible history on witness, shares, masks, commitments and challenges. It introduces no fresh independent randomness for each observation.

If the history laws are equal to `p`, the expression simplifies exactly to

```text
TV(joint_0,joint_1) = sum_h p(h)*TV(K_0(.|h),K_1(.|h)).
```

Perfect equality of the joint laws holds exactly when their history laws are equal and their conditional kernels agree at every history of positive common probability, up to null sets.

For unequal histories, put `delta_H=TV(p_0,p_1)` and `m_h=min(p_0(h),p_1(h))`. Marginal projection and the overlap inequality give

```text
delta_H <= TV(joint_0,joint_1)
TV(joint_0,joint_1)
  <= delta_H+sum_h m_h*TV(K_0(.|h),K_1(.|h)) <= 1.
```

The upper bound follows from `min(p_0*K_0,p_1*K_1)>=m_h*min(K_0,K_1)`. It is a sufficient approximate distance certificate, not generally a necessary one. The full overlap expression remains exact.

## Deterministic source specialization

Suppose actual source proves `Z=F(w_i,H)` on each execution's real support, with a deterministic total common alphabet extension elsewhere. This is an additional source hypothesis. Such a mathematical extension does not establish a terminating implementation.

Define

```text
Equal = { h : F(w_0,h)=F(w_1,h) }.
```

At a history in `Equal`, the joint laws overlap by `min(p_0(h),p_1(h))`. At any other history their designated values differ and their joint masses do not overlap. Thus

```text
TV(joint_0,joint_1)
  = 1-sum_(h in Equal) min(p_0(h),p_1(h))
  = delta_H+sum_(h outside Equal) m_h.
```

In particular the distance is at least each execution's probability of a history outside `Equal`. If `p_0=p_1=p`, it is exactly `Pr_(h from p)[F(w_0,h)!=F(w_1,h)]`.

No independence of `H` from the witness or share entropy is needed. No equality between the actual challenge sequences of two proofs is assumed. If `H` already includes `Z`, the identity remains true but provides no additional separation beyond the history itself.

## Semantic sharing and lookup

For the complete word sharing map, let `D` decode the global share vector and let `J(w,eta)` be the shared representation. It satisfies `D*J(w,eta)=w`. Share entropy directions lie in the kernel of `D`.

If an actual honest semantic lookup projection factors as `F(w,h)=G_h(D*J(w,eta))` without additional hidden randomness, the share entropy cancels from that projection once the actual visible `h` is given. The graph formula then describes the joint record. Changing actual roots or challenges must be accounted in `p_i`; it does not by itself prove joint privacy.

A valid construction might instead have genuine hidden randomness remaining conditional on `H`, or an actual history support on which the compared disclosed values agree. Those possibilities require the real conditional kernels and point law. Hidden coins cannot be moved into `H` to force the deterministic hypothesis, and an independent mask law before conditioning cannot be reused after conditioning without proof.

The retained lookup verifier samples its looker batching challenge before receiving `Y`, then queues both original opening relations on that same oracle. The actual original trace commitment precedes the IMUL reduction. The actual IMUL lookup has twelve limb columns from `a,c_lo,c_hi`, with separate obligations for `b`. These source facts do not provide the unacquired honest index, weight, pushforward or denominator map. No actual `F(w,H)` or same statement private cash witness pair is instantiated here.

The full privacy analysis must include all original trace and lookup oracles, both lookup relations, clear claims and compensations, mask inner products, main and masked rounds, duplicated and lift translated queries, folds, terminal values, outer interactions and repeated or concurrent proofs using the same actual entropy model.

## Computational and proof limits

Any deterministic extraction of `(H,Z)` from the full view has distance at most that full view's statistical distance. Positive statistical distance alone does not establish an efficient distinguisher, a hash break, Fiat Shamir failure, quantum attack or knowledge failure.

If an actual allowed known witness pair and efficient source and projection algorithms are supplied, the test `Z=F(w_0,H)` and `F(w_0,H)!=F(w_1,H)` has an execution probability difference equal to the first law's mass outside `Equal`. The reverse test gives the second law's mass. Efficiency of the required total evaluations and the actual permitted comparison must be proved. No such actual payment pair, source algorithm, point probability or attack is supplied by this review.

Comparing same statement witnesses is not construction of an efficient simulator. The criterion can be vacuous when only one witness is allowed. The actual privacy definition, original cash relation, computational and quantum hypotheses, transcript binding, proximity, soundness and extraction remain separate obligations. No security score is inferred from the equations.

## Complete private cash decision

The local result is an exact joint history and source disclosure criterion, including a general conditional kernel and deterministic source specialization. It supplies the necessary conditioning framework for one actual common construction. It supplies neither the missing source map nor the construction itself.

The minimum missing construction remains a complete common private cash program and representation, actual same trace and lookup source maps, both semantic directions, a matched native expected verifier and single combined opening, canonical bounded parsing and finalization, complete resources, practical recipient completion or refusal, and the applicable joint privacy and proof security arguments.

The [same private witness](private-witness-join.md), [whole encrypted output](whole-encryption-completion.md), [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) requirements remain. Current limits, original primitives, authenticated atomic state, confidential bootstrap, private scanning and encrypted recovery are unchanged. Backend adoption remains refused pending the complete construction.
