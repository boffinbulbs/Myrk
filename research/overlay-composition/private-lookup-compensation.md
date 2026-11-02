# Private lookup compensation and joint opening boundary

## Construction status

This source and conditional mathematical review identifies verification and hiding obligations of a compensated private lookup oracle. It proves why an unchanged claim pad and an aligned two oracle compensation do not establish the required joint hiding. No lookup replacement, private payment proof, program, proving profile or execution class is implemented or admitted.

The [word witness extension](word-witness-extension.md) preserves an entire fixed word relation under a private index injection. That construction leaves original operation values unchanged. It therefore does not automatically randomize a lookup pushforward derived from those values. The [original codeword privacy boundary](original-codeword-privacy.md) and [masked opening](masked-oracle-opening.md) continue to define the same message and complete view requirements.

## Actual retained source route

The retained historical revision is `6e75a2d1d2e716578ae3ccb62806413fb1615176` of [binius-zk/binius64](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). No new primary capture was selected or performed. Existing RAW source and license identities are retained in the [source record](private-lookup-compensation-sources.json). Selected actual caller bodies were reread as data. No compiler, helper, example or proof was executed.

The actual committed transparent table wrapper has this order.

1. Sample the looker batching challenge.
2. Receive the private `Y` commitments in table order.
3. Run the bare lookup reduction on the same channel.
4. Queue the evaluation relation against `eq_z` and then the product relation against the transparent table `T`, using the same `Y` handle.
5. Return actual index claims for the caller to consume.

The two queued relations have the forms

```text
<Y, eq_z> = a
<Y, T>    = e.
```

The looker batching challenge precedes the `Y` commitments because the producer needs it to construct the pushforward. Later reduction challenges follow those commitments. The looker challenge and the subsequent encoder mask challenge remain distinct events.

The wrapper source does not establish the bare reduction's exact weights, denominators or reachable evaluation point family. Those called bodies remain outside the retained selection. No sequence of powers for lookup weights or full support assumption for later points is inferred from names or comments.

## Universal unchanged claim condition

Let `d` be a fixed additive perturbation of `Y`, chosen before the later evaluation point. Preserving the old evaluation claim would require

```text
<Y+d, eq_z> = <Y, eq_z>
<d, eq_z> = 0.
```

If this is asserted as an identity for the full formal point family, then `d=0`. At each Boolean vertex `b_j`, the equality indicator is the coordinate selector, so

```text
<d, eq_b_j> = d[j].
```

Requiring every such value to vanish makes every coordinate zero. The additional unchanged table relation `<d,T>=0` cannot restore a nonzero mask once the first universal condition has forced zero.

This is a conditional point family lemma. It does not claim that the actual bare reduction reaches every Boolean vertex, has uniform full support or has a particular failure probability. A proposal relying on a smaller reachable family must identify that actual family, its common evaluation kernel and the corresponding transcript and completeness argument.

Choosing a mask after seeing the later point does not implement the source's already committed oracle. Replacing its root, resampling challenges, resuming a prefix or moving the commitment after the reduction changes the actual protocol. No such change is selected here.

## Compensated relations and both local maps

A prospective compensated representation could instead define

```text
U   = Y + d
p_z = <d, eq_z>
p_T = <d, T>
u_z = a + p_z
u_T = e + p_T.
```

An original valid lookup witness and the same actual `d` then satisfy

```text
<U, eq_z> = u_z
<U, T>    = u_T.
```

This forward identity follows by linearity. Its local converse needs an actual constrained relation tying `U`, `d`, the original `Y` and its original hidden indices together. If those original source relations and both compensation equations hold, subtraction recovers

```text
Y = U-d
<Y, eq_z> = u_z-p_z = a
<Y, T>    = u_T-p_T = e.
```

These are conditional maps for the displayed equations. They do not establish a complete accepted lookup proof. The original index, pushforward, product and denominator predicates still need their actual source bound verification. A supplied compensation value or host success result does not enforce them.

Both compensations must derive from the same actual private mask and the same original oracle used by the entire payment witness. A separate existential mask for each opening would not implement this representation. The actual committed coefficient identity and all new relation consumers must be enforced in the matched prover and verifier.

## Clear compensation is part of the view

The inspected wrapped producer sends a decrypted oracle relation claim through `inner_channel.send_one` and records it. The matched verifier receives that value as public inout, constrains equality to the calculated claim in its outer relation and queues the same value to BaseFold.

Therefore a proposal that transmits both `u_z` and `p_z` in the clear also reveals `a=u_z-p_z`. Likewise clear `u_T` and `p_T` reveal `e`. Verification of the two shares does not conceal their difference. This is a deterministic projection of that proposed view.

Whether an original claim is permitted public information must follow from the actual statement and allowed witness differences. Calling a value a public claim, or checking its validity, does not establish that privacy policy. This review does not construct two actual private payment witnesses distinguished by these values or claim a complete upstream attack.

Keeping a compensation private would require an actual verification mechanism for that private equality and original oracle relation. The current native BaseFold claim interface takes field values. A symbolic assertion deferred to an outer proof must still be checked by a complete hiding outer relation and the single combined opening. No private claim mechanism is supplied by the displayed identities.

## Aligned query compensation

The selected FRI query source samples one global index sequence and opens original oracles in commitment order. Each oracle translates an index by its own lift before opening its committed leaf. Raw leaf values are received before the within oracle and outer batch folds.

Consider a proposed pair of original message oracles `U=Y+d` and `V=d`. Suppose they use the same field representation, encoder, own dimension, leaf layout and lift, and are opened at the same resulting original indices `Q`. Then their visible original message components are

```text
G_Q*U = G_Q*Y + G_Q*d
G_Q*V =             G_Q*d.
```

Subtracting them returns `G_Q*Y`. Independent encoder masks for `U` and `V` do not change that calculation because the original message components themselves are present in their opened leaves. Folding the leaves later does not erase those received values.

This is an exact conditional obstruction for that aligned proposal. It does not describe a new implemented two oracle protocol or reject all possible geometries, representations or private opening schemes. Different layouts need their actual source maps and full joint analysis. They cannot be declared independent merely because their commitment handles differ.

More generally, for a justified fixed linear view `v=A*y+B*eta+c`, any row operator `L` with `L*B=0` leaves the projection `L*v=L*A*y+L*c`. If an allowed original witness difference has `L*A*delta != 0`, this randomness does not hide that projected fixed view. The aligned subtraction is one such operator. The actual binary coordinate space must be used for partial word masks.

This projection criterion supplies no adaptive Fiat Shamir, hash commitment, online simulation, quantum or knowledge theorem. Actual roots, previous messages and query locations can depend on earlier randomness. Their conditioning and source order remain part of the complete security obligation.

## Minimum joint construction

The necessary construction must preserve the same hidden original indices and lookup predicates while providing one jointly hiding view of the original trace, `Y`, its compensation, any other original oracles, all clear claims, mask inner products, folded leaves and terminal vector. It must avoid leaving an unchecked original source relation or a visible projection that recovers a forbidden original value.

Possible architectures remain subject to an actual source, prover, verifier and parser selection. Merely adding a mask oracle, moving its commitment, renaming a clear claim, selecting a supplied root or claiming an outer proof does not provide that construction. No alternative is adopted by this review.

The [word witness extension](word-witness-extension.md) remains a conditional semantic map for the fixed word relation. Its original operations must still bind all signature, hash, cipher, range, carry, shift, source index and private copy requirements. The joint lookup construction must use those same word values. No new free table or detached proof can replace that association.

## Resources and remaining gates

Extra compensation messages, original oracles or private equality relations change the actual commitment count, outer batching, oracle dimensions, mask count, challenge order, relation multiplicities, queried leaf values and retained buffers. One combined opening does not remove those contents. Equal or repeated indices can affect rank while still consuming actual returned values and transport.

Source, entropy, masks, codewords, trees, field claims, parallel scratch, pools, descriptors, complete proof bytes and the bounded canonical parser must be accounted simultaneously. Current raw, owner, stored, kernel, transport and aggregate limits remain unchanged. No allocation, measured peak, wire size, security level or proving class is admitted here.

The bare lookup, product and sumcheck source closure, index embedding, denominator exceptions, field and generator implementation, encoder helpers, tree and hash binding, complete transcript consumption and dependency feature and license graph remain open. No healthy program or test was repeated to obtain this review.

The [same private witness](private-witness-join.md) and [whole encrypted output](whole-encryption-completion.md) require the same input authorization, stable nullifier, private membership, current spent state, native conservation, output opening, recipient, private sender randomness, full KEM, KDF, context and GCM. Practical recipient completion or refusal remains a separate missing construction.

The local result is the compensated relation contract and exact unchanged claim, clear share and aligned query boundaries. A complete joint hiding architecture remains unfinished, and backend adoption remains refused. No program, compiler, proof, ledger or production capability is added. The [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) retain all base privacy, consensus, confidential bootstrap, recovery and network gates.
