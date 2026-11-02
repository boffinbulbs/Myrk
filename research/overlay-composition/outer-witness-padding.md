# Outer witness padding and joint distribution

## Construction status

This source and conditional mathematical review connects the outer field relation to its actual witness padding. It gives both assignment maps and the distribution of the source's two multiplication triples under explicit ideal field sampling assumptions. It does not supply a complete private cash circuit, joint hiding theorem, accepted proof theorem, implementation class or runtime admission.

The [private lookup compensation](private-lookup-compensation.md) and [original codeword privacy boundary](original-codeword-privacy.md) leave a missing same-witness hiding construction. Moving all original computation into an outer field circuit would require a new complete lowering of the entire private payment relation. The inspected wrapper instead proves an inner verifier relation. These are different source constructions.

## Source identity and scope

The historical source is [binius-zk/binius64 at `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). The [source record](outer-witness-padding-sources.json) retains the original notices and exact source identities. No implementation or dependency is imported.

One new whole body, `crates/spartan-verifier/src/constraint_system.rs`, was retained. Its 9169 decoded UTF8 bytes have computed Git blob `762372676c4ac46923cc31e8b79634345d17207b`, matching separately retained primary directory metadata at that revision. The connector returned decoded text without the planned Contents base64 envelope or independent returned SHA. Acquisition stopped before the two other selected wiring bodies. This comparison is limited source identity evidence. It is neither raw HTTP identity nor a new returned SHA comparison, complete tree, build or dependency audit.

The new body, including its tests, was read as data. Existing frontend constraint and blinding definitions, outer prover packer and entry, verifier entry, wrapped claims and original query sources provide retained context. The actual prover and verifier wiring bodies, mask dimensions helper, full field and sampler implementations remain outside this selection. Source comments and embedded tests are not executed evidence or protocol theorems.

## Actual padded relation

Let the original valid field constraint system have `m` ordered multiplication constraints, precommit count `n_pre` and private count `n_priv`. Each original equation has the form

```text
A_k(w) * B_k(w) = C_k(w),  0 <= k < m.
```

The actual constructor first copies all original constraints in order. For each committed segment it reserves free dummy wires immediately after that segment's original coordinates, then appends dummy multiplication triples. The retained frontend `BlindingInfo::for_fri_queries(q_test)` selects

```text
d = q_test + 1 free dummy wires
t = 2 dummy multiplication constraints
d + 3*t = q_test + 7 appended coordinates per segment.
```

The precommit dummy constraints precede the private dummy constraints. With this selected `t`, their positions in the complete constraint list are `m,m+1` and `m+2,m+3`. The constructor pads the resulting constraint list to the next power of two with `one * one = one`.

For a segment with original count `n`, the added positions are

```text
free:      n, ..., n+d-1
triple j:  n+d+3*j, n+d+3*j+1, n+d+3*j+2,  j=0,1.
size:      2^ceil(log2(n+d+6)).
```

The actual packer copies original field scalars into the prefix and fills unused capacity with zero. It draws each free dummy scalar through `F::random`. For each dummy triple it draws `a,b` and writes `c=a*b`. Uniformity, independence and fresh entropy of these draws require actual sampler and RNG hypotheses. Trait names do not establish them.

The free dummy coordinates have no constraint references, assuming the original system has valid original ranges. The three coordinates of each appended triple appear in its multiplication equation. The remaining tail has no added constraint references. Honest zero filling of that tail does not constrain an adversarial tail to zero.

The source's local `validate` function checks host containers and multiplication equalities with assertions. It is not a canonical bounded network parser, proof verifier or typed refusal boundary. Its checks do not replace actual source validation and complete proof verification.

## Both assignment maps

The forward map assumes a valid original constraint system with finite counts, all references within their original segments, genuine field operations and the expected public `one=1`. Extend any satisfying original assignment by arbitrary free dummy values and arbitrary pairs `a_j,b_j`, setting `c_j=a_j*b_j` in each committed segment. The unchanged original equations hold, each new dummy equation holds and each final `one * one = one` equation holds. Unused tail coordinates may be zero as in the honest packer.

For the reverse map, restrict any assignment satisfying the complete padded relation to the original segment prefixes. The original first `m` equations are still present with the same operands and indices, so that restriction satisfies the original relation. Every appended dummy equation also enforces its own third coordinate to be the product of the first two.

These maps preserve a relation that already exists. They do not create omitted signature, hash, KEM, encryption, state, range or copy constraints, join separate witnesses or extract a witness from a proof. They also assume safe finite index arithmetic. The source's additions, casts, shifts and allocations need actual preflight bounds before a program can be admitted.

## Correlated random coordinates

For independent uniform `A,B` over a genuine finite field `F_Q`, the triple `(A,B,A*B)` has `Q^2` possible values. It is not uniform over `F_Q^3`. Counting all three coordinates as independent random field masks is invalid.

For fixed coefficients with `gamma != 0`,

```text
alpha*A + beta*B + gamma*A*B
  = gamma*(A+beta/gamma)*(B+alpha/gamma) - alpha*beta/gamma.
```

The exceptional value `-alpha*beta/gamma` has `2Q-1` preimage pairs. Each other value has `Q-1` pairs. The corresponding probabilities are `(2Q-1)/Q^2` and `(Q-1)/Q^2`. If `gamma=0` and at least one of `alpha,beta` is nonzero, the observation is uniform.

Nonuniformity alone is not a full privacy failure. The total variation distance between this single product observation and a nonzero additive translate is `1/Q`. Other independent mask contributions can make a larger observation uniform. Actual allowed witness differences and the full joint distribution remain necessary.

## Two weighted dummy constraints

The intended operand contribution of two dummy constraints has the mathematical form

```text
X = u*A_1 + v*A_2
Y = u*B_1 + v*B_2
Z = u*A_1*B_1 + v*A_2*B_2.
```

Here the four primitive draws are assumed independent uniform in `F_Q`. The weights are fixed independently of them. In the padded constraint relation, the formal weights are equality indicator values at the two actual dummy constraint indices. This review does not claim that the unselected wiring helpers implement every such coefficient correctly or that adaptive transcript conditioning preserves the independence assumption.

For `u,v,u+v` all nonzero, `X,Y` are independent uniform field values. Conditional on them, eliminating `A_2,B_2` leaves a scaled product after affine translations of independent uniform `A_1,B_1`. Its exceptional value is

```text
Z = X*Y/(u+v).
```

For each fixed `X,Y`, this value has conditional probability `(2Q-1)/Q^2`; every other `Z` has probability `(Q-1)/Q^2`. Therefore the total variation distance of `(X,Y,Z)` from uniform `F_Q^3` is

```text
(Q-1)/Q^2 < 1/Q.
```

The elimination identity is

```text
Z = X*Y/v - (u*Y/v)*A_1 - (u*X/v)*B_1
    + (u*(u+v)/v)*A_1*B_1.
```

Completing the product gives the exceptional value above. This derives the distribution from the same four primitive draws rather than treating the two product coordinates as fresh randomness.

If `u,v` are nonzero but `u+v=0`, the conditional distribution of `Z` is uniform unless `X=Y=0`, where `Z=0`. The resulting distance from uniform `F_Q^3` is `(Q-1)/Q^3`. If exactly one weight is nonzero, the triple lies on one multiplication surface and its distance from uniform is `1-1/Q`. If both weights vanish, the triple is constant.

These are finite distribution calculations for the displayed ideal experiment, not executed field tests, a source soundness theorem or achieved security. They explain why two correlated triples require their actual weights and exceptional events. A count of two is not by itself the complete hiding certificate.

## Joint query and claim obligation

Consider a justified fixed linear projection containing queried original codeword values and these three operand contributions. Write the query portion as

```text
L = G*w + B*eta + D*triples,
```

where `eta` contains independent uniform free dummy coordinates. Those free coordinates do not enter the multiplication constraints. If the actual query coefficient matrix `B` has full row rank, `L` is uniform and independent of the original witness and triples, conditional on those other values. In that restricted view, the three weighted contributions retain the distribution above. This provides a conditional composition argument for that projection.

If each fixed witness gives a view within distance `epsilon` of the same uniform distribution, two such witness views are within `2*epsilon` by the triangle inequality. That bound concerns only the justified restricted experiment. It is not an achieved full proof privacy parameter.

The source count `q_test+1` does not prove full row rank for every actual query set. The actual dummy coefficient positions, bit reversal, novel basis, own oracle dimensions, duplicate indices, lift translations and allowed query locations must determine `B`. Ambient Reed Solomon rank for all coefficients is different from the rank of these specific dummy columns.

In particular, under the earlier encoder and zero-domain hypotheses, a row at zero selects the degree zero original coefficient. Dummy coordinates appended at positive indices contribute zero to that row. If an allowed original witness difference changes that coefficient, those dummy coordinates cannot hide that projection. This is a conditional source placement boundary. No actual private payment witness pair or complete attack is constructed here.

The complete proof view also contains clear relation claims, mask inner products, sumcheck messages, folded leaves, terminal values and multiple oracle interactions. Their actual additional operators, correlations and nonlinear dependence cannot be discarded. A limited query and operand projection is not the entire view. The actual multiplication check, combined opening and transcript mechanisms need their full source and joint analysis.

## Minimum complete architecture

A whole private cash relation in an outer field circuit remains a candidate architecture question. It would require a real compiler or construction carrying the same original hidden note, verification key, signature, nullifier secret, membership path, amount, asset, creation data, authorization and output opening through every required operation. It would also require the supported recipient completion or refusal construction and authenticated atomic state.

The actual wrapper does not already perform that replacement. The [outer layout](outer-layout-preservation.md) preserves selected existing field equations under its stated conditions. The [word extension](word-witness-extension.md) preserves an existing fixed word relation. Neither supplies a complete word-to-private-cash field compiler or joint distribution certificate.

At minimum, adoption still needs the actual original relation and both maps, complete padded wiring and multiplication check, all oracle and transcript distributions including exceptional weights and query ranks, real field and RNG correspondence, binding and proximity, bounded canonical fully consumed parsing, dependency and license closure, resources and applicable classical, quantum and knowledge security. No supplied root, Boolean, host result, callback, profile or detached proof replaces these obligations.

Original wires, free masks, correlated triples, multiplication masks, encoder masks, codewords, trees, claims, query duplicates, folded buffers, pools and complete transport must be accounted simultaneously. The `q_test+7` source count is neither compiled whole program geometry nor measured memory or wire size. Current caps and proving profiles remain unchanged.

The [same private witness](private-witness-join.md), [whole encrypted output](whole-encryption-completion.md), [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) retain their proof, privacy, consensus, confidential bootstrap, recovery and network requirements. Backend adoption remains refused pending the complete construction. No running chain or production capability is claimed.
