# Main round source binding and interpolation domain

## Construction status

This source and conditional mathematical review connects the actual outer quadratic factory, shared column store and interpolation to the [masked round protocol](masked-round-correspondence.md). It supplies a producer correspondence under explicit field, source and interpolation assumptions and identifies the remaining complete proof and private cash construction.

No backend, private cash program, proving profile, execution class or complete accepted proof theorem is adopted. No compiler, helper, witness, prover, verifier or upstream test was executed.

## Source scope

The source is [binius-zk/binius64 at `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). The [source record](main-round-sources.json) retains the original notices and exact source identities.

An initial closed selection retained the quadratic factory, prover traits and round state. A separate prior selection retained its four actual interpolation, shared evaluator, column store and equality tracker callees. Seven requests retained seven whole bodies totaling 116617 decoded UTF8 bytes. Each selected size and computed Git blob matched separately retained immutable primary directory metadata. The connector supplied no independent source SHA or base64 envelope. No raw HTTP identity, complete tree, dependency, artifact, hardware or toolchain audit is claimed.

All seven bodies and their tests were read as data. Both selections are closed. Field arithmetic, packed buffer and line/fold helpers, parallel runtime, allocator, complete wiring and authenticated opening source remain separate obligations.

## Actual factory and column identity

The actual `quadratic_mlecheck_prover` consumes the supplied owned field columns, creates an `MleStore` with the evaluation point length, pushes each column in order and registers a `QuadraticMleEvaluator`. The retained Spartan caller supplies the three columns for `a*b-c` and the leading quadratic composition `a*b`.

The production factory does not clone those input columns. The store asserts the expected variable count when a borrowed or owned column enters. A column identifier is an index into this store. It contains no separate owner identity. The fixed caller must keep the returned identifiers associated with the same actual store and source columns.

The store distinguishes owned, borrowed and split-half entries. An owned entry folds in place. A borrowed entry remains borrowed through the initial read and is promoted to a fresh half-size buffer when folded. A split-half entry keeps one parent allocation containing two logical columns. Its two halves fold independently, and their live prefixes shrink without joining the columns.

Repeated reads by multiple evaluators do not create independent columns or witnesses. Final values are returned in original push order. These host storage facts do not authenticate the original trace or prove private mutable memory, copy, address, time or state constraints.

## Deferred fold correspondence

The shared evaluator group immediately reduces each round polynomial against the sampled challenge, but stores that challenge for the next column pass. Its logical variable count is one below the physical store count while that fold is pending.

On the next execute, the store either folds then reads or combines the fold with the read pass. The combined pass splits each input into the same low and high ranges, applies line extrapolation, persists owned results or promotes borrowed results, and decrements the store count. The final `finish` applies any last pending fold before requiring zero remaining variables and reading the scalar in each column.

Conditional on correct field and buffer helper semantics, the fold is

```text
M_next(u) = (1-r)*M(u,0) + r*M(u,1).
```

Induction over the high-to-low challenges gives the multilinear extension of the original column at the sampled point. The challenge vector must be reversed when the caller expects low-to-high coordinate order.

The recursive read path bisects matching column halves at the same variable. It passes the actual bisected variable index to the reduction. The main MLE-check builds its equality factor over the low chunk coordinates and combines higher subresults by `lo+z*(hi-lo)`. The current highest coordinate is reserved for interpolation.

This actual main MLE-check path does not register an `EqTracker` for its point. The selected tracker implementation supports the ordinary sumcheck and converted path. Its prefix product must not be silently multiplied into the main MLE-check path as an extra factor.

## Actual quadratic samples

For a fixed remaining Boolean coordinate `u`, write each multilinear column on the current variable as

```text
M(u,X) = M(u,0) + X*(M(u,1)-M(u,0)).
```

In characteristic two, the direction coefficient is `M(u,1)+M(u,0)`. For the real composition `A*B-C`, the leading quadratic term is the product of the directions of `A` and `B`. The affine `C` column contributes no quadratic term.

The evaluator therefore accumulates two equality-weighted values: the composition at the high branch and its leading coefficient from the direction branch. Wider products are reduced and packed lanes are summed before interpolation. Correctness requires the actual wide multiplication to reduce to the field product, additive reduction of accumulated values, correct live lanes and complete matching chunks. A trait name or host word multiplication is not this theorem.

For the resulting prime polynomial `P(X)=p_0+p_1*X+p_2*X^2`, these two samples are

```text
y_1   = P(1)
y_inf = p_2.
```

Together with a genuine current claim `s=(1-alpha)P(0)+alpha P(1)`, they determine the polynomial when `alpha!=1`:

```text
p_0 = (s-alpha*y_1)/(1-alpha)
p_2 = y_inf
p_1 = y_1-p_0-p_2.
```

This proves the local interpolation map for a genuine main round under its nonsingular condition. It does not make an arbitrary claimed `s` the correct original weighted evaluation.

## Interpolation at the exceptional coordinate

The actual helper implements the first equation by multiplication with `(1-alpha).invert_or_zero()`. Its property tests assume `alpha!=1`. Those tests were read as data and do not enforce a live point restriction.

At `alpha=1`, under the stated inverse-or-zero semantics, the helper chooses `p_0=0`. A genuine endpoint claim then fixes only `P(1)=s`. It does not determine the original constant coefficient. The selected samples and endpoint claim cannot recover an arbitrary genuine polynomial at that coordinate.

If the true polynomial has constant coefficient `b`, the generated polynomial differs from it by `-b*(1-X)`. It agrees at one and in its leading coefficient. It is the same polynomial when `b=0`. Otherwise the producer correspondence above does not extend to all evaluation points without an additional construction or completeness argument.

The verifier's compressed-coefficient recovery is a different step. It reconstructs a constant coefficient from received nonconstant coefficients without dividing by `1-alpha` and permits `alpha=1`. That fact does not remove the honest factory's interpolation condition.

The inspected caller obtains its original point through channel sampling. No exclusion of one is implemented in the selected caller or interpolation helper. The complete native field sampler, actual point support and honest completeness policy remain unreviewed. A source comment about an honest challenge is not evidence for that policy. No actual failing proof, bad accepted proof, probability for the live implementation or full upstream security failure is demonstrated.

No challenge exclusion, resampling, root replacement, reset or prefix retry is introduced. A future usable construction needs the actual declared point domain and truthful terminal behavior, or a reviewed complete interpolation change with its matching verifier and security argument.

## Both correspondence directions

For the forward producer map, assume the actual original columns and dimensions, genuine field and packed operations, valid equality weights, the same store throughout, correct line/fold helpers, a genuine original claim and the nonsingular interpolation condition in every round. The chunk sum gives the intended high and leading samples. Interpolation gives the genuine prime polynomial. Folding preserves the original column extensions. Induction reaches the terminal evaluations of those same original columns.

The store's final scalar values and actual round polynomial evaluations can then satisfy the retained caller's multiplication check and same-oracle opening relations. The original private signature, key, membership, value, encryption and state obligations must already be present in those columns and their wiring.

For a converse from a complete accepted proof, host column identifiers, phase assertions and interpolation formulas are insufficient. The verifier must bind the terminal values to the same original committed columns, consume all native program wiring, outer constraints and the single combined opening, and establish the applicable random challenge, proximity, binding and extraction guarantees. A valid local compressed polynomial chain is not a deterministic witness extractor.

No matching public statements, supplied field claim, Boolean, result, callback, root, token or peer-selected program authenticates that association. The exact field and generator, full word and compiler source, original lookup predicates and both lookup openings remain separate obligations.

## Resources and whole private cash

The inspected paths retain original owned or borrowed columns, promoted buffers, split-half parents, equality chunks, per-worker accumulator vectors, reduction results, round coefficient state and pooled capacity. Recursive parallel joins and descriptors also need actual bounds. A logical truncated slice does not prove that its parent allocation or pool capacity has been released.

The source's chunk constant and two samples per quadratic claim do not establish complete program dimensions, simultaneous memory, wire size or an execution class. All raw, owner, stored, kernel, transport and aggregate limits remain unchanged. No larger class or weaker cryptographic profile is selected.

The complete [same private witness](private-witness-join.md), [whole encrypted output](whole-encryption-completion.md), [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) still require actual private payment proof and parsing, supported recipient completion or refusal, authenticated atomic state, consensus, confidential bootstrap, recovery and network gates. The source maps here do not supply that whole construction. Adoption remains refused pending it.
