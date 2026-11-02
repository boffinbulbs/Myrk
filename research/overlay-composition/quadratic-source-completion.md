# Quadratic source recurrence without endpoint division

## Construction status

This conditional mathematical construction completes the entire honest quadratic round recurrence for arbitrary field coordinates by computing a genuine endpoint from the same original columns. It extends the [main round source binding](main-round-source-binding.md), [masked round correspondence](masked-round-correspondence.md) and [native proof transcript](native-proof-transcript.md) reviews.

The inspected implementation retains its existing two sample interpolation. The construction below is a prospective source change. No implementation, compiler, private cash program, backend, field, profile or execution class is adopted. No helper, model, randomness, witness, prover, verifier or upstream test was executed.

The complete same private cash architecture remains unfinished. Correcting one producer correspondence would leave original witness binding, joint hiding, complete verification, recipient completion, resources and state authority to be established.

## Retained source

The source is [binius-zk/binius64 at `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). The [source record](quadratic-source-completion-sources.json) retains exact identities and original notices for the reused source and caller contexts.

No new primary source was acquired for this construction. Earlier complete bodies were read as data, and the relevant factory, shared evaluator, mask driver, compressed verifier and Spartan caller contexts were reread. Earlier source selections remain closed. This is not a complete transitive field, codec, packed arithmetic, dependency, hardware or toolchain audit.

The actual Spartan caller constructs three multiplication columns, supplies `a*b-c` and leading composition `a*b`, samples the evaluation point and starts with zero as the claimed multilinear evaluation of the Boolean row residuals. It later reverses the round challenges and sends the same three final column values.

## Same original columns and genuine claims

Fix a finite dimension `n`, a genuine field of characteristic two, and three original Boolean tables `A,B,C`. Their multilinear extensions and every subsequent restriction refer to these same tables.

The initial claim is the weighted Boolean evaluation

```text
s_0 = sum_v eq(z,v)*(A(v)*B(v)-C(v)),
```

where `v` ranges over the Boolean cube. It is not generally the direct polynomial evaluation `A(z)*B(z)-C(z)`.

At round `t`, earlier high variables have been restricted to their actual challenges. Write the remaining source extensions as `A_t,B_t,C_t`. Let `X` be the highest remaining variable, `alpha` its original evaluation coordinate and `z_low` the remaining lower coordinates. Define

```text
P_t(X) = sum_u eq(z_low,u)
         *(A_t(u,X)*B_t(u,X)-C_t(u,X)).
```

Each source column is affine in `X`, so `P_t` has degree at most two. The actual high and infinity samples are

```text
y_1   = P_t(1)
y_inf = coefficient of X^2 in P_t.
```

For the multiplication composition, the infinity sample is the weighted product of the two column directions. In characteristic two those directions are `hi+lo`. Actual packed lane, chunk, wide multiplication and additive reduction semantics remain hypotheses.

The genuine current claim satisfies

```text
s_t = (1-alpha)*P_t(0)+alpha*P_t(1).
```

## Information at the endpoint

The inspected helper derives the constant through `(s_t-alpha*y_1)*(1-alpha).invert_or_zero()`. When `alpha!=1`, the two samples and genuine claim determine the quadratic. At one the claim repeats `y_1`, and the helper selects zero for the constant under the stated inverse semantics.

In the full ambient quadratic coefficient space, the kernel of the samples and endpoint claim at one consists of multiples of `1-X`. These observations cannot recover every arbitrary genuine constant coefficient. This is not a lower bound or demonstrated failure for the actual constrained polynomials reachable from a particular valid private cash program.

An important source restriction applies to the first round. If every original Boolean row satisfies `A(v)*B(v)=C(v)`, both genuine first round endpoints are zero. The ambient ambiguity therefore does not show a first honest round failure.

Later affine restrictions require a separate argument. Put `R_b=A_b*B_b-C_b` and let the column directions be `DeltaA=A_1-A_0` and `DeltaB=B_1-B_0`. Direct expansion gives

```text
R_r = (1-r)*R_0+r*R_1+r*(r-1)*DeltaA*DeltaB.
```

Even when both original endpoint residuals are zero, the restricted residual contains the displayed cross term. Its actual later equality weighted contraction must be accounted for before extending the first round endpoint fact to every later round. No actual private cash witness pair, runtime failure, accepted bad proof or live point probability is demonstrated here.

## Division free producer construction

A prospective producer can compute one additional internal genuine endpoint

```text
y_0 = P_t(0)
```

from the same low source column halves and the same equality weights. It then forms

```text
p_0 = y_0
p_2 = y_inf
p_1 = y_1-y_0-y_inf.
```

These are the genuine coefficients of `P_t` for every `alpha`, including zero and one. For a genuine current claim they satisfy the required endpoint equation without division. At nonsingular coordinates the result equals the inspected interpolation.

The additional endpoint is source computation inside the prover. An unchecked endpoint sent by a peer would not establish this correspondence. No new public endpoint message, oracle, challenge exclusion, resampling, transcript reset or replacement root is part of this mathematical construction.

Evaluate the polynomial at the actual round challenge `r_t` and restrict all three same source columns by that challenge. Then

```text
P_t(r_t) = sum_u eq(z_low,u)
           *(A_(t+1)(u)*B_(t+1)(u)-C_(t+1)(u)).
```

This is precisely the next genuine weighted claim. Induction over every round reaches

```text
s_n = A(r)*B(r)-C(r)
```

for the original columns, with the actual source coordinate order respected. This deterministic honest correspondence requires no challenge independence and has no exceptional `alpha=1` branch. Dimension zero is a terminal scalar case that still requires its actual source and terminal predicate.

## Matched compressed and masked rounds

For `P(X)=p_0+p_1*X+p_2*X^2`, a genuine endpoint claim satisfies `s=p_0+alpha*(p_1+p_2)`. The actual compressed verifier therefore recovers `p_0=s-alpha*(p_1+p_2)` for every `alpha`.

The retained masked driver adds the main coefficients to `beta` times the genuine mask coefficients, omits the constant, sends the remaining coefficients and only then samples and applies the round challenge to both provers. Its final source values and mask evaluation retain their original associations.

A producer that computes the genuine internal endpoint can therefore feed the same degree two and two nonconstant message construction at the mathematical level. This is not a proof of source, key, layout, version or wire compatibility for an implementation.

The mask prover constructor receives a scaled initial claim argument. Its `execute` uses that carried claim as a phase guard and computes the unscaled genuine mask coefficients from the mask, prefix and suffix values. The driver applies `beta` to those coefficients once. The argument name does not establish a double scaling error or authenticate an arbitrary initial mask claim.

For the restricted privacy corollary, assume a finite field `F`, `n>=1`, fixed independent `z,r,beta`, nonzero `beta`, and independent uniform active mask coefficients independent of the main source as in the earlier masked round lemma. The prospective internal endpoint introduces no additional observed value. The full restricted driver coordinate identities and distribution result continue to apply to the genuine producer for all `z`. This gives no privacy at `beta=0`, no proof of actual randomness independence and no theorem for the full oracle or adaptive transcript view.

## Actual internal contract and resources

The actual evaluator already reads low and high source values but retains only the high and infinity accumulators. It interpolates through `RoundEvals<P,2>`. The shared evaluator's `degree()` supplies the number of accumulator slots to allocate and partition among workers. The equality chunk arrives during accumulation, while the current `alpha` arrives at interpolation.

Consequently, the prospective third source functional is not already available merely because the columns were read earlier. A complete implementation needs explicit sampled value and slot accounting, every shared and converted adapter, source ownership, live packed lanes, equality factors, pending folds, arithmetic and error behavior. Internal sample count, emitted polynomial degree and outgoing message count are distinct quantities that a complete implementation must audit. A larger internal sample count does not by itself require a larger verifier degree or message count.

The mathematical outgoing degree and count do not establish an implementation resource profile. Additional internal accumulators, per-worker scratch, reductions, descriptors, parent buffers and retained pool capacity must be accounted together with all original oracles, masks, codewords, trees, queries, folds and transcript bytes. No allocation, simultaneous peak, full wire size or execution class is established here. All current limits remain unchanged.

## Converse and whole private cash

One weighted zero claim at one sampled point does not deterministically imply that every original Boolean multiplication row is valid. The corresponding formal multilinear polynomial vanishing at all formal points would imply zero row residuals by evaluating Boolean vertices. That universal statement is not an assertion about actual reachable challenge support or a witness extractor.

A complete accepted proof converse needs the actual original source relation, same committed columns, expected native program wiring, outer proof and the single combined opening, together with the applicable challenge, binding, proximity, soundness and knowledge arguments. Canonical bounded decoding, consuming transcript finalization and atomic state authority remain required.

Computing an internal endpoint does not randomize the original private trace or private lookup values. Keeping the wrapped inner word route requires a joint hiding representation for that same original trace, lookup indices and both lookup relations across every raw query, clear claim, mask inner product, round, fold, terminal value and outer interaction. Moving the complete cash relation into an outer field circuit would require its full original crypto and state lowering plus the actual joint oracle privacy and resource construction. Neither architecture is instantiated here.

The complete [same private witness](private-witness-join.md), [whole encrypted output](whole-encryption-completion.md), [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) requirements remain. The private payment proof and bounded verifier, practical recipient completion or refusal, authenticated atomic ledger, confidential bootstrap, independent nodes and encrypted recovery are still required before a release claim. Adoption remains refused pending that whole construction.
