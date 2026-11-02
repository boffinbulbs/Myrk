# Masked round correspondence and joint view

## Construction status

This source and conditional mathematical review follows matched outer multiplication check rounds and their committed mask relation. It establishes local equations and a restricted fixed-challenge distribution statement. It does not complete the original private cash circuit, main prover source closure, full joint privacy, accepted proof soundness, parser, resources or security construction.

The [outer witness padding](outer-witness-padding.md) describes actual free dummy values and correlated multiplication triples. Its three terminal operand contributions are part of a larger view. The complete round transcript and same committed mask must also be accounted for. No backend, proving profile, execution class or program is adopted.

## Source scope

The immutable source is [binius-zk/binius64 at `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). The [source record](masked-round-sources.json) retains exact identities and original notices.

Six directory metadata reads resolved five whole bodies before acquisition: verifier `mlecheck.rs`, prover `sumcheck/zk_mlecheck.rs`, verifier `sumcheck/common.rs` and `sumcheck/verify.rs`, and the prover sumcheck module entry. All five bodies, including tests, were read as data. Eleven requests were made once each without retry or failure. The selection is closed.

The planned evidence mode uses decoded UTF8 source bytes and computed Git blobs matched against separate actual immutable primary directory metadata. All five lengths and blobs matched. The connector supplied no independent source SHA or base64 envelope. Neither raw HTTP identity nor a new returned SHA comparison is claimed. This limited comparison is not a complete tree, artifact, dependency, license, field, hardware or toolchain audit.

The actual module entry resolves `quadratic_mlecheck_prover` to `quadratic_mle_evaluator.rs`. That body and its helpers were not selected. The relation below therefore assumes a genuine main prover with the specified polynomial, degree and endpoint recurrence. Source interfaces and honest tests do not prove that assumption.

## Actual mask representation

The mask is a separable polynomial

```text
g(X) = sum_i g_i(X_i)
g_i(X) = sum_(k=0..d) c[i,k] * X^k.
```

The buffer stores monomial coefficients. The actual accessors and Horner evaluation do not interpret its entries as evaluations at integer points. Row `i` starts at `i*2^m_d`, with coefficient index `k` in the low address bits. Only `i<n` and `k<=d` contribute to `g`.

For an original evaluation point `z`, the source computes

```text
mu = MLE_z(g)
   = sum_i (c[i,0] + z_i * sum_(k=1..d) c[i,k]).
```

This is the Boolean multilinear extension of `g`, which generally differs from `g(z)` for degree greater than one.

The actual dimension helper chooses a power-of-two row width for `d+1` coefficients and enough padded rows both to cover `n` variables and to satisfy

```text
L = 2^(m_n+m_d) >= n*d + 1 + n_extra_dof.
```

The retained outer caller uses degree two and draws random packed values across the complete mask buffer. Unused coefficient positions are ignored by `g`, but remain in the committed oracle. A comment describing zeros outside the active mask is not an enforced zero condition on that caller's random buffer. Counting spare coordinates does not prove the required joint rank or hiding.

## Matched round order

The actual driver and verifier have this order.

1. Send or receive `mu`.
2. Sample the mask batching challenge `beta`.
3. For each variable from high index to low index, send or receive the nonconstant coefficients of the batched round polynomial, then sample the round challenge and fold.
4. Send or receive `nu=g(r)`, where `r` is the complete round point in the correct coordinate order.
5. Return the reduced main evaluation and mask evaluation to the caller.

The batching polynomial is `h=f+beta*g`. It is not formed by replacing `f` with its multilinear extension before adding the mask. The source's special weighted endpoint recurrence is preserved.

For a round polynomial `P(X)=sum_(k=0..d) a_k X^k`, current claimed value `s_i` and original point coordinate `z_i`, the verifier recovers the omitted constant coefficient by

```text
a_0 = s_i - z_i * sum_(k=1..d) a_k.
```

Consequently `(1-z_i)P(0)+z_i P(1)=s_i`. The next value is `P(r_i)`. This uses no division and permits `z_i=0` and `z_i=1`.

Ordinary sumcheck uses a different compression in the selected common source. It omits the highest coefficient and reconstructs it from `P(0)+P(1)`. That operation must not be substituted for the MLE-check's omitted constant coefficient.

The mask round prover emits `g_i(X)` plus the sum of already bound mask evaluations and the multilinear-extension contributions of the remaining variables. Only the constant coefficient changes by that offset. Its transmitted nonconstant coefficients are exactly `c[i,1..d]` before scaling by `beta`.

The driver retains the same mask, folds its prefix state and ultimately returns `nu`. The outer caller reverses the sampled point into low-to-high coordinate order before building the terminal transparent mask relation. These source orders must match the actual main prover and combined opening.

## Forward equations and acceptance boundary

Assume a genuine main round sequence for `f`, initial claim `s`, the same original `z` and the same mask coefficient buffer. The initial batched claim is `s+beta*mu`. Adding main and scaled mask round coefficients preserves the endpoint recurrence. Recovering the omitted coefficient therefore reconstructs the honest full batched polynomial at every round.

At the terminal point, subtracting `beta*nu` from the final batched evaluation recovers the main evaluation. The retained Spartan verifier then checks

```text
a_eval*b_eval - c_eval = reduced_main_eval.
```

It also queues the mask relation against the same committed coefficient buffer. The producer's expanded transparent table has entries `r_i^k` at active coefficient positions and zero elsewhere, so its inner product with that buffer equals `g(r)=nu`. The matched verifier evaluates that same transparent multilinear table with coefficient index bits before row index bits.

The bare round function does not authenticate this buffer or run the combined opening. It also does not separately open the initial scalar `mu`. Its initial claim, round chain, terminal relation and mask opening must be verified together by the complete caller.

For a converse, compressed coefficients reconstruct a local chain satisfying the displayed endpoint identities. That fact alone does not make the chain the genuine reduction of the original polynomial. Actual main source, fixedness, committed mask binding, random challenge soundness, terminal operand relations, outer verification and one combined opening remain required. There is no deterministic accepted-proof witness extraction here.

For example, if the original weighted main evaluation error is `D_f` and the discrepancy between actual `MLE_z(g)` and claimed `mu` is `D_g`, the initial batched error is `D_f+beta*D_g`. With `D_f!=0`, fixed errors and an independent uniform classical field challenge, cancellation has probability at most `1/|F|`. This is a conditional local polynomial bound. It does not establish the subsequent round soundness, actual Fiat Shamir distribution, quantum or knowledge theorem.

The source permits `beta=0`. No exclusion, resampling or retry is introduced. At that value the round messages receive no protection from this mask, although the source's remaining checks still apply. Its probability is `1/|F|` only under a justified independent uniform challenge model.

## Restricted full-round distribution

Consider an ideal experiment with `n>=1`, fixed original point `z`, fixed prescribed round challenges `r`, nonzero `beta`, independent uniform active mask coefficients and genuine main round coefficients independent of those mask coefficients. Let `f[i,k]` be the nonconstant main round coefficients and define

```text
Y[i,k] = f[i,k] + beta*c[i,k],  k>=1
ell[i,k] = r_i^k - z_i.
```

The same buffer gives

```text
nu - mu = sum_(i,k>=1) ell[i,k]*c[i,k]
f_terminal - s = sum_(i,k>=1) ell[i,k]*f[i,k].
```

The second identity telescopes the actual endpoint recurrence. Therefore the visible round coordinates satisfy

```text
sum ell[i,k]*Y[i,k]
  = f_terminal - s + beta*(nu-mu).
```

The map from mask coefficients to `mu` and all nonconstant mask coefficients has rank `n*d+1`: one aggregate constant coefficient supplies `mu`, independently of the `n*d` nonconstant coefficients. Thus `mu` and the masked coefficients `Y` are uniform, while `nu` follows from the displayed equation. Two genuine main round sequences with the same initial and terminal scalar induce the same distribution of these coordinates in this restricted experiment.

This accounts for every transmitted coefficient of this driver, rather than only its three terminal operand values. It does not conceal those terminal values or establish that they are permitted public information. It also does not cover the rest of the committed-oracle proof.

In particular, actual mask codeword queries, clear relation claims, other masks, folded values and terminal vectors constrain the same coefficient buffer. Their rows must be included in the same joint map. The storage inequality `L>=n*d+1+n_extra_dof` is not a proof of surjectivity of that actual combined map.

The restricted experiment also fixes challenges independently of mask entropy. Conditioning on a real commitment root, earlier transcript or query location can change the mask distribution. An actual online simulator, adaptive hash and Fiat Shamir analysis, repeated proof treatment and applicable classical or quantum theorem remain missing. No field cardinality or source name is promoted to an achieved privacy parameter.

## Remaining whole construction

The actual quadratic main factory and its complete original coefficient/witness source map remain unreviewed. The matched wiring, field, generator, RNG, hash, transcript consumption, parser and security obligations remain open. No host Boolean, callback, supplied claim, root, peer program or profile replaces them.

The mask buffer, main prover state, prefix and suffix arrays, temporary round coefficients, original committed messages, encoder masks, codewords, trees, pooled capacity, query duplicates and complete transport must be accounted together. Degree two means two field coefficients per variable in this round driver. That count is not the whole proof wire size, simultaneous peak or an admitted class. Current caps and profiles remain unchanged.

The [same private witness](private-witness-join.md) and [whole encrypted output](whole-encryption-completion.md) still require one actual hidden note, key, signature, nullifier secret, path, authorization, native conservation, recipient, sender randomness, full KEM, KDF and GCM source relation with authenticated atomic state. Practical recipient completion or refusal remains unselected. The [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) retain proof, privacy, consensus, confidential bootstrap, recovery and network gates. Adoption remains refused pending that complete construction.
