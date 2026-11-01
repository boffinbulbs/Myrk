# Single challenge opening reduction

This source review identifies the polynomial curve used by the retained opening argument. It gives a conditional classical unique decoding correspondence and selects a concrete domain admission boundary. It does not establish complete STARK soundness, hiding, Fiat Shamir security or payment acceptance.

The source baseline is `367faefc0f13918045001b39a09544de8ac0f4ab`. The [owned prover](../fallible-source/src/owned_prover.rs), [hiding wrapper](../storage-pcs/backend/src/hiding_pcs.rs), [PCS transcript](../storage-pcs/backend/src/pcs_transcript.rs), [opening prover](../storage-pcs/backend/src/two_adic_pcs.rs) and [opening verifier](../storage-pcs/backend/src/verifier.rs) supply the concrete calls. The [source record](challenge-sources.json) identifies these call sites and the reviewed primary edition. Their [dependency versions](../fallible-source/Cargo.lock) and original source attribution remain unchanged. This review changes no implementation or execution profile.

## Actual words and coefficient order

Fix one committed evaluation height $n_h=2^h$. The retained code evaluates its input matrices on the common shifted subgroup

$$D_h=g\langle\omega_h\rangle\subset F\subset E,$$

where $E$ is the challenge extension field. Row order is bit reversed. A permutation of coordinates does not change Hamming distance, so this physical order can be retained in a Reed–Solomon codeword map.

Enumerate every opening at this height in commitment, matrix, point and column order. Let $f_j:D_h\to F$ be the committed column word, $z_j\in E$ its requested point and $y_j\in E$ its claimed evaluation. A column requested at two points gives two entries. Define

$$u_j(x)=\frac{y_j-f_j(x)}{z_j-x},\qquad x\in D_h.$$

This is a total word only if every $z_j$ lies outside $D_h$. No polynomial representation of a malicious $f_j$ is assumed in this definition.

The prover's `num_reduced[h]` and verifier's `ladder_offsets[h]` start at zero independently for each height. Each requested point advances the counter by the full matrix width. Their actual reduction is

$$R_h(\alpha)(x)=\sum_{j=0}^{N_h-1}\alpha^j u_j(x).$$

The prover folds the first offset into the packed row product and rescales later points by their column count. The verifier uses the same offset for its claimed value sum and authenticated row sum. It then multiplies their difference by $1/(z_j-x)$. These bodies preserve consecutive powers. They do not sample an independent coefficient for every entry.

The hiding wrapper appends the proof's random codeword claims before the inner verifier describes its PCS transcript. On the prover side those claims are removed from the public opening vectors only after the inner argument finishes. They therefore count in $N_h$.

| Quantity | Actual small source class | Conditional complete overlay projection |
|---|---:|---:|
| Original trace height $H$ | 256 | 8,192 |
| Committed polynomial dimension $d=2H$ | 512 | 16,384 |
| Evaluation word length $n=8d$ | 4,096 | 131,072 |
| Main opening pairs $2(W+4)$ | 12 | 84,364 |
| Eight quotient matrices, each width $4+4$ | 64 | 64 |
| Auxiliary matrix width $4+4$ | 8 | 8 |
| Total pairs $N$ | 84 | 84,436 |
| Power curve degree $N-1$ | 83 | 84,435 |

The second column describes the fixed small owned adapter. The final column is a source projection with $W=42,178$, not an instantiated wide proving class. These instances have one evaluation height. Generic mixed heights have separate counters and require separate word maps. The query count 64, the number of matrices and the number of point occurrences are different quantities.

## Conditional unique decoding correspondence

The primary source is Ben-Sasson, Carmon, Ishai, Kopparty and Saraf, [Proximity Gaps for Reed–Solomon Codes, revision 3](https://eccc.weizmann.ac.il/report/2020/083/revision/3/download/), dated 3 July 2021. Theorem 6.1 supplies the power curve result, supported by Sections 4, 6.1 and corrected Appendix D. Theorem 6.2 concerns a larger radius. The relevant number is 6.1, rather than 6.11.

Use $V_h=\operatorname{RS}[E,D_h,d_h-1]$, containing evaluations of polynomials of degree less than $d_h$. Its dimension is $d_h$ and rate is $\rho_h=d_h/n_h$. This translates the paper's maximum degree convention into the implementation's dimension convention.

Suppose the full words $u_0,\ldots,u_{N_h-1}$ are fixed before an independent uniform $\alpha\in E$ is drawn. For $0\le\delta_h\le(1-\rho_h)/2$, Theorem 6.1 implies the following contrapositive. If no tuple of codewords in $V_h$ agrees with all those words on one common set of at least $(1-\delta_h)n_h$ coordinates, then

$$
\Pr_\alpha\!\left[\Delta(R_h(\alpha),V_h)\le\delta_h\right]
\le \min\!\left(1,\frac{(N_h-1)n_h}{|E|}\right).
$$

The strict threshold on the number of good challenges gives the non-strict upper bound above. In particular, the incompatibility hypothesis holds if at least one input word is farther than $\delta_h$ from every codeword. The common agreement set is a stronger conclusion than separate closeness of each word. For one input word, the incompatible case has no good challenge.

The proof correspondence uses a degree $N_h-1$ parameterized curve, rather than a uniform affine combination. Different heights share the challenge. A union bound over their incompatible-group events needs no independence between those events, but still does not prove the later mixed degree FRI fold argument.

For honest consistent claims and a column polynomial of degree less than $d_h$, the divided difference has degree at most $d_h-2$, so it belongs to the code above. A malicious word or inconsistent claim requires the actual proximity and evaluation argument. This observation supplies no replacement validity callback.

The statement is conditional classical oracle mathematics. It does not show that a hash commitment fixes the required words against the relevant adversary, that the actual Fiat Shamir challenge is independent uniform after all conditioning, or that FRI verifies proximity with the stated radius and error. No numeric security level is inferred.

## Transcript and authentication boundary

The actual owned call order is:

1. Commit the real main data, observe its root and public values, then draw the AIR constraint challenge.
2. Commit the quotient and auxiliary data, observe those roots, then draw the out of domain point.
3. Produce and observe every claimed evaluation, including the random codeword tuple, then draw the PCS batching challenge.
4. Observe each FRI commitment before its folding challenge. Observe the final polynomial and query grinding before query indices.
5. Authenticate input rows with `verify_multi_batch`, form the corresponding reduced query values and check the fold chain and committed fold rows.

Step 5 authenticates queried rows after the challenges. It is not itself a proof of fixed complete words before Step 3. A commitment binding and oracle compilation argument is still needed. The caller's fixed AIR, expected statement, dimensions and domains are also separate obligations. Transcript shape labels alone do not identify the constraint equations or payment statement.

The actual hiding preflight checks metadata, height and disclosure budget before consuming the shared private opened flag. The flag is consumed before the inner PCS performs denominator inversion. The same owned data reaches the retained commitment and opening calls. The owned prover constructs an actual `Proof` before calling `finish_produced`. This review does not change those lifetimes or resume a partial attempt.

## Selected domain admission boundary

The existing uni-STARK verifier rejects $\zeta$ on the original trace domain. The retained PCS verifier rejects a zero denominator at an actual sampled query point before batch inversion. These checks do not establish that every requested point avoids the whole committed evaluation domain. The prover computes inverse denominators over the entire domain before claim observation. The original field inversion routine documents a panic for a zero input. This is source inspection, not an executed failure case or a demonstrated soundness attack.

The next integration boundary is a typed, deterministic whole-domain preflight for each actual matrix height and requested point. For the retained shifted two-adic domain it can use

$$z\in D_h\quad\Longleftrightarrow\quad z^{n_h}=g^{n_h}.$$

Here $n_h$ divides $|F|-1$, so $X^{n_h}-g^{n_h}$ already has exactly its $n_h$ distinct roots in $F$. Viewing the equation in $E$ introduces no additional roots. Domain membership must use the actual physical LDE height and common shift, not the raw trace height or a quotient reconstruction domain.

The proposed admission must precede prover flag consumption, inverse denominator construction and claim transcript operations. The verifier must enforce the same geometric rule before replaying claims or drawing its batching challenge. It must return a genuine typed domain cause without fabricated query indices, reset randomness or supplied proof verdicts. It is not implemented or tested by this document.

Explicit refusal of a bad sampled point is different from resampling it. A future proof must account for the actual sampling and refusal policy. No profile or query budget is changed by this selection.

## Remaining scope

The current Johnson helper in pinned `p3-security` cites newer results, including Dao, Kominers and Thaler's [Reed-Solomon Codes Beyond Johnson](https://eprint.iacr.org/2026/2056), Theorem 5.12 and Appendices B.1–B.2. It includes its own polynomial curve transfer argument and rounding terms. Those primary proof hypotheses have not been established for this complete source composition. The unique decoding correspondence above does not validate that helper or transfer an independent affine theorem to it. No calculator was executed.

The [instance security record](instance-security.md) retains the separate DEEP, masks, salts, repeated observation, hash, multiround Fiat Shamir and knowledge obligations. The [quotient basis correspondence](../quotient-basis/README.md) addresses a different polynomial identity. Complete signature construction within the existing resource classes and one hidden witness joining private payment authorization to atomic ledger acceptance remain unfinished.

This increment contains source and mathematical review only. It executes no witness, metadata collector, field model, prover, verifier, transcript or old reference test. Documentation links and source references are checked separately. Original upstream licenses and authorship remain applicable.
