# Normalized quotient basis correspondence

This reference connects the retained normalized coset quotient construction to coefficient segment polynomials. It establishes a polynomial change of basis and a conditional mask distribution identity. It does not establish a complete proof system security bound.

The source baseline is `3b9bd07f8f6aacc4bdac025e900aeaa28463eeb4`. The [current hiding adapter](../fallible-source/src/hiding_pcs.rs), [retained mask kernel](../storage-pcs/backend/src/storage.rs) and [hiding implementation](../storage-pcs/backend/src/hiding_pcs.rs) supply the construction. The original Plonky3 0.8.0 `p3-commit/src/domain.rs` and `p3-uni-stark/src/verifier.rs` supply the domain operations and verifier recomposition. Their pinned versions are retained in the [lockfile](../fallible-source/Cargo.lock).

## Original domains and normalized recomposition

Let $D=\xi_0\langle\omega\rangle$ have size $cH$, and let $K=\langle\omega^c\rangle$ have size $H$. Its disjoint chunks are $D_i=\xi_iK$, where $\xi_i=\xi_0\omega^i$. Define

$$
a_i=\xi_i^H=a_0\eta^i,\qquad \eta=\omega^H,\qquad
Z_i(X)=\frac{X^H}{a_i}-1.
$$

The field characteristic does not divide $c$. Define the source normalization constants and reconstruction weights by

$$
\gamma_i=\left(\prod_{j\ne i}Z_j(\xi_i)\right)^{-1},\qquad
L_i(X)=\gamma_i\prod_{j\ne i}Z_j(X).
$$

The $L_i$ are ordinary Lagrange polynomials in the variable $Y=X^H$. If $q_i$ is the remainder of a polynomial $Q$, of degree less than $cH$, modulo $X^H-a_i$, then

$$Q(X)=\sum_{i=0}^{c-1}L_i(X)q_i(X).$$

Indeed, the right hand side has degree less than $cH$ and agrees with $Q$ on all $cH$ points of $D$.

Since $\prod_i(Y-a_i)=Y^c-a_0^c$, differentiation gives $\prod_{j\ne i}(a_i-a_j)=ca_i^{c-1}$. Also $\prod_i a_i=(-1)^{c+1}a_0^c$. Consequently

$$\gamma_i=\frac{(-1)^{c+1}}c.$$

The eight equal size chunks in the retained source therefore have $\gamma_i=-1/8$. The final mask multipliers $\gamma_i/\gamma_7$ all equal one. This conclusion depends on the actual equal size split and normalized vanishing polynomials. Generic domain families need their actual constants.

## Actual mask coordinates

Write the source masks as $t_i(X)=\sum_{k=0}^{H-1}r_{i,k}X^k$. The actual masked functions are

$$\widetilde q_i=q_i+Z_it_i,\qquad
t_{c-1}=-\sum_{i<c-1}\frac{\gamma_i}{\gamma_{c-1}}t_i.$$

The mask contribution to reconstruction is

$$
\sum_iL_iZ_it_i=\left(\prod_i Z_i\right)\sum_i\gamma_it_i=0.
$$

The implementation's coefficient coordinates matter. For the fixed global LDE shift $g$, it transforms evaluations into the variable $Y=X/g$. Its low coefficients subtract $g^kr_{i,k}$, and its high coefficients add $(g/\xi_i)^H g^kr_{i,k}$. Evaluating that correction at $Y=X/g$ gives exactly $Z_i(X)t_i(X)$. The arrays represent common global $X$ coefficients rather than different local mask bases for each coset.

The verifier reconstructs with the original size $H$ chunk domains. It authenticates openings over the larger size $2H$ masked domains. These are separate uses of domain metadata. Enlarged chunk domains overlap in this split, so they cannot replace the original reconstruction domains.

## Fourier change to coefficient segments

Write the coefficient segmentation of $Q$ as

$$Q(X)=\sum_{j=0}^{c-1}X^{Hj}s_j(X),\qquad \deg s_j<H.$$

Reduction modulo $X^H-a_i$ gives $q_i=\sum_j a_i^js_j$. Set

$$V_{ij}=a_i^j,\qquad U_{ji}=\frac{a_i^{-j}}c.$$

Geometric sums over the distinct powers of $\eta$ show that $UV=VU=I$. Thus $s=Uq$. Apply the same transform to masks, $T=Ut$. Normalized coupling gives $T_0=0$. The identities $U_{ji}/a_i=U_{j+1,i}$ for $j<c-1$, and $U_{c-1,i}/a_i=U_{0i}/a_0^c$, yield

$$
\begin{aligned}
\widetilde s_0&=s_0+X^HT_1,\\
\widetilde s_j&=s_j+X^HT_{j+1}-T_j &&(1\le j<c-1),\\
\widetilde s_{c-1}&=s_{c-1}-T_{c-1}.
\end{aligned}
$$

These corrections telescope, so $\sum_jX^{Hj}\widetilde s_j=Q$. This is an exact change of polynomial basis.

More generally, $L_i(X)=\sum_jU_{ji}X^{Hj}$. Therefore, for any tuple of candidate polynomials $p_i$, including a tuple without honest mask coupling,

$$\sum_iL_i(X)p_i(X)=\sum_jX^{Hj}(Up)_j(X).$$

The reconstruction identity consequently applies to candidate quotient oracles as well as honest outputs. It does not assert that those oracles were authenticated or proved low degree.

The restriction of $U$ to the subspace $\sum_it_i=0$ is a bijection onto the coordinates $(T_1,\ldots,T_{c-1})$. Its inverse is $t_i=\sum_{j=1}^{c-1}a_i^jT_j$. Under independent uniform coefficient sampling, the free transformed masks are therefore jointly uniform. The argument applies coefficient by coefficient and separately to extension basis coordinates. It assumes the stated sampling law. It does not establish pseudorandomness, repeated proof privacy or a simulator for an authenticated transcript.

At an ideal polynomial oracle level, evaluation at a common point commutes with this fixed transform. Hashing a committed row does not commute with a change of basis. The argument constructs no substitute commitment or verifier acceptance path.

## Conditional polynomial degree envelope

If every candidate chunk has degree less than $2H$, its reconstructed polynomial $R$ has degree at most $(c+1)H-1$. This follows from $\deg L_i=(c-1)H$ and does not assume honest mask cancellation.

For the actual small `QuarticAir`, the masked trace columns have degree at most $2H-1$. Its four constraint polynomials have degree bounds $8H-4$, $2H$, $3H-2$ and $3H-2$, respectively. These follow from its quartic equation, transition selector and first and last row selectors. Thus its constraint combination $C_\alpha$ has degree at most $8H-4$.

For $c=8$, the point test polynomial

$$P(X)=C_\alpha(X)-(X^H-1)R(X)$$

has degree at most $10H-1$. A fixed nonzero $P$ has at most that many roots. Turning this elementary statement into a DEEP error requires fixed candidate polynomials, a justified challenge distribution and the relevant codeword list and commitment hypotheses. It is not a soundness bound for the complete protocol. The argument above is specific to the four small AIR equations. The complete overlay requires its own actual polynomial selector degree accounting.

## Primary theorem correspondence

The primary comparison is Atapoor, Delpech de Saint Guilhem and Al Kindi, [STARK-Based Signatures from the RPO Permutation](https://cic.iacr.org/p/3/2/38/pdf), IACR Communications in Cryptology 3(2), published 3 August 2026, DOI 10.62056/absgbn-3y. Protocols 1 and 2 and Theorems 2 and 3 were inspected in the typeset edition, pages 13–16 and Appendix B.1–B.2.

That protocol uses independent constraint coefficients, coefficient segments with telescoping masks, a DEEP point sampled outside the trace and code domains, and independent FRI batching coefficients. Its auxiliary mask arrives after the evaluation claims. Theorem 2 includes a squared list factor and an excluded domain denominator. These facts require correspondence with the actual source before transferring a security term.

The basis argument above addresses the quotient polynomials and their coupled mask law. It leaves these concrete obligations:

| Retained source fact | Remaining correspondence |
|---|---|
| Constraint coefficients are reversed powers of one challenge | Round by round analysis of that combination |
| Quotient count is padded to eight | The segment count and degree choices used by a bound |
| Source samples an extension point and rejects invalid cases | Exact distribution and rejection accounting |
| PCS batching uses powers across all function and point pairs | Proximity bounds for that coefficient family and incidence |
| Auxiliary root precedes the DEEP point, and its functions enter an opening reduction | Full hiding distribution and transcript schedule |
| SHA3 leaf and node hashing authenticates actual rows with salts | Commitment binding and oracle compilation |

The primary [hiding note](https://eprint.iacr.org/2024/1037), Haböck and Al Kindi, remains a separate prerequisite for a complete privacy argument. No result from its unreviewed proof is applied here.

The pinned `p3-security/src/deep.rs` uses a linear list factor and a field size denominator. It explicitly notes differences from its cited theorem. `Proof::proven_security` in `p3-uni-stark` passes the proof's committed `degree_bits` to the report, while AIR metadata is derived using the original trace domain. The `max_combo` input counts OOD points per column. These meanings must be preserved together. No calculator was executed and no achieved security level is reported.

## Independent finite reference

The integer reference uses $\mathbb F_{17}$, $H=2$, $c=4$, $\xi_0=3$ and $\omega=9$. Its [literal fixture](fixtures/literals.json) was derived independently before the model. It records the Vandermonde matrix and inverse, polynomial remainders, masks and transformed segments.

The reference obtains coset remainders by polynomial long division and reconstruction weights by polynomial products. It compares the resulting transforms with the saved literals. It exhausts 4,913 free triples for one mask coefficient and checks their distinct images. The coefficientwise mathematical argument, rather than an enumeration of all mask polynomials, gives the corresponding distribution statement.

Seven hostile perturbations check mixed normalization, an uncoupled mask, chunk permutation, transposed transform, wrong segment spacing, an altered chunk and overlapping enlarged domains. Restoring original data must restore the polynomial equality. A reference inversion failure is distinct from a PCS or cryptographic verifier rejection.

The program imports no production field, commitment, transcript, proof, original normalization test or security calculator. Its tiny field is a reference domain, not a replacement protocol parameter. Recorded execution and source identities belong to this reference alone. Full signature proving, theorem composition and private payment acceptance remain unfinished.

## Recorded execution and reproduction

One isolated Python 3.14.5 run on Windows passed the literal comparisons, both matrix inverse directions, the 4,913 coefficient image cases, seven hostile controls and seven restored positive checks. The unchanged external guard enforced 512 MiB process and aggregate job limits, 2 GiB freshly available memory and a 120 second deadline. Observed process private commit was 9,904,128 bytes and aggregate job commit was 11,194,368 bytes. No production proof or previously completed experiment was repeated. The [validation](validation.json) binds the source and [saved result](results/reference.json).

```text
python -I -S research/quotient-basis/static_check.py
```

This command checks saved source identities and evidence without importing the model. A new model run requires a fresh finite admission, the [unchanged Windows guard](run_guarded_windows.ps1), `KOVA_QUOTIENT_BASIS_GATE=reviewed-external-resource-admission` and a new result basename in `KOVA_QUOTIENT_BASIS_OUTPUT`. Mathematical parameters have no command line or environment override. Output creation is exclusive.

After that admission, a new run from the repository root uses:

```powershell
$env:KOVA_QUOTIENT_BASIS_GATE='reviewed-external-resource-admission'
$env:KOVA_QUOTIENT_BASIS_OUTPUT='reference-new.json'
.\research\quotient-basis\run_guarded_windows.ps1 -Executable (Get-Command python).Source -Arguments '-I -S research/quotient-basis/model.py' -WorkingDirectory (Get-Location).Path -Prefix 'basis-new'
```
