# Conditional auxiliary isolation

This laboratory derives the affine space supplied by the retained source prover's auxiliary polynomial. A finite integer reference checks its Galois constraints, actual batching powers and translated opening incidence. The result selects a conditional isolation argument for further composition. It does not establish complete proof privacy or payment acceptance.

## Concrete source incidence

The [owned caller](../opening-domain/src/owned_prover.rs) opens the auxiliary matrix first at $z$, the main matrix at $z$ and its trace translate $gz$, and all eight quotient matrices at $z$. Each matrix has the same physical LDE height in the retained small class. The original trace has height $H=256$ and the prepared domain has height $N=2H=512$. Physical LDE height is $4096$.

The [auxiliary entry](../storage-pcs/backend/src/hiding_pcs.rs) samples $N(e+r)$ base-field values as a matrix of width $e+r$. Unlike main preparation, it introduces no additional trace mask. Interpolation is an invertible base-field map, so ideal independent uniform evaluations correspond to independent uniform polynomials of degree less than $N$. Actual seeded pseudorandom generation needs its own computational assumption.

The [inner PCS](../storage-pcs/backend/src/two_adic_pcs.rs) binds every individual column claim before drawing $\alpha$. Powers increase in matrix, point and column order, independently for each physical height. The auxiliary columns receive $1,\alpha,\ldots,\alpha^{e+r-1}$. The random-column claims remain in the [hiding proof tuple](../storage-pcs/backend/src/hiding_pcs.rs). Removing them from the caller's public vector does not remove their disclosure.

The [raw writer](../fallible-input/src/lib.rs) emits $W$ original values followed by $W+2r$ random fields per original row. Reinterpreting this stream at width $W+r$ produces one row containing the original values and $r$ random fields, followed by a wholly random row. This fixes the logical main mask placement before extension and bit reversal.

## Conditional affine space

Let $F=\mathbb F_p$, $E=\mathbb F_{p^e}$ and let $A_j\in F[X]_{<N}$ be independent uniform auxiliary polynomials. Fix $z\in E$, distinct base-field query points $Q\subset F$, and an externally fixed $\alpha\in E$. These are algebraic hypotheses. They do not assert independence for the actual Fiat Shamir transcript.

Let $m_z\in F[X]$ be the minimal polynomial of $z$, and assume $Q$ avoids its roots. Define

$$V(X)=m_z(X)\prod_{x\in Q}(X-x),\qquad t=\deg V\le N.$$

Condition on each individual $A_j(z)$ and every $A_j(x)$ for $x\in Q$, using a nonempty observation fiber. The differences between admissible auxiliary columns are exactly

$$\Delta A_j(X)=V(X)S_j(X),\qquad S_j\in F[X]_{<N-t}.$$

The minimal polynomial is necessary because a base-field polynomial's extension evaluation also fixes its Galois conjugates. The reduced auxiliary contribution is

$$T_\alpha(X)=\sum_{j=0}^{e+r-1}\alpha^j\frac{A_j(X)-A_j(z)}{X-z}.$$

Its conditional differences are

$$\Delta T_\alpha(X)=P_z(X)\sum_j\alpha^jS_j(X),\qquad P_z(X)=\frac{V(X)}{X-z}.$$

If $\operatorname{span}_F\{1,\alpha,\ldots,\alpha^{e+r-1}\}=E$, the coefficient map is surjective with equal fibers. Consequently $T_\alpha$ is uniform on an affine translate of

$$P_z(X)E[X]_{<N-t}.$$

This is the kernel of evaluation, among polynomials of degree less than $N-1$, at the nontrivial Galois conjugates of $z$ together with $Q$. It is smaller than the unconstrained polynomial space. Treating all separately opened columns as a single extension-valued claim would give the wrong fiber.

For composition, consider another batch contribution $B(X)$ of degree less than $N-1$. Its values on those kernel roots are fixed by the disclosed columns if every contributing polynomial is opened at $z$, queried rows are included, and no requested point equals a nontrivial conjugate of $z$. Under independent ideal auxiliary entropy, changing $B$ within that same observation fiber can then be absorbed by a translation of the auxiliary kernel. This gives the conditional isolation argument. It supplies neither the distribution of the main and quotient observations nor their hash compilation.

For the actual trace translate, conjugate collision is excluded algebraically when $z\ne0$ and $\operatorname{ord}(g)=H>e$. If $z^{p^k}=gz$, iteration $e/\gcd(e,k)$ times implies $g^{e/\gcd(e,k)}=1$, contradicting its order. At $z=0$ the conjugate orbit is a singleton. This source geometry does not add a resampling or rejection policy.

## Rank condition

When at least $e$ consecutive powers are present, full extension degree of $\alpha$ suffices. Proper-subfield challenges can give a smaller image. In degree four, the union of proper subfields is $\mathbb F_{p^2}$. Its measure under an ideal uniform draw is $p^2/p^4$. This counts a rank exception. It is not an achieved privacy error, a soundness score or a probability proved for the implemented transcript.

The reference includes a synthetic translated-word change that lies outside the auxiliary image at sixteen nonzero base-field challenges. This disproves an unconditional full-space isolation claim in that example. It does not exhibit a distinguishing actual FRI transcript, a satisfiable Kova witness pair or an accepted invalid proof. The retained source already describes its auxiliary construction as statistical rather than perfect zero-knowledge. No challenge filter, authorization primitive or profile change is selected here.

## Independent reference

The [reference](reference.py) uses integer arithmetic in $\mathbb F_{17}[u]/(u^2-3)$. It imports no production field or earlier model. Its degree bound eight, extension degree two and four auxiliary columns are finite oracle algebra cases. They instantiate no proof backend or production profile.

Take $z=u$, $g=4$ and $Q=\{3\}$. The [saved literals](fixtures/literals.json) independently specify

$$V=(X^2-3)(X-3),\quad P_z=(X+u)(X-3),\quad M=(X^2-3)(X^2+3)(X-3).$$

The polynomial $M$ preserves both current and translated claims and the queried base value. Its two divided differences have separately saved coefficients. For $\alpha=1$, the source-shaped batch shift has kernel coordinates

$$\frac{M/(X-u)+M/(X-4u)}{P_z}=8+3uX+2X^2.$$

One guarded run checked all 289 challenges and 83,521 first-basis assignments. The 272 full-degree challenges give bijective first-basis maps and actual translated-shift coverage. Seventeen base challenges have rank one. A separate four-column enumeration checked 83,521 assignments with 289 equal preimages for each extension value. Five polynomial modes and six hostile alternatives with restored checks passed.

The hostile alternatives omit a conjugate, omit the queried-row constraint, condition only a composite claim, replace actual challenge powers by a fixed extension basis, collapse the translated point, or reverse only a denominator sign. These are arithmetic controls, not cryptographic verifier rejections.

The [validation record](validation.json) reports the unchanged external limits: 512 MiB process and aggregate job commit, 2 GiB freshly available memory and a 120 second deadline. Observed private commit was 8,781,824 bytes and aggregate job commit was 10,088,448 bytes. These are small reference measurements. They admit no wide construction. No Rust, production field, RNG, MMCS, challenger, owner, witness walk, prover or verifier ran.

The runtime command is `python -I -S research/joint-hiding/reference.py`. It requires a separately reviewed finite admission and `KOVA_JOINT_HIDING_GATE=reviewed-external-resource-admission`. The [external guard](run_guarded_windows.ps1) installs the recorded limits and fresh memory check. Result creation is exclusive. Reproduction requires a newly reviewed snapshot and result destination. The static evidence checker reads saved identities and records without executing the reference.

## Primary source and remaining composition

Haböck and Al Kindi's [author copy](https://www.researchgate.net/profile/Ulrich-Haboeck/publication/381742262_A_note_on_adding_zero-knowledge_to_STARKs/links/6a2d569bd551e312d7201973/A-note-on-adding-zero-knowledge-to-STARKs.pdf) is dated 20 February 2025 and has 21 pages. The [archive](https://eprint.iacr.org/2024/1037) records its latest revision on 22 February 2025. Lemmas 1 and 2 separate field-evaluation masking from auxiliary isolation. Section 4.2, Lemma 5 and Theorem 8 treat normalized Lagrange quotient masking in an ideal honest-verifier oracle protocol. The complete author text was reviewed. Typeset formula inspection and a raw PDF identity were unavailable, so this record does not assert archive byte equality or apply those theorems to Kova.

The conditional result above fixes one precise auxiliary correspondence. Complete composition still needs the joint main and coupled quotient observation distribution, actual challenge generation, salt and hash assumptions, repeated proofs, concurrent views and knowledge analysis. The derived eighth quotient mask remains dependent. Parent RNG journals omit child salt streams. The original private flag prevents reopening one authority and does not establish privacy across fresh proofs of one witness.

The complete signature remains outside the existing width and resource classes. The same hidden witness must ultimately bind membership, note ownership, authorization, stable nullifier, conservation, encrypted delivery and atomic ledger consumption. Private payments remain the default requirement. No payment acceptance or network capability is provided.
