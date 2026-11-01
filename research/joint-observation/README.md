# Joint trace and quotient observations

This laboratory derives a conditional oracle argument for the main trace and normalized coupled quotient masks. It includes query points on original quotient chunk domains, where one mask vanishes. A finite independent integer reference checks those observation fibers, translated main queries and quotient degree assumptions. This is not a complete privacy simulator or a payment proof.

## Honest quotient and reconstruction degree

The actual small [AIR](../storage-pcs/tests/common/air.rs) asserts a quartic equation, a selected transition, and first and last boundaries. With masked trace degree at most $2H-1$, its constraint degrees are bounded by $8H-4$, $2H$, $3H-2$ and $3H-2$. The retained raw-domain selectors have degrees $1$, $H-1$ and $H-1$. They are polynomial selectors even though their evaluation formulas use canceled quotients.

For an honest relation-satisfying trace, every constraint vanishes on the raw trace subgroup. Therefore its folded polynomial $C_\alpha$ is divisible by $Z_H=X^H-1$, giving

$$\deg Q=\deg(C_\alpha/Z_H)\le7H-4<8H.$$

The original construction on $8H$ points consequently determines this honest quotient everywhere. In contrast, the earlier [candidate envelope](../quotient-basis/README.md) of $10H-1$ bounds $C_\alpha-Z_HR$ for a candidate reconstruction $R$. It does not bound the honest quotient. These are different polynomial questions. The complete overlay still needs its own actual selector and degree correspondence before this small-AIR conclusion can be applied to it.

## Normalized observation fibers

Write the eight original quotient cosets as $H_i=s_iH$, and define

$$Z_i(X)=X^H/s_i^H-1,\qquad L_i(X)=\gamma_i\prod_{j\ne i}Z_j(X).$$

The actual equal-size split has $\gamma_i=-1/8$. Its seven independently sampled masks and derived final mask satisfy

$$\widehat q_i=q_i+Z_it_i,\qquad t_7=-\sum_{i<7}t_i,\qquad Q=\sum_iL_i\widehat q_i.$$

The [source kernel](../storage-pcs/backend/src/storage.rs) has exactly these physical coordinates. Its coefficient update subtracts $g_0^km_{i,k}$ at degree $k$ and adds $(g_0/s_i)^Hg_0^km_{i,k}$ at degree $H+k$. On the physical coordinate $x=g_0Y$, this is $Z_i(x)\sum_km_{i,k}x^k$.

In the retained small class, the reconstruction union $g_0H_{2048}$ lies inside physical $D=g_0H_{4096}$. A query can therefore lie on an original $H_i$. At such an anchor, $L_i=1$, the other reconstruction weights are zero, and the selected chunk is fixed to $Q(x)$. It is not independently uniform. The other seven coordinates can still vary.

At a point outside all original cosets, every $Z_i$ is nonzero. Scaling the seven-dimensional mask constraint gives the kernel of the reconstruction row. At an anchor in $H_i$, the other seven mask values vary freely and their output is exactly the kernel fixing coordinate $i$. Thus the image remains the recomposition kernel at both types of point.

For several observations, close the extension point $z$ under its Galois orbit and add the distinct base query set $Q_D$. If this set has at most $H$ points, evaluation of each uniform base-field mask polynomial is surjective onto the Galois-consistent observation space. The coefficient coupling then gives uniformity on the joint recomposition fiber. This is conditional on ideal independent field masks. It is not a claim about the distribution of a hash commitment or the actual challenger.

## Main trace closure and coordinate claims

The corresponding main observation closure is

$$K=\operatorname{Gal}(z)\cup g\operatorname{Gal}(z)\cup Q_D\cup gQ_D.$$

Here $g$ is the raw trace subgroup generator. It preserves the physical evaluation domain. Omitting $gQ_D$ loses the main values needed to compute transition constraints at quotient queries. The base-field randomizer has the form $Z_Hr$ with $\deg r<H$. If $K$ avoids the raw trace subgroup and $|K|\le H$, its evaluations cover the required Galois-consistent space independently of the original witness values. Serialized duplicate rows remain distinct transport contents even when their algebraic points coincide.

The [kernel](../quotient-source/src/quotient_kernel.rs) uses assertion coefficient $\alpha^{m-1-j}$ for assertion $j$. For a fixed extension basis $\beta_k$, write that coefficient as $\sum_k\beta_kc_{j,k}$ with $c_{j,k}$ in the base field. The actual base-coordinate quotient polynomial is

$$Q_k(X)=\frac{\sum_jc_{j,k}P_j(X)}{Z_H(X)}.$$

Its extension evaluation $Q_k(z)$ can be derived from the masked main values and known selectors. Taking basis coordinates of the combined value $Q(z)$ afterward does not recover the separately disclosed $Q_k(z)$. The reference checks this distinction with independent literals.

Combining these two fibers gives a conditional joint oracle observation argument for an honest low-degree quotient and admissible points. The [auxiliary argument](../joint-hiding/README.md) remains a separate conditional step with its challenge-power rank hypothesis. Original source ownership, private flags and transcript objects are unchanged.

## Independent finite reference

The [reference](reference.py) uses only integer arithmetic in $\mathbb F_{257}[u]/(u^2-3)$. Its raw height eight, extension degree two and eight chunks form a synthetic oracle case. They instantiate no Kova backend, security profile or new execution class. It imports no prior reference or production field.

The [literals](fixtures/literals.json) independently specify generator values, normalizers, chunk powers and polynomial coefficients. A synthetic quartic and affine transition fixture has honest quotient degree 52 below its construction bound 64. It is not the actual four-assertion Kova witness.

One guarded run checked all 128 physical points as separate single-query cases, comprising 64 anchors and 64 non-anchors. For each, the mask map has rank 21 and its three-row recomposition map has rank three, with zero composition. A joint anchor and non-anchor case has ranks 28 and four in a 32-coordinate observation space. Main closure maps have ranks six, six and eight. Eight hostile alternatives exercise wrong normalization, an independent final bank, wrong coupling, missing translates, collapsed coordinate claims, reversed assertion order, degree aliasing and false anchor uniformity.

The aliasing control adds $X^{64}-241$. It preserves all 64 construction values while changing an off-construction value and an extension claim. This checks the need for the degree premise. It is not a cryptographic verifier rejection.

The [validation record](validation.json) preserves the unchanged external limits of 512 MiB process and aggregate job commit, 2 GiB freshly available memory and a 120 second deadline. Observed private commit was 9,179,136 bytes and aggregate job commit was 10,473,472 bytes. No Rust, RNG, MMCS, owner, challenger, native witness, prover or verifier ran. These small measurements admit no wide proof.

Reproduction uses `python -I -S research/joint-observation/reference.py` with a separately reviewed finite admission and `KOVA_JOINT_OBSERVATION_GATE=reviewed-external-resource-admission`. The [guard](run_guarded_windows.ps1) installs both limits and checks fresh memory. Result creation is exclusive. A new run requires a newly reviewed snapshot and result destination. The static checker inspects saved evidence without executing the reference.

## Remaining protocol obligations

Admissibility is essential. The actual uni-STARK verifier refuses $z$ on the raw trace domain. The current [owned producer](../opening-domain/src/owned_prover.rs) samples $z$ and delegates opening. Its [PCS preflight](../opening-domain/src/domain.rs) excludes the physical LDE domain, which is a different set. A verifier refusal alone does not establish producer refusal before claims disclose values. The producer's raw trace-domain policy still requires source integration. This source observation is not an executed leakage control or accepted proof attack.

The complete overlay degree correspondence, actual challenge and failure policies, seeded mask independence, salts, authenticated transcript compilation, repeated fresh proofs, concurrency and knowledge remain explicit obligations. No whole primary-paper theorem or achieved security score is asserted. Private payments and hidden inputs remain requirements across the same witness, authorization, nullifier, conservation, encrypted delivery and atomic ledger consumption. No new payment or network acceptance capability is supplied.
