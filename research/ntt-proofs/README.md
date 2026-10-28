# Normal residue NTT references

This corpus defines length 256 forward and inverse transforms over $q=8380417$ with primitive 512th root $\psi=1753$. Coefficients are canonical unsigned normal residues. The test harness publishes input and output polynomials, mode and context. This is a primitive validation boundary, without a private signature, owner authorization, signed coefficient decoder or production payment route.

The schedule follows the normal residue algorithms in the pinned `ml-dsa 0.1.1` source and NIST FIPS 204 Algorithms 41 and 42. The package's `module-lattice 0.2.3` dependency supplies generic algebra. `source_record.json` retains exact source commits, paths and hashes. The independent generator imports neither Rust source nor a proof backend. Required source attribution remains separate from the independently implemented arithmetic oracle.

## Independent transform definition

Let $\operatorname{rev}_8(i)$ reverse the eight binary digits of $i$. Define

$$
r_i=\psi^{2\operatorname{rev}_8(i)+1}\bmod q,
\qquad 0\le i<256.
$$

The checks $\psi^{256}=q-1$ and $\psi^{512}=1$ establish the required order. All 256 points are distinct roots of $X^{256}+1$.

For input coefficients $a_0,\ldots,a_{255}$, the forward definition is direct evaluation

$$
A_i=\sum_{j=0}^{255}a_j r_i^j\pmod q.
$$

The inverse definition is

$$
a_j=256^{-1}\sum_{i=0}^{255}A_i r_i^{-j}\pmod q,
\qquad 256^{-1}=8347681\pmod q.
$$

The root sum identity gives zero for nonzero exponent differences with absolute value below 256, and 256 for difference zero. It therefore establishes the inverse formula and its exact ordering.

The generator evaluates the forward formula by Horner evaluation at each odd root. Its inverse oracle uses independently accumulated inverse root powers and the normalization factor. Neither oracle invokes butterfly stages. Both staged directions must match these direct quadratic definitions on every valid fixture. Additional round trips are consistency checks rather than the sole oracle. A matching wrong forward and inverse pair can pass round trips while violating the fixed root ordering.

## Forward schedule

For indices 1 through 255, the twiddle table is

$$
\zeta_k=\psi^{\operatorname{rev}_8(k)}\pmod q.
$$

Index zero is an unused zero sentinel to match the inspected table. It is not a used twiddle equal to $\psi^0$.

Forward stage $s\in[0,7]$ has length $L=128\mathbin{\gg}s$. Its groups have twiddle index $k=2^s+g$. Within a group, paired indices are $j$ and $j+L$. For canonical inputs $u,v$, compute

$$
t=\zeta_kv\bmod q,
\qquad
u'=u+t\bmod q,
\qquad
v'=u-t\bmod q.
$$

Each stage contains 128 butterflies, ordered by group and then local index. The eight stages use 1024 exact modular multiplications and 2048 modular sum or difference equations. The ninth recorded coefficient state is the final forward output.

## Inverse schedule and normalization

Inverse stage $s\in[0,7]$ has length $L=2^s$. Group $g$ uses decreasing table index $k=(256\mathbin{\gg}s)-1-g$ and canonical negative twiddle $q-\zeta_k$. Its butterfly is

$$
u'=u+v\bmod q,
\qquad
t=u-v\bmod q,
\qquad
v'=-\zeta_k t\bmod q.
$$

The eight inverse layers have 1024 exact modular multiplications and 2048 sum or difference equations. They produce the unnormalized inverse. Normalization multiplies all 256 coefficients by 8347681 modulo $q$, for 1280 total inverse multiplications.

The staged harness normalizes positions 0 through 127 in one row and 128 through 255 in the next. Each row must preserve the untouched half. The eleventh recorded state is the fully normalized result. A zero input can hide an omitted scale factor, so dense and basis cases independently check normalization.

The inverse here uses normal residues and inverse 256. It does not use a Montgomery normalization factor from another representation. Actual signed signature polynomial decoding and conversions to these residues remain separate constrained work.

## Exact local arithmetic

Every twiddle product and normalization product uses the exact bounded multiplication relation

$$
xy=qk+z,
\qquad x,y,k,z\in[0,q-1].
$$

The recorded auxiliary values include its quotient and both radix 4096 carries. The underlying canonical complement and bounded carry argument excludes false products that vanish only modulo the unrelated AIR prime $p=2013265921$. The corpus contains one deliberate product with integer residual exactly $p$ inside an otherwise canonical forward computation.

For canonical $u,t,u',v'$ and Boolean flags $h,b$, the forward sum and difference equations are

$$
u+t-qh-u'=0,
\qquad
u-t+qb-v'=0.
$$

Their residual ranges are respectively $[-2q+1,2q-2]$ and $[-2q+2,2q-1]$. Both lie strictly inside $(-p,p)$, so field equality is exact integer equality. Canonical outputs make the Boolean reduction and borrow flags unique. The same argument applies to inverse addition and difference before multiplication. These bounds concern the stated canonical residues rather than arbitrary signed or unbounded coefficients.

The transform proof must additionally connect every constrained product and sum to the correct input and output wires, stage, twiddle and normalization half. Valid isolated multiplication proofs do not establish that complete dataflow.

The [multiplication reference](../arithmetic-proofs/README.md) records the exact limb bounds and field alias rejection argument. The [transform laboratory](../../docs/ntt-proof-lab.md) defines the implemented wrapper and its remaining signature integration gates.

## Corpus and visibility

`ntt_vectors.json` contains 47 classified cases, including 31 valid transforms. Fifteen polynomial patterns each run in both directions: zero, basis positions 0, 1, 128 and 255, a constant polynomial, all one coefficients, all $q-1$ coefficients, two alternating patterns, a ramp, three deterministic dense polynomials and a sparse boundary pattern. A further valid transform uses a fresh public context.

The rejection cases include altered twiddles, sequential powers instead of bit reversed powers, a skipped stage, incorrect inverse signs, missing or wrong normalization, cyclic rather than negacyclic roots, wrong output ordering, a false AIR field product, wrong mode, changed input and changed output. `construction_checks` separates actual local multiplication, addition, schedule, row linkage, normalization and public output classifications. Wrong public output cases can retain a correctly computed staged witness whose final state does not equal that expected public output.

`api_rejections.json` has eight unsupported mode or noncanonical coefficient cases, including values at $q$, unsigned negative aliases and coefficient plus $p$ aliases. The public format contains canonical unsigned residues rather than an implicit signed conversion.

`stage_vectors.json` records every intermediate coefficient array for all 47 constructions. `butterfly_operations.csv` has 54016 records with wire indices, slot, stage, twiddle index, twiddle value, canonical product operands, quotient, result, carries, sum reduction, difference borrow and outputs. Normalization records identify the half and coefficient. These data are deliberately public synthetic fixtures, not actual signing polynomials or secret randomness.

`zetas.json` retains both the complete derived twiddle table and independently defined odd evaluation points. `hash_vectors.csv` supplies three full digest goldens under the separate proof adapter domains `thorum.ntt-proof-lab.leaf.v1`, `thorum.ntt-proof-lab.node.v1` and `thorum.ntt-proof-lab.transcript.v1`.

The public vector has 2113 base field elements:

$$
\operatorname{mode}_1\mathbin\Vert
\operatorname{u32le}(a_0)\mathbin\Vert\cdots\mathbin\Vert\operatorname{u32le}(a_{255})
\mathbin\Vert
\operatorname{u32le}(A_0)\mathbin\Vert\cdots\mathbin\Vert\operatorname{u32le}(A_{255})
\mathbin\Vert\operatorname{context}_{64}.
$$

Mode one selects forward and mode two selects inverse. Public coefficient bytes must be bound individually to their canonical bits. A packed field equality alone would not distinguish a coefficient from coefficient plus $p$. The context remains opaque transcript data.

The mathematical transform remains valid under a changed context, but an existing proof must fail under the changed expected statement. `statement_rebinding.json` records that separate verifier obligation. It does not misclassify a correct polynomial transform as an invalid equation merely because context changed.

## Reproduction and interpretation

| Executable boundary | Recorded result |
|---|---|
| Recorded original profile release corpus | 12 unit tests and one external integration test pass |
| Recorded original profile debug corpus | 11 unit tests and one external integration test pass |
| Real proofs | Both transform directions and fresh randomized repeated proving verify |
| Invalid proofs and constrained wiring | Seven raw false proofs fail verification, with 25 causal wiring faults and four field aliases rejected by their checks |
| Public binding | 52 targeted public mutations fail acceptance |
| Independent data | All 47 cases and 2113 public fields, 309 valid stage states and 35584 valid product, carry and flag records match |
| Adapters | Three full digest goldens match |

These test counts describe the recorded original profile corpus. The whole crate commands below also select the separately documented compact profile. The corpus retains 54016 operation rows in total, including hostile cases. The 35584 valid arithmetic comparisons refer to the valid subset rather than every retained row. These results are correctness evidence, without a performance, privacy or independent audit claim.

```text
python research/ntt-proofs/reference_vectors.py --check
python research/ntt-proofs/profile_check.py
cargo test -p thorum-ntt-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-ntt-proof-lab --release --locked --offline -- --test-threads=1
```

The generator uses Python integers and standard library modules. It neither creates nor verifies a STARK proof. Direct DFT comparison, stage reference checks, actual AIR evaluation and raw invalid proof rejection are separate evidence. Operation counts are analytical. No timing, memory, proof size, throughput or cryptographic security result is inferred from the fixture dimensions.

Private authorization must keep keys, signatures, matrices and intermediate polynomials internal to the same relation and bind the exact signed transaction. Separate components now implement coefficient conversion, canonical key and signature sources, finite samplers, hints and conditional row reconstruction. Their complete common witness linkage, all eight row challenge equality, hidden note authorization and payment composition remain unfinished. The [component map](../../README.md#proof-research-map) links those exact boundaries. Public polynomial test data do not define a production privacy mode. Hidden input commitments, stable nullifiers, private payments by default and the separate confidential stake and kernel gates remain unchanged.

The transform is invertible. A published transform output permits recovery of its input, so the public harness does not establish polynomial confidentiality. Source inspection and these deterministic vectors do not constitute complete NIST conformance validation, an audit or a composed quantum security argument.
