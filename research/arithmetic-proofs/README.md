# Exact modular multiplication references

This reference corpus defines exact canonical multiplication modulo $q=8380417$ over an AIR whose base field prime is $p=2013265921$. Its test harness publishes operands and result while keeping the quotient and auxiliary carries in the witness. That visibility is a primitive experiment boundary. It does not establish private NTT arithmetic, ML-DSA verification, owner permission, complete transaction coupling or a production payment path.

The construction uses integer bounds to prevent replacing multiplication modulo $q$ with a weaker equality modulo the unrelated AIR field $p$.

## Canonical values and radix equations

Set $B=4096=2^{12}$, so

$$
q=2046B+1.
$$

The four canonical integers are $x,y,k,z\in[0,q-1]$. Each has a 23 bit little endian Boolean representation and an independently constrained 23 bit nonnegative complement $\bar v$. Its range equation is

$$
v+\bar v=q-1.
$$

Before that equality is interpreted over integers, Boolean bits give $0\le v,\bar v\le2^{23}-1$. Its residual therefore lies in

$$
-(q-1)\le v+\bar v-(q-1)\le2(2^{23}-1)-(q-1),
$$

or exactly $[-8380416,8396798]$, strictly inside $(-p,p)$. A zero residual in the AIR field is consequently zero as an integer. The nonnegative complement then proves $v\le q-1$. This argument is required before applying canonical limb bounds.

Split each value into a low 12 bit and high 11 bit limb:

$$
v=v_0+Bv_1,
\qquad
0\le v_0\le4095,
\qquad
0\le v_1\le2046.
$$

The high limb bound follows from canonicality rather than the 11 bit width alone. A high limb of 2046 permits only low limb zero, but the conservative boxes below do not need that extra correlation.

For signed carries $c_0,c_1$, define

$$
R_0=x_0y_0-k_0-z_0-Bc_0,
$$

$$
R_1=x_0y_1+x_1y_0-2046k_0-k_1-z_1+c_0-Bc_1,
$$

$$
R_2=x_1y_1-2046k_1+c_1.
$$

The carries use nonnegative shifted bit encodings:

$$
u_0=c_0+2\in[0,8191],
\qquad
u_1=c_1+4096\in[0,16383].
$$

Thus 13 Boolean bits give $c_0\in[-2,8189]$, and 14 give $c_1\in[-4096,12287]$. A negative signed carry is represented by subtracting its fixed shift inside the field. An arbitrary negative field residue cannot substitute for this bounded bit encoding.

## Residual bounds and exact soundness

Using only the established canonical limb bounds and all allowed shifted carry values gives these conservative integer intervals:

| Residual | Lower bound | Upper bound |
|---|---:|---:|
| $R_0$ | $-33550334$ | $16777217$ |
| $R_1$ | $-58710016$ | $33542145$ |
| $R_2$ | $-4190212$ | $4198403$ |

For example,

$$
R_1\ge-2046\cdot4095-2046-2046-2-4096\cdot12287=-58710016,
$$

and

$$
R_1\le2\cdot4095\cdot2046+8189+4096\cdot4096=33542145.
$$

All intervals lie strictly between $-p$ and $p$. Therefore the three required field equalities $R_i=0\pmod p$ imply exact integer equalities $R_i=0$. The recombination identity is

$$
R_0+BR_1+B^2R_2=xy-qk-z.
$$

Both carries cancel. The canonicality and exact limb constraints imply $xy=qk+z$ over integers. Since $0\le z<q$ and $k\ge0$, the witness quotient and result are the unique Euclidean values

$$
k=\left\lfloor\frac{xy}{q}\right\rfloor,
\qquad
z=xy\bmod q.
$$

This is an arithmetic argument under the recorded bit and equality constraints. It is not a cryptographic proof system security argument or independent audit.

## Completeness and carry ranges

For any canonical $x,y$, set $(k,z)=\operatorname{divmod}(xy,q)$. The maximum quotient is $q-2$, because $(q-1)^2=q(q-2)+1$. The result is canonical by Euclidean division.

The low equation numerator lies in $[-8190,16769025]$. It is divisible by $B$ for a valid exact product. Hence its integer carry satisfies

$$
-1\le c_0\le4094.
$$

Using that bound, the middle equation numerator lies in $[-8382463,16760834]$ and is likewise divisible by $B$, giving the conservative valid carry interval

$$
-2046\le c_1\le4092.
$$

Both valid intervals fit strictly inside the encoded intervals. The high equation follows from the recombination identity after the first two equations are exact. Thus the selected bit widths admit every canonical product without silently excluding a valid residue. The carry boxes are conservative, and the document does not claim that every endpoint is attainable.

The fixture $(x,y)=(20479,6705151)$ gives $(k,z)=(16385,1654784)$ and $c_0=4094$, so the first carry's upper bound is attained. The corner $x=y=q-1$ gives $c_0=-1$ and $c_1=-2046$.

## Genuine AIR field aliases

The canonical values

$$
x=y=8380416,
\qquad
k=8380174,
\qquad
z=6414577
$$

satisfy

$$
xy-qk-z=2013265921=p.
$$

A naive field check accepts this false integer product. The regular bounded carry trace fails the limb equations.

There is a stronger altered trace whose three field limb equations all vanish. Use the same canonical values and correct complements, with shifted carries

$$
u_0=2012774402,
\qquad
u_1=2050.
$$

Put $u_0$ into the first carry bit cell and set the remaining carry zero bits to zero. The second carry has an ordinary 14 bit representation. The resulting integer limb residuals are

$$
(R_0,R_1,R_2)=(-8244323946495,2013265921,0),
$$

all multiples of $p$. Canonical values, complements and public bindings remain correct, but the first carry bit is nonboolean. The Boolean carry constraint rejects this trace. It isolates the need for bounded carries rather than relying on an already broken field multiplication equality.

Additional aliases cover residuals $\pm p$, $\pm2p$ and $\pm4p$. Cases with ordinary floor carries fail the field limb equations. Separate cases supply modular field carries and retain all three field equalities while failing carry bit constraints.

The public harness binds every public byte individually to its corresponding 8, 8 and 7 bit chunks, with a zero fourth byte. Bytewise unsigned values $v$ and $v+p$ are distinct even though compressing them to one AIR field element would make them equal. The separate API corpus includes $x+p$, $y+p$ and $z+p$ with otherwise valid rows. These fail both the actual bytewise AIR bindings and typed statement validation. The diagnostic `naive_packed_public_bindings_valid` records acceptance by the deliberately weaker packed equality, without attributing that behavior to the implemented wrapper.

## Fixture format and scope

`multiplication_vectors.json` has 206 cases, including 166 valid products and 40 rejections. Cases cover corners zero, one and $q-1$, radix and high bit boundaries, the attained first carry upper bound, 128 deterministic pairs, wrong quotient and remainder, noncanonical private values, malformed complements, nonboolean bits, signed carry endpoints, negative carry aliases and false field products. `api_rejections.json` has nine invalid public statements.

Each case includes a public statement, complete 76 element public vector, raw 211 field cells for one repeated witness row, expected classifications and independently computed integer diagnostics. Offsets are:

| Cells | Offset | Width |
|---|---:|---:|
| Value bits for $x,y,k,z$ | 0 | $4\cdot23$ |
| Complement bits in the same order | 92 | $4\cdot23$ |
| Shifted carry zero bits | 184 | 13 |
| Shifted carry one bits | 197 | 14 |

The tiny harness repeats the row through its fixed 256 row trace. Its public vector is `u32le(x) || u32le(y) || u32le(z) || context64`. `context` is opaque transcript data. Raw nonboolean cells are canonical AIR field representatives, allowing the corpus to test field aliases without pretending that malformed cells have valid bit encodings.

The generator uses only Python integers and standard library modules. It neither imports Rust nor a proof backend. Deterministic pairs use an explicit xorshift64 recurrence rather than production entropy. `bounds.json` records formulas, intervals and proof steps independently of prototype checks.

`hash_vectors.csv` supplies independent full digest goldens for `thorum.arithmetic-proof-lab.leaf.v1`, `thorum.arithmetic-proof-lab.node.v1` and `thorum.arithmetic-proof-lab.transcript.v1`. Their complete framed preimages, SHA3-512 outputs and little endian word encodings are retained separately from the multiplication relation.

```text
python research/arithmetic-proofs/reference_vectors.py --check
python research/arithmetic-proofs/profile_check.py
cargo test -p thorum-arithmetic-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-arithmetic-proof-lab --release --locked --offline -- --test-threads=1
```

The generator checks and rewrites deterministic reference files only. It does not create or verify a STARK proof. Oracle classification, actual AIR checks and raw invalid proof verification are separate evidence. No source license, parameter set, production encoding, mode, nullifier identity or payment privacy default is changed by this component.

Future private authorization must keep owner keys, signatures, derived matrices and intermediate values internal, with explicit connections to the same hidden note and exact signed transaction. This multiplication gadget alone does not constrain signed coefficient conversions, NTT dataflow, rejection sampling, `UseHint`, `w1` packing, signature challenge equality or the complete owner relation. A public operand harness is not a private authorization protocol.
