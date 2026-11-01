# Exact Keccak bit relation with fixed wiring

This specification gives a whole 24 round bit relation corresponding to the retained Plonky3 0.8.0 `KeccakAir`, under explicit round and field assumptions. It specializes the [state event obligation](private-state-events.md) to immutable values and fixed references. It selects no AIR layout, copy argument, proof profile or runtime. The [source record](keccak-wiring-sources.json) identifies the actual equations, constants, generator and surrounding source.

## Coordinates and elementary equations

Use semantic coordinates $A^r[x,y,z]$ with $0\le x,y<5$, $0\le z<64$ and $0\le r\le24$. The original column arrays are stored in the other order: `a_prime[y][x][z]`. A flat lane is $x+5y$. Bit $z$ has weight $2^z$ in its lane. Four little endian 16 bit limbs represent each lane:

$$\operatorname{limb}_{\ell}(A[x,y])=\sum_{j=0}^{15}2^j A[x,y,16\ell+j],\qquad 0\le\ell<4.$$

The relation is over BabyBear, of characteristic $p=2013265921$. The argument below also works over an odd prime field with $p>65535$. Every bit node $v$ satisfies $v(v-1)=0$. For Boolean inputs, the actual retained field operations are

$$X(a,b)=a+b-2ab,\qquad N(a,b)=(1-a)b.$$

An XOR node has equation $c=X(a,b)$. An ANDNOT node has $c=N(a,b)$. An affine round constant node has $c=a$ when its fixed constant is zero and $c=1-a$ otherwise. Each output is a new immutable node. A reference to an existing node is that same variable, not a supplied read value. Gate types, input references, destination identities and constants are fixed by the supported relation, never supplied as a peer program.

All integer limb sums lie in $[0,65535]$, below $p$. Equality of two such packed limbs therefore implies equality of their 16 Boolean bits. A field equality without the Boolean restrictions would not establish that statement.

## Complete round definition

For each round $r=0,\ldots,23$, define the following in order. All coordinate arithmetic on $x,y$ is modulo five and on $z$ modulo 64.

1. For each $(x,z)$, form a four node XOR chain over $A^r[x,0,z],\ldots,A^r[x,4,z]$. Its last value is $C^r[x,z]$. The chain order is left associated in increasing $y$.
2. Define $D^r[x,z]=X(C^r[x-1,z],C^r[x+1,z-1])$.
3. Define $T^r[x,y,z]=X(A^r[x,y,z],D^r[x,z])$. Finish all these immutable values before the chi operation.
4. Define a fixed reference view, not a new value bank,

$$B^r[x,y,z]=T^r[a,b,(z+64-R[a][b])\bmod64],\qquad a=(x+3y)\bmod5,\quad b=x.$$

5. Define $V^r[x,y,z]=N(B^r[x+1,y,z],B^r[x+2,y,z])$, then $U^r[x,y,z]=X(B^r[x,y,z],V^r[x,y,z])$.
6. At $(x,y)=(0,0)$ create 64 affine nodes $A^{r+1}[0,0,z]=X(U^r[0,0,z],K[r,z])$, where the second argument is the fixed round bit. For all other coordinates, $A^{r+1}[x,y,z]$ is an alias of the already defined $U^r[x,y,z]$.

The rotation table is the actual `R` indexed as above:

```text
 0 36  3 41 18
 1 44 10 45  2
62  6 43 15 61
28 55 25 21 56
27 20 39  8 14
```

The lane map is bijective: from $(a,b)$ recover $x=b$ and $y=2(a-b)\bmod5$. Each rotation is also bijective on its 64 bit positions. Thus the view is a fixed permutation of $T$, not a new writable array. Chi must use this immutable view for all neighbors. Reading a previously written chi output would define a different function.

For the exact correspondence to the retained AIR, $K[r,z]$ means its actual `RC_BITS[r][z]`. The retained generator instead uses the corresponding `RC[r]` words. Their 24 hexadecimal literals are:

```text
0000000000000001 0000000000008082 800000000000808a 8000000080008000
000000000000808b 0000000080000001 8000000080008081 8000000000008009
000000000000008a 0000000000000088 0000000080008009 000000008000000a
000000008000808b 800000000000008b 8000000000008089 8000000000008003
8000000000008002 8000000000000080 000000000000800a 800000008000000a
8000000080008081 8000000000008080 0000000080000001 8000000080008008
```

Both original representations are retained in the source record. No constant generator or existing upstream consistency test was executed. A future evaluator must independently check every bit against these pinned words as well as the raw `RC_BITS` table. The correspondence proof uses the actual AIR table, rather than assuming a generated replacement is identical.

## Fixed references and event order

The 1,600 input bits are initialized once from the actual permutation input. Within each round, parity chains precede $D$, then $T$, then the chi nodes and finally iota. A gate reads only its named earlier producers. Its output is assigned exactly once. Round $r+1$ references the completed output of round $r$. This is a directed acyclic value relation. It needs no witness dependent sorting or arbitrary memory address in its mathematical definition.

This specialization removes the need for the dense generic permutation matrix from the abstract permutation relation. It does not implement long distance copy constraints in an AIR. If a layout creates separate read cells, their equality to the named producer must be constrained by an actual reviewed mechanism. A host map or externally supplied root would not satisfy the definition. Reusing physical storage also requires proving that every remaining reference still sees its original immutable value.

The output interface is the 1,600 references $A^{24}$. They are not new independent output values. A limb interface uses the packing expressions above. If an implementation introduces separate input or output limb variables, its packing equalities and resource cost must be added explicitly. These private permutation inputs and outputs do not replace the payment statement or its 196 public authorization values.

## Correspondence with the retained AIR

Consider a complete 24 round segment with actual one hot flags selecting rounds zero through 23, original preimage binding at round zero and all within-segment state transitions. This is a statement about that segment's input and output relation. It is not a claim about an arbitrary caller builder, an incomplete round prefix or an entire padded proof trace.

### From the bit relation to original rows

For each round, pack $A^r$ into the original `a` limbs. Store the packed original input in `preimage` throughout the segment. Set `c` to $C^r$, `c_prime` to $C^r[x,z]\mathbin\oplus C^r[x-1,z]\mathbin\oplus C^r[x+1,z-1]$, and `a_prime[y][x][z]` to $T^r[x,y,z]$. Pack $U^r$ into `a_prime_prime`, use its $(0,0)$ bits for the special decomposition and pack $A^{r+1}[0,0]$ into the final iota limbs. Set the round flags to their actual one hot values. The export flag can be zero.

The original input reconstruction follows because `c XOR c_prime` is exactly $D$. Taking parity over five theta output bits gives `c_prime`, so the original cubic parity condition holds. The fixed `b` view, chi and iota equations hold by construction. Packed state transitions hold from one round to the next. These rows therefore satisfy the retained round equations and preserve the same input and output.

### From accepted original rows to the bit relation

The reverse implication needs the original parity and range equations, not just matching honest outputs.

1. Original `c` bits are Boolean. Its XOR3 equation makes `c_prime` Boolean. Original `a_prime` bits are Boolean. The equation reconstructing each `a` limb therefore gives a unique canonical input bit vector $a=T\mathbin\oplus(c\mathbin\oplus c')$.
2. Write $s=\sum_y T[x,y,z]$. The original cubic imposes $(s-c')(s-c'-2)(s-c'-4)=0$. Since $s-c'\in[-1,5]$ and $p>65535$, this is the integer condition $s-c'\in\{0,2,4\}$. Consequently, the Boolean parity of the five $T$ bits is $c'$.
3. Since there are five rows in that parity, the parity of the reconstructed input bits is $c'\mathbin\oplus(c\mathbin\oplus c')=c$. Thus original `c` is the true input parity. Its XOR3 equation now gives the exact $D$ above. The original theta bits equal $T$ in the bit relation.
4. The original `b` accessor is the stated fixed rotation and lane map. Its ANDNOT and XOR expressions are Boolean. Canonical limb uniqueness forces `a_prime_prime` to pack exactly $U$. The separately constrained lane zero bit decomposition has those same bits, and its constant equation gives exactly the iota output.
5. Original limb transitions and canonical packing identify the next round's input bits with this output. Induction through all 24 rounds produces the specified bit relation. Its XOR chain intermediates are obtained from the already determined inputs.

This establishes equality of the two segment input and output relations under the stated assumptions. It does not establish a bijection of every auxiliary witness: the retained final export bit is not a permutation output and may have two allowed values. Choosing zero in the forward map is sufficient. The proof does not treat an unchecked round label as a valid one hot schedule.

## Sponge and padding boundaries

The [four slot wrapper](../signature-complete-native/src/keccak.rs) enforces internal slot transitions even on the final physical row. Only its last slot uses the outer transition selector. The [actual sponge](../signature-packed/src/sponge.rs) starts each six row permutation at round zero, connects rate limbs by Boolean XOR and preserves capacity limbs across continuations. A replacement must preserve those joins using its actual previous output and actual next message, not externally supplied permutation states.

The [source schedule](../signature-storage/src/program.rs) and [complete schedule](../signature-overlay/src/full_program.rs) use 72 byte SHA3-512 rates for owner and note, 136 byte SHAKE256 rates for challenge, `tr`, `mu` and final comparison, and a 168 byte SHAKE128 rate for matrix expansion. Suffix bytes are 6 and 31 respectively, with the final high bit 128. Public and hidden message sources, squeezes and continuation blocks remain those exact source functions. A permutation output alone does not establish these sponge relations.

The retained generator creates 32 rows for one real permutation and a separately computed zero-input padding block. The overlay copies the actual selected zero-input round windows for dormant intervals. Its final physical row contains a partial dummy permutation, not a terminal round duplicated arbitrarily. The 24 round bit relation selects no replacement trace padding or new height. Dropping old dummy work would require a complete new clock, selector, boundary and quotient correspondence. No padded AIR execution is admitted here.

## Exact circuit counts and execution refusal

This specific representation retains every indicated gate, including all 64 affine iota outputs even when the fixed bit is zero. It does not fold constants or remove dead values. Input reference counts include variable references. The fixed round bits are constants, not witness reads.

| Per round operation | New nodes | Input references |
|---|---:|---:|
| Five input parity chains | 1,280 | 2,560 |
| Theta difference | 320 | 640 |
| Theta state | 1,600 | 3,200 |
| Chi ANDNOT | 1,600 | 3,200 |
| Chi XOR | 1,600 | 3,200 |
| Iota affine outputs | 64 | 64 |
| Total | **6,464** | **12,864** |

All 24 rounds contain 155,136 operation nodes and 308,736 input references. With 1,600 input bits there are 156,736 distinct Boolean value nodes. Reusing the exact variables gives 156,736 Boolean equations and 155,136 gate equations, of degree at most two before any AIR placement or selectors. Fixed rho/pi references, other output aliases and repeated references add no abstract value nodes. These counts are manual specification arithmetic, not generated circuit measurements.

This is not a reduction in materialized field count. The retained 24 round column segment has $24\cdot2633=63192$ field cells. Storing each new bit node in its own field cell uses 156,736 cells, before any explicit copy mechanism or surrounding signature work. Current necessary raw bounds allow at most $256\cdot8=2048$ cells. If every listed node were materialized once with width eight, its raw height would be at least 19,592, requiring at least 32,768 rows in a power of two trace. A hypothetical one gate per row layout would instead need at least 262,144 power of two rows before other work. Neither is an implemented layout or a claim that its references fit the current next-row opening interface.

Naively applying this gate decomposition to all 414 real signature permutations gives 64,226,304 operation nodes before absorption, message binding, sampling, arithmetic, note joins or padding. Sharing input and output references must be described explicitly before deriving a complete graph. There is no measured allocation, peak, serialization, full assertion count, height/width pair, degree, quotient chunk count, mask budget, LDE or FRI schedule for a full successor here. Local degree two does not justify importing the old eight quotient chunks or experimental security profile.

The construction decision is therefore to keep the exact circuit as a mathematical correspondence and refuse its direct materialization as a prover candidate. A successor still needs an actual representation or proving construction that binds fixed references and reduces complete authenticated geometry within justified resources. Full public shape, normalized quotient coupling, auxiliary and main data, all claims and queries, duplicate rows, salts, trees, FRI, buffers, descriptors, simultaneous ownership and complete bounded proof parsing remain obligations. No resource or security class was increased.

## Independent controls and status

The existing `keccak` 0.2.2 primary package contains a full 25 lane zero-input Keccak-f1600 result and a second result after permuting that first state, attributed there to XKCP. The exact retained source and license identities are recorded for prospective independent literals. This is a local retained copy, not a newly captured original XKCP artifact or a second executed implementation. Neither that crate's tests nor any new permutation evaluator ran here.

A future finite evaluator must check the full outputs, all round constants and rotations, both witness-map directions and actual incorrect variants: swapped axes, wrong rotation direction, shifted round constants, chi using changed neighbors, incorrect ANDNOT operand order, omitted bitness, changed limb order, broken round transition, unchecked round flags and false final-state substitution. Sponge rates, suffixes, message association, capacity preservation and partial padding need separate controls if that integration is selected. These are future requirements, not test results.

Validation here is source identity, local links and whitespace only. No helper, graph generator, compiler, model, protocol hash, witness walk, proof, old test or network operation ran. The full runtime/dependency/feature/license closure still precedes any program selection. Source inspection is not an upstream or toolchain audit. Original Plonky3 MIT or Apache 2.0, Thorum MIT and RustCrypto/XKCP fixture attribution remain applicable.

The complete [private authorization relation](authorization-construction.md), [atomic transition contract](../../docs/private-transition-state.md), confidential stake, bootstrap, consensus and network gates remain open. Payments remain private by default. This circuit is not a working payment proof or blockchain. The [full delivery roadmap](../../docs/delivery-roadmap.md) remains unchanged.
