# Exact modular multiplication proof laboratory

## Implementation boundary

The [arithmetic component](../crates/thorum-arithmetic-proof-lab/src/lib.rs) proves exact canonical multiplication modulo $q=8380417$, using bounded integer limbs over the different AIR field prime $p=2013265921$. The reusable multiplication constraints are a foundation for later private ML-DSA arithmetic. The isolated harness publishes its operands and result while keeping quotient and carry witnesses internal.

This component does not implement an NTT, signature verification, owner authorization or complete transaction coupling. The public operand interface is a primitive test boundary rather than a production payment route. Future composition must keep owner keys, signatures, derived matrices and intermediate values private, with constrained dataflow to the same hidden note and exact authorized transaction.

The existing hidden input commitments, stable nullifiers and private payment default remain unchanged. The separate [SHA3 and SHAKE component](hash-proof-lab.md) supplies another prerequisite. Neither primitive alone or their separate acceptance establishes private ownership. Complete private payment and confidential stake feasibility remain required before kernel integration.

## Exact arithmetic relation

Let $B=4096=2^{12}$, so $q=2046B+1$. The four private gadget values satisfy $x,y,k,z\in[0,q-1]$ and the intended integer relation

$$
xy=qk+z.
$$

Every value has 23 Boolean bits and a 23 bit nonnegative complement satisfying $v+\bar v=q-1$. The complement residual is bounded by $[-8380416,8396798]$, strictly inside $(-p,p)$, so the field equality is exact integer equality. This establishes canonicality before the limb argument.

Split $v=v_0+Bv_1$, with $0\le v_0\le4095$ and $0\le v_1\le2046$. Define signed carries through 13 and 14 Boolean shifted bits:

$$
c_0+2\in[0,8191],
\qquad
c_1+4096\in[0,16383].
$$

The three constrained residuals are

$$
R_0=x_0y_0-k_0-z_0-Bc_0,
$$

$$
R_1=x_0y_1+x_1y_0-2046k_0-k_1-z_1+c_0-Bc_1,
$$

$$
R_2=x_1y_1-2046k_1+c_1.
$$

| Residual | Conservative integer range under all allowed encoded carries |
|---|---|
| $R_0$ | $[-33550334,16777217]$ |
| $R_1$ | $[-58710016,33542145]$ |
| $R_2$ | $[-4190212,4198403]$ |

Each interval lies strictly between $-p$ and $p$. Thus $R_i=0$ in the AIR field implies $R_i=0$ as an integer. The identity

$$
R_0+BR_1+B^2R_2=xy-qk-z
$$

cancels both carries. Together with canonicality, it proves the unique Euclidean quotient and remainder. A single unbounded field equation would not supply this argument.

Completeness follows by taking $(k,z)=\operatorname{divmod}(xy,q)$. Then $k\le q-2$ and $z<q$. The exact low and middle equations give conservative valid carry bounds $c_0\in[-1,4094]$ and $c_1\in[-2046,4092]$, both inside their encoded intervals. These are conservative boxes rather than a claim that every endpoint is attainable. The [independent derivation](../research/arithmetic-proofs/README.md) records every bound and dependency.

For example, canonical values $x=y=8380416$, $k=8380174$ and $z=6414577$ have integer residual $p$. A naive field product check accepts them. Stronger altered traces can also make all three field limb equations zero with an unbounded carry. The Boolean shifted carry constraints reject those cases.

## Public harness and reusable gadget

`Statement::new(x: u32, y: u32, z: u32, context: [u8;64])` requires each public value to be below $q$. Proving and verification repeat this validation. `Witness::for_operands(x,y)` constructs the Euclidean quotient and carries for canonical operands. The witness has no plaintext export or general serialization interface.

`prove_mod_mul(&Witness, &Statement)` produces proof bytes or an error. `verify_mod_mul(&[u8], &Statement)` receives an independently supplied expected statement and no private witness. Successful witness construction or a local host check cannot substitute for cryptographic verification.

The harness's public vector has 76 base field elements:

$$
\operatorname{u32le}(x)\mathbin\Vert
\operatorname{u32le}(y)\mathbin\Vert
\operatorname{u32le}(z)\mathbin\Vert
\operatorname{context}_{64}.
$$

Each public byte is linked individually to the corresponding 8, 8 and 7 value bits, followed by a zero fourth byte. The AIR rejects byte distinct $v$ and $v+p$ even though their packed field elements coincide. Typed canonical validation supplies a separate boundary. The 64 byte context is opaque transcript data and does not authenticate a transaction.

The reusable `mul` constraints expose reconstructed canonical values for future private wiring. The wrapper additionally holds all 211 cells constant through its 256 row trace. Its public bindings do not define how a future private NTT or owner proof should expose data. That future relation must explicitly connect each multiplication to its actual private inputs and outputs.

The evaluator requires `AirBuilder<F = BabyBear>`. Its no wrap bounds use the exact prime 2013265921 and do not establish portability to arbitrary smaller fields.

The same crate exposes reusable [coefficient and hint constraints](coefficient-constraints.md). `packing` constrains five byte windows, strict response norms and canonical signed conversion. `hints` constrains exact decomposition, strict low part signs and hint application. Their returned expressions need connection to the same hidden key, signature and reconstruction in a complete verifier. A test only hiding proof harness exercises hint arithmetic, false proof rejection and canonical transport with public synthetic diagnostics. It adds no production signature acceptance interface and leaves the multiplication profile below unchanged.

## Proof profile

The profile is `thorum.arithmetic-proof-lab.modq8380417.mul.radix4096.serial.p3-0.8.0.v1`. Existing proof profiles and note identities remain unchanged.

| Property | Fixed value |
|---|---|
| Original trace | 256 rows and 211 columns |
| Stored hiding degree | Nine bits, with 512 extended rows |
| Maximum symbolic constraint degree | Two |
| Public vector | 76 field elements |
| FRI queries and log blowup | 64 queries and 2 |
| FRI folding rounds | Nine |
| Quotient chunks | Four chunks of four extension elements |
| Challenge extension | Degree 4 over BabyBear |
| Random codewords | Four |
| Merkle salts | 16 base field elements per committed row |
| Grinding difficulties | Zero bits |
| Proof byte cap | 2,097,152 bytes |

Both commitment layers use the inspected hiding configuration with fresh operating system seeded private randomness for every proof. Verification requires no fresh entropy. The mask budget condition is $256\ge2(64+4\cdot2)=144$. These declarations are configuration evidence, without an independent zero knowledge or quantum knowledge soundness argument. The [profile guard](../research/arithmetic-proofs/profile_check.py) records fixed declarations and resolved dependency features.

The adapter namespaces are `thorum.arithmetic-proof-lab.leaf.v1`, `thorum.arithmetic-proof-lab.node.v1` and `thorum.arithmetic-proof-lab.transcript.v1`. They retain full SHA3-512 digests. The upstream composition still includes fixed Keccak256 metadata fingerprints. Digest width alone does not establish a composed security level.

Transport validation bounds bytes, JSON structure and typed proof dimensions before backend verification. Limits are depth 24, 200,000 tokens, 16,384 collection items, 64 string bytes and 20 digits per unsigned integer. Canonical reencoding and fixed shape checks cover degree, trace widths, roots, quotient and randomization dimensions, queries, nine FRI rounds, salts and bounded Merkle paths. These are acceptance limits rather than runtime or memory measurements.

## Independent evidence and remaining work

The [reference corpus](../research/arithmetic-proofs/README.md) records 206 classified traces with 166 valid products, nine invalid public statements, independent integer bounds and three proof adapter goldens. It includes canonical corners, radix boundaries, an attained carry endpoint, deterministic pairs, malformed complements, noncanonical values, negative carry aliases and genuine false field products. Deliberately weaker naive field checks are reported separately from the implemented bytewise harness and bounded arithmetic constraints.

Reference classifications, actual AIR comparison and raw invalid proof rejection concern separate boundaries. Finite tests and the arithmetic argument do not constitute an audit of the proof backend or complete protocol.

| Validation boundary | Executable coverage |
|---|---|
| Independent arithmetic relations | All 206 cases and their 76 field public vectors checked against the actual AIR |
| Honest witness construction | All 166 valid cases match the independent 211 cell row at every trace row |
| Integer aliases | Canonical false products with residuals equal to nonzero multiples of the BabyBear modulus fail the bounded constraints |
| Range and byte binding | Ten causal attacks cover nonboolean carries, noncanonical values, bit aliases and byte distinct public integers |
| Cryptographic rejection | Seven raw invalid proofs bypass witness prechecks and fail actual backend verification |
| Public binding | All 76 public fields and a different proof profile fail verification after mutation |
| Public primitive interface | Real proofs cover zero, maximal operands and an attained carry endpoint, with changed result and context rejection |

Separate tests distinguish the reusable evaluator's row local equations from the wrapper's constant trace. A future composed program must supply its own correct dataflow. The primitive operands and result are public in this harness, and the quotient is mathematically recoverable from them. This harness therefore supplies arithmetic evidence rather than a private ownership capability.

Separate components implement canonical [key sources](key-source.md), [signature decoding](signature-challenge.md), bounded [matrix sampling](matrix-sampling.md), [challenge sampling](challenge-sampling.md) and [conditional row reconstruction](reconstructed-row.md). Remaining private authorization work connects those exact producers, transforms, hints and all eight packed row outputs to full final challenge equality in the same valid signature and hidden note relation. Cached host values cannot replace constrained derivations. A valid owner authorization must bind the same complete transaction, including its root, nullifiers, outputs, delivery bytes, fee and authenticated context.

Global spent state, eligible roots, authenticated recipient delivery, recovery, confidential staking and metadata evaluation retain their existing gates. The corpus contains deterministic public synthetic fixtures rather than entropy evidence. No new timing, peak memory, throughput, independent audit or quantum security result is asserted. Historical measurements retain their original versions and workloads.
