# Compact polynomial transform constraints

The [compact module](../crates/thorum-ntt-proof-lab/src/compact.rs) implements the exact length 256 forward and inverse normal residue transforms with eight multiplication slots and a scalar polynomial register bank. It reuses the existing `Mode`, `Statement`, `Witness`, `Error`, twiddle schedule and bounded multiplication evaluator. The original transform profile and its public API remain available with their original parameters.

This component publishes both complete polynomials in a diagnostic statement. The transform is invertible, so this boundary provides no coefficient confidentiality or spending permission. A complete private signature relation must keep these values internal and connect the same decoded coefficients, matrix arithmetic and reconstruction. The optimization does not complete private authorization or change hidden note and nullifier identities.

## Fixed register program

The modulus is $q=8380417$, primitive root $\psi=1753$ and inverse normalization factor $256^{-1}=8347681\pmod q$. The fixed program has 225 Boolean counter selectors, including terminal position 224. A 256 cell scalar bank holds the current polynomial. Eight multiplication slots use $8\cdot211=1688$ columns. Sixteen write windows use $16\cdot46=736$ columns, and sixteen flags constrain sum reduction and subtraction borrows. Total width is

$$
225+256+1688+736+16=2921.
$$

| Phase | Forward rows | Inverse rows |
|---|---|---|
| Eight input writes per row | $[0,32)$ | $[0,32)$ |
| Eight butterfly layers, sixteen chunks per layer | $[32,160)$ | $[32,160)$ |
| Eight inverse normalization products per row | None | $[160,192)$ |
| Eight output snapshots per row | $[160,192)$ | $[192,224)$ |
| Held terminal padding | Row 192 onward | Row 224 onward |

Both modes have trace height 256. Forward execution jumps from counter191 directly to terminal224, and selectors192 through223 are forced zero. Inverse execution reaches terminal224 after223. The initial selector, exact predecessor equations, one hot sum and final terminal condition prevent omitted, repeated or substituted instructions.

Each layer retains the existing group and local index ordering. Its sixteen chunks have disjoint coefficient destinations within that layer. Serial chunk updates therefore give the same complete layer result as simultaneous evaluation of all 128 butterflies.

## Canonicality by constrained induction

Every bank cell is initially zero. Each possible written value $W_s$ has 23 Boolean value bits and a 23 bit complement with

$$
W_s+\bar W_s=q-1.
$$

For bank position $i$, exact routing constrains

$$
B'_i=B_i+\sum_{(p,s)\to i}PC_p(W_s-B_i).
$$

The fixed one hot counter selects at most one authorized write to a position. Every other position is held, including output and padding rows. Zero initialization, canonical writes and complete transitions establish that every bank value remains canonical. A host range check, an uninitialized private bank or omitted hold equations cannot replace this induction.

Public coefficients use separate little endian byte pins with eight, eight, seven and zero bits. This excludes byte distinct integers differing by the AIR field prime. Output snapshots are connected to the current bank without writing it. The public vector retains 2113 fields: mode, 256 input u32 byte groups, 256 output groups and a 64 byte opaque context.

## Exact arithmetic

Every row evaluates all eight bounded multiplication gadgets. On nonarithmetic rows both operands are constrained zero. Boolean sum and borrow flags are zero outside butterfly instructions. Unused write windows and all padding writes have explicit zero rules.

For a forward butterfly, let $t=\zeta b\bmod q$. Its canonical writes are

$$
W_0=a+t-qc_+,\qquad W_1=a-t+qc_-.
$$

For an inverse butterfly, the canonical difference is $d=a-b+qc_-$, with writes $W_0=a+b-qc_+$ and $W_1=\zeta d\bmod q$. Every product uses the retained exact limb constraints, rather than multiplication modulo the unrelated AIR field. Inverse normalization constrains all 256 products by the fixed factor.

Algebraic selection connects each slot to its exact current bank operands. Destination routing is fixed verifier data derived from mode and program. It is not a private witness supplied schedule. Actual derived symbolic degree is two in both modes; no declared degree hint replaces that calculation.

## Separate proof profile

The interface is `compact::prove_compact_ntt(&Witness,&Statement)` and `compact::verify_compact_ntt(&[u8],&Statement)`. The types are shared with the existing module, while proof profiles and namespaces remain distinct. A compact proof is rejected by the original verifier.

| Property | Fixed compact value |
|---|---|
| Profile | `thorum.compact-ntt-proof-lab.modq8380417.radix4096.eight-slots.p3-0.8.0.v1` |
| Original trace | 256 rows, 2921 columns |
| Stored hiding degree and actual degree | Nine bits and degree two |
| Public fields | 2113 |
| Quotient chunks and FRI rounds | Four chunks of four extension elements and nine binary rounds |
| FRI queries and log blowup | 64 and 2 |
| Random codewords and row salts | Four and sixteen base field elements |
| Grinding work | Zero |
| Proof transport caps | 8 MiB, 2000000 tokens, 8192 collection members |
| Other scanner bounds | Depth24, unescaped strings64 bytes, unsigned integers20 decimal digits |

Both commitment layers retain the hiding configuration and independent fresh OS seeded proving generators. Verification requires no private entropy. Full SHA3-512 adapter domains are `thorum.compact-ntt-proof-lab.leaf.v1`, `node.v1` and `transcript.v1`. The trace satisfies the local mask budget $256\ge2(64+4\cdot2)=144$. Canonical reencoding and exact fixed shape checks precede backend verification. These declarations supply no whole protocol zero knowledge or quantum knowledge soundness argument.

## Evidence and resource boundary

The [reference record](../research/compact-ntt/README.md) retains the same 47 transform classifications, 31 valid direct DFT cases, 309 valid stage states and 35584 valid arithmetic records. The new schedule matches their complete public vectors, layer boundaries, products, quotients, carries and reduction flags. References retain their original versions and hashes.

Causal tests keep local multiplication exact while substituting twiddles, operands, destinations, initial state, normalization or output/padding holds. A separate set of 169 hostile AIR checks covers every product slot and write destination, including noncanonical final values that bypass typed statement checks. Actual backend tests include inverse verification, fresh repeated proofs, 52 targeted public field mutations, four bytewise field aliases, a different profile and 25 transport corruptions. Eight raw false proofs bypass local prechecks and are rejected directly by cryptographic verification.

At four bytes per base field cell, raw trace payload is $256\cdot2921\cdot4=2991104$ bytes. With hiding expansion two and blowup four, the main trace LDE payload is

$$
256\cdot2\cdot4\cdot(2921+4)\cdot4=23961600\text{ bytes}.
$$

These are array dimension calculations. They exclude trace copies, quotient and masking arrays, commitment trees, extension elements, FFT scratch and serialization. They are not measured peak memory, runtime, throughput or full signature feasibility. No historical benchmark is rewritten and no new performance comparison is asserted.

Future private use must constrain exact canonical initialization, every register lifetime and the same internal final coefficients. Private sampling, complete signature parsing, matrix multiplication, hint application, challenge equality, hidden note linkage and exact transaction authorization still require one connected relation or a separately reviewed private composition.
