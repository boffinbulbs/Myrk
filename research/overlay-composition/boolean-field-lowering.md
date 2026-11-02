# Direct Boolean field lowering and checked cash arithmetic

## Construction status

This source and conditional mathematical construction expands an entire fixed validated word relation into Boolean equations over a genuine field. It preserves one source bit vector for every original word, all original operand occurrences and both semantic directions. It also gives checked addition equations that remain correct in characteristic two.

This is a mathematical lowering schedule. No compiler, generated circuit, field implementation, witness, prover, parser or execution class is adopted or executed. The original complete private cash program does not yet exist. The native binary multiplication part retains an explicit basis and product table obligation.

The [source record](boolean-field-lowering-sources.json) reuses retained source at [binius64 revision `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). There is no new acquisition or failed request retry.

## Actual target distinction

The [common private witness](private-witness-join.md) conservation argument and [whole encrypted output](whole-encryption-completion.md) elementary integer equations assume a prime characteristic greater than three. Their bounds justify ordinary small integer column equality in that field. They cannot be imported unchanged into the inspected binary outer scalar route, where `2=0`.

The retained wrapped entry uses `Ghash128b` and a wrapper requiring `BinaryField`. Those source types do not audit the field implementation, basis or hardware. The construction below works mathematically over any genuine field `K`. It does not select an actual field or change the original cryptographic algorithms.

The actual word predicates are ZERO, bitwise AND, full unsigned 64 by 64 bit IMUL and a six word native binary field BMUL. Operands are ordered XOR vectors of fixed shifted references. Structural validation, expected program identity, constant and public word values, valid shifts and refusal of scratch references are prerequisites.

## One global bit source

For every original constant, inout and private word allocate one 64 bit vector. Bit `j` represents ordinary integer weight `2^j`. Reuse that same vector at every original reference and repeated operand occurrence. Constant and inout bits equal the actual expected original instance values. Private words and auxiliary gate outputs remain private.

Constrain every source bit and every auxiliary gate output by

```text
b*(b-1)=0.
```

Over a genuine field this permits exactly zero and one, including in characteristic two. The expected constant one must be fixed by the actual program and verifier. A prover supplied one is insufficient.

Decoding a bit vector into an ordinary integer is a mathematical interpretation of its positions. It is not equality of that integer to its residue in `K`. In characteristic two, the field expression `sum_j 2^j*b_j` would discard every positive position and is unsuitable for this purpose.

Use separate Boolean gates

```text
AND(a,b): u=a*b
XOR(a,b): h=a+b-2*a*b.
```

For example, the XOR equation has the rank one form `(2*a)*b=a+b-h`. In characteristic two this becomes the correct linear equation. NOT is `1-a`. Each gate is uniquely determined on Boolean inputs in every characteristic. All affine forms and constant coefficients must eventually be implemented by the actual target constraint representation.

## Ordered operands and predicates

Each fixed logical shift maps a target bit to a source bit or zero. An arithmetic right shift may copy its original sign bit. Rotations permute bits. The half word variants use the original separate 32 bit halves. Apply the original inner shift before the outer shift, with the original valid amounts. No Boolean selector for a peer chosen shift is introduced.

Starting at zero, XOR every original term in its original operand order for each of the 64 bit positions. Empty operands are zero. Repeated terms are preserved and cancel through the equations. The same source bits are used wherever a word reappears.

ZERO compares every resulting operand bit to zero. AND forms the 64 pairwise AND results and compares them with the same original result operand. These equations enforce the complete original predicates on the decoded words.

## Full adder without integer field embedding

For Boolean inputs `x,y,c`, use five gate outputs:

```text
t = x XOR y
s = t XOR c
u = x AND y
v = t AND c
c_next = u XOR v.
```

If both `x,y` are one, `u=1` and `v=0`. If exactly one is one, `u=0` and `v=c`. If both are zero, both vanish. Thus `u,v` cannot both be one and `c_next` is exactly the ordinary carry bit. In all cases the decoded integers satisfy `x+y+c=s+2*c_next`.

This last identity is an ordinary integer conclusion from Boolean gate semantics. It is not an equation interpreted modulo the field characteristic.

A width `w` ripple adder starts with carry zero, applies this construction at every position and constrains the final carry to zero. It enforces exact checked `w` bit addition. Dropping that final constraint would instead allow overflow. All copied sum and carry bits remain the same constrained variables.

## Full unsigned IMUL

For input bits `a_i,b_j`, form all 4096 products `p_i,j=a_i AND b_j`. For each `i=0..63`, row `R_i` is the 128 bit vector whose position `i+j` contains `p_i,j` for `j=0..63`, with all other positions zero.

Starting with a zero 128 bit accumulator, add the 64 rows in increasing `i` using the full ripple adder. Fix the initial carry and final carry to zero for every row addition. Compare the final lower 64 sum bits to the actual LO operand and the upper 64 to the actual HI operand.

For the forward direction, each row is the nonnegative integer `a_i*(B<<i)`. Every prefix sum is at most the full product `A*B`, which is below `2^128`. Therefore every required zero overflow carry is honest. The deterministic partial products and additions extend every valid original IMUL assignment.

For the reverse direction, bitness and gate uniqueness force every partial product and ripple carry. Each zero overflow carry makes the next accumulator the exact ordinary prefix sum. Induction gives the final full 128 bit unsigned product and both required original halves. There is no field product substitution, low half truncation or free expected product witness.

This literal schedule has `4096+64*128*5=45056` auxiliary gates per IMUL, with 64 final carry comparisons and 128 output comparisons. These are unoptimized symbolic counts. Nothing was allocated or measured.

## Native BMUL basis obligation

The retained native predicate reassembles each operand as `lo | (hi<<64)` and checks

```text
c == u128::from(B128::new(a)*B128::new(b)).
```

A complete lowering must establish the actual constructor and inverse encoding as an ordered binary basis map for that same native multiplication. Its name and comments alone are insufficient. In particular, this review does not replace the native operation with a guessed literal GHASH polynomial or bit order.

Under that additional actual basis contract, let trusted fixed bits `chi[k,i,j]` be the coordinates of the product of basis elements `i,j`. Then

```text
c_k = XOR over (i,j) with chi[k,i,j]=1 of (a_i AND b_j).
```

There are 16384 shared pairwise ANDs. Starting each output accumulator at zero uses `tau=sum chi[k,i,j]` XOR gates and 128 final comparisons, with `0<=tau<=128^3`. Bilinearity over the binary basis proves both directions for the complete native product under the stated contract.

The actual basis product constants, their full source correspondence and feature or hardware closure have not been supplied here. They are fixed expected program data, never a free prover table, host callback or peer selected field. Thus this conditional BMUL construction is not an instantiated compiler for every native word system.

## Entire fixed relation correspondence

Given a complete structurally valid fixed original relation `C`, take its original word assignment, constant words and public instance. Reuse all original word bits and extend them by the deterministic gates above. Every original satisfied predicate gives satisfied field equations, subject to the BMUL basis contract where used.

Conversely, take any satisfying expanded assignment. Bitness gives actual 64 bit source words. Fixed constants and instance bits recover their expected original values. Ordered shifts and XOR gates recover every original operand. ZERO, AND, full IMUL and the conditionally bound native BMUL then recover every original predicate on those same words. This covers internal words and every reuse, rather than separate witnesses for different operations.

No claim about arbitrary accepted proof extraction follows. The field equations must actually be emitted and enforced on the same committed representation by the complete expected verifier and proof system.

## Checked confidential conservation

The same full adder supplies a characteristic independent version of the specified ordinary payment conservation relation. Keep the same at most 17 asset representatives: every input asset, every output asset and the fixed native identifier. Duplicates are allowed. Build equality of all 256 actual asset bits by Boolean XNOR gates and a product chain.

Gate each note's same 64 value bits by its same asset equality flag. For each representative, also compare its full asset identifier with the fixed native identifier and AND each fee bit with that equality flag. Accumulate inputs and outputs in their original order with checked 64 bit ripple adders, adding only that gated fee on the output side. Compare all final sum bits for each representative. Every final overflow carry is zero.

Every occurring asset has a representative, so these equations give exact per asset conservation and the original checked `u64` overflow behavior. Conversely, successful original checked sums supply the gates. Zero amounts and duplicate representatives retain their earlier semantics. This changes no amount, asset, fee, mint or burn rule.

The original common byte identities and asset equality flags must be constrained throughout. A host map, separately chosen private amount or public asset label does not implement them. No existing cash circuit or runtime is patched by this specification.

## Literal geometry and remaining architecture

For the schedule above, let `N` be the number of original source words, `O` the total number of operand terms and `Z,A,I,B` the original predicate counts. Count one gate per operand term and bit, even for a first XOR with zero. Let `N_c,N_p` be source constant and public word counts. The auxiliary gate count is

```text
G = 64*O + 64*A + 45056*I + sum_B(16384+tau_b).
E = 64*Z + 64*A + 192*I + 128*B.
Q = 64*N + 2*G + E + 64*(N_c+N_p).
```

`E` counts output and zero overflow comparisons. `Q` counts source and auxiliary bitness, gate equations, comparisons and fixed instance bit equations when all original source bits are allocated as variables. Hardwired zero and one are constants. These counts describe this literal semantic construction before frontend translation, blinding, dummy products, power of two padding, all proof buffers and any additional payment operations. They are neither a lower bound nor the geometry of an actual complete payment proof.

A direct proof of the resulting entire field relation could structurally avoid invoking the inner word IOP and its original trace and lookup `Y` route. It would need to prove the equations directly. Wrapping an unchanged inner trace or appending a detached proof does not make that change.

The outer packer itself copies original private values before adding free dummies and correlated product coordinates. Direct lowering therefore still needs an actual complete hiding construction for its same original outer witness and entire verifier view. Its padding count or a ZK name does not establish that property. The expected outer verification and complete combined opening remain mandatory on the inspected route.

The standalone field route still sends its padded private and mask buffers through BaseFold. Under the earlier encoder basis and helper hypotheses, the original codeword lane is visible and the separate encoder mask does not hide that component. The original packed message may itself contain dummy randomness. Its complete joint source and hiding law must be proved, without assuming that randomness absent or sufficient.

The decisive missing object remains an actual complete `C_cash`: all original canonical 418 byte openings, same hidden keys and signatures, authorization, eligible membership, stable nullifiers, checked conservation, whole same opening KEM/KDF/GCM and original state associations. The current host checker calls native cryptographic checks and consumes caller supplied anchor and spent sets without changing state. A host `Result` is not a circuit gate or authenticated acceptance authority.

Practical recipient completion or refusal, actual BMUL or other primitive lowering, full joint outer hiding and entropy model, native expected wiring and complete opening, canonical bounded parsing and finalization, security and simultaneous resources remain unresolved. The [proof entropy source](proof-entropy-source.md), [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) gates remain. No cap, class, profile or primitive is enlarged or weakened. Whole private cash architecture adoption remains refused.
