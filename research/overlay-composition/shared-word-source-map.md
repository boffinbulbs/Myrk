# Shared word source map and lookup boundary

## Construction status

This construction replaces every private word in an entire fixed word relation with two XOR shares. It gives both semantic directions and identifies the remaining joint trace and lookup hiding construction. It extends the [word witness extension](word-witness-extension.md), [private lookup compensation](private-lookup-compensation.md) and [original codeword privacy](original-codeword-privacy.md) reviews.

The result is source and conditional mathematics. No transformer, compiler, witness, proof, backend, profile, execution class or complete private cash program is implemented or adopted. No candidate program or cryptographic operation was executed.

## Retained source and acquisition boundary

The primary source remains [binius-zk/binius64 at `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). The [source record](shared-word-source-map-sources.json) preserves the unchanged source identities and original notices.

The retained core source defines an operand as an XOR vector of shifted word references. A term applies its inner shift before its outer shift. Structural validation checks the segment, index and canonical shift sequence of every term. It does not require sorted or unique XOR terms.

The actual core predicates are ZERO, bitwise AND, unsigned multiplication with ordered low and high results, and a six word represented field multiplication predicate. The proof below preserves their complete operand values. It does not distribute nonlinear multiplication over individual shares.

A separate bounded selection sought the actual bare lookup constructor, weights and denominator source needed for the joint architecture. Its first metadata request returned a connector transport failure without metadata or an HTTP status. The selection was closed immediately. The other two metadata resources were not requested, whole body selection was not finalized and no new source body or source byte was retained. No retry or alternate source was used. The actual bare lookup source map remains unreviewed.

Earlier whole body reviews and selected actual caller contexts supply this construction. No new complete transitive field, codec, hardware, dependency or toolchain audit is claimed.

## Entire fixed relation transformation

Let `C` be a structurally valid fixed word constraint system in the inspected public inout mode. Its declared private vector `w` has `N` words, including original private internal and gate created words. Constants and public inout words keep their original values and classification.

Choose two maps `f_0,f_1` into a prospective private segment such that every selected position is distinct. Each original private index uses one global pair. Every occurrence of that original index must reuse the same pair.

For each original private word, assign

```text
a_i = eta_i
b_i = w_i XOR eta_i
w_shared[f_0(i)] = a_i
w_shared[f_1(i)] = b_i.
```

The mathematical shares `eta_i` can be arbitrary words for semantic preservation. No randomness generator or witness allocation is selected.

In every operand of every constraint, replace each private term `L(Private(i))` by the two consecutive terms

```text
L(Private(f_0(i))), L(Private(f_1(i))),
```

where `L` is the identical original ordered pair of shifts. Preserve all constants, public references, constraint kinds, constraint order, operand order and shifts. The same replacement applies to every private reference, including internal original wires. No decoded original private word needs a separate declared coordinate in this mathematical representation.

Using `f_0(i)=2i` and `f_1(i)=2i+1` requires checked arithmetic and a declared private count of `2N`. The actual source segment bound requires `2N<=2^26`, and indices and conversions must fit their actual types. This source bound is not Kova's aggregate memory or proving class admission.

An original operand with `m` terms and `p` private term occurrences now has `m+p` terms. Repeated occurrences count with multiplicity. These expanded vectors, serialization lengths and allocations need their own actual bounds. Constraint counts and predicate operand counts remain the same, while private count, term count and proof program geometry can change.

## Both semantic directions

Every fixed source shift is linear over word XOR. Logical shifts select input bits or zero. Arithmetic shifts can also copy a source sign bit. Rotations permute bits. The half word variants perform these operations within their original halves. Composing the same two fixed shifts preserves this linearity.

Consequently,

```text
L(a_i) XOR L(b_i) = L(a_i XOR b_i) = L(w_i).
```

The actual operand evaluator XORs its term values, so every rewritten operand equals its original operand. Empty operands and repeated term cancellation retain their original meanings.

All complete predicates therefore agree:

| Predicate | Preserved relation |
| --- | --- |
| ZERO | Original operand equals zero |
| AND | Original `A & B = C` |
| IMUL | Original unsigned product has the same ordered low and high words |
| BMUL | Original six evaluated words satisfy the same represented field predicate |

Thus every valid original assignment, with every choice of share words, gives a valid transformed assignment.

Conversely, take any valid transformed assignment and define `w_i=a_i XOR b_i` using the same global pair for each original index. The identical term argument gives every original operand value. Every original constraint then holds on that one decoded original assignment.

Per-occurrence unrelated share pairs would not establish this reverse association. The proof also does not establish an accepted proof extractor, actual field arithmetic, an original cryptographic circuit or a missing state and copy predicate. The complete original relation must already contain those operations and source associations.

## Marginal shares and joint trace privacy

Under the ideal assumption that the `eta_i` are independent uniform 64 bit words independent of the original witness `w`, each individual share is uniform independently of the original word. Equivalently, require the share randomness to be uniform conditional on every allowed original witness. The joint pair determines that word by XOR. The construction has `64N` independent random bits, rather than `128N`.

If consecutive shares are packed into the inspected `B128` representation, one coefficient contains `(eta_i,w_i XOR eta_i)`. Under the actual constructor and basis bijection this is a 64 dimensional affine binary subspace of a 128 bit field coordinate. It is not an independent uniform full field mask. Other placements also require their actual source and encoding maps.

For a fixed independent binary linear disclosure operator, write the complete justified linear portion as

```text
shared_trace = J*w + H*eta
view = A*J*w + A*H*eta + c.
```

It is uniform on the corresponding affine coset. Hiding the allowed same-statement witness differences requires

```text
A*J*(w-w') belongs to image(A*H).
```

This is a binary image condition, with actual packing, field operations and disclosure rows. Marginal uniform shares, a word count or a field dimension label cannot replace it. Observing both shares permits decoding. This observation is not a claim that every actual queried leaf reveals both original words or that an accepted private payment attack has been demonstrated.

All raw original leaves, duplicated and lift translated queries, clear relation claims, mask inner products, folds, terminal values and outer interactions must be included where such a fixed linear description is justified. Adaptive roots and transcript conditioning need their own joint distribution and simulation argument.

## Decoded operands and actual lookup chronology

The retained word prover constructs operation columns by evaluating each constraint operand against the witness in constraint order. The complete sharing transformation preserves those decoded operation values. In the actual IMUL reduction, the fixed base lookup uses twelve limb columns: four 16 bit limbs from each of `a`, `c_lo` and `c_hi`. The `b` column has separate rerandomization and recombination obligations. No presumed formula treating all four words as one list of gamma powers is introduced.

The retained IOP transparent lookup verifier samples the looker batching challenge before receiving the private pushforward oracle `Y`. It then invokes the bare reduction and queues both `<Y,eq_z>` and `<Y,T>` against the same oracle, in that order. The original index claims remain for the caller to check.

This is the verifier wrapper source. It does not provide the actual honest prover's complete index, weight, pushforward, randomness or denominator map.

The strongest conditional source statement is the following. If the actual lookup constructor is a deterministic function of the same decoded semantic inputs, looker order and dimensions, and the same complete challenge and other input tape, then those inputs produce the same `Y`. Under that conditional map, share entropy has canceled before the lookup and supplies no new independent randomness to `Y`.

The missing constructor premise must be established from actual source. It is not a claim that every actual `Y` coefficient is unchanged across real proofs. Private count and term growth can change program geometry. The actual trace commitment precedes IMUL, so a changed shared trace can change observed roots and subsequent Fiat Shamir challenges. Fixing a complete challenge tape is an additional conditional experiment, not an equality between actual proof challenge histories.

## Whole private cash decision

The completed local result is a semantic transformation for the entire validated original word relation, with both directions and the actual joint trace and lookup boundary. It does not supply a complete private cash backend.

The minimum missing construction is one actual common private cash program and representation that jointly hides the same original trace, lookup indices and `Y`, both original lookup relations, clear claims, masks, rounds, queries, folds, terminal data and outer proof. It needs actual source maps, a matched expected verifier, canonical bounded parser and full consumption, complete simultaneous resources, supported recipient completion or refusal and the applicable privacy, binding, proximity, Fiat Shamir and knowledge arguments.

A separate encoder mask, detached outer proof, unchecked table, free claim or marginal share argument cannot supply that common construction. The [same private witness](private-witness-join.md), [whole encrypted output](whole-encryption-completion.md), [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) gates remain. Current resource limits and original primitives are unchanged. Adoption remains refused pending the complete construction.
