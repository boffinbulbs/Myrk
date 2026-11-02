# Word witness extension and joint hiding conditions

## Construction status

This is a source based mathematical family for extending an entire fixed word relation with fresh private coordinates. It gives both semantic maps and a precise joint hiding condition. No transformation program, compiler, witness, proof, execution class or complete private cash architecture is implemented or admitted.

The [original codeword privacy boundary](original-codeword-privacy.md) identifies the original trace values disclosed by the inspected query path. The [masked opening](masked-oracle-opening.md) gives the restricted fixed linear view criterion. This construction addresses randomness inside that same trace. An independent encoder mask and a separate outer proof remain insufficient substitutes for that obligation.

## Retained source

The primary source remains the historical revision `6e75a2d1d2e716578ae3ccb62806413fb1615176` of [binius-zk/binius64](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). No new primary capture was selected or performed. Existing complete body reviews and actual constructor, operand, packing, wrapper and opening call sites supply the context. The [source record](word-witness-extension-sources.json) preserves the exact unchanged repository and RAW primary identities.

The actual core system contains ordered ZERO, AND, IMUL and BMUL constraint vectors. Each operand is an XOR vector of shifted word references. A reference names a constant, inout or private word. Scratch references are refused. Shift sequences apply the inner operation before the outer operation. These properties determine the semantic map below. They are not an audit of the complete compiler or accepted proof relation.

Original licenses and source bytes remain unchanged. No library, dependency, registry, root, profile or resource limit is changed. No upstream or existing healthy program was executed for this construction.

## Fixed relation and private injection

Let `C` be a structurally valid fixed word constraint system in the inspected public inout mode. Let `N` be its declared private word count and `P` its public constant plus inout count. Let `R_C(S,w)` mean its original word predicates hold for public statement `S` and private word vector `w` of length `N`.

Choose a prospective private word count `N'` and an injection

```text
f : {0,...,N-1} -> {0,...,N'-1}.
```

Construct the mathematical system `C_f` as follows.

1. Preserve the constants, public inout values, constraint kinds, vector order, operand order and every shift sequence.
2. Replace each private reference `Private(i)` by `Private(f(i))` in every operand term of every constraint. Leave constant and inout references unchanged.
3. Set the declared private count to `N'`. No constraint refers to a private position outside `image(f)`.

The choice must satisfy the actual segment count, tag, index and finite arithmetic limits. Source structural validation can then preserve shift validity because the shifts do not change, and preserve reference validity because every mapped index is inside the new private segment. This is a conditional statement about the mathematical construction. No serialized system or transformation was generated.

Let `eta` assign arbitrary 64 bit words to the private positions outside `image(f)`. Define the extended witness by

```text
w_f[f(i)] = w[i]
w_f[j]    = eta[j] for j outside image(f).
```

Public constants and inout words keep their original values. The new private randomness does not turn an original private value into a public input.

## Both semantic directions

Each referenced original word and its mapped word are equal. Applying the same inner and outer shifts therefore gives equal term values. XOR in the same vector order gives equal operands, including repeated terms that cancel. The argument does not require a sorted operand set or a unique symbolic spelling for every word map.

All original predicates consequently have the same operand values.

| Constraint | Preserved original predicate |
|---|---|
| ZERO | The actual XOR operand equals zero |
| AND | The original bitwise conjunction equals its original result operand |
| IMUL | The full unsigned 64 by 64 product equals the ordered low and high words |
| BMUL | The six original low and high word operands satisfy the same represented field predicate |

Thus, for every valid original assignment and every extension word vector,

```text
R_C(S,w) implies R_C_f(S,w_f).
```

Conversely, restrict any valid assignment of `C_f` to the mapped coordinates:

```text
w[i] = w_f[f(i)].
```

The same term and operand argument proves

```text
R_C_f(S,w_f) implies R_C(S,w).
```

This is preservation of the entire original fixed word relation. It is not a native host verdict in place of constraints. A future proof must enforce the actual mapped constraint system and bind every operand to that same committed trace. The argument does not establish proof knowledge extraction, the actual field implementation, or correspondence between a native multiplication instruction and the retained literal GCM source.

The original relation itself must already include every required source operation, private copy and state condition. Renaming references does not supply an absent memory chronology, signature predicate, encryption operation or payment ledger rule. It also cannot join separate existential witnesses by matching their public statements.

## Full field coordinates and actual packing

The actual producer packs two consecutive private 64 bit words into one `B128` coefficient. Uniform independent words in both positions of an otherwise unused pair give a uniform field coefficient only under the actual constructor, ordered basis and packed field contracts. One free word in a partially occupied pair supplies a 64 bit coordinate subspace, not an independent uniform 128 bit field value.

For a prospective field length `K=2^D`, a convenient mathematical family declares `N'=2K`, with `P <= 2K`, and reserves a set `U` of full unused word pairs. The injection must leave both word positions of every pair in `U` free. It requires

```text
N <= 2*(K-|U|).
```

Then the inspected wider segment rule gives a trace of `K` field coefficients. The original private words occupy mapped positions. All other declared private words are extension variables. They are distinct from the zero padding that the current implementation writes beyond its actual declared private vector.

This family also handles an odd original word count. The original last word is preserved at its mapped index. An unused high word beside it can be an extension variable, and restriction discards it. The semantic maps apply to actual word references, rather than assuming the original odd pair's zero high word must stay part of the new representation.

No `K`, set `U`, injection, entropy request or executable program is selected here. The source's separate per segment limit is not Kova's aggregate process and job memory limit. Additional declared words change the actual proof program and resource plan even when the original constraint vector lengths are unchanged.

## Original query rows

Let `G_Q` contain the actual original encoding rows at the distinct queried leaf indices after each lift translation. Under the actual encoder and field hypotheses, the original query view is `G_Q*pi`. The separate encoder mask has zero coefficient in this projected view.

For the full ambient field coefficient space, genuine Reed Solomon evaluation rows satisfy

```text
rank(G_Q) = min(|Q|,K).
```

The novel basis and input bit reversal are invertible changes of coordinates. For at most `K` distinct evaluation points, interpolation of degree below their count gives any target values. A larger row set contains `K` independent rows and has only `K` columns. This proves the displayed ambient rank identity.

Actual valid private payment assignments are restricted by Boolean words, padding, signatures, encryption, source equations and the same public statement. Their allowed differences need not span the ambient coefficient space. This rank identity is therefore not a universal payment proof entropy lower bound, measured rank or security score.

Query duplicates still remain in the actual transcript, field contents and transport. Distinct common domain queries may also map to the same smaller original leaf. Rank reduction in this restricted projection does not remove their memory or wire costs.

## Fixed view certificate

For fixed independent disclosure operators and independent uniform extension variables, write a justified field linear representation as

```text
pi = J(w) + D*eta
view = A*J(w) + A*D*eta + c.
```

The restricted view is uniform on a coset of `image(A*D)`. It hides the permitted original witness differences exactly when

```text
A*(J(w)-J(w')) belongs to image(A*D)
```

for every pair of allowed original witnesses for that same public statement. Partially free word pairs require the corresponding binary coordinate subspace in this criterion. A field dimension count alone cannot replace that actual image.

For original codeword queries, `A` includes `G_Q`. For the complete protocol it must also include every other disclosed field value for which this fixed linear description is justified. A choice covering query rows alone does not establish joint hiding.

The actual wrapper sends each decrypted oracle relation claim in the clear through its inner channel. The matched verifier receives that value as public inout, constrains its equality to the calculated claim and passes the same value to BaseFold. The inner trace claim comes from ring switching on the same packed witness and the same trace handle is finalized. These values are additional view components. Their outer equality and the combined opening remain real verification obligations.

Mask inner products, later fold leaves, the terminal vector and other original oracles are additional components. A proposed extension needs actual source rows and coefficients for the entire joint view. It cannot omit a row because the value was called a claim or was checked later.

## Why a suffix count is insufficient

Consider the original encoder's zero domain point under the actual basis and helper contracts. Every positive degree novel basis element vanishes there, so that row selects the degree zero coefficient. Its original message coordinate is index zero after bit reversal as well.

Consequently randomness placed only in other coefficient positions has no effect on that projected value. If the allowed original witness differences change the selected coefficient, such randomness does not hide that fixed view. The actual source permits query index zero. Its probability and any tolerated exception need an explicit complete profile and transcript argument.

This is an exact conditional placement obstruction, not an executed attack or a claim that two valid private payment witnesses with that difference have been constructed. Moving the original coordinate and reserving a free coordinate there could address this one row, but would still need the complete source transformation, all other rows and a full joint proof. Neither appending a number of random words nor copying an outer dummy count supplies that proof.

## Lookup and adaptive transcript obligations

The private lookup pushforward oracle `Y` also has original codeword leaves and two ordered queued relations. Its coefficients are derived from actual hidden indices and source weights. The word injection above preserves original operand values, so it does not automatically randomize this derived oracle. A free pad on `Y` changes its index, pushforward and relation equations unless an actual constrained construction accounts for it.

A complete architecture must provide one jointly valid hiding representation for the trace, `Y`, outer precommit and private oracles, their masks, claims, queries and terminal data. The same original word assignment must determine every original operation and hidden lookup index. No detached proof or supplied table can replace that association.

Actual disclosure operators can depend on earlier messages, roots and challenges. Conditioning on a randomness dependent history does not preserve an independent uniform mask assumption automatically. The fixed view lemma therefore supplies no online simulator or adaptive Fiat Shamir theorem. Actual hash commitments, transcript conversion, repeated proofs, concurrent views, field subspaces, Galois closure, salt if any, RNG streams, classical hypotheses, quantum queries and knowledge remain separate obligations.

The actual bare lookup, product and sumcheck implementation still needs complete source correspondence and denominator exception handling. No assumed sequence of powers for lookup weights is introduced. No new primary capture or program is selected to bypass these gaps.

## Joint feasibility and minimum missing construction

The original four constraint counts and operand arities remain unchanged in this mathematical extension. The private segment size, word index dimension, packed trace length, wiring tensors, key collection, ring switching, compiler derived outer circuit, oracle shapes and later proof schedules can all change. A future implementation would need to rebuild and bind the actual fixed program. Reusing old roots, layouts, proof prefixes or prepared prover data would not implement the map.

All source data, entropy, original and folded codewords, masks, trees, query multiplicities, claim values, parallel scratch, retained buffers, descriptors, complete transport and canonical parser must be accounted simultaneously. Current raw, owner, stored, kernel, transport and aggregate limits remain unchanged. This construction has no resource admission, allocation, measured peak or proof wire result.

The completed local result is the entire fixed word relation extension with both semantic directions and the necessary joint image condition. The minimum missing construction is an actual source bound choice that satisfies that condition across trace and lookup data and the complete adaptive transcript, with a matched verifier, parser, resource plan and applicable security analysis. No such complete choice or practical class is established here. Backend adoption remains refused.

The [same private witness](private-witness-join.md) and [whole encrypted output](whole-encryption-completion.md) still require actual private authorization, state, native conservation and one opening through full KEM, KDF, context and GCM. Practical recipient completion or refusal remains separate. This extension cannot make a recipient matrix sampler terminate or select a feasible horizon.

The [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) retain private payments, confidential bootstrap, actual reward origin maturity, finality, consumed bonds, durable signing, recovery and independent network validation. No working blockchain or production release is claimed by this construction.
