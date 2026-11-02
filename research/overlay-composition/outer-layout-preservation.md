# Outer layout and equation preservation

This source and mathematical decision continues the [wrapped transcript relation](wrapped-transcript-relation.md). It reads the complete historical Spartan frontend builder, compiler, constraint system and wire elimination at `binius-zk/binius64` revision `6e75a2d1d2e716578ae3ccb62806413fb1615176`. The [source record](outer-layout-sources.json) preserves actual identities and review limits. No compiler, upstream test, witness, prover or verifier executed for this source and mathematical review. No implementation, backend, proof class or security profile is adopted.

## Public derivation is a program obligation

The actual frontend has five wire kinds. Constants, inout and derived wires occupy the public segment. Precommit and private wires occupy separate committed segments. An addition or multiplication creates a derived wire without a gate equation exactly when both declared inputs are public. Otherwise it creates a private wire and emits the corresponding equation. The witness and instance generators use the same declared partition. The instance generator evaluates public values and represents private values by `None`.

For a fixed operation sequence, correct initial partition and actual field operations, induction shows that every derived addition or multiplication is determined by public inputs alone. Its missing gate equation is justified by the actual verifier recomputation of that same operation. This is not permission to accept a peer's claimed derived value or expose a hidden payment source. The verifier constructs the expected public vector itself.

Hints need an additional condition. The symbolic builder does not call the hint closure and emits no equation for it. It classifies outputs using only the declared input wire kinds. The interface cannot prove that the closure reads only those inputs. A closure capturing a secret outside its declared inputs would invalidate a blanket public-derivability claim, even if it declared no inputs. This is an interface limitation, not an observed accepted proof or a claim that the inspected wrapper does this.

The inspected wrapper's inverse hint uses its declared field value. Its transpose coefficient hint additionally captures the fixed basis index. These routes still need the actual field implementation and their following equations. The inverse has the nonzero product check; the transpose has subfield membership and reconstruction. A private hint remains a free field witness until real equations constrain its required meaning. Its honest host result, a successful constructor or a captured validity callback supplies no such constraint.

Runtime-arity hint output length is checked with `debug_assert` in both concrete generators. A future fixed program must establish its exact length and bounds in the actual source. That assertion is not an adversarial release-mode shape check. All generators must execute the same public/private and output-count decisions. The full inner reductions and their dummy-word specialization remain outside this local correspondence.

## Actual elimination step

An operand is a sorted set of wire identifiers. Repeated occurrences cancel modulo two. Its field value is the sum of its members, and merging operands is symmetric difference. These semantics require characteristic two. They are not general coefficient arithmetic over an odd-prime field.

The actual compiler builds the intermediate relation, runs wire elimination and finalizes it. The elimination pass selects only an unknown private wire from a zero equation. It never selects a precommit, inout, constant or derived wire as its pivot. Its cost model chooses whether a substitution is economical; those heuristic weights are not a benchmark, security parameter or proof of a resource bound.

Write a selected equation as `E = w + R = 0`, with pivot `w` appearing once. The pass removes that equation, marks `w` pruned and merges `E` into every other operand containing `w`, including each of the A, B and C positions of every multiplication constraint. It maintains the corresponding addition and multiplication use lists as members appear or cancel.

The mathematical preservation argument is local and exact:

1. For an original satisfying assignment, `E = 0`. Every changed operand `D + E` therefore has the same value as `D`. Projection onto surviving wires satisfies all changed constraints.
2. Given a satisfying assignment after the step, reconstruct `w` as the value of `R`. Then `E = 0`, and every changed operand again equals its original operand. The restored zero equation and every original multiplication hold.
3. For successive steps, reconstruct pivots in reverse elimination order. At each removal the current equation contains no previously pruned pivot, because every use of earlier pivots has already been substituted. Later pivots are available when the reverse traversal reaches an earlier equation.

This proves preservation of existential field assignments under the stated sorted-operand, complete-use-list and field hypotheses. It is not a proof that a signature, note, ciphertext or arbitrary hint had its intended semantics in the original relation. It also is not a compiler audit, proof extractor or implemented reconstruction API. The honest witness generator instead evaluates the original operation sequence and simply skips storage for pruned wires.

The complete-use invariant is essential to the actual source argument. Every zero row and every A/B/C operand is enumerated when the use lists are built. Substitution updates both added and removed unknown-wire uses. A missing use would invalidate this argument. Tests were read as data; no mutation test or optimizer run establishes that invariant here.

## Finalization and expected public values

Finalization converts each remaining zero operand `A` to `A * 1 = 0`. It allocates or reuses the actual constant one and removes zero-constant references from operands. Multiplication rows retain their field equations. The constant one must be fixed to one in the actual expected public instance; a caller-supplied witness with a different constant is not the same relation.

Let `C` be the constant count, `I` the inout count and `D` the number of derived wires referenced by surviving constraints. The public segment orders constants, then inout, then those derived wires in original identifier order. Precommit identifiers retain their own order. Surviving private identifiers receive consecutive private positions in original identifier order. Only pruned private wires and unused derived intermediates have no mapped slot. Dead derived intermediates are still computed when later operations need their values.

The implementation maps operands through `layout.get` and drops unmapped terms. This is correct only with the established invariant that no pruned private wire remains in a surviving operand, while every surviving derived reference was marked alive. It is not a general license to drop an unknown source. Constants are placed by their allocated identifier, so iterating the backing hash map does not choose their final order.

The witness generator initializes the actual constant vector and computes both public and private operations. The instance generator initializes the same constants and recomputes the actual public operations, filling only live public positions. Under the fixed-sequence, pure-public-hint and partition hypotheses, their public vectors agree by operation induction. The proof must be checked against that actual independently reconstructed vector.

`WitnessGenerator::build` checks its recorded first assertion error. It does not revalidate every final multiplication, all required writes or an untrusted transcript. `ConstraintSystem::validate` asserts multiplication equations over supplied vectors; it is a host diagnostic and does not itself establish lengths, expected constants, source origin, program identity or proof validity. The actual top-level verifier and completed commitment protocol remain required.

## Resource and hiding limits

The local source uses `u32` wire identifiers and unchecked increments, casts and power-of-two size calculations. It is not an admitted bounded parser or resource policy. Before constructing any real instance, a future version must justify every count, index, allocation and shift with its actual geometry and truthful refusal path. No large count or malformed input was executed in this review.

The public, precommit and private segments are separately rounded to powers of two. Blinding enlarges each committed segment before rounding. The inspected source's formula adds `q + 1` dummy wires and three wires for each of two dummy constraints, hence `q + 7` nominal positions when its query argument is `q`. These are source formulas, not a selected query count or an established hiding theorem.

The source comments claim protection for opened codeword symbols, operand contributions and unopened unsalted leaves. Those claims require the real linear maps, joint rank and distributions, adaptive query schedule, mask equations, hashes and commitment protocol. Counts of dummy wires or constraints alone do not prove them. The existing [joint instance security obligations](instance-security.md) remain separate, including repeated proofs, salts, full-word binding, transcript compilation and quantum applicability. No source security identifier becomes a Kova score.

The actual combined resource record still needs inner word constraints, outer verifier equations, live and padded public/private/precommit values, original and substituted operand references, use lists, temporary vectors and hash maps, witness/instance generators, pad keys, masks, transforms, codewords, trees, claims, queries, proof bytes, parser limits and simultaneous retained lifetimes. Eliminating some private coordinates can increase operand references. No compiled count, allocation, peak, proof size or feasible complete class is measured here.

## Remaining complete construction

This closes the selected local frontend source review and gives the conditional elimination and public-instance correspondence. It does not complete the [common private cash witness](private-witness-join.md), actual word reductions, field/hash/transcript/BaseFold/FRI argument, full dependency and license closure, practical recipient completion policy, matching bounded proof parser or joint security/resource construction. Backend adoption remains refused.

The same hidden note, verification key, real signature, nullifier secret and path must still connect membership, owner, actual authorization, stable nullifier, native asset/value conservation and fresh authenticated state. The same output opening must supply its commitment and every encrypted plaintext byte through actual KEM, KDF and full GCM, without recipient spending secrets. No hint, host Boolean, public source disclosure, detached proof or supplied root replaces these constraints. The [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) retain proof, privacy, confidential bootstrap, atomic state, recovery and network gates.
