# Integer word predicates and source binding

This source and mathematical decision continues the [word claims and wiring](word-claims-and-wiring.md) review at historical `binius-zk/binius64` revision `6e75a2d1d2e716578ae3ccb62806413fb1615176`. The [source record](integer-word-sources.json) pins the actual integer multiplication verifier and core constraint, index, shift and layout bodies. The selected upstream tests were read as data. No upstream program, witness, compiler or proof ran for this review. No dependency, backend, proving class or security profile is adopted.

## Actual unsigned multiplication predicate

The core `ImulConstraint` stores four XOR operands in the order `[a, b, lo, hi]`. Each operand is a list of actual shifted value references. Its native checker evaluates those operands, multiplies the two unsigned 64-bit values in `u128`, and checks both halves. It does not truncate the product before checking the high half. The separate host `Word::imul` return order `(high, low)` does not change this constraint order and does not certify adversarial result words.

The actual proof reduction uses exponentiation rather than a direct array of integer carries. For Boolean source rows, write

`a = sum_i 2^i a_i`, `b = sum_i 2^i b_i`,

`C = lo + 2^64 hi`, with all four words in `[0, 2^64 - 1]`.

For a genuine multiplicative generator `g` of `F = GF(2^128)`, the exponent equation is

`(g^a)^b = g^lo * (g^(2^64))^hi = g^C`.

That equation alone is insufficient. Its modulus is `M = 2^128 - 1`, not `2^128`. The actual verifier also checks the least significant bit equation

`a_0 * b_0 = lo_0`.

These two predicates, together with the stated bit and range conditions, are equivalent to the full unsigned integer equation `a*b = C`. Indeed,

`0 <= a*b <= (2^64 - 1)^2 < M`, and `0 <= C <= M`.

Equality of generator powers gives `a*b = C` modulo `M`. In these intervals, the only unequal pair is `a*b = 0, C = M`. A zero product has `a_0*b_0 = 0`, while `C = M` has `lo_0 = 1`. The actual parity predicate excludes that pair. Conversely, a true integer product satisfies both exponentiation and parity. This is a deterministic conditional algebraic argument. It is not a generated proof, an attack execution or a soundness theorem for the interactive reduction.

The verifier's generic field bound permits degree at least 128. If a genuinely primitive generator belongs to a larger binary field, its order exceeds every possible 128-bit `C`, so the endpoint alias disappears. The parity equation remains part of the actual source. The field trait and the name `MULTIPLICATIVE_GENERATOR` do not themselves verify the chosen representation, generator order or arithmetic implementation. The actual caller specializes to `B128`. Its complete field implementation remains outside this review.

## The five actual phases

1. The verifier samples a row point, receives one exponentiation root claim and runs a 64-leaf product-tree reduction. It receives 64 leaf evaluations and checks their multilinear recombination at the returned suffix point.
2. Inverse Frobenius is applied to each leaf value and every coordinate of its evaluation point. The source computes actual repeated squarings. This uses the field's characteristic, extension degree and Frobenius identities. Twisting only the value would not establish the same multilinear claim.
3. The verifier samples a six-coordinate batching point before the batched selector and output-product sumcheck. It receives the 64 `b` evaluations and the three exponent roots, then samples a new six-coordinate point to recombine `b`. It checks the selector and `LO*HI` terminal expression against the returned sumcheck evaluation.
4. It batches the three fixed-base exponentiation trees, with an explicit fourth zero slot. A product-tree reduction reaches four limb claims for each of `a`, `lo` and `hi`. The verifier checks their actual recombination, including selector and limb coordinates.
5. It twists those twelve limb claims onto the shared table `T[j] = g^j`, invokes the committed transparent-table lookup reduction, folds its returned index claims, and runs the final combined index, parity and `b` rerandomization sumcheck. The raw four 64-entry evaluation arrays are received before the final equation and returned at one common row point.

Here `LOG_N_LIMBS = 2`, so each word has four 16-bit limbs. The table has 65536 logical rows. Its multilinear extension is evaluated directly as

`T_tilde(y) = product_j (1 + y_j * (g^(2^j) - 1))`.

At Boolean coordinates this selects the correct exponent. The expression is multilinear, so it determines that table's MLE under the actual coordinate order. The `hi` limb twists are 64, 80, 96 and 112, while `a` and `lo` use 0, 16, 32 and 48.

The source's transparent table is public fixed data. It does not make the private word proof transparent or disclose the recipient, note or encryption key. The called lookup route introduces a pushforward oracle whose actual opening obligations remain necessary. Its implementation, nonzero denominator contracts, malformed-input handling and full hiding and soundness arguments are not established by this call site.

The final parity term is literally

`eq(b_eval_point, r_out) * (a_evals[0]*b_evals[0] - c_lo_evals[0])`.

It is batched with the folded lookup-index equation and the `b` rerandomization equation. The random-point array entries are field evaluations, not necessarily Boolean. Booleanity belongs to the underlying committed bit columns and their exact representation. Imposing bit equations on these random evaluations would change the protocol.

The 256 returned values, twelve limb columns, 65536 table rows and six-coordinate folds are source dimensions. They are not total retained memory, actual proof size, compiled circuit geometry, a security score or an admitted resource class. Even a succinct public table evaluator does not remove the committed pushforward or the rest of the proof.

## Binding those words to the real source

The previously inspected caller invokes this integer reduction before binary multiplication and AND. The four integer arrays therefore precede the later AND challenge used for their Lagrange collapse. They enter the shift reduction in the actual operand order `[a, b, lo, hi]`. They are outstanding claims about the same fixed program's source words, not independently accepted products.

The core `ValueIndex` is a packed `u32` with a two-bit segment tag and a 30-bit index. Its segments are constants, inout, private and scratch. Construction bounds the index to that representation. Deserialization recovers the packed word, but does not establish that it references a declared value in a particular program. `ConstraintSystem::validate` separately rejects scratch references and checks every index against its own actual segment length. Padding cannot be addressed as a declared value through those references.

Each term has an actual value index and two ordered shifts. Evaluation reads the referenced source once, applies the inner shift first, then the outer shift. An operand XORs every term, starting at zero. Repeated terms cancel modulo two. An empty operand is zero. This word operand is a vector, unlike the outer frontend's sorted field-wire operand set. Structural validation does not require a globally sorted, duplicate-free list or a unique encoding for every equivalent linear map.

The eight shift variants distinguish logical left, logical right, arithmetic right and rotate right, plus four independent 32-bit-half operations. Full shifts require amounts below 64 and half shifts below 32. The core shift-table address is `variant*64 + amount`. It reserves 64 slots for every variant, including half variants whose upper slots are not valid canonical program terms. That is consistent with the indicator's masked half-word amount coordinate only when the actual program validation and exact table indexing are preserved.

Amount zero has one canonical spelling, logical left by zero. A lone shift belongs in the inner slot. A genuine pair must remain a pair under the actual composition classifier, rather than collapse to one shift or to zero. The source explicitly permits different irreducible pairs to denote the same linear map. Canonical term validation is therefore not a theorem of unique serialization for equivalent programs.

For a valid shift, every output bit reads a fixed input bit or zero. Arithmetic right replicates the appropriate sign bit and the half variants keep the two halves separate. A two-shift term composes those bit maps in order. The earlier [indicator argument](word-claims-and-wiring.md#exact-shift-indicators), together with this actual enumeration and source indexing, identifies the same Boolean-vertex map under the stated `Word` and field implementation hypotheses. Equality of multilinear extensions then follows from equality at all vertices. The source's exhaustive and property tests remain unexecuted data here.

This supplies the missing nominal connection between the selected core predicates and the selected wiring consumer. It does not establish the uninspected compiler's lowering, actual packed witness construction, committed bit-column encoding or every transitive protocol reduction.

## Fixed layout and validation boundary

The compiler layout stores constants, inout, witness, internal and scratch words back to back without proving padding. The core system keeps only constants, inout/private counts and constraints. Public placement uses constants plus inout as public values. Hidden inout placement moves inout into the committed segment. These modes are explicit protocol choices and do not change what each source index names.

Constraint counts are actual counts. Operand columns are padded later to powers of two with all-zero rows, which satisfy each operation predicate. An empty IMUL or BMUL set skips its protocol entirely. An empty AND or ZERO set retains a zero padding row and zero variables. The mode and counts must come from the verifier-owned program, not a peer-selected serialized program.

Validation bounds each declared inout/private segment by `2^26` words and checks actual terms, shift ranges and composition. That upstream policy permits 512 MiB of logical words per segment. It is not Kova's aggregate 512 MiB execution guard, a simultaneous memory bound or permission to allocate such a segment. Constants and constraint vectors are backed by serialized data and do not receive that count bound. Their allocation, nested operand sizes and parser framing remain separate obligations.

The version-10 core deserializer reads the constants, counts and four constraint vectors and returns the object. It does not itself call `validate` or establish trusted program identity. The native `verify` method checks opened constants and constraints in ZERO, AND, IMUL, BMUL order. It is distinct from structural validation and proof verification. Its result does not authenticate state or constrain a hidden encryption program.

The scalar shift kernel reads only the selected source word. Its bulk write and XOR adapters stop at the shorter slice. A caller using an uninitialized destination must establish that every destination cell it later reads was written. The local adapter's zip is not that caller-wide guarantee. The selected layout methods also use ordinary size arithmetic. Complete checked preflight remains necessary before any allocation, power-of-two expansion or indexed operation.

## Conditional maps and remaining construction

For the forward mathematical map, take the same fixed, structurally valid program and its actual finite word assignment. Expand every referenced word into its 64 bits, apply the actual ordered term maps, and form the four operands. A true unsigned product supplies the exponent trees, limb values, lookup indices and parity relation described above. All operation claims must refer to those same sources and the same constants and expected public words.

This does not construct a successful runtime prover. The concrete prover bodies, packing, hint and oracle generation, denominator exceptions, challenge handling and complete compiler remain additional source and semantic obligations. Honest integer values alone do not prove that every original protocol execution succeeds.

For the reverse mathematical map, assume the actual committed representation fixes those Boolean source columns, every product-tree, sumcheck and lookup relation is valid, all returned claims refer to those same columns, and the shift, public-value, native fixed-program wiring, outer proof and combined opening obligations are all settled. Then the source binding yields the intended operand bits, and the exponent-plus-parity argument gives the original full unsigned product. Apply this separately to every actual constraint row. Zero padding contributes no extra program operation.

These are explicit relation hypotheses, not consequences of an accepted proof established by this review. The complete reduction soundness, joint hiding, transcript binding, classical and quantum assumptions, knowledge, field implementation and bounded parser remain open. No source comment, trait name, hardcoded field constant or honest replay substitutes for them.

The selected local predicate and index gap is closed at the source and conditional mathematical level. The whole private native-cash architecture remains unfinished. Its minimum missing construction is still one actual private program containing the [same payment witness](private-witness-join.md), practical recipient completion or truthful refusal, the complete [same-opening KEM/KDF/GCM](whole-encryption-completion.md), real signature authorization, authenticated eligibility and atomic spent-state consumption. It also needs a matched prover, verifier, canonical bounded parser, complete source and license closure, all retained allocation lifetimes and a justified joint security profile.

Neither this word relation nor the upstream segment cap changes Kova's current proof-geometry and transport refusals. Native word packing and a different proof-system name do not discharge those gates. The sender still has no recipient spending secret, input commitments and paths remain hidden, and payments remain private by default. The [minimal launch](../../docs/minimal-launch.md) requirements and [full roadmap](../../docs/delivery-roadmap.md), including later private contracts and Safe, remain intact.
