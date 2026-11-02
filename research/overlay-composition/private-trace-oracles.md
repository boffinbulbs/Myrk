# Private trace packing and oracle obligations

This source and mathematical decision connects the [integer word predicates](integer-word-correspondence.md) to their actual word storage, packed trace and committed lookup obligations. It uses historical `binius-zk/binius64` revision `6e75a2d1d2e716578ae3ccb62806413fb1615176`. The [source record](private-trace-sources.json) distinguishes eight newly read complete bodies from preserved caller context. Upstream tests were read as data. No upstream program, compiler, witness, encryption or proof ran. No backend, dependency, primitive, profile or proving class is adopted.

## One assignment, two representations

The selected `ValueVec` stores constants, inout and private words contiguously. A vector created for circuit evaluation also has a scratch tail. `public()` returns constants plus inout, `non_public()` returns only private values, and `combined_witness()` excludes scratch. A source term resolves its segment and index against those actual counts. The word producer and verifier must use the same fixed constraint system and expected statement. A correctly indexed vector for a different program proves a different relation.

The vector's backing blocks contain two words and have 16-byte alignment. An odd word count leaves an unused zero word in the last block. That allocation padding is separate from the polynomial padding added by the prover. Alignment, a `Pod` declaration or an honest word buffer does not establish adversarial proof correctness or reduce retained proof contents.

The actual monolithic prover packs `witness.non_public()` and observes `witness.inout()` before sending the trace oracle. Public constants are already part of the fixed program. The verifier checks the actual inout length, constructs public words from those constants and inout values, and receives the hidden trace. The public and hidden polynomial domains are padded separately. Flat storage offsets must not be substituted for the shift relation's segment selector and word coordinates.

In the retained producer, consecutive words are packed as

`u_k = word[2k] + 2^64 * word[2k+1]`,

`packed[k] = B128::new(u_k)`.

The order is low word first. A final unpaired word uses zero as its high word. The implementation first fills complete packed SIMD groups, then places all remaining word pairs and the unpaired word in one final group. It pads only after the final real word. This avoids inserting an unused lane between the remaining pairs and the odd final word.

The initial guard checks that `ceil(private_words/2)` fits the declared scalar field-element count. It is an upper fit check, not an equality check against every count in the constraint system. The selected storage constructors also do not authenticate that a caller supplied the expected constants and segment lengths. Those are real caller and verifier obligations. Honest zero fill alone does not prove that all adversarial padding is zero or that every packed coefficient belongs to the intended source segment.

The complete SIMD groups are written through spare capacity and made live with `set_len`. In this particular loop, the source groups and destination slice have equal lengths by construction. For operation columns, the nonempty constraint slice and output rows also have equal lengths. The empty AND case explicitly zeroes its one output row before making it live. These local length arguments address the selected write sites. They do not audit the allocator, Rayon, `PackedField`, field buffer or every unsafe caller.

## A conditional bit correspondence

Fix a genuine binary field `F` of dimension 128 over `F_2` and an ordered basis `beta_0, ..., beta_127`. Assume the actual `B128::new` representation and ring-switch basis implement

`enc(u) = sum_{j=0}^{127} bit_j(u) * beta_j`.

This is a bijection between 128-bit strings and field elements. Injectivity follows from linear independence of the basis, and surjectivity follows from spanning. Thus a canonical original coefficient has one unique pair of 64-bit words. This is an algebraic representation argument, not knowledge extraction from a commitment or a theorem about an unreviewed field constructor.

For private word `w_r`, its bit `j` occupies coefficient `floor(r/2)` and basis position `64*(r mod 2) + j`. Conversely, splitting a coefficient's unique basis coordinates at position 64 recovers those two words. The low seven bit coordinates of the packed multilinear describe the six bit positions within a word and the low word-index bit. The remaining coordinates describe the field-element index. The actual ring-switch and opening relations must preserve this association.

If a commitment fixes coefficients in that exact field and representation and all claimed bit evaluations are correctly reduced to those coefficients, the recovered source coefficients are Boolean by their `F_2` basis coordinates. This does not follow merely from a host `u64`, a serialized result or a field type name. It also does not require random-point multilinear evaluations to be Boolean. Their values generally lie in the extension field.

The forward map packs the same original private word assignment, with the actual odd-word and final zero-fill behavior. The reverse map recovers the same words from the same original committed coefficients and uses the actual shift and fixed-program wiring relations to recover the referenced operands. Both maps assume the full field, packing, ring-switch, commitment and opening correspondence. No accepted-proof or hiding theorem is established here.

## Source columns remain obligations

The retained operation-column producer evaluates each actual shifted operand against that same `ValueVec`, in actual constraint order and operand position. Integer multiplication materializes `[a,b,lo,hi]`. Binary field multiplication uses its six low/high operands. Empty multiplication sets skip those reductions. The AND producer materializes only A and B and derives its honest C as `A & B`.

That AND optimization does not remove the actual C operand from the verifier-owned program. The AND reduction returns a C claim, and the shift and native fixed-program wiring consumer must bind it to the original C references. The honest calculation is not an adversarial constraint. The same rule applies to the integer and represented field result columns.

The prover passes the same public and nonpublic slices to its shift reduction. It sends the public-segment and wiring claims, reduces the private trace claim through ring-switching, queues its trace relation and finalizes that oracle with the actual packed buffer. The selected finalization call is not an implementation of the complete commitment or deferred opening. Those concrete channel bodies remain required.

## Actual oracle specs and challenge order

`OracleSpec` records a logarithmic scalar message length and a masking flag. The setup channel records `is_zk = protocol_is_zk && is_witness_dependent`. Both the trace and the integer lookup pushforward are declared witness dependent at their actual receive sites. A masking flag describes intended channel behavior. It does not prove hiding, fresh entropy, repeated-proof privacy or the correctness of a combined opening.

`OracleSetupChannel` uses a zero-sized dummy field element. Its arithmetic, observations, assertions and relation checks perform no real verification. Receives return dummy elements, word sampling returns zero, and packing returns only the expected number of dummy elements. The caller discards the verifier result and reads the recorded specs. This is structural discovery, not execution of a valid proof.

For a fixed operation sequence whose branch decisions and oracle dimensions depend only on the fixed program and public shape, the setup run and real verifier emit the same oracle schedule. This follows by induction over the operations: each fixed receive emits the same spec, each sample closes the same current round, and dummy arithmetic changes no later control flow under the hypothesis. A value-dependent branch or an early real error invalidates that argument. These hypotheses must hold through every actual callee, including the still unreviewed bare lookup and channel compilation bodies.

The schedule records round boundaries as well as a flat spec list. Sampling a field element or word closes a nonempty current round. Queuing an oracle relation closes it too. Empty rounds are omitted. Taking only the flat list deliberately drops the boundaries. A list of oracle sizes cannot alone justify merging commitments across a challenge on which later oracle contents depend.

For the selected monolithic call sites, the visible inner oracle sequence is the trace followed, when IMUL is present, by one pushforward with `log_msg_len = 16`. Other currently selected word operations use field-channel reductions. This is a manual source-path statement under complete callee and schedule invariance hypotheses, not an evaluated setup, a complete wrapped-oracle count or an allocation measurement. The outer precommit, private and mask oracles remain additional parts of the actual wrapped verification.

## Both lookup openings on one commitment

The newly inspected IOP lookup wrapper samples the looker batching challenge `gamma` before receiving the pushforward commitment. The pushforward depends on that challenge. It receives every table's witness-dependent pushforward before invoking the subsequent bare lookup reduction. Later lookup challenges must therefore bind those commitments, while `gamma` must retain its actual earlier position. Moving every commitment before every challenge would change the construction.

For a fixed table `T`, actual lookup indices `I` and fixed looker weights `lambda_l`, a corresponding pushforward has the form

`Y[t] = sum_{lookers l, rows x: I_l(x)=t} lambda_l * eq(r_l,x)`.

The actual bare reduction must supply the exact challenge-derived looker weights, padding order and index embedding. No particular power sequence is established by this call-site review. With the same finite indices and weights, the corresponding product identity is just a reordering of the finite sum:

`sum_t Y[t]*T[t] = sum_{l,x} lambda_l * eq(r_l,x) * T[I_l(x)]`.

This identity explains the required association. It does not show that a prover-supplied vector equals that pushforward. The bare reduction, denominator checks, index claims and actual committed openings must enforce that relation.

The transparent-table wrapper queues two relations in order, against the SAME received oracle handle:

`<Y, eq_z> = pushforward_eval_claim`,

`<Y, T> = product_claim`.

The handle is cloned for the first call and reused for the second, rather than receiving two independent oracles. The public table closure is owned and may be evaluated later. Table and pushforward obligations are queued here, while the actual index claims return to the integer verifier for their final bit-column binding. A successful call to a channel that defers opening does not itself settle either relation.

For the actual 16-bit table specialization, the declared pushforward contains 65536 scalar coefficients. Counting 128 bits of logical field content per coefficient gives 1048576 bytes before masking, coding, commitment trees, queries, transcript and allocation overhead. This manual source specialization is not an allocation, simultaneous peak, serialized size or lower bound for all possible constructions. It does not select a Kova proving class or make its complete resource and parser gates pass.

## Batch and transport boundaries

The selected `ValueTable` is storage for a different batch setting. It omits constants and stores inout plus private words in wire-major order. Constants are supplied when reconstructing one instance. For valid counts and instance index, reading a strided row and reconstructing a `ValueVec` return the same declared source word by direct index substitution. This storage identity does not prove the M4 protocol or authenticate a public payment statement. Its hidden inout values are existential unless the complete surrounding relation binds them to the expected statement.

`ValuesData` is a versioned owned word segment, not an authenticated witness. Its decoder delegates the word vector to the shared serialization layer. `Proof` is a versioned byte container plus a challenger-type string. Its decoder reads a string and byte vector. Neither selected body supplies a Kova payload cap, nested allocation policy, fixed proof shape, expected statement, full-consumption rule or authority to select a challenger from peer input. Their source names and documentation do not certify zero knowledge or cross-host security.

## Remaining private cash construction

This review gives a conditional original-word/packed-coefficient association and exposes the exact two openings that a standalone lookup claim cannot replace. It leaves the actual bare lookup, product-tree and sumcheck reductions, concrete masked commitment channel, field implementation, compiler lowering and complete parser and resource correspondence unfinished. Schedule discovery, padding, source headers and host validation are not substitutes for those predicates or a joint security argument.

The [same private payment witness](private-witness-join.md) must still reach real authorization, authenticated eligible membership and spent state, conservation and the complete [same-opening encrypted output](whole-encryption-completion.md) inside one actual private program. Practical recipient completion and truthful refusal remain unselected. Full KEM/KDF/GCM semantics, entropy and nonce policy, atomic state, confidential bootstrap, recovery, independent nodes and the complete proving-resource and security gates remain prerequisites of the [minimal private cash launch](../../docs/minimal-launch.md). The [full roadmap](../../docs/delivery-roadmap.md), including later private contracts and Safe, is unchanged. Payments remain private by default.
