# Private authorization construction boundary

This source decision rejects scheduling the unchanged signature gadgets as a complete private payment construction in the current proving class. It identifies the private equality boundary that a successor must preserve. It adds no AIR, prover, parser, execution class or acceptance API. The [source record](authorization-sources.json) distinguishes inspected definitions from remaining implementation closure.

## Actual authorization and private interface

The [payment statement](../../crates/thorum-relation-lab/src/payment.rs) publicly contains chain and protocol context, an anchor, ordered stable nullifiers, output commitments and encrypted envelopes, and the fee. It does not publish input note commitments. Its canonical bytes enter the retained authorization message and context. The [authorization mapper](../signature-complete-native/src/authorization.rs) derives all 196 authorization bytes from that actual statement. It accepts neither an arbitrary job digest nor a private witness. Its 239 byte pure message is `00 || 29 || PURE_CONTEXT || authorization_input`, where `29` is hexadecimal for the 41 byte context length.

The [signature source](../signature-overlay/src/lib.rs) privately receives exactly the verification key, signature and 418 byte note opening. The verification key is public in the ordinary ML-DSA API but hidden in this proof witness. The current public field vector is the 196 authorization bytes, each represented separately in BabyBear. These public values are not a verified payment or authenticated ledger context.

The actual [source equations](../signature-packed/src/sources.rs) and [sponge joins](../signature-packed/src/sponge.rs) establish the following component interface:

1. Held words of the hidden verification key feed both the owner SHA3-512 computation and the SHAKE256 `tr` computation. At row 234 the same note's owner binding equals the computed owner digest. The note chain bytes equal the chain in the mapped public context. Fixed note framing selects the v2 payment encoding.
2. `mu` consumes the actual private `tr`, the pure message prefix and every public authorization byte. Decoded signature data, matrix expansion, transforms, modular arithmetic, inverse normalization, UseHint and the final challenge comparison must remain connected to those sources. Their preservation is a successor obligation, not a new equivalence result here.
3. The v2 note commitment is computed from the same held note bytes, written after row 413 and held afterward. The current overlay does not consume that digest in a membership or nullifier gadget. `NOTE_COMMITMENT` is a private intermediate, not an additional public input or an authenticated anchor opening.

The third item is an intended component boundary. It is not an executed attack or evidence that a complete payment verifier accepted mismatched witnesses. There is no complete private payment verifier in this assembly. The [transparent checker](../../crates/thorum-relation-lab/src/payment.rs) performs additional native checks while holding all private inputs and receiving caller supplied state. Calling it from a host cannot replace constraints in a private proof.

For each input slot, a complete relation must use one private tuple

$$w_i=(o_i,pk_i,\sigma_i,s_i,\pi_i),\qquad c_i=H_{\rm note}(o_i).$$

Here the opening includes its exact encoding and creation version. The same tuple must satisfy all of the following, using the original [note domains and encodings](../../crates/thorum-relation-lab/src/note.rs):

1. The owner binding in $o_i$ equals SHA3-512 of the exact $pk_i$ used by the signature relation. That relation authorizes the verifier derived `ExpectedAuthorization` of the same actual payment statement.
2. The hidden membership leaf is derived from this exact $c_i$, and $\pi_i$ leads to the statement anchor. The verifier separately authenticates that anchor's eligibility, origin and branch in its current state.
3. The secret binding in $o_i$ is derived from the same $s_i$. The public stable nullifier is the original version specific derivation from chain, $s_i$ and this same $c_i$. A current protocol or anchor change cannot rename it.
4. The input amount, asset, creation version and payment policy used for conservation and spend eligibility come from this exact $o_i$. Outputs bind their actual commitments, recovery bytes and encryption relation. Input and output totals include the fee with checked ranges.

These are internal private equalities, including slot and byte order. Publishing $c_i$, the owner key, a path or signature intermediates to join components would violate the intended visibility. Replacing $c_i$ with a caller supplied digest would remove the necessary equality. Two separate existential component statements do not establish one common witness merely because they authorize the same public payment. No composition protocol establishing those equalities is selected here.

## A restricted scheduling obstruction

Consider only transformations that retain each original `KeccakAir` round as an atomic gadget, preserve its columns and equations, and reschedule those gadgets with separate operands. This restriction excludes rewriting the round equations, supplying hash results, sharing incompatible live cells and dropping witness dependent hash calls. It is not a lower bound for all possible signature proof systems.

The retained Plonky3 0.8.0 `KeccakCols` has 2,633 fields. Its declaration accounts for 24 step flags, one export flag, three 100 field limb banks, two 320 field parity banks, 1,600 `a_prime` bits, 64 additional bits and four final limbs:

$$24+1+100+100+320+320+1600+100+64+4=2633.$$

The original [four slot wrapper](../signature-complete-native/src/keccak.rs) borrows four separate complete column windows and forwards the original AIR equations. Its first three transitions point to the next slot in the same physical row. Its fourth points to the next physical row. It invokes the AIR on every row, including padding. One remaining atomic slot alone already exceeds the current raw width limit of eight. A narrower wrapper cannot expose the original complete `KeccakCols` window by slicing eight fields.

The actual nonpadding hash schedule has 69 source permutations, 56 matrix streams with six permutations each, and nine final permutations. The [program](../signature-storage/src/program.rs), [full schedule](../signature-overlay/src/full_program.rs) and [actual constructor loops](../signature-packed/src/sponge.rs) therefore require

$$69+56\cdot6+9=414\ \text{permutations},\qquad 414\cdot24=9936\ \text{atomic rounds}.$$

This count excludes dummy padding, preflight recomputation and nonhash signature work. It counts the retained bounded schedule, even when a different sampler construction might stop earlier. Serializing one unchanged atomic round per row needs at least 9,936 active rows, hence at least 16,384 rows in a power of two trace. Keeping four slots needs at least 2,484 active rows before any other scheduling constraints. Neither is a proposed complete new layout.

The actual [preflight](../proof-preflight/src/preflight.rs) fixes prepared height $2H$, blowup eight and physical LDE height $16H\le4096$. Thus its admitted raw height satisfies $H\le256$, in addition to raw width at most eight. A 4,096 row storage limit is not permission for a 4,096 row raw trace. The current owner is still more specific: its [source extension](../fallible-source/src/extension.rs) accepts only the actual 256 by two raw class and its prepared and LDE shapes.

There are two further independent interfaces:

1. The [packed source](../signature-packed/src/packed.rs) holds 2,547 private source words across transitions and constrains routed Boolean ports to read those exact words. Deleting the held words requires a new constrained consistency mechanism for every read. Native array access, a row hash or a host memory check supplies no such relation.
2. The original overlay declares 196 public values, while preflight and the [quotient kernel](../quotient-source/src/quotient_kernel.rs) admit at most eight. Changing that public statement requires a reviewed relation and matching verifier schema. Relabeling authorization bytes or forwarding a digest does not preserve the existing interface automatically.

Consequently, serializing the four hash slots, reusing the arithmetic workspace, streaming raw rows or integrating compact metadata cannot by themselves produce a member of the current execution class. This refusal follows before any new symbolic collection or execution. It does not claim that every possible complete private authorization construction is impossible.

## Minimum successor construction

A successor needs a new constrained representation, rather than another retained gadget schedule. No particular decomposition or execution class is selected. The following deliverables are required together before selecting a program:

1. A complete equation map for the same hidden payment witness above, preserving the exact ML-DSA authorization, SHA3/SHAKE padding and rates, rejection samplers, coefficient ranges, NTT order, multiplication carries, UseHint, holds, initialization, terminal rows and wrap behavior. Every private read needs an actual constrained producer. A proposed memory or copy argument needs its own equations and soundness assumptions.
2. A constructive old to new witness mapping and an acceptance to relation argument. Honest witness generation alone does not establish the reverse direction. Constants, synthetic expected values and independent native success cannot serve as private constraint inputs.
3. Complete dimensions and resource expressions for the proposed relation: raw height and width, public values, assertion order and degree, prepared order and height, physical domains, normalized quotient chunks, coupled masks, auxiliary data, all claims, complete query rows and duplicates, salts, trees, FRI, descriptors, buffers and simultaneous ownership. A smaller width with greater height must include that greater height everywhere.
4. A matching complete verifier and bounded proof schema. The [existing transport refusal](transport-feasibility.md) remains: the current conditional full overlay main query rows alone require at least 5,399,232 canonical JSON bytes against the actual 2,097,152 byte small payload limit. This is an encoding bound, not an entropy bound. Changing encoding alone does not reduce the retained main LDE or establish the missing relation.
5. A source and dependency closure for the actual successor, independent literal and adversarial controls, and a fresh finite resource admission. The full existing gadget bodies, current owner, storage, hiding/MMCS/PCS/FRI, challenger, verifier and feature/license paths must be reviewed for that selected construction. This record does not claim that their entire execution closure was newly reviewed or audited.

The actual [producer](../trace-domain/src/owned_prover.rs) is fixed to `QuarticAir`, height 256 and its two public values. Its context does not accept an arbitrary AIR. A future adapter must preserve the latest ownership and busy-claim rules, original shared private opening flags, raw and physical domain guards, truthful first cause and terminal cleanup. It must produce an actual proof in one uninterrupted transcript before reporting proof production. No aborted prefix may become setup for a resumed proof.

Normalized quotient coupling, full claim batching and the ideal observation fibers retain their [separate evidence](instance-security.md). A new representation needs a fresh correspondence for fixed authenticated words, domains, degree, query closure and joint masking. Hash and salt compilation, child RNG streams, repeated and concurrent proofs, actual multiround Fiat Shamir, DEEP/proximity/batching, knowledge and classical versus quantum applicability remain open. There is no achieved security level or privacy simulator in this decision.

## Acceptance and status

Complete authorization remains blocked pending that construction. The same complete proof must also support the verifier owned [private transition context](../../docs/private-transition-state.md), current nullifier and anchor checks and atomic ledger consumption. Numeric work and monetary components, unverified job bytes, the byte journal and parent header work do not establish those properties.

Payments remain private by default. Confidential stake and bootstrap, durable signer history, atomic authenticated state and network activation remain separate launch requirements. The [full delivery roadmap](../../docs/delivery-roadmap.md) and its later application stages remain unchanged.

Validation here consists only of source identities, retained record comparisons, local links and whitespace. The schedule equations above are source arithmetic, not a new evaluator result. No compiler, metadata collector, helper, model, protocol hash, witness walk, prover, verifier, old test or network operation was run. Source path review is not a cryptographic library audit. Original Thorum MIT and Plonky3 MIT or Apache 2.0 attribution and licenses remain unchanged.
