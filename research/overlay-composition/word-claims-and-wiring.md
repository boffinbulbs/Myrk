# Word claims and committed wiring

This source and mathematical decision continues the [outer layout](outer-layout-preservation.md) and [wrapped transcript](wrapped-transcript-relation.md) reviews at historical `binius-zk/binius64` revision `6e75a2d1d2e716578ae3ccb62806413fb1615176`. It follows the actual word verifier's ordered claims, public-value closure and fixed-program wiring equation. The [source record](word-claims-sources.json) identifies complete bodies and remaining imports. No upstream protocol, compiler, test, witness or proof executed for this review. No backend, primitive, resource class or security profile is adopted.

## Order and actual source claims

The actual reduction order is integer multiplication, binary multiplication, bitwise AND, zero constraints, optional instance transport, shift and public-value consistency. The caller then ring-switches the committed trace claim and completes its opening. The pending wiring equation has an additional real verifier consumer. These are all parts of one verification, rather than independently accepted components.

The integer and binary multiplication routes return per-bit operand evaluation arrays before the AND reduction samples its univariate challenge. That later challenge supplies Lagrange weights collapsing the earlier arrays into the same oblong form as the AND claims. Reordering the messages would change their fixedness relative to that challenge. The source's order does not by itself establish the complete Fiat-Shamir or soundness theorem.

An absent integer or binary multiplication set skips its reduction under the fixed constraint system's guard. AND still runs over its padding row. `Instances::Single` and a batch with zero instance variables are different transcript modes: the batch can retain a zero-round claim-transport step. A future fixed Kova program cannot choose among these modes from a supplied peer verdict or convenient count.

AND receives 64 extension-domain values, prepends 64 zeros on the base domain, then samples its univariate challenge and runs its degree-two MLE check. It finally checks the received A, B and C evaluations against that result. The honest prover's host computation of a C column is not enough. Those same referenced operand columns must also be tied to the committed trace through the actual shift and wiring equations.

Binary multiplication receives six 64-entry arrays. It recombines low and high columns using the actual field basis and checks the product relation against its MLE target. This is a represented field multiplication predicate, not a reinterpretation of arbitrary word AND or automatically the retained GCM's scaled and byte-reversed GHASH operation. The complete integer multiplication runtime is not in this capture: its module entry only reexports `common` and `verify`.

Zero constraints contribute a zero evaluation claim at an inherited AND challenge prefix, extended with fresh challenges when required. They have no separate message or sumcheck. The actual challenge distribution, commitment fixedness and joint soundness must justify this reuse. Source comments asserting independence or a polynomial error bound are not imported as a protocol theorem.

## Public values have their own closure

The active public-value path is `reduce_constraints::verify_public_eval`. The separately retained `protocols/pubcheck.rs` function is not the call used here. The active path receives a public-segment evaluation claim, ring-switches it, runs a product sumcheck and checks the final product against two values computed by the verifier: the packed actual public words and the ring-switch indicator. It applies the exact zero-padding factors for the larger word-index space.

The packed public words come from actual constants and inout values in the fixed constraint system, with two words per field element and the correct final unpaired word. The wrapper allocates those concrete packed values as outer public inputs. It does not specialize an arbitrary statement into constants while constructing the outer circuit.

Ring-switching first receives the complete partial-evaluation vector and checks its low-coordinate evaluation against the outstanding claim. It transposes that vector in the actual basis and only then samples its row-batching point. The output is another claim requiring the appropriate public check or committed opening. Transpose, basis, packing and normalized evaluation correspondence remain required; a field name or supplied hash is not that argument.

## The exact pending wiring equation

The shift route batches the four operation types in order: zero, AND, integer multiplication and binary multiplication. It samples operation and operand weights, runs its sumcheck over two shift slots, three bit-index axes and the padded word space, and receives the hidden trace evaluation. The word space has a public half and a hidden half, with the shorter actual segment zero-padded.

Let `p` be the independently checked public-segment evaluation, `w` the committed hidden-segment claim and `s` the segment-selector challenge. The actual combined trace claim is

`t = (1 - s) * p + s * w`.

The source avoids deriving `w` by division by `s`; it receives and later opens that claim instead. The final local equation has the form

`sumcheck_target = t * lagrange_factor * outer_shift_indicator * inner_shift_indicator * wiring_claim`.

The bit-index factors are computed separately. The wiring claim arrives through the explicit public-claim route. Its input vector contains the operation/operand challenges, each operation's constraint-index point, both shift slots' points, word-index point and segment point. The wiring function stores the actual fixed constraint system and the shape derived by this verifier. It sums that system's real indexed operand terms. It reads no hidden witness words to evaluate the wiring polynomial.

`check_eval` returns the claim without settling it. `check_native` evaluates the same fixed-program polynomial and requires equality. The complete wrapped verifier extracts the actual public values and calls this consumer before outer verification and the combined opening. The source's deferred-claim API explicitly leaves an obligation unpaid. Its `check` accepts a constraint system from the caller and does not authenticate that pairing. A Kova boundary must retain the exact verifier-owned program identity and consume the whole claim; a detached serialized claim or a different system cannot become acceptance authority.

The inspected reduction, shift and public-consistency bodies use field-channel operations and actual packed public words. They do not call the wrapper's dummy `sample_bits`, word `select` or `subset_sum`. This discharges that concern only for these bodies. The uninspected integer multiplication callees and other transitive protocol paths remain before a blanket shape-invariance claim.

## Fixed sparse contraction

Each wiring entry has an actual constraint index, operand position, ordered inner and outer shifts and value segment/index. Its contraction multiplies the corresponding five axis weights and sums over every real term. Repeated identical entries cancel modulo two. Empty padding rows contain no terms and contribute zero.

The grouped generic evaluation is the same finite sum factored by constraint. Its equality to the flat contraction follows directly by distributivity, provided both use the same complete term list and correctly sized tables. No random claim or test result is needed for that algebraic identity. It does not establish that an unreviewed core operand/index constructor described the intended word operation.

The native path instead sums unreduced wide products and reduces once. Its equality additionally requires the actual identities `reduce(wide_mul(a,b)) = a*b` and additivity of reduction over the accumulated wide representation. These are implementation and field-representation obligations, not a theorem from the `WideMul` trait name or permission to replace the GCM's literal reduction. No native or hardware path runs here.

For the declared 64-bit specialization, the wiring code materializes 4096 inner-shift/operand weights and 512 outer-shift weights, plus the public/hidden word tensors and each present operation's constraint tensor. These are manual source table lengths, not compiled geometry, measured memory or a permitted class. Native evaluation also walks the actual constraint terms. Calling the equation public does not make the verifier's time or retained buffers constant. Both verifier and prover resources must be justified.

## Exact shift indicators

The source builds the multilinear indicators of logical left, logical right, arithmetic right and rotate-right relations on bit indices, plus their two-independent-32-bit-half variants. Its carry recurrence keeps the two cases `i+s=j` and `i+s=j+2^b`, starting at no carry for an empty prefix. At Boolean coordinates, the per-bit transition is exactly integer addition. Induction on the bit positions gives those two cases at the last position.

Every recurrence step uses its current coordinate at most linearly, with earlier carries depending only on lower positions. The resulting functions are multilinear. Left shift exchanges input and output indices; rotation adds the disjoint wrapped case; arithmetic right shift adds the overflow case gated by the all-one sign-bit index. Half-word variants use only five low index/amount bits and multiply by equality of the two half selectors. They ignore the top amount bit, preserving masked 32-bit amounts without mixing halves.

These vertex identities and multilinearity determine the claimed multilinear extensions, under the actual characteristic-two field and equality/interpolation operations. Their connection to canonical core shift indices and source word constructors still requires those actual bodies. The retained upstream tests were read as data, not run. No fresh sampler, random challenge or evaluator supplies evidence here.

## Limits of the construction

This review identifies the actual source binding and public check that an honest host C column, deferred wiring token or skipped outer assertion cannot replace. It does not prove the called integer reduction, core constraint/index validation, full sumcheck/MLE/ring-switch theorem, field/basis implementation, commitment/transcript/hash/FRI security, dependency and license closure or bounded canonical parser. No complete private-cash program, practical recipient-completion domain or combined resource class is selected.

The [common hidden payment witness](private-witness-join.md), [whole encrypted output](whole-encryption-completion.md) and [minimal launch](../../docs/minimal-launch.md) retain their exact note, real authorization, stable nullifier, membership, native asset/value conservation, same-opening KEM/KDF/GCM, fresh atomic state, confidential bootstrap and recovery obligations. No public private-input disclosure, host validity callback, detached proof, new primitive or weaker profile is introduced. The [full roadmap](../../docs/delivery-roadmap.md), including later private contracts and Safe, is unchanged.
