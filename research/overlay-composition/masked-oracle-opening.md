# Masked oracle opening and joint exposure

This source and mathematical decision continues the [private trace](private-trace-oracles.md) review at historical `binius-zk/binius64` revision `6e75a2d1d2e716578ae3ccb62806413fb1615176`. The [source record](masked-oracle-sources.json) pins nine complete matched verifier and prover compiler, channel and opening bodies. Their embedded tests were read as data. No upstream compiler, native example, witness, RNG or proof ran. No backend, primitive, profile or proving class is adopted.

## Commitments, handles and actual completion

The prover channel receives raw message polynomials. For an oracle whose fixed spec requests hiding, it calls `encode_masked` and retains the returned mask, encoded codeword and Merkle commitment. An unmasked oracle takes a different encoding path. Actual mask sampling, Reed-Solomon encoding, Merkle hashing and FRI queries remain called implementations outside this selection. Their names and documentation are not a hiding or binding theorem.

The prover must later finalize each oracle with its message buffer. The selected code checks that finalization occurs once. It does not compare every finalized coefficient to the original commitment at that API boundary. The complete proof must bind the message actually opened to the originally committed encoding. Honest ownership of a buffer does not replace that obligation.

The oracle handles contain an index into a channel's commitment and relation arrays. They have no separate runtime owner identifier. The selected callers use the same channel and its actual returned handles. An arbitrary handle from a different channel is not acceptance authority. Bounds checks on its index alone do not authenticate a pairing.

The verifier derives the Merkle commitment shape from its own fixed oracle specs and FRI parameters. It checks that message size, mask dimension, batch size and codeword depth agree. The descriptive size and witness-dependence arguments passed to `recv_oracle` are not its authority for that shape. The program, spec sequence and parameters must remain verifier owned.

Both channels queue relations and defer the combined opening until `finish`. Finish requires all configured oracle receives to have occurred. If every relation queue is empty, the selected code skips opening. Otherwise, it requires at least one relation per committed oracle. Consequently, a successful generic finish is not by itself proof that a payment program queued its required obligations. The actual fixed entry must retain its trace, lookup, outer and native wiring checks. The wrapped entry runs outer verification before this combined opening and keeps its instance generator alive for deferred transparent closures.

The selected verifier finish returns the underlying Merkle channel. It does not itself establish complete byte consumption by an application parser. Extra-byte refusal, bounded decoding, resource admission and the expected statement remain separate requirements.

Several count, shape, missing-finalization and handle preconditions use assertions or panics. They are not a complete typed refusal boundary for unauthenticated network input. The fixed-program caller and a future bounded parser must establish those preconditions before selecting these lower operations.

## The actual order of the combined opening

Let oracle `i` have message `pi_i`, mask `omega_i` when enabled, and ordered relations `s_ij = <pi_i,t_ij>`. The actual channel performs these steps in oracle-index order.

1. It samples a relation-batching challenge `lambda`, even when each oracle has only one relation. It forms `T_i = sum_j lambda^j t_ij` and `S_i = sum_j lambda^j s_ij`. The prover modifies the first transparent buffer by adding the remaining scaled buffers. The verifier evaluates the same fixed polynomial in `lambda` through an owned transparent closure.
2. The prover sends `sigma_i = <omega_i,T_i>` for each masked oracle. Only after receiving all those values does the verifier sample one shared masking challenge `gamma`. An all-unmasked configuration omits this challenge.
3. For a masked oracle, the actual folded message and target are `pi_i' = (1-gamma)pi_i + gamma omega_i` and `S_i' = (1-gamma)S_i + gamma sigma_i`. Unmasked messages and targets pass through unchanged. This is interpolation, rather than a replacement by `pi_i + gamma omega_i`.
4. A degree-two batched sumcheck reduces all folded inner products to one shared point. The prover sends one `alpha_i` evaluation per oracle. The verifier reverses binding-order challenges into variable order and checks every transparent factor with its actual zero-padding factor.
5. Only after those evaluations arrive does the verifier sample the outer oracle-combining point. One combined multilinear and one combined FRI opening settle the reduced claims. The degree-one MLE check and FRI share their actual folding challenges.

The relation claims and transparent coefficients must be fixed before `lambda`. Commitments and mask inner-product claims must be fixed before `gamma`. The queued-closure API does not prove closure purity or transcript fixedness for arbitrary callers. The actual compiler, field operations, wrapper and transcript must establish those properties. Lookup's earlier looker-batching challenge remains distinct from this later masking challenge. Its pushforward is committed after that earlier challenge, preserving the dependency identified in the [trace review](private-trace-oracles.md).

## Forward identities and conditional converse

For a fixed message and transparents, inner-product linearity proves that all correct original relations give `<pi_i,T_i> = S_i`. It then gives the actual interpolated identity

`<pi_i',T_i> = (1-gamma)S_i + gamma sigma_i`.

This is the forward algebraic map for the selected folding step. It does not establish the RNG, encoding, commitment, sumcheck or FRI implementations.

The converse is not deterministic from one batched equation. For a fixed original relation-error list, its batched error is a polynomial `D_i(lambda)` of degree at most `k_i-1`, where `k_i` is that oracle's relation count. A nonzero list can cancel at a particular challenge. Under an independently uniform classical field challenge and genuinely fixed coefficients, the root bound is at most `min(1,(k_i-1)/|F|)`. A union bound over the actual lists is possible under the same hypotheses. This conditional elementary bound is not the complete protocol's soundness, Fiat-Shamir or quantum theorem.

After that step, write `d_i = <pi_i,T_i>-S_i` and `e_i = <omega_i,T_i>-sigma_i`. The masked residual is `(1-gamma)d_i + gamma e_i`. If `d_i` is nonzero and both errors were fixed before an independently uniform `gamma`, this is a nonzero polynomial of degree at most one, with at most one root. If the mask claim is correct, `gamma = 1` removes the original message contribution entirely. The source does not exclude or resample that value. Exceptional challenges belong in the full error analysis, rather than a deterministic accepted-proof implication.

A reverse relation map therefore assumes actual binding to the same original message and mask polynomials, validity of all lower reductions and openings, and the appropriate no-cancellation conditions or a proved soundness error statement. It cannot recover each original relation merely from `Ok`, a queued handle, a mask flag or an honest replay. No accepted bad proof, malformed-input execution or attack was produced in this review.

## Two different padding rules

Let `N` be the maximum oracle variable count and `n_i` the original count for oracle `i`. Phase A checks a zero-padded inner product. Its terminal factor includes `eq(0,point[n_i..N])` over every extra coordinate.

Phase B uses the actual FRI lift/repeat geometry. Write `ell_i = log_lift_i` and `d_i = N-n_i-ell_i`. The combined oracle uses

`L_i(x,z,w) = pi_i'(x) * eq(0^ell_i,z)`.

It is constant along the `d_i` repeat coordinates `w`. Its point evaluation therefore has only the lift-coordinate zero factor. The outer combination is `Q = sum_i eq(index_i,r_outer)*L_i`. Its target uses that same lift-only factor. Replacing it by the Phase A factor would change the relation.

The prover's `place_repeated` fills exactly the low source-sized part of each lift block and repeats that block over the high coordinates. At Boolean coordinates this is the stated function. Both sides are multilinear, so they agree everywhere under the actual field and packed-lane representation. The implementation handles both whole packed blocks and blocks narrower than one packed element. This mathematical placement argument is conditional on the called packed-field and buffer operations. The source tests were not executed.

## Actual opening and terminal check

The shared masking challenge, when present, is supplied first to the FRI folder. Outer oracle-combining challenges follow it. The fresh standard variable challenges come last. They are not freely reorderable windows.

In each standard round the prover sends the MLE coefficients before a possible folded-codeword commitment, then samples the challenge. The verifier receives those coefficients, processes the matching FRI round, recovers the polynomial using the matching high-to-low evaluation coordinate and samples the same next challenge. It finally invokes the real FRI query verifier and asserts equality between the final MLE value and the final FRI value. The returned FRI value is checked, rather than discarded.

This identifies the actual terminal consumer. It does not prove the uninspected fold, query, code, field, hash or transcript implementation, or import the BaseFold, binary-FRI and BCS paper claims from source comments. The concrete compiler calls `FRIParams::optimal_for_batch`; its arity-strategy argument is not used at that call site. A caller-supplied strategy name therefore does not establish the actual folding geometry.

## Joint exposure is a separate obligation

A useful conditional criterion for a fixed linear view is exact. Suppose all masks form a uniformly random vector `omega` independent of private vector `pi`, and that a restricted view has the form `v = A*pi + B*omega` with fixed matrices independent of both vectors. Then the distribution of `v` is uniform on the coset `A*pi + image(B)`. It is independent of the private vector precisely when every allowed difference `A*(pi-pi')` belongs to `image(B)`. This follows because all fibers of the linear map `B` have the same cardinality.

Applying that criterion requires the actual joint observation map. Mask inner products, all query openings, folded values, cross-oracle claims and repeated observations must appear together. Counting mask coordinates or proving the interpolation identity does not determine that map. The real commitments, hashes, adaptive challenges, salts and RNG are not a fixed linear view. Their simulation, binding, entropy, classical and quantum assumptions remain additional obligations. No such matrix, full simulator or achieved security level is claimed here.

## Retained data and feasibility

The prover stores masks, codewords, Merkle commitments and queued transparent buffers across oracle commitments. Finalized original messages remain live until finish. After relation batching, it computes mask inner products and folds the message buffers in place. The codewords and their commitments continue to represent the original committed data.

Phase A borrows the messages and moves the combined transparents into sumcheck stores. Later the prover allocates one `2^N` combined buffer while original codewords, commitments, masks and remaining folded messages are still live. Messages are consumed during placement. Masks are dropped as the original codeword/commitment pairs move into the FRI folder. Allocator pools may retain capacity after logical drops. These overlapping lifetimes matter even without cloning the main messages.

The declared 16-bit lookup pushforward alone has 1048576 bytes of 128-bit field contents, and its equal-length mask adds the same logical contents when enabled. Encoded data, trees, relation buffers, sumcheck storage, combined materialization, queries and transport are separate. These are source-based content and lifetime observations, not an actual allocation, simultaneous peak, complete private-payment geometry, wire size or universal lower bound.

The prover compiler seeds an internal `StdRng` from a supplied `CryptoRng`. The no-ZK constructor asserts that every spec is unmasked before using its fixed seed. Neither trait bounds nor this source inspection establish fresh independent masks across repeated or concurrent proofs. No RNG was invoked here. The selected code also copies specs and FRI parameters when building certain upstream compiler/channel values. Those operations were read as source, not adopted into Kova's existing owned proving path.

The minimum remaining construction is still one complete [private payment program](private-witness-join.md), practical recipient completion or truthful refusal, the actual [same-opening encrypted output](whole-encryption-completion.md), matched source-bound authorization and authenticated atomic state, and a complete bounded prover, verifier and parser with justified resources and joint security. Bare lookup and sumcheck reductions, actual encoding/FRI/query/Merkle/transcript and field closure remain open. This local source correspondence supplies no new accepting payment route or permission to enlarge current caps. The [minimal private cash launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md), including later private contracts and Safe, retain all base gates. Payments remain private by default.
