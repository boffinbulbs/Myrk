# Wrapped transcript and outer constraint relation

This source and mathematical decision follows the [word proof boundary](word-proof-boundary.md). It reviews the actual wrapper message, symbolic builder, witness replay and verification bodies at historical `binius-zk/binius64` revision `6e75a2d1d2e716578ae3ccb62806413fb1615176`. The [source record](wrapped-transcript-sources.json) distinguishes newly read complete bodies from retained contexts. No backend, executable root, private payment proof, resource class or security profile is selected.

## Actual message relation

The wrapped prover creates one private field key for each precommit position in the compiled outer relation. It packs and blinds that vector and sends its precommit oracle before the inner interaction. The actual combined oracle order is outer precommit, inner oracles, then outer private and mask oracles. Both concrete wrappers check the first specification and final suffix against the outer verifier's specifications.

For an ordinary private field message at position `i`, the actual channel relation is

`cipher_i = message_i + key_i`.

The symbolic receiver allocates an inout wire for `cipher_i` and a precommit wire for `key_i` and returns their difference. The witness replay writes those same two positions and returns their sum. The actual field has characteristic two, so sum and difference agree. The concrete verifier receives the ciphertext as an outer public inout value and creates a value-less precommit placeholder. It does not learn the key or the decrypted message from that placeholder.

The source has separate unencrypted routes. `send_public_claim` sends and records a field element without consuming a pad key. Observed elements and sampled field challenges also enter the outer public inout sequence. A complete application must establish that each use of a public route really is permitted public information. A field element's type or a method name does not prove independence from a private note, verification key, amount or recipient association.

No complete hiding theorem follows from the local pad equation. The precommit root, oracle evaluations, public claims, challenges and remaining transcript are also visible. Their binding, hiding and joint distributions require the actual commitment and protocol analysis. In particular, the proof's challenge-dependent messages cannot simply be treated as a fixed list independent of all keys. Fresh and concurrent proofs, RNG ownership, pad reuse and conditional leakage remain separate obligations. No RNG or protocol instance runs in this review.

## Three matched traversals

The symbolic builder, honest replay and actual verifier must traverse the same fixed verifier operations and allocation order:

| Operation | Symbolic outer relation | Honest outer witness | Actual outer public instance |
|---|---|---|---|
| Private receive | Allocate ciphertext inout and key precommit, return their difference | Write next recorded ciphertext and key, derive plaintext | Read actual ciphertext, allocate inout and unknown key placeholder |
| Public claim | Allocate one inout, no key | Write next recorded unencrypted claim | Read actual unencrypted claim |
| Field challenge or observation | Allocate one inout | Consume recorded value | Derive from the actual inner channel and allocate that value |
| Packed statement | Allocate one inout per packed element | Pack the actual public words and write them | Independently pack the actual expected public words |
| Zero assertion | Record a wire equation, or reject a nonzero constant | Evaluate the corresponding witness equation | Defer wire equations to the actual outer proof |

The last row matters. The concrete wrapped channel's wire assertion returns success locally because the outer circuit carries its constraint. That return value is not complete verification and cannot become a Kova proof verdict. Its `finish` reconstructs the public vector, runs the outer verifier and completes the combined opening. The ordinary inner wiring claim is separately checked by the top-level wrapped verifier against the actual fixed word program. All of these consumers remain mandatory.

The replay is an honest witness constructor. It does not independently verify an adversarial proof. It consumes recorded events and keys, panics if required values are exhausted and asks the witness generator to build the result. Its entry-level `finish` does not itself show that both iterators are exhausted. Exact fixed layout, operation counts, compiler checks and bounded transcript consumption must establish the complete boundary. No accepted malformed transcript or replay failure is claimed here.

Symbolic `sample_bits` returns a zero word. Symbolic word selection and subset sums use concrete word indices. The actual verifier samples the real bits. Therefore correspondence additionally requires that every such use is either excluded from the outer circuit and checked by its real native verifier consumer, or has an exact argument that the symbolic and actual circuit shapes agree. The previously identified public wiring check is one deliberate exclusion. It is not permission to specialize an arbitrary private or challenge-dependent branch using dummy zeros. The unreviewed called word reductions and compiler remain necessary.

## Conditional semantic correspondence

Assume a fixed verifier-owned program, identical ordered operations across the three traversals, correct field and builder implementations, and a compiler that preserves every emitted equation and public/private position. Also assume that each queued oracle relation and the same precommit oracle are bound by the actual completed commitment protocol, and that the outer proof is sound for its exact relation.

An honest inner execution gives a forward witness by writing each actual ciphertext, public message, sampled value, observed value and packed statement to its corresponding inout position, and its actual pad to the corresponding precommit position. Arithmetic induction on the fixed operations gives the same decrypted values and intermediate equations. This maps an admitted inner execution to the intended outer relation when the required inverses exist and the actual compiler accepts its complete witness.

Conversely, a satisfying outer relation under those hypotheses fixes every private receive to the ciphertext minus its bound pad and enforces every recorded arithmetic and zero equation. The actual verifier independently fixes the public values and consumes the outstanding wiring and opening checks. Induction then recovers the exact inner verifier equations for that one transcript. Transferring these equations to an accepted original private payment additionally needs the actual inner protocol's soundness and the complete source-bound payment relation. Neither is supplied by the wrapper alone.

These are conditional relation arguments, not an existing accepted-proof, Fiat-Shamir, zero-knowledge, knowledge-extraction or quantum theorem. The actual frontend compiler, witness and instance generators, field implementation, BaseFold channels, transcript and full opening argument are not yet a complete reviewed closure. No host Boolean, supplied root, separate component proof or serialized verifier object may replace those hypotheses.

## Exact field gadgets and failure boundaries

`CircuitElem` distinguishes a constant from a builder-owned wire. All-constant operations fold at the field level. Wire operations delegate to the actual builder. Its combination operations compare weak builder identities before mixing wires. The lower-level `to_wire` method assumes that the caller already has the right builder. It does not independently enforce that assumption. A future integration must prove the actual call graph preserves ownership; it cannot import the existing Kova owner's guards by naming the same abstraction.

The hinted inverse emits `x * inverse = 1`. At zero this relation is unsatisfiable; it does not implement an inverse-or-zero operation. The source explicitly leaves the zero-admitting method unimplemented and uses an unsafe nonzero contract for inversion. Correct callers and honest zero-challenge failure semantics remain required. A new integration cannot reset its challenger, resample or resume a prefix to hide such a terminal failure. No zero case was executed or observed here.

The transpose gadget is a real constrained decomposition, rather than a host bit-transpose answer. For an extension of degree `d`, it hints `d*d` subfield coefficients, constrains each by the Frobenius equation `c^(2^k) = c`, reconstructs each original field element in the actual basis and computes the transposed basis combinations. Subject to the stated field and basis hypotheses, subfield membership and unique basis expansion imply the claimed transpose in both directions.

For a degree 128 extension over binary bits, `d = 128` and `k = 1`. The generic source would then request 16384 coefficient hints before optimization. This is a manual specialization of the source formula, not generated circuit metadata, retained field cells, a proof size, a lower bound on another construction or a feasible combined resource record. The retained test instantiates `Ghash128b` and `BinaryField1b`, but the complete field implementation remains outside this closure. The source tests were read as data and never executed. Full hints must be constrained by reconstruction and range equations; their honest values alone have no authority.

## Private cash adoption remains refused

The wrapper supplies no private note semantics. The [common witness](private-witness-join.md) and [whole encrypted output relation](whole-encryption-completion.md) still require one private note, key, real signature, nullifier secret and path across membership, owner, actual authorization, stable nullifier, checked native-asset conservation and fresh authenticated state. Each same output opening supplies both the commitment and all encrypted plaintext, linked to the actual recipient key, private sender input, ML-KEM, KDF, nonce, AAD, body and tag. Recipient spending secrets are absent from the sender witness. Private source words do not become public inputs because a cryptographic interface calls a key public.

Practical ML-KEM recipient completion and refusal remain unselected. This wrapper does not justify a convenient sampler cutoff, changed seed, host matrix or accepted successful prefix. The literal GCM reference does not select an AIR, prove hardware equivalence or remove the full signature, state and delivery obligations.

Actual resource closure must include the complete inner program, outer verifier relation, pad and blinded precommit storage, recorded interactions, reconstructed public and private vectors, masks, operand and wiring columns, transforms, codewords, trees, queries, claims, combined opening and parser bytes, pooled allocations and simultaneous lifetimes. The verifier deliberately keeps its instance generator alive through opening because queued transparent closures use it. Sequential inner and outer phases do not eliminate retained allocations or proof contents.

The minimum next construction remains complete compiler and reduction correspondence, actual fixed program and supported recipient domain, full commitment/transcript/parser/security closure and justified joint geometry. Existing small classes and full-signature refusals remain unchanged. No larger cap, weaker primitive, profile substitution, executable verifier or working private chain is supplied. The [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) keep their proof, privacy, confidential bootstrap, atomic state, recovery and independent validation gates.
