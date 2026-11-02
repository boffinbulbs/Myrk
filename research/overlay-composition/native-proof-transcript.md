# Native proof transcript and completion boundary

## Construction status

This source and conditional mathematical review connects the actual native field and word channel to transcript bytes, challenger state and explicit completion. It extends the [main round source binding](main-round-source-binding.md) and [original codeword privacy](original-codeword-privacy.md) reviews.

The complete private cash architecture remains unfinished. No native backend, field, hash, challenger, private program, parser, proving profile or execution class is adopted. No helper, compiler, hash, randomness, witness, proof or upstream test was executed.

## Source scope

The source is [binius-zk/binius64 at `6e75a2d1d2e716578ae3ccb62806413fb1615176`](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). The [source record](native-proof-transcript-sources.json) identifies six complete bodies and the retained caller contexts.

Three proper directory metadata reads resolved the transcript source. Before any body acquisition, six whole bodies were selected with exact paths, sizes and Git identities. Nine requests retained 43736 decoded UTF8 source bytes. All six lengths and computed Git blobs matched separate immutable primary directory metadata. The connector did not supply an independent source SHA or base64 envelope. No raw HTTP, complete tree, dependency, artifact, field, hardware or toolchain audit is claimed.

All six bodies and embedded tests were read as data. The selection is closed. The actual field decoder, complete hash and tree construction, byte codecs, production challenger selection and dependency feature closure remain outside this source selection.

## Actual native entry

The retained `ZKVerifier::verify` takes the expected verifier object, public words and a mutable borrow of `VerifierTranscript`. It creates the native BaseFold channel, wraps it, observes the statement, runs the inner verifier and checks the native expected wiring equation. Its `wrapped_channel.finish()` runs the outer verifier and the single combined opening over the same queued oracles.

This entry does not consume the borrowed transcript or call its consuming `finalize`. The caller that owns the transcript must perform that separate completion check. Success from the inner verifier, the outer verifier or the combined opening does not imply complete byte consumption.

This is an API boundary, not a demonstrated attack on every upstream application. A surrounding application may perform the required finalization. No complete upstream application or accepted malformed proof was executed here.

The concrete FRI channel delegates field and word operations to this native transcript outside the symbolic inner verifier builder. Dummy builder word values therefore do not replace the native queries on this inspected entry. Arbitrary generic channels and unrelated entry points are not covered by that statement.

## Three byte routes

The transcript distinguishes these operations:

| Operation | Proof tape | Challenger observation |
| --- | --- | --- |
| `observe` | No read or write | Written statement bytes |
| `message` | Prover writes, verifier reads | The same bytes when advanced |
| `decommitment` | Prover writes, verifier reads | None at this route |

`FiatShamirBuf` observes bytes when its inner buffer advances. On a write, its unsafe implementation reads the bytes that the caller promises are initialized. The generic buffer contract and actual codecs must satisfy that premise. This source inspection is not an unsafe memory audit.

An advice value read through `decommitment` is not authenticated merely because it was read. The actual caller must check it against the same prior commitment or other source relation. In the retained FRI route, roots are observed and the openings are decommitment advice. The actual tree, hash, codec, index range and terminal vector checks still need their complete binding argument.

Statement observation must bind the actual expected public statement and program. A peer supplied challenger, verifier, profile, root, field value or success token is not that authority.

## Conditional byte replay correspondence

Fix one expected program, options, deterministic challenger implementation and canonical codecs. Assume corresponding encoders and decoders round trip, all operations complete within their declared bounds, and both sides start with the same challenger state.

Let `T` be the tape produced by the complete ordered prover operation sequence. Pair every observed statement operation, message, advice read and challenge request with its corresponding verifier operation. The operation order includes sample widths and the exact distinction between observed and unobserved bytes.

Induction over that sequence gives the following local correspondence:

1. Statement observation feeds the same encoded bytes without changing either tape cursor.
2. A message writes and reads the same next encoded bytes. Those bytes advance both challenger states in the same way.
3. Decommitment reads the same next advice bytes and advances neither challenger state through that route.
4. Equal deterministic challenger states and equal sample requests return equal challenge bytes and update the states equally.

The verifier therefore recovers the same typed values and challenges, provided every source predicate and round trip assumption holds. This is an honest byte replay statement. It does not establish that the original witness satisfies a payment relation or that a proof is hiding, binding, sound or extractable.

The reverse local statement requires successful canonical decoding, all actual protocol checks and complete consumption. It associates the checked values with the exact consumed tape. It does not turn arbitrary protocol messages into a unique original private witness. Same witness source constraints, original oracle binding and the applicable soundness or knowledge theorem remain necessary.

Neither direction permits replacing an advice check with an unverified host value, omitting a pending wiring claim or discarding the outer proof or combined opening.

## Explicit completion and bounded parsing

`VerifierTranscript::finalize(self)` returns an error when any bytes remain. Its destructor instead emits a warning about unread bytes. A warning is not a rejecting verifier result.

For a fixed successful read schedule consuming a prefix `P`, the protocol prefix alone cannot distinguish `P` from `P || S` when a suffix `S` is never read. Explicit finalization rejects a nonempty remaining suffix. This conditional parser fact is not an implemented malformed proof experiment or a claim that all surrounding applications omit finalization.

A complete Kova verifier would need an owning entry with these actual behaviors:

1. Resolve the fixed expected program, version, field, challenger and options from authenticated local rules.
2. Reject unsupported shapes and overlong input before allocating according to untrusted counts.
3. Decode only the declared canonical bounded proof and statement representation.
4. Run the expected native wiring checks, outer verifier and the single combined opening over the same transcript and committed sources.
5. Propagate every error and require successful consuming transcript finalization before reporting acceptance or changing state.

This is a missing construction specification. No such adapter or complete parser was implemented in this review.

The inspected generic reader is not that bounded parser. `read_scalar_slice(len)` allocates `len` default field elements before reading them. `read_vec(n)` collects the caller's requested count. Error conversion in the native channel can map decoding failures to `ProofEmpty`. These methods do not supply authenticated count limits, canonical field decoding, transport framing or complete network refusal behavior.

Debug bytes are conditional on `Options.debug_assertions`, whose default uses the build setting. A fixed wire format must select and bind the expected behavior. A debug assertion or panic is not a typed resource refusal.

## Field challenge and interpolation domain

The actual prover and verifier field sample implementations both call

```text
DeserializeBytes::deserialize(challenger.sampler())
```

and expect the challenger buffer to be infinite. There is no exclusion of field one or local rejection loop in these bodies. Infinite byte availability alone does not prove successful field decoding, uniform field sampling or independence from prior observations.

The actual selected field representation and decoder determine the pushforward from challenger bytes to field values. The production challenger and full transcript determine those bytes. Those sources and their hypotheses are required before assigning a live point support or probability.

The earlier main round helper computes

```text
p_0 = (claim-alpha*y_1)*(1-alpha).invert_or_zero().
```

Its arbitrary genuine polynomial correspondence requires `alpha!=1`. At one it selects zero for the constant coefficient under the stated inverse semantics. The native transcript method above does not discharge that condition. The actual point law, honest completion or terminal refusal policy, or a complete reviewed interpolation construction is still missing.

No probability of this coordinate in the live implementation, actual failing proof, accepted bad proof or complete upstream security failure is established. No challenge exclusion, resampling, reset or transcript prefix retry is selected.

The division free compressed coefficient recovery in the masked verifier is a different operation. Its acceptance of endpoint one does not repair the producer interpolation domain.

## Native word challenge and packing

`sample_bits_reader` reads four bytes, interprets a little endian `u32`, clamps the requested width to 32 and masks its low bits. Width zero still consumes four bytes. The native word channel converts the result to a 64 bit word.

Conditional on uniform independent input bytes, masking gives a uniform value on the indicated low bit range. The source operation itself does not establish that conditional byte law. A requested width above 32 produces the clamped range, so actual protocol query dimensions must establish the expected bound. No larger query domain or profile is selected.

`subset_sum_word` selects field elements by the actual low word bits and asserts at most 64 elements. `select_word` asserts a nonempty power of two array and selects the low index bits with `len-1`. These are native concrete operations on this entry, not dummy symbolic values.

`pack_words_concrete` sums `F::basis(i*64+bit)` for each set bit in a word chunk. Under the actual field basis correspondence this preserves the low word and bit layout of the committed trace. A partial final chunk contributes zero in its unused high word positions. The actual basis and field constructor still need their own source proof. Host words and arbitrary field evaluations do not supply adversarial bitness or the original private word constraints.

`recv_public_claim` defaults to a plain receive. Its documented caller obligation requires the actual claim check and public source dependence. A comment or method name does not prove that a witness dependent decrypted relation claim is public under the payment privacy policy.

## Challenger chronology and security boundary

The selected generic `HasherChallenger` starts from `H::digest([])`. Its initial sampler buffer contains that digest, and its internal hash state has absorbed it. A refill finalizes and resets the state, then feeds the resulting digest into the new state.

Switching a sampler to an observer absorbs the current buffer index encoded as `u64` little endian. Switching back flushes the observer's pending bytes, then creates a sampler positioned to refill. The index is the current digest buffer position, not a separately proven count of all previously sampled bytes.

These actual transitions explain why matched operation chronology matters. They do not select a Kova hash, establish domain separation for every protocol, prove safe use of arbitrary digest implementations or supply an interactive, ROM, BCS or QROM theorem. Deterministic replay is compatible with a witness dependent transcript. It is not a simulator or a privacy proof.

All original message components, clear claims, mask inner products, main and masked rounds, queries with duplicates and lift translations, folds, terminal vectors, outer interactions and repeated proofs still need one actual joint hiding argument. Conditioning on roots, messages or query choices can alter the prior law of the same randomness. Reused masks and correlated product coordinates cannot be counted as independent fresh entropy for each observation.

## Prospective effects and resources

The selected transcript body also contains a grinding operation. It tries nonce values serially on cloned trial challengers until a sampled condition holds, then writes one nonce into the real transcript. Its width assertion is at most 32 bits. Its search has no selected finite trial bound, and its nonce arithmetic and failure behavior need their actual completion model. No grinding operation or clone experiment ran.

Source comments about expected work and soundness credit are not imported security theorems. No grinding parameter or security score is adopted.

The prover's finalization can inspect `BINIUS_DUMP_PROOF` and create a proof dump file. This is a prospective filesystem and confidentiality effect that must be closed before any later execution. No proof was produced or dumped during this source review.

The transcript owns or retains proof bytes, typed vectors, the challenger, digest buffers and observer buffers. The full verifier also retains native wiring data, original codewords, trees, masks, transparent closures, folding buffers and pool capacity. A reader count or digest size is not a simultaneous peak or full wire measurement.

All current raw, owner, stored, kernel, transport, process and aggregate limits remain unchanged. No feasible complete private class is established by these source methods, byte replay formulas or parser specification.

## Whole private cash decision

The inspected route remains refused as a complete Kova private cash backend. The exact minimum missing construction joins the following parts:

1. One complete original private payment relation and source lowering for the same hidden note, verification key, real signature, nullifier secret, membership path, asset and value, policy, authorization, encrypted delivery and state transition.
2. A matched native proof construction whose actual field challenges and main round interpolation honestly complete or truthfully refuse under the declared supported domain.
3. Joint hiding and source binding for the same original trace, private lookup indices and both lookup relations, outer proof, all clear claims and every committed oracle view.
4. An owning bounded canonical verifier and parser that performs the actual checks and full consumption before any atomic state change.
5. Complete resource geometry, supported recipient completion or refusal and the applicable binding, proximity, Fiat Shamir, privacy and knowledge arguments.

The [same private witness](private-witness-join.md), [whole encrypted output](whole-encryption-completion.md), [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) requirements remain. Actual recipient matrix completion depends on the recipient source, not on resampling sender randomness. Source reading does not solve that practical completion boundary.

Authenticated atomic state, reward origin and maturity, confidential checkpoint bootstrap, independent nodes, private scanning and encrypted recovery remain separate real gates. No transparent fallback, weaker primitive, larger proving class or detached proof join is introduced.
