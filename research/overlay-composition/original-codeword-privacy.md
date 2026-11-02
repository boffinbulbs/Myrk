# Original codeword disclosure and privacy boundary

## Implementation status

This is a source review and conditional mathematical construction for a prospective private word backend. It resolves the selected encoding and native query route, and identifies the missing hiding construction for the same original word trace. Kova has no adopted backend, complete private payment proof, proving profile or execution class from this work.

The [encoded oracle correspondence](encoded-oracle-correspondence.md) follows the original commitments, first and later folds, queried cosets and terminal check. The [masked opening](masked-oracle-opening.md) gives the preceding batching and mask interpolation. This review connects their selected call sites to the actual encoder and distinguishes independent encoder masks from randomness inside the original committed message.

## Primary source coverage

The historical primary revision is `6e75a2d1d2e716578ae3ccb62806413fb1615176` of [binius-zk/binius64](https://github.com/binius-zk/binius64/tree/6e75a2d1d2e716578ae3ccb62806413fb1615176). Current upstream HEAD was not verified. Two directory metadata reads resolved eight complete bodies. The fixed path, size and blob list preceded the eight body requests in the acquisition record. Its durable list write failed and was repaired after capture. The distinction is retained in the source provenance. No request was retried or replaced.

| Complete selected body | RAW bytes | Role |
|---|---:|---|
| `crates/iop/src/merkle_channel.rs` | 9,034 | Native verifier commitments, openings and terminal vector |
| `crates/iop-prover/src/merkle_channel.rs` | 18,594 | Matched producer commitments and openings |
| `crates/math/src/reed_solomon.rs` | 16,354 | Encoder, input permutation, repetition and adjoint |
| `crates/math/src/ntt/mod.rs` | 12,012 | Transform and domain interfaces |
| `crates/math/src/ntt/domain_context.rs` | 15,014 | Actual basis and twiddles |
| `crates/math/src/ntt/neighbors_last.rs` | 32,021 | Scalar, packed and parallel forward scheduling |
| `crates/math/src/ntt/subspace_polys.rs` | 16,355 | Normalized basis polynomials and generator row identities |
| `crates/math/src/binary_subspace.rs` | 15,816 | Ordered basis and subset enumeration |

The eight bodies total 135,200 RAW bytes. All whole bodies and embedded tests were read as data. All lengths, SHA256 identities and computed Git blobs agree with returned primary SHAs and separately resolved directory metadata. The ten request selection is closed. Two ceiling slots remained unselected. The [source record](original-codeword-sources.json) includes these identities and the retained actual producer, wrapper and packing contexts.

No upstream example, test, compiler or proof was run. No library or dependency was imported. Original MIT and Apache notices remain unchanged. Metadata is connector returned JSON. Pinning these bodies is not complete Git tree, installed artifact, feature, dependency license, field, toolchain, unsafe memory or hardware equivalence.

## Actual original message path

The inspected `ZKProver::prove` borrows the caller's `ValueVec` and calls the inner `IOPProver::prove` through its wrapped channel. The inner prover takes `witness.non_public()`, which excludes public values and scratch. It calls the actual `pack_witness` and sends that packed buffer as the trace oracle.

The packing pairs consecutive original words in little endian order:

```text
pi[j] = B128::new(word[2*j] + 2^64 * word[2*j+1]).
```

An unpaired last word has a zero high word. The trailing partial packed group precedes zero padding. The actual packing routine takes no RNG and fills the remaining entries with zero. This observation applies to this trace construction. A caller could supply private words with additional randomness, but that is a separate program and distribution obligation.

The wrapped producer's `send_oracle(buffer)` delegates that same buffer directly to its inner BaseFold channel. It does not apply the transcript message pad to oracle coefficients. The BaseFold producer checks the original buffer length against its own oracle specification and passes that buffer to `encode_masked` when the specification is marked private. The independent encoder mask is generated there.

The resulting source chain is therefore

```text
same ValueVec private words
    -> deterministic original-word packing and zero padding pi
    -> wrapped send_oracle forwarding the same buffer
    -> encode_masked(pi, fresh encoder mask omega)
    -> actual codeword and original commitment.
```

Outer Spartan transcript keys, dummy witness values and multiplication masks have their own actual buffers and oracles. The outer producer's `pack_and_blind_witness` does add random dummy values to its own precommit and private segments. That does not alter the already committed inner word trace `pi`. Protecting an inner interactive message with an outer transcript key and hiding the original trace's queried encoding are distinct obligations.

## Exact lane correspondence

Let `R_k` reverse exactly `k` index bits. Let `d` be the original code dimension, `r` its inverse rate logarithm and `b` its batch logarithm. The actual `encode_batch` checks its NTT subspace equals the fixed code subspace and checks the input dimension. It copies the input into an output buffer, calls `bit_reverse_packed`, repeats it to the encoded length and calls the forward NTT with

```text
skip_early = r
skip_late  = b.
```

The actual bit reversal and field buffer helpers are outside this selection. The following correspondence explicitly assumes their scalar contracts, packed lane order and the selected NTT's scalar meaning.

For a lane `l` and original index `j`,

```text
R_(d+b)((R_b(l) << d) | j) = (R_d(j) << b) | l.
```

An active NTT layer `a < d+r` pairs scalar positions differing by `2^(d+r+b-1-a)`. Hence it preserves the low `b` lane bits. Dividing a lane's positions by `2^b` gives the single lane pair indices and block twiddles. Repeating the entire permuted input also repeats each lane's permuted input. Under the explicit helper and field hypotheses,

```text
E_b(M)[(x << b) | l] = E_0(M_l)[x]
M_l[j] = M[(R_b(l) << d) | j].
```

This is an index and loop correspondence. Upstream test identities provide retained data, rather than an executed check or a substitute for the argument. Packed interleaving, reference fallback, arithmetic and all integer preconditions remain implementation obligations.

For `encode_masked`, `b=1`, `M=pi || omega` and `R_1` is the identity. The actual leaf convention consequently has the conditional map

```text
C[2*x]     = E_0(pi)[x]
C[2*x + 1] = E_0(omega)[x].
```

The bit reversal explains how the concatenated input becomes two interleaved output lanes. No missing interleave error is inferred from the concatenation call site.

The first fold uses the equality tensor of the mask challenge `gamma`, giving

```text
(1-gamma)*E_0(pi)[x] + gamma*E_0(omega)[x]
    = E_0((1-gamma)*pi + gamma*omega)[x].
```

Linearity establishes this forward identity. One sampled interpolation does not recover both original coefficient vectors. The source permits `gamma=1`, so its exceptional values must remain part of the actual soundness analysis.

## Basis, lift and conditional converse

The selected Gao Mateer basis is generated by descent through `L(x)=x^2+x` from the field's trace one element. The source checks `beta_0=1` and has `L(beta_i)=beta_(i-1)`. Under genuine binary field arithmetic and valid dimensions, the basis is independent: apply `L^k` to a proposed nonzero linear combination with greatest occupied index `k`. Lower terms vanish and the highest term becomes `1`.

That argument does not verify the actual field constant or arithmetic implementation. The dimension bounds, nonzero normalization, machine word shifts and allocation arithmetic need complete caller preflight. `BinarySubspace::new_unchecked` does not establish independence by itself.

Padding `eta` high original message index bits with zero makes the corresponding low reversed coefficient bits zero. Earlier transform layers preserve those low bits. With matching basis prefixes and twiddles, their nonzero lane computes the smaller transform. Each of the last `eta` layers pairs `(c,0)` and produces `(c,c)`, so the larger encoded sequence repeats the smaller entries contiguously `2^eta` times. This connects the preceding lift index translation to the original message under the same helper, packed and domain hypotheses.

The selected forward routines use depth, breadth and fused shared scheduling, with packed lane interleaving and some raw slice construction. Reading those bodies is not an unsafe memory or parallel execution audit. Their fast inverse methods remain unimplemented. The inspected encoder uses the forward method. Small packed shapes call a reference implementation outside this selection.

The novel basis has polynomial degrees `0` through `2^d-1` and nonzero leading coefficients under the field and normalization hypotheses. Evaluation at at least `2^d` distinct domain points is injective. Thus a full valid codeword identifies a unique original coefficient vector, and the exact lane order identifies `pi` and `omega` separately.

Accepted finite query openings and a proximity argument are a different premise. They require actual binding, proximity, folding, batching, challenge and transcript hypotheses before they can support a converse about a proof. This injectivity argument is neither commitment knowledge extraction nor a deterministic inverse for sampled checks.

## Actual native authentication route

On the inspected top level path, setup symbolically executes only the inner IOP verifier through the outer circuit builder. Actual `ZKVerifier::verify` constructs a native `VerifierMerkleTranscriptChannel` through `BaseFoldVerifierCompiler::create_channel_from_transcript`. The wrapped finish first runs outer IOP verification and then runs the combined BaseFold opening and FRI on that native channel.

Consequently the actual FRI word indices, `select` and `subset_sum` on this path are native transcript operations. They do not use the symbolic builder's dummy zero query value. Generic alternative channels and other inner transitive word operations need their own correspondence. The actual fixed program wiring claim remains a native check before wrapped finish.

The matched native Merkle channels send and receive roots as observed messages. Opening data are decommitment advice. The verifier retains its own leaf size and depth with each root, converts actual query words to indices, checks their range and reads the requested scalar leaves. It verifies a shared internal layer and then calls actual `verify_opening` for every queried leaf, preserving duplicates. For the full terminal vector it calls actual `verify_vector` against that same original root.

The called tree, hash, field codec and transcript bodies are not included here. Their names do not establish hash binding, canonical decoding, complete opening consumption, typed bounds or byte EOF. The inspected top level verifier borrows a transcript and returns without establishing a complete Kova parser. Source count assertions and shifts do not replace bounded network refusal.

## The original trace disclosure

Under the exact lane map above, each opened masked leaf contains both

```text
E_0(pi)[x] and E_0(omega)[x].
```

The native verifier reads all leaf scalars before computing the first fold. It therefore sees the original message encoding value itself. The independent encoder mask has coefficient zero in that component. Later interpolation and outer verification do not erase a value already in the transcript view.

Let `G_x` be the original encoder's row at that query position. Project the restricted fixed linear view onto its original message component. For an allowed difference `delta_pi`, the projected difference is `G_x*delta_pi`, while the projected encoder mask image is zero. The preceding [linear hiding criterion](masked-oracle-opening.md) therefore requires

```text
G_x*delta_pi = 0
```

for hiding by this independent encoder mask alone. Whenever an allowed difference violates that equation, this mask alone does not hide the projected view. This is a conditional local linear obstruction. It does not claim that every complete upstream application leaks a secret or provide an executed attack or accepted bad proof.

The actual original trace could include separately justified hiding randomness. If it has a representation `pi = J(witness) + D*eta`, its complete disclosed view needs the image of `G*D` to cover the allowed image of `G*J`, jointly with every other claim, query and fold disclosure. Merely having random note fields or unrelated cryptographic intermediates is not a proof of that distribution or rank condition. The actual program, constraints, independence and correspondence must establish it.

The inspected generic inner packing and forwarding path introduces no such randomization into `pi`. Outer precommit keys and random dummy values occupy different oracles. Their independent randomness has zero coefficient in the already disclosed `G*pi` component unless an actual source construction couples it to the same original trace. The source's private oracle flag and independent encoder mask therefore do not supply the missing trace hiding argument.

This is sufficient to refuse adoption of the inspected route as a complete Kova private word backend. It is not a global rejection of word proofs, an assertion about a later upstream revision, or a replacement security theorem.

## Minimum complete construction

Before further implementation selection, the architecture needs an actual hiding representation or proof mechanism for the same inner word trace, with both semantic directions to its original Boolean words and operations. It must preserve integer multiplication, represented multiplication, bitwise relations, source indices, private copies, stable authorization and encrypted output association. Adding a host pad or unused random buffer without those equations cannot establish it.

The hiding argument must cover the complete original leaf view, private lookup table relations, outer and inner claims, terminal vector, commitments, salt if any, and repeated or concurrent proofs. The fixed linear criterion alone does not handle adaptive Fiat Shamir indices, hash roots or their conditioning. Exact entropy, transcript, classical and quantum hypotheses and knowledge obligations remain separate.

Additional random word positions would change the actual program, packing, source index space, constraints, oracle dimensions and retained proof resources. No such repair is implemented or admitted. Outer dummy counts do not automatically transfer to an inner oracle. Existing raw, owner, stored, kernel, transport and aggregate limits remain unchanged.

The encoding phase can retain the original message, mask, concatenation temporary and output simultaneously. Original codewords and trees remain for queries while first and later folded buffers are constructed. Parallel tasks, scratch, retained pools, query multiplicities and terminal data require simultaneous accounting. No measured peak, wire size, security level or feasible class follows from this source review or from the parameter optimizer's estimates.

## Private cash requirements

The [same private witness](private-witness-join.md) and [whole encrypted output](whole-encryption-completion.md) remain mandatory. Input note, actual verification key and signature, nullifier secret, membership path and commitment must be the same hidden assignment through authorization and current spent state. One canonical output opening must feed its note meaning and every encrypted plaintext byte with the same recipient, private sender randomness, KEM, KDF, context and complete GCM.

The practical recipient completion or refusal policy remains unselected. Sender randomness does not change the recipient's matrix seed. No trace hiding proposal resolves that separate completion problem, actual state construction, full parser, consensus or confidential bootstrap by itself.

The selected conditional encoder and native query maps are complete at this local boundary. A complete private cash proving architecture remains unfinished. No new program, cryptographic execution, compiler, proof, parser, ledger, dependency, resource class or production capability is added. The [minimal launch](../../docs/minimal-launch.md) and [full roadmap](../../docs/delivery-roadmap.md) retain all base requirements and later private contracts and Safe milestones.
