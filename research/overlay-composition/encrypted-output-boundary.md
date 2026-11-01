# Encrypted output construction boundary

This source and mathematical decision identifies the exact sender operations that a common private payment proof must constrain. It refuses selection of a complete executable encryption construction because the finite sampling policy, full cipher correspondence and combined proving representation remain missing. It changes no primitive, backend, profile or resource limit. The [source record](encrypted-output-sources.json) distinguishes source inspection, archive identity and the remaining closure.

The [common private witness](private-witness-join.md) requires the same canonical output opening in the note commitment, recipient binding, value/asset relation and encrypted plaintext. A host encryption result, ciphertext hash or separately accepted component does not establish those private equalities.

## Actual sender path and two different seeds

The retained host uses `ml-kem` 0.3.3, `aes-gcm` 0.11.1 and `sha3` 0.12.0. Its sender witness holds a private 32-byte encapsulation input. Call that input $m$ here. It is distinct from the public matrix seed $\rho$ contained in the recipient encapsulation key. Calling both objects a seed must not make them the same wire.

The actual ML-KEM-1024 key consists of four encoded NTT polynomials followed by $\rho$. The decoder performs the original 12-bit decode/re-encode modulus check, rather than accepting a reduced noncanonical key. The supported parameters are $q=3329$, polynomial length 256, $k=4$, $\eta_1=\eta_2=2$, $d_u=11$ and $d_v=5$. The ML-DSA modulus and its existing arithmetic gadgets cannot be substituted.

The actual encapsulation sequence is

$$h=\operatorname{SHA3\!\mbox{-}\!256}(\operatorname{canonicalEK}),\qquad
(K,r)=\operatorname{Split}_{32,32}(\operatorname{SHA3\!\mbox{-}\!512}(m\Vert h)).$$

Then K-PKE encryption uses the same $m$ and derived $r$. Four noise polynomials for the ephemeral vector use PRF counters 0 through 3, four first-error polynomials use 4 through 7, and the final error polynomial uses 8. These are SHAKE256 outputs with the exact original counter byte and CBD decoding. The transposed matrix uses the recipient key's $\rho$ and sixteen separate SHAKE128 index streams. It is not sampled from the private sender input $m$.

The source computes the actual forward NTT, matrix/vector and vector/vector products, inverse NTT, noise/message additions, compression and little endian coefficient packing. Its inverse transform includes the exact factor 3303. Compression contains a fixed reciprocal multiply, right shift, integer truncation and low-bit mask. A statement that it approximately rounds a rational number is not a replacement for its exact bounded integer operations.

The `module-lattice` field constructor itself does not validate a range. A constrained construction needs actual range invariants at sources, samples, every arithmetic reduction and every packed output. The source's `u16`/`u32`/`u64` arithmetic is distinct from equality modulo the proof field. Copying a machine integer into a field does not reproduce truncation, borrow, shift or overflow semantics.

## Matrix sampler and the finite construction gap

For stored matrix row $i$, column $j$, the encryption call requests transpose mode. The retained function swaps its local indices and then calls `XOF(rho,j,i)`. In this mode the resulting stream is SHAKE128 of $\rho\Vert\operatorname{byte}(i)\Vert\operatorname{byte}(j)$ in the stored transposed matrix. The swap and the call's argument order must both be retained.

Each stream is read through a 96-byte buffer. Each three-byte group produces

$$d_1=b_0+2^8(b_1\mathbin{\&}15),\qquad d_2=(b_1\gg4)+2^4b_2.$$

The reader returns the first candidate below 3329. When both are below 3329, it returns $d_1$ and caches $d_2$ for the next call. When only the second is accepted, it returns that second candidate. When neither is accepted, it consumes the group and continues without emitting a coefficient. Refill preserves the same XOF state. A final cached value can be unused after the 256th coefficient.

There is no explicit byte or candidate limit in this loop. Source inspection therefore supplies no finite worst-case trace length for all accepted canonical keys. This is **not** a proof of nontermination for any actual key, or a theorem that no finite bound exists. No seed was evaluated to investigate that question.

A fixed finite encryption relation would need a justified horizon and explicit completion/refusal semantics, or another complete construction with an accounted variable-length proof rule. All sixteen streams, actual absorption/squeeze continuations, rejected candidates, pending candidate, cursors and accepted counts must be constrained. Skipping rejected candidates or trusting a host-generated matrix changes the relation. Publishing a witness-dependent trace or recipient-key association is not a privacy-preserving workaround.

If a future bounded class refuses an original successful encryption whose sampler exceeds its horizon, its completeness statement must be restricted accordingly. A cap selected merely to fit the present prover would not prove completeness for the original host function. No horizon, new execution class, sampling theorem, resampling policy or changed primitive is selected here.

## Context, KDF and exact plaintext association

After real encapsulation, the host derives the recipient digest with its original framed `thorum.crypto-lab.recipient-key.v1` domain and complete recipient key. Its AAD is the ordered framing of encryption domain, suite version, actual encoded crypto context, recipient digest, actual KEM ciphertext and public nonce.

The AES key is the first 32 bytes of SHA3-512 over the original framed `thorum.crypto-lab.experimental-sha3-kdf.v1` domain, the same KEM shared key $K$ and that full AAD. This KDF is retained experimental laboratory semantics, not a newly selected production construction or a composition-security theorem.

The output crypto context must itself be derived from the same chain, current protocol version, validation tag, output index and full note commitment. Its shorter tag cannot replace the full commitment. The plaintext is every byte of the same canonical private opening. No free plaintext digest or manually supplied intermediate key is admitted.

For the ordinary 418-byte v2 payment opening, manual framing gives:

| Object | Contents bytes |
|---|---:|
| Framed crypto recipient-key hash preimage | 1610 |
| Full AAD | 1789 |
| Framed experimental KDF preimage | 1875 |
| Ciphertext body | 418 |
| Body with 16-byte postfix tag | 434 |
| Actual laboratory envelope framing with KEM ciphertext and nonce | 2036 |

These are source incidence calculations, not executed serialization fixtures, allocated buffers, process peaks, an admitted transport or a private proof size. They do not include the rest of the payment, proof, tree, claims or delivery-retention objects.

## GCM counter, tag and polynomial representation

The actual type fixes a 12-byte nonce and 16-byte tag. The host creates $H=\operatorname{AES}_k(0^{128})$, then $J_0=\operatorname{nonce}\Vert\operatorname{BE32}(1)$. The first counter block supplies the tag mask. Data blocks use the subsequent big endian counters. For a 418-byte plaintext there are 27 payload blocks, ending with two used keystream bytes. The requested payload counters are 2 through 28, with no counter wrap in this restricted shape.

The AEAD adapter encrypts the body and appends the tag afterward. GHASH processes the **ciphertext body**, separately zero-padded AAD and body, then a final block containing their big endian 64-bit bit lengths. It does not authenticate the plaintext in place of the ciphertext, include the appended tag in its own input, or join the two partial blocks before padding.

The logical single-message schedule requests 29 AES block inputs including $H$, the tag mask and payload. Its GHASH message stream contains $\lceil1789/16\rceil+\lceil418/16\rceil+1=140$ blocks. These are manual logical service counts. They are not measured block evaluations, CPU instructions or counts of extra lanes and key precomputation in a parallel backend.

The retained GHASH implementation reverses input block **bytes**, maps its key through byte reversal and `mulx`, evaluates POLYVAL and reverses the final result. The software POLYVAL multiplication then uses carryless product construction and the exact `mont_reduce` transform. Its low-level multiplication cannot be replaced by an assumed ordinary polynomial remainder operation merely because both are described as arithmetic in a binary field.

The portable product source retains its BearSSL and Thomas Pornin attribution. Those original source and license identities remain in the source record.

Concretely, for four little endian product limbs $(v_0,v_1,v_2,v_3)$, the retained 64-bit reduction performs this ordered transform. Left shifts retain only the low 64 bits and right shifts are logical:

$$v_2\leftarrow v_2\oplus v_0\oplus(v_0\gg1)\oplus(v_0\gg2)\oplus(v_0\gg7),$$
$$v_1\leftarrow v_1\oplus(v_0\ll63)\oplus(v_0\ll62)\oplus(v_0\ll57),$$
$$v_3\leftarrow v_3\oplus v_1\oplus(v_1\gg1)\oplus(v_1\gg2)\oplus(v_1\gg7),$$
$$v_2\leftarrow v_2\oplus(v_1\ll63)\oplus(v_1\ll62)\oplus(v_1\ll57).$$

The last two equations use the **updated** $v_1$. The resulting element has low limb $v_2$ and high limb $v_3$. This is a source transcription, not an independently executed field implementation or a newly proved equivalence of hardware and software backends. A bit relation must preserve the actual representation and updates, or prove its complete replacement equivalent.

The AES and POLYVAL crates dispatch between target-dependent hardware and portable implementations. No target feature, forced software flag or CPU-specific execution was selected. Full AES key schedule, substitution network, round routing, fixslicing, hardware intrinsic semantics and POLYVAL backend equivalence remain required before claiming a complete matching constraint implementation.

## Correspondence and refusal decision

A future honest witness map must start with the original same-opening sender witness and construct every derived value, sample, arithmetic intermediate, cipher state, ciphertext and tag. Conversely, an accepted constraint assignment must imply that those same sources produce exactly the retained host encryption and the exact public envelope. Both directions require canonical decoding, ranges, copies, full hash/squeeze semantics, sampler completion, modular arithmetic, AES and GHASH constraints. Naming the host function as a predicate or calling its `Result` a constraint proves neither direction.

Complete executable construction is refused at this boundary. The minimum unresolved work is:

1. A finite, source-matched sampling/completeness and refusal policy for all sixteen matrix streams.
2. Complete exact constraints and correspondence for modular decoding/compression/NTT, AES and represented GHASH, including the actual backend semantic boundary.
3. One bound private source and constrained read/write/copy/hold/padding/terminal path for the same note, key, sender randomness, shared key, AAD and ciphertext.
4. A complete joint authorization/payment layout, verifier, proof schema, parser and resource/security account.

The existing necessary raw `H<=256`, `W<=8`, `PV<=8` and monomorphic small owner are unchanged. The retained atomic Keccak representation and the prospective wire placement already fail their separate geometry gates. No full combined height/width, assertion count/order/degree, source/prepared/LDE contents, quotient/chunks/coupled masks, copy auxiliary, claims/query duplicates, salts/trees/FRI, entropy, simultaneous buffers/descriptors/leases or proof transport is supplied by the counts above. No resource class is expanded to turn this decision into an execution.

Output recipient nullifier secrets, decapsulation keys and spending signatures remain absent from the sender witness. Inputs, assets, values, private commitments, paths, key associations and signature intermediates remain hidden in the required common relation. Entropy quality, nonce policy, repeated/concurrent observations, actual hash/oracle compilation, Fiat Shamir and knowledge/quantum applicability remain separate security obligations.

The [complete roadmap](../../docs/delivery-roadmap.md), confidential stake/bootstrap, authenticated eligibility, reward origin/maturity/finality and atomic ledger/network gates remain unchanged. This review adds no working blockchain or accepting payment route.

## Evidence and next work

The selected retained source and thirteen package archives were inspected as data. Archive SHA256 identities match the exact existing lock tuples. This does not establish equality of every installed source member with its archive, resolve the unified feature/target graph or audit a library/toolchain. Full transitive executable, feature, license and provenance closure remains before a new program.

No Cargo metadata/fetch, compiler, encryption, key generation, sampler, protocol hash, evaluator, model, proof, native witness, network or old test was run. Source checks use stock file identities, baseline Git blobs, local targets and whitespace only. Future controls must include canonical key boundaries, swapped matrix axes, both rejected candidates, cached final candidates, wrong compression rounding/masking, changed plaintext/context, counter byte order, plaintext versus ciphertext GHASH, separate padding, tag inclusion, represented field reduction and source aliasing. These controls are requirements, not passing tests.

The next necessary source and mathematical task is the complete AES-GCM bit/field correspondence within this same-opening encryption path, followed by its joint resource decision. It must cover the full key schedule, all data and tag blocks, exact GHASH representation and actual backend correspondence. A tiny block-cipher demonstration or isolated sampler-prefix experiment would not satisfy that task.
