# Whole encrypted output and finite completion

This source and mathematical construction joins the actual ordinary v2 note opening, recipient key, deterministic ML-KEM encapsulation, framed KDF and complete GCM output in one relation. It gives a family of finite relations, both semantic directions and an explicit distinction between successful execution and termination on every canonical key. It selects no executable circuit, proving class, production parameter or acceptance path. The [source record](whole-encryption-sources.json) states the nominal scope and evidence limits.

The construction refines the [common private witness relation](private-witness-join.md), [encryption boundary](encrypted-output-boundary.md) and [whole portable GCM relation](gcm-word-relation.md). The saved [integer GCM reference](../gcm-word-reference/README.md) is separate measured evidence. Its host word representation is not the field geometry of this construction. No reference, cipher, sampler, seed search or previous test runs in this increment.

## One opening and exact sources

Fix one ordinary recipient-v2 Payment output at its actual ordered index. Its canonical private opening has exactly 418 bytes. It contains the chain, creation version, asset, amount, owner binding, recipient nullifier-secret binding, recipient-key binding, serial, blinding and Payment policy. The original framed domains and field widths remain unchanged. The complete same byte vector supplies both the note commitment and every encrypted plaintext byte.

Use the actual canonical recipient encapsulation key `ek`, 1568 bytes, and private sender input `m`, 32 bytes. The key splits into 1536 encoded NTT coefficient bytes and a 32-byte matrix seed `rho`. These are three different objects. In particular, `m` is not `rho`.

The output opening's recipient-key field equals the original relation hash of its chain and this same `ek`, under `thorum.relation-lab.recipient-key-binding.v2`. Its owner and nullifier-secret bindings remain the fields of the same recipient capability. A sender does not need the recipient's nullifier secret, decapsulation key or future signature. Correct encoding does not establish possession, intended recipient identity or key generation provenance.

For all bytes use Boolean coordinates. For each fixed machine word use its complete bit vector. The elementary Boolean and carry equations from the GCM relation apply over a prime of characteristic greater than three. Do not equate large integers by their field residues. Every copy below is a mathematical identity of actual source variables. An eventual AIR still needs an enforced copy or memory construction, not a host table of these identities.

The source order is acyclic:

1. Derive the canonical opening and its full 64-byte commitment.
2. Derive the exact output context from chain, protocol version, validation tag, actual output index and full commitment. Keep the original hash and its first 32 bytes as the tag. The tag does not replace the commitment equality.
3. Derive the actual KEM ciphertext and shared key from `ek` and `m`.
4. Derive full AAD, KDF key and body/tag from those same sources and the actual public nonce.
5. Put the entire envelope into the actual ordered payment statement. Derive its authorization context and 196-byte authorization input, then constrain each real input signature and the joint payment relation.

The proof bytes, its own digest and a work seal do not enter their own statement. No supplied digest, Boolean, callback, root, separate encryption verdict or equality of public statements joins separate hidden witnesses.

## Canonical key domain and the completion question

The retained `EncryptionKey::from_bytes` splits `ek`, decodes the four polynomials and compares their re-encoding to the original 1536 bytes. Decoding 12-bit words performs one conditional subtraction of 3329. Re-encoding therefore admits precisely coefficients below 3329. `Elem::new` itself performs no range check.

There is no key-generation provenance check. For each arbitrary 32-byte `rho`, the 1536-byte all-zero coefficient encoding followed by that `rho` passes this particular round trip. This is a symbolic observation about the key decoder, not an evaluated key, a valid payment, a secure recipient or a demonstrated attack.

Each of the sixteen matrix streams depends only on this `rho` and its fixed pair of indices. Resampling `m`, changing the note or changing the GCM nonce cannot change matrix completion for that recipient key. A recipient preprocessing certificate would require its own authenticated construction and same-key constraints. A host cache or supplied matrix is insufficient.

Thus a practical finite class needs either a justified bound over its actual accepted recipient domain or an explicit, separately selected recipient-domain/refusal policy. Canonical encoding alone proves neither. No new such policy is selected here.

## Exact bounded sampling relation

Let `B` be a positive mathematical integer counting three-byte candidate groups per matrix stream. It is a fixed relation parameter, not a peer-chosen value or an admitted resource cap. No practical numeric `B` is selected.

For stored transposed row `i`, column `j`, the actual `transpose=true` swap followed by `XOF(rho,j,i)` yields the message `rho || byte(i) || byte(j)`. Both indices range from zero through three. Use SHAKE128 with its actual 168-byte rate, suffix 31, final high bit and complete Keccak rounds.

Constrain the XOF prefix of length

$$L(B)=96\left\lceil B/32\right\rceil.$$

The prefix preserves the original 96-byte refill and three-byte group alignment. Extra bytes after the selected prefix's completion are deterministic continuation bytes, not additional original consumed candidate groups. Computing this padded prefix is a mathematical construction choice, not an observed runtime call count. The [whole Keccak relation](keccak-fixed-wiring.md) must be expanded with actual absorption, padding and squeeze state transitions. A free XOF-output array is not a constraint.

For every group `(b0,b1,b2)` in the first `B` groups form, in order,

$$d_0=b_0+256(b_1\mathbin{\&}15),\qquad
d_1=(b_1\gg4)+16b_2.$$

Both have 12 constrained bits. Let `a_t` equal the exact comparison `[d_t<3329]` for candidate positions `0 <= t < 2B`.

Comparisons and equality are deterministic bit equations. One explicit comparison uses binary subtraction `x + borrow_next*2 = y + borrow + difference_bit` at each bit from low to high, with Boolean difference/borrow and initial borrow zero. The final borrow is `[x<y]`. Equality uses XNOR on each pair of bits and a chain of Boolean AND gates, starting at one. All intermediate Boolean outputs are constrained. This avoids an unproved large-field comparison or tuple compression.

Maintain a nine-bit rank `r_t` in `[0,256]`, starting at zero:

$$u_t=a_t[\,r_t<256\,],\qquad r_{t+1}=r_t+u_t.$$

The addition has its actual bit carries and no overflow. For every output coordinate `0 <= ell < 256`, define

$$e_{\ell,t}=u_t[\,r_t=\ell\,].$$

Require final rank 256. Each output coefficient is the selected candidate's twelve bits. This can be expressed without a field-count assumption by a fixed chain of conditional bit writes starting at zero, plus a Boolean `seen` bit that starts at zero, refuses a second write and must finish at one. The `e` identities drive those writes. There is no equality of a huge modular sum to an integer count.

By rank induction, each accepted candidate before completion advances by one and writes the corresponding next coordinate exactly once. Rejected candidates never advance or write. Once the rank is 256, all subsequent selectors are zero and outputs hold. Consequently the relation chooses exactly the first 256 accepted candidates, in original order, without gaps or later replacement.

This includes the original pending-second behavior. If both candidates are accepted, `d0` precedes `d1`. If `d0` is the 256th output, the pending `d1` is unused. If only `d1` is accepted it is used immediately. A successful prefix cannot skip a rejected group, restart a reader or change its seed.

## A finite bound for successful executions

There is a precise, impractical bound that does **not** assume SHAKE outputs are independent or uniform. Fix a deterministic 1600-bit squeeze transition with the retained byte/rate semantics. A SHAKE128 rate block has 168 bytes, hence exactly 56 aligned three-byte groups. At a conceptual rate-block boundary, record the 1600-bit sponge state and the number of accepted candidates so far, between zero and 255 while unfinished.

The next block and next pair are deterministic. There are at most `256 * 2^1600` unfinished pairs. If a pair repeats before completion, the deterministic future repeats and can never reach 256. Therefore any successful sampler must complete within

$$256\cdot2^{1600}\text{ rate blocks},\qquad
B_* = 56\cdot256\cdot2^{1600}\text{ candidate groups}.$$

This is the pigeonhole principle applied to block state and progress, not a cryptographic theorem. It requires no bijectivity, randomness or positive acceptance rate. The 96-byte buffering does not invalidate the argument because both 96 and 168 are divisible by three. The conceptual candidate sequence is the same byte prefix, even when a host refill has prefetched part of a later block. Pending accepted second candidates are consumed in order before a new group, or remain unused after completion.

The conclusion is conditional on **successful termination**. It does not prove that every canonical `rho` produces enough accepted candidates. It supplies no useful deployment bound, execution permission, allocation plan or successful seed. It sharpens the distinction between an unbounded source loop and the finite horizon of its successful executions. The relevant remaining question is a feasible uniform bound or explicit admissible-domain policy, not a claim that no finite successful-execution bound can exist.

## Complete PKE arithmetic, not free modular values

Fix the actual ML-KEM-1024 parameters `q=3329`, `n=256`, `K=4`, `Eta1=Eta2=2`, `Du=11`, `Dv=5`. They are different from the ML-DSA arithmetic modulus. Preserve these exact operations:

1. `Hek = SHA3-256(ek)`. Compute `SHA3-512(m || Hek)` and split its first and last 32 bytes into `Kshared` and `rcoins`. These two hashes use raw concatenation, not the relation's framed domain function.
2. Generate `y` from four SHAKE256 streams `rcoins || counter`, counters 0 through 3. Generate `e1` from counters 4 through 7 and `e2` from counter 8. Each outputs 128 bytes, decoded into 256 four-bit values. For each value, count the low two bits and high two bits, then conditionally reduce their difference modulo 3329 exactly as the source does.
3. Compute `yhat=NTT(y)`. Form the actual matrix/vector and dot products, reducing after each original fold addition from zero. Set `u=InvNTT(Astored*yhat)+e1` and `v=InvNTT(that dot yhat)+e2+mu`, with the original addition association. Here `mu` is the 256-bit message decoded in little endian bit order and decompressed by `(3329*bit+1)>>1`.
4. Apply the literal compression and encoding to form `Encode11(u)` followed by `Encode5(v)`, after compression. These parts have 1408 and 160 bytes and are the same 1568-byte KEM ciphertext used in AAD and the envelope.

For canonical inputs, addition, subtraction and negation use `small_reduce`: subtract `q` exactly when the unsigned comparison says the intermediate is at least `q`. Its source all-ones/zero mask is constrained to that comparison. Canonical sums and differences are below `2q`, so one subtraction suffices. The four-bit CBD value gives `x+q-y` in `[q-2,q+2]`, also within that domain.

Multiplication requires the actual wider reduction, including the two-product base cases. For this modulus the source has

$$s=24,\quad M=\lfloor2^{24}/3329\rfloor=5039,\quad
\delta=2^{24}-3329M=2385.$$

Every reduction input on the selected canonical multiplication paths is at most

$$X=2(3328)^2=22,151,168.$$

This exceeds `2^24`. A proof restricted to smaller inputs would miss actual `BaseCaseMultiply` sums. The exact manual inequality

$$X\delta=52,830,535,680 < 3329\cdot2^{24}=55,851,352,064$$

implies that `floor(x*M/2^24)` is either `floor(x/q)` or one less, for `0 <= x <= X`. Hence the source remainder lies in `[0,2q)`, is below `2^16`, survives its explicit truncation unchanged and becomes the canonical residue after `small_reduce`. The `u32` products/sums and `u64` reciprocal product do not overflow within this domain. This is a hand-derived range lemma, not an executed arithmetic control or a claim about arbitrary callers of the generic field macro.

Preserve the base-case source association:

$$b1g=R(b_1\gamma_i),\quad
c_0=R(a_0b_0+a_1b1g),\quad c_1=R(a_0b_1+a_1b_0),$$

where `R` is that literal reduction. Use the retained `ZETA_POW_BITREV` and `GAMMA` definitions with root 17, seven-bit reversal and canonical constants. No runtime constant generator or alternative NTT is selected.

The forward butterfly layers have lengths 128 down to 2 and consume table indices 1 through 127. Each reads both old operands before writing `right=oldleft-t`, `left=oldleft+t`, with `t=zeta*oldright`. The inverse layers run from 2 through 128, indices 127 down to 1, write `left=oldleft+oldright`, `right=zeta*(oldright-oldleft)`, and finally multiply all coordinates by 3303. Snapshot reads and actual vector fold order are part of the relation.

Compression is the exact integer source operation, not its approximate rational commentary. For `d` equal to 5 or 11, retain

$$\left(\operatorname{low16}\left(
\left(((x\ll d)+1665)\lfloor2^{34}/3329\rfloor\right)\gg34
\right)\right)\mathbin{\&}(2^d-1).$$

Canonical `x` and these two fixed `d` values keep the wide product below `2^46`. Encoding takes each coefficient's actual `d` low bits in little endian order. General decoding/accumulator and truncation paths retain their specified widths. No field residue, rounded-real formula or unchecked constructor replaces these machine operations.

## Full context, KDF and GCM join

Write `F(x)=u32BE(len(x)) || x`. All domains below are the exact retained ASCII bytes with no appended zero. For relation hashing, `Hdom(d;xs)` means SHA3-512 of `F(d)` followed by every `F(x)` in order.

The actual output context is

$$t=\operatorname{first32}Hdom(
\texttt{thorum.relation-lab.output-encryption-context.v1};
chain,protocolBE4,validationTag,indexBE4,c64),$$

followed by `ctx=F(chain)||F(protocolBE4)||F(t)`. The same actual full `c64` equals the commitment of the complete opening under `thorum.relation-lab.note-commitment.v2`. The note's recipient-key binding uses its separate v2 domain and the same `ek`. Creation version equals this output's protocol version and its chain and policy are the actual ordinary v2 fields.

The crypto recipient binding is a different value:

$$b=SHA3\text{-}512(F(\texttt{thorum.crypto-lab.recipient-key.v1})\Vert F(ek)).$$

Build AAD as `F(thorum.crypto-lab.recipient-envelope.v1) || F(suiteBE2) || F(ctx) || F(b) || F(kemct) || F(nonce)`, with the original suite value 1. Derive the AES key as the first 32 bytes of SHA3-512 of `F(thorum.crypto-lab.experimental-sha3-kdf.v1) || F(Kshared) || F(AAD)`.

For the ordinary instance, context is 80 bytes, AAD is 1789 and the KDF preimage is 1875. These source lengths do not supply proof dimensions or executed fixtures. SHA3-256 and SHA3-512 use their actual 136-byte and 72-byte rates with suffix 6. SHAKE128/256 use rates 168/136 and suffix 31. Every invocation keeps its own complete absorbed message, capacity state, high-bit padding, round transitions and squeeze continuations. A permutation correspondence alone is not the sponge relation.

Use the fixed literal noncompact portable GCM relation for the entire 418-byte opening, the derived AES key, same AAD and public 12-byte nonce. Its 120 expanded words, omitted-NOT compensation, all payload counters, GHASH ciphertext blocks, separate padding, bit lengths and final tag remain exact. All derived KEM/cipher bytes are actual wires into later hashes and terminal outputs. There is no second free expected-ciphertext witness. The whole body of 418 bytes and tag of 16 bytes equal the actual envelope. Canonical envelope framing and end consumption remain required.

This is correspondence to the fixed literal mathematical path. Equivalence of the selected runtime's hardware paths, experimental KDF composition, actual nonce/entropy policy and complete AEAD/security obligations remain separate. Deterministic equations cannot establish fresh entropy or nonce uniqueness.

## Both semantic directions and their exact limits

Let `R_B` be the complete relation above, including source identities, all original canonical/range/policy conditions, full bit operations, constrained hashes, final envelope equality and all sixteen successful matrix prefixes. It is a mathematical definition by fixed operation expansion. It is not an existing generated circuit, AIR, proof or implementation of private memory.

For an original successful sender witness whose sixteen matrix streams complete within `B` groups, record the same opening, key, `m`, nonce and all source operations. Extend only the deterministic unobserved XOF suffix to the padded length. Rank induction gives its exact matrices. The range lemma, original NTT ordering, hashes and portable GCM correspondence supply all remaining assignments. Thus it gives an `R_B` witness, subject to the stated literal-backend correspondence assumptions.

Conversely, a satisfying full `R_B` assignment has actual canonical source bytes, exactly the original first 256 accepted candidates in every matrix and unique outputs at each fixed arithmetic/hash/cipher operation. Process the original source schedule in order. Induction yields the same KEM ciphertext, shared key, AAD, derived key and full portable GCM bytes on the same opening. Therefore it satisfies those original sender-check obligations under the same source/backend assumptions. Local host `Result` success is not an equation in this argument.

Increasing `B` changes no completed result. The family covers precisely the successful original deterministic sender computations, with their literal correspondence assumptions. In particular the impractical `B_*` covers all successful matrix computations by the finite-state argument. This does **not** turn a nonterminating canonical-key case into a successful encryption, establish that such a case exists, or make `B_*` feasible.

Neither direction establishes original-object provenance, recipient possession, production registry authority, an accepted current proof, zero knowledge, knowledge extraction, authenticated state or a cryptographic security level. The input side still needs the very same hidden note/key/signature/secret/path through eligibility, owner authorization, stable nullifier, spent state and conservation. Output sender knowledge must not acquire recipient spending secrets merely to close that join. Actual reward origin, maturity, finality and atomic state are separate obligations from creation version and encryption.

## Concrete representation refusal and remaining work

The explicit selector construction materializes one `e` for each of sixteen streams, 256 output positions and `2B` candidate positions. That is `8192B` Boolean field cells before comparisons, ranks, bit writes, any hash, PKE arithmetic, GCM or payment relation. Completion requires at least 128 groups even without rejection, giving at least 1,048,576 selector cells for this representation.

Current necessary raw height at most 256 and width at most eight provide at most 2048 raw field cells. Thus this direct materialization is refused before a layout or program is selected. This is a manual bound for this particular representation, not a universal signature/encryption complexity lower bound, measured allocation, peak, wire size or new resource admission. Replacing selectors with a streaming write or copy argument changes the construction and needs its own sound constrained access proof. The current second copy phase is unimplemented.

No complete `H/W/PV`, assertion order/count/degree, prepared source, main LDE, normalized quotient/chunks/eighth mask coupling, copy auxiliary phase, claims/multiplicities, duplicate query rows, denominators, salts, trees, FRI, entropy, buffers, descriptors, leases, simultaneous peak or bounded transport/parser is supplied. Degree two elementary equations do not select a whole AIR degree, old quotient count or security profile. The original full signature refusal and distinct stored/kernel/owner limits remain unchanged. There is no cap or class expansion.

The minimum remaining construction is now more specific:

1. A practical fixed completion/refusal policy for the actual accepted recipient domain, with original successful semantics, failure privacy and honest completeness stated separately. The astronomical successful-execution bound cannot serve as a practical profile.
2. A complete constrained state/copy and operation placement for **all** same-opening PKE/KDF/GCM and original private authorization, with both semantic directions and actual resource/verifier/parser/security correspondence. No sampler prefix or isolated cipher block demonstrates this.
3. Full selected backend, dependency, feature and license closure before executable selection. Existing archive checksums do not prove all installed source members or a unified target graph. The literal modular lemma and cipher reference do not audit libraries or the toolchain.
4. Actual eligible roots, reward origins, current unspent state, supported descriptors and atomic fresh-state application. An ordinary private-cash scope still needs these base obligations. Later contracts and Safe do not replace or relax them.

No new runtime or primary capture is selected. Source identity, historical blob, local-link and whitespace checks are the only new technical checks. All earlier execution admissions remain consumed. Payments remain private by default and the [minimal launch boundary](../../docs/minimal-launch.md) retains the [full roadmap](../../docs/delivery-roadmap.md), including separately versioned private contracts and Safe.
