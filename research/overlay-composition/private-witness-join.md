# Common private payment witness and missing equations

This source and mathematical specification defines the shared private identities required for an ordinary recipient-v2 payment. It gives a deterministic confidential asset conservation relation and identifies the concrete gaps between the current components. It implements no combined AIR, proof, parser, state authority or payment acceptance API. Complete execution remains refused. Exact source identities and review limits are in the [source record](private-witness-sources.json).

The [wire placement contract](two-phase-wire-binding.md) does not supply the missing whole relation. The construction below states what must be placed and bound before a backend can be selected. Original laboratory domains, versions and signature algorithms are preserved. It does not select production cryptography or a new resource class.

## Scope and actual component differences

The transparent `check_payment` handles one through eight inputs and outputs, checked per-asset `u64` totals, canonical public statement bytes, exact authorization and reproduced encryption. It receives private witnesses and caller-owned accepted anchors and spent sets. It does not authenticate that state or change it.

The existing owner-binding AIR instead has two inputs, two outputs, a shared **public** asset, fixed depth 32, four 418-byte recipient-v2 payment openings and 520 public values. Its internal equations share the input commitments, amounts, owner bindings, nullifier secret bindings and path roots. It does not verify signatures or encryption. Its `context` field is public transcript data, not a computation deriving all payment semantics from a transaction.

The signature overlay has one 2592-byte verification key, one 4627-byte signature, one 418-byte note and 196 public authorization bytes. It derives those public bytes from an actual `PaymentStatement`. It binds its note owner to that same key and computes a private note commitment, but does not consume that commitment in membership or nullifier constraints. One instance does not authorize two distinct input keys. A future payment relation needs actual authorization for every input, with any shared-key optimization separately constrained.

Thus forwarding one component's public statement into another is insufficient. The public shared-asset laboratory shape also cannot represent arbitrary hidden multi-asset payments by assigning an asset label supplied by a peer.

The semantic scope here is ordinary recipient-v2 **Payment-policy** notes. Legacy-v1 openings, bond registration/withdrawal, issuance, minting, burns and contracts require their own complete versioned rules. In particular, the host checker can create a bond-policy output, whereas the 418-byte signature source fixes Payment policy. The correspondence below is explicitly restricted to the ordinary v2 domain. It does not silently claim all objects accepted by the host checker or activate a production class.

## One canonical private source

Write $F(x)=\operatorname{u32BE}(|x|)\Vert x$ and

$$H_D(x_1,\ldots,x_k)=\operatorname{SHA3\!\mbox{-}\!512}(F(D)\Vert F(x_1)\Vert\cdots\Vert F(x_k)).$$

The ordinary v2 opening has exactly these fields in order. Every field, including a fixed-width field, has its four-byte length prefix.

| Field | Actual contents |
|---|---|
| Domain | `thorum.relation-lab.note-opening.v2` |
| Encoding version | `u16BE(2)` |
| Chain | 32 bytes |
| Immutable creation version | `u32BE` |
| Private asset | 32 bytes |
| Private amount | `u64BE` |
| Owner binding | 64 bytes |
| Nullifier-secret binding | 64 bytes |
| Recipient-key binding | 64 bytes |
| Serial | 32 bytes |
| Blinding | 32 bytes |
| Policy | one zero byte |

The resulting opening is 418 bytes. Its amount occupies bytes `129..137`, owner `141..205`, secret binding `209..273`, recipient binding `277..341`, serial `345..377`, blinding `381..413` and policy byte `417`. These are source-derived half-open offsets, not a newly executed encoding fixture. All other framing, domain and version bytes are fixed. There is no alternate parsing of the same witness bytes.

For input $i$, allocate one logical private record

$$w_i=(o_i,k_i,\operatorname{sig}_i,s_i,\operatorname{index}_i,\operatorname{path}_i).$$

Every use of the note refers to the **same** canonical byte vector $o_i$ and its constrained field projections. Every key use refers to the same $k_i$. Those identities must become actual constrained wires or a justified copy argument in one proof. Separate host buffers containing supposedly matching objects are not an implementation.

Actual private input and output counts equal the respective public statement counts. No extra note or unchecked activity slot may disappear through a truncated pairing of arrays.

For output $j$, use one private opening $o'_j$, a canonical recipient public key $r_j$ and actual encapsulation randomness $\rho_j$. The same $o'_j$ supplies its amount, asset, public commitment and encrypted plaintext. The sender does **not** supply the recipient's nullifier secret, decapsulation key or future spending signature. Requiring those would contradict the actual recipient-capability construction.

## Input equations and stable identity

Use the exact retained v2 domains:

$$c_i=H_{\texttt{thorum.relation-lab.note-commitment.v2}}(o_i),$$

$$\operatorname{owner}(o_i)=\operatorname{SHA3\!\mbox{-}\!512}(k_i),$$

$$\operatorname{secretBinding}(o_i)=H_{\texttt{thorum.relation-lab.nullifier-secret-binding.v2}}(\operatorname{chain},s_i),$$

$$\operatorname{NF}_i=H_{\texttt{thorum.relation-lab.note-nullifier.v2}}(\operatorname{chain},s_i,c_i).$$

Owner hashing is raw SHA3-512 of all 2592 key bytes. It has no framed key domain. Replacing it with $H_D(k_i)$ would change the relation. The 2592-byte object is the ML-DSA verification key, not a signing secret.

Membership starts at

$$q_{i,0}=H_{\texttt{thorum.relation-lab.merkle-leaf.v1}}(\operatorname{chain},c_i).$$

For every actual path level, a private Boolean direction selects the ordered pair of the prior rolling digest and that level's sibling. Apply `thorum.relation-lab.merkle-node.v1` to chain, left and right. The final digest equals the actual expected anchor. Index bits, depth, all sibling bytes, rolling digest copies and every hash absorption boundary need constraints. The host permits depth at most 32 and exact index range. The existing AIR is fixed to 32. A real supported tree profile must determine the depth and padding rules from authenticated policy, not accept a peer's choice of root semantics.

The chain of every input equals the statement chain, input creation version is at most the statement protocol version, and input policy is Payment. All amounts and version comparisons are bounded integers. Current protocol version, anchor, path, epoch, request generation and authorization context are excluded from the stable nullifier derivation. Changing an immutable committed creation version changes the note itself. Updating the current rules or anchor must not rename the same old consumption right.

The input commitment, asset, value, creation version, key, signature, secret and path remain private. Public nullifiers must be distinct and absent from the authenticated current spent state. These latter public-state checks must be repeated atomically at commit under the [state acceptance contract](../../docs/private-transition-state.md). A private proof of the derivation cannot make a stale spent set current.

## Authorization is derived from the whole actual statement

Let $S$ be the actual canonical `PaymentStatement`, including ordered nullifiers, every output commitment, every actual envelope byte, native fee, chain, protocol version, validation tag and anchor. The source enforces one through eight entries on each side and an accumulated 65536-byte laboratory bound.

The authorization message is

$$m=H_{\texttt{thorum.relation-lab.payment-authorization.v1}}(\operatorname{canonical}(S)).$$

Its crypto context contains the statement chain and protocol version, and the first 32 bytes of $H_{\texttt{thorum.relation-lab.payment-auth-context.v1}}(m)$. `Context::encode` is the exact 80-byte length-framed encoding. The actual authorization input is the 196 bytes

$$A_{196}=F(\texttt{thorum.crypto-lab.authorization.v1})\Vert F(\operatorname{u16BE}(1))\Vert F(\operatorname{Context.encode}())\Vert F(m).$$

For each input, verify the real retained ML-DSA-87 signature under the same hidden $k_i$ over these bytes with the nonempty 41-byte FIPS context `Thorum crypto laboratory authorization v1`. The pure-message prefix is zero, byte 41, that context, then the exact $A_{196}$. The private `tr` and resulting `mu` must come from the same key and that message. Full signature decoding, samplers, NTT, ranges, carries, norms, hints and challenge equality remain necessary.

Expected authorization is computed from the actual received canonical statement by supported verifier code. An arbitrary 196-byte vector, job digest, hash supplied by a caller or owner-binding component `context` field cannot select the authorized effect. Actual hash-binding and collision assumptions remain part of the security correspondence. The signatures and proof are excluded from $S$, so they do not need to sign or hash themselves.

## Output and encrypted plaintext equations

Each output creation version equals the statement protocol version. Its chain is the same statement chain, and its policy is Payment in this ordinary scope. Compute $c'_j$ from the same canonical private $o'_j$ and require equality to the ordered public output commitment. Output commitments are distinct, as in the source checker.

Require the recipient binding inside that note to equal

$$H_{\texttt{thorum.relation-lab.recipient-key-binding.v2}}(\operatorname{chain},r_j),$$

where $r_j$ passes the actual canonical ML-KEM-1024 public-key decoder. The output's owner and nullifier-secret bindings come from a recipient capability. They are binding images, not the recipient's secrets. Capability authenticity as the intended receiver remains an application obligation. The relation does not prove future recipient key possession or force the sender to know the recipient's nullifier secret.

The output encryption context is derived from chain, current protocol version, validation tag, ordered output index and the full $c'_j$ with the exact `output-encryption-context.v1` domain. Its tag is the first 32 hash bytes. The full commitment must still match independently. A short tag does not replace the 64-byte commitment.

The required encryption equation is the actual retained operation sequence: canonical ML-KEM-1024 key decoding, deterministic internal encapsulation with the private 32-byte $\rho_j$, its actual KEM ciphertext and shared secret, actual context/recipient/KEM/nonce associated data, the experimental framed SHA3-512 KDF truncated to 32 bytes, then AES-256-GCM encryption of **all of the same $o'_j$**, using the public envelope nonce. Compare the actual KEM ciphertext and complete authenticated ciphertext to the ordered public envelope. Its original codec, suite, lengths and all bytes must match.

This is a necessary operation contract, not a newly constrained encryption gadget. `verify_encryption_witness` presently performs those operations on the host using private plaintext and randomness. Its return value is not usable as a proof constraint. No full ML-KEM/KDF/AES-GCM arithmetization or matching verifier is selected here. A successful envelope parse, supplied ciphertext hash, delivery promise, Boolean callback or separately accepted encryption result cannot fill that gap. Entropy quality, nonce policy, composition security and repeated observations also require separate treatment.

There is an acyclic honest construction order: canonical output note, its commitment, output context, actual encryption and envelope, full public statement, expected authorization, input signatures, then the joint proof. This preserves the [preseal job order](../../docs/preseal-job.md). Proof bytes and work seals remain later objects.

## Confidential multi-asset conservation equations

The source's `BTreeMap` is an implementation of checked integer per-asset sums, not a private constraint. The public shared asset in the existing owner AIR cannot substitute for it. A prospective exact relation can avoid a public asset list and random asset compression as follows.

Take the private asset identifiers of all inputs and outputs, and one additional fixed all-zero native asset identifier. There are at most 17 representatives, with duplicates allowed. Each 32-byte identifier is represented by 256 constrained Boolean bits. For each representative $a$ and each note asset $b$, compute every bit equality as a separate quadratic XNOR node, then multiply those bits through a fixed product chain. Its final Boolean $e_{a,b}$ is one exactly when the entire 256-bit identifiers agree. Do the same against the fixed native identifier.

For every representative, accumulate each side in the actual original note order:

$$L_a=\sum_{i\in\mathrm{inputs}}e_{a,\operatorname{asset}(o_i)}\operatorname{value}(o_i),$$

$$R_a=\sum_{j\in\mathrm{outputs}}e_{a,\operatorname{asset}(o'_j)}\operatorname{value}(o'_j)+e_{a,\mathrm{native}}\operatorname{fee}.$$

Every accumulation starts at zero and is a sequence of **checked 64-bit integer additions**, followed by coordinatewise equality of the final 64 sum bits for $L_a=R_a$. Gate each value's actual 64 bits with its equality flag. Use actual ripple-carry equations with Boolean sum/carry bits, initial carry zero and final overflow carry zero for each addition. An equality only modulo BabyBear is insufficient. No 67-bit total is accepted merely because eight `u64` inputs fit there: the original per-asset checker refuses totals above `u64::MAX`.

With Boolean operands, each addition column has left and right integer values at most three. The actual field characteristic is greater than three, so these column equations, ranges and zero overflow establish ordinary integer addition without field wrap. XNOR and its product chain use separate nodes, so their local equations have degree at most two before placement and selectors. This does not determine combined AIR degree, widths or quotient chunks.

Every occurring asset has a representative. If the equations hold, that asset's input total equals its output total plus the native fee where appropriate, without overflow. Conversely, the host's successful checked per-asset sums satisfy every representative equation. Duplicate representatives merely repeat the same obligation. Zero amounts contribute nothing and need not create map entries, matching `add_amount`. This proves the semantic conservation equivalence for the bounded ordinary relation. It is not a complete proof-system theorem or an executed adversarial test.

This construction specifies exact finite equations without revealing private asset identifiers. It selects no actual layout or optimization. All comparison nodes, product chains, Boolean values, copies, carry banks, resource counts and transport still require a complete accounted placement. Ordinary payments have no mint or burn allowance in these equations. Other relation kinds need their own authorized terms.

## Both correspondence directions and their limits

Given an original successful host witness in the stated ordinary v2 domain, its canonical opening bytes, exact keys/signatures/secrets/paths and output encryption randomness supply the common private sources above. Reusing those identities and carrying out the actual operations supplies the stated semantic relation and checked asset sums. This is a constructive mathematical map, not an executed witness walk.

Conversely, assume **all** stated canonical, range, hash, signature, membership, encryption, equality and integer-operation predicates are implemented and satisfied on those same sources. Projecting the sources gives each original ordinary `check_payment` obligation: context equality, allowed root, distinct unspent public nullifiers, correct input note policy/version/owner/authorization, same-note membership and nullifier, output commitment/recipient/encryption, and checked per-asset conservation. The eligible state and spent set in this statement must be the actual authenticated expected state. No supplied validity predicate is part of the construction.

The converse is about the semantic field records and checker obligations. It does not assert that an arbitrary byte string can be converted into a Rust private `NoteOpening` through its public constructors. Valid creation provenance, recipient key invariants and supported note versions need actual creation and authenticated-history rules. Nor is it a theorem about an accepted existing proof: no current proof enforces this complete predicate list.

For the existing fixed two-input/two-output owner component, a projection is possible only when its exact shape, common public asset, depth-32 and canonical opening restrictions hold. Each signature projection is a separate input's **same** note/key/signature, with the single shared expected authorization. These projections explain component correspondence. They do not license separately generated existential witnesses or separate accepted proofs as a joint witness.

## Eligibility and construction decision

Current note bytes contain a creation **version**, not an authenticated reward creation height. The Merkle leaf hashes chain and commitment. Membership in a caller-owned root alone cannot establish reward maturity, initial checkpoint finality, branch eligibility or whether a nullifier remains unspent. The authenticated state must supply a justified eligible-root construction or additional constrained origin evidence, with exact supported tree/version rules and current atomic checks. No such state service is implemented.

The exact minimum remaining construction includes constrained output encryption, a common private source/read/copy path for every obligation, actual private version comparisons and multi-asset arithmetic, supported statement and class encoders, eligible authenticated state and atomic consumption, and one matched prover/verifier/proof schema for the joint relation. The host encryption check and public asset component are concrete gaps, rather than authorizing substitutes.

No complete height, width, public shape, assertion count/order/degree, source/prepared/LDE geometry, normalized quotient/chunks/coupled masks, copy auxiliary phase, claims/query duplicates, salts/trees/FRI/entropy, buffers/descriptors/leases/simultaneous peak or bounded complete transport is selected. The existing full signature is already preflight-refused. The proposed wire placement also exceeds current limits before this added work. No class, capacity, authorization primitive or security profile is increased.

Full hiding, binding, repeated/concurrent proof observations, actual multiround Fiat Shamir, classical interactive/ROM/BCS versus QROM and knowledge/extraction obligations remain separate. The complete private proof/parser and confidential stake/bootstrap/consensus gates remain launch blockers. Payments stay private by default and the [full roadmap](../../docs/delivery-roadmap.md) remains unchanged.

## Required future controls and review scope

Required controls are specifications, not executed tests: swap input notes between signature/membership/nullifier; change one source byte after another consumer reads it; use a different secret or verification key; change only immutable creation version or current version; reorder outputs or encryption contexts; encrypt a different private opening; require a forbidden output secret; alter one private asset bit; balance field residues while overflowing integer totals; split zero and duplicate assets; reuse a spent note under a different anchor; and supply a valid membership path for an immature or orphaned origin. Each needs actual refusal and owned cleanup at the implemented layer.

New source inspection covers the complete relation note/capability/payment/Merkle/codec/error bodies, crypto context/authorization/envelope/sender-witness operation bodies, owner-binding AIR and constructor, selected component public/proof boundaries, signature authorization preprocessing, packed source binding and overlay integration boundaries. Existing detailed signature arithmetic and Keccak/state-event reviews remain preserved contextual evidence. No new full-body or transitive review of every signature arithmetic, cryptographic backend, PCS/MMCS/FRI/challenger/owner/verifier dependency is claimed.

This increment runs only stock source identity, baseline Git blob, local-target and whitespace checks. It executes no compiler, helper evaluator, model, protocol hash, encryption, signature, RNG, witness, prover, verifier, ledger, network or old test. All previous execution admissions remain consumed. Original licenses, notices and provenance remain unchanged.
