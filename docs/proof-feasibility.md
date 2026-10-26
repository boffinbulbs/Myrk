# Proof backend feasibility

## Status and evidence boundary

The private ledger relation remains separate from the primitive laboratory and native reference validation. A local reference checker receives note openings, amounts, authorization evidence and encryption randomness in plaintext. Its result is not a proof, a privacy guarantee, or a network acceptance rule. The [research target](research-target.md) defines the required private relation and release gates. The [primitive laboratory](crypto-lab.md) records the current experimental signature and recipient envelope profile.

The original [hiding proof laboratory](proof-lab.md) generates actual STARK proofs over four private u64 amounts with a public fee and 64 byte context. It proves bounded integer conservation without note linkage. The separate [canonical note component](note-proof-lab.md) constrains four exact v2 SHA3-512 commitment computations and the same private amount bits in one conservation proof. Both verifiers receive proof bytes and independently supplied typed public statements. Neither component proves ownership, membership, nullifier derivation or uniqueness, recipient encryption or ledger acceptance.

The note component exposes both input commitments as well as both outputs, a shared asset, per note creation versions, fee, context and a fixed two input, two output shape. Direct transaction use would identify consumed notes and expose input to output linkage. The public commitments are a component boundary, without selection of a production private payment format. Complete private payments must hide input commitments and membership paths behind an authenticated root and stable nullifiers, or use an independently justified alternative.

Backend evidence was inspected on October 26, 2026. Exact `p3-* 0.8.0` dependencies are adopted only for the two isolated proof components. The canonical note component additionally uses `p3-keccak-air 0.8.0` for permutation constraints. No proof backend is selected for consensus. The inspected execution dependency below remains a source evaluation rather than an adopted execution system. Source inspection and successful component builds do not establish a cryptographic audit, complete witness privacy or a composed quantum security argument.

## Sender encryption relation

Recipient recovery and sender encryption consistency are distinct checks. A sender must be able to construct its encryption witness without possessing the recipient secret key. Let $p_E$ be the recipient public key, $m_K$ the secret 32 byte encapsulation randomness, $\eta$ the public nonce, $q$ the authenticated application context, and $n$ the encoded private note data. The experimental relation recomputes

$$
(ct_K,z) = \operatorname{MLKEM1024.EncapsInternal}(p_E,m_K)
$$

$$
b = \operatorname{EnvelopeAAD}(p_E,q,ct_K,\eta)
\qquad
k = \operatorname{ExperimentalKDF}(z,b)
$$

$$
ct_N = \operatorname{AES256GCM.Enc}(k,\eta,n,b)
$$

Acceptance requires equality of every recomputed encapsulation ciphertext byte and every authenticated note ciphertext byte with the supplied envelope. The framing, domains, key derivation, nonce size and limits are the unchanged laboratory suite in [crypto-lab.md](crypto-lab.md). The context excludes the final ciphertext, signature, proof and transaction identifier, avoiding a circular dependency.

`seal_for_relation` returns the envelope and an `EncryptionWitness`. The witness owns encapsulation randomness in zeroizing storage and has no Debug, cloning, serialization or secret export interface. It remains inside the trusted local prover boundary. Possession of this randomness and the public recipient key can recover the shared secret and note plaintext. Publishing the witness would disclose the encrypted data.

`verify_encryption_witness` checks the complete encryption computation locally without a recipient secret key. It accepts the private plaintext and witness directly. It does not provide zero knowledge or claim constant time behavior. A proof backend must constrain this same computation inside the private relation. A host assertion that encryption succeeded cannot replace those constraints. Recipient recovery additionally requires decapsulation, authenticated decryption and validation that the recovered note opens the intended commitment.

Fresh operating system randomness is used when generating each witness and nonce. A deterministic computation given a witness does not prove that the original randomness was sampled correctly. Entropy quality, retention, backup and erasure remain separate implementation obligations.

The retained v1 note experiment delivers its nullifier secret inside the encrypted private opening, and its sender can predict the resulting public nullifier. The [v2 recipient capability](recipient-capability.md) instead exposes a binding to a recipient retained secret. Its sender interface and private opening exclude the secret, while typed recovery checks the same capability and expected commitment. Internal binding also rejects encryption to a key that differs from the note's committed recipient key. This is an executable separation of capabilities, without a complete sender unlinkability proof or production recipient routing construction.

The experimental nullifier is a framed secret prefix SHA3-512 construction, with another domain separated hash image of that secret exposed in the capability. Distinct domains avoid identical framed inputs. They do not by themselves establish pseudorandomness with this auxiliary information or the required quantum oracle model. FIPS 202 defines the hash functions, while SP 800-185 separately defines KMAC as a pseudorandom function. Neither standard is a proof of this laboratory composition. A production construction needs its own reduction, parameter analysis and independent review. [SHA3 standard](https://csrc.nist.gov/pubs/fips/202/final), [derived function standard](https://csrc.nist.gov/pubs/sp/800/185/final).

## Inspected execution dependency

The inspected stable release is `miden-vm 0.36.2`, published October 20, 2026, at commit `d90c09e1226a099a9114705023097544275ac511`. Its package license is `MIT OR Apache-2.0`. The manifest declares Rust 1.96.1 as the minimum supported version, while the upstream toolchain file selects 1.99.0. The repository's validated Rust 1.94.1 toolchain does not satisfy that declared minimum. Older indexed API documentation must not be treated as this release's interface. [Release record](https://github.com/0xMiden/miden-vm/releases/tag/v0.36.2), [versioned manifest](https://github.com/0xMiden/miden-vm/blob/v0.36.2/Cargo.toml), [versioned toolchain](https://github.com/0xMiden/miden-vm/blob/v0.36.2/rust-toolchain.toml).

The upstream security policy identifies the implementation as alpha, unaudited and unsuitable for production. Supported release security fixes are provided on a best effort basis. A successful local proof or benchmark would not remove that limitation. [Security policy](https://github.com/0xMiden/miden-vm/blob/v0.36.2/SECURITY.md).

### Proof configuration and verification policy

The current `Prover` defaults to `Blake3_256`. Other exposed proof hash choices are `Rpo256`, `Rpx256`, `Poseidon2` and `Keccak`. Each is represented by a 256 bit digest. The default PCS settings are recorded below. [Prover configuration](https://github.com/0xMiden/miden-vm/blob/v0.36.2/prover/src/prover.rs), [hash identifiers](https://github.com/0xMiden/miden-vm/blob/v0.36.2/core/src/proof.rs), [PCS parameters](https://github.com/0xMiden/miden-vm/blob/v0.36.2/air/src/config.rs).

| Parameter | Value |
|---|---|
| FRI blowup | 8 |
| Folding arity | 4 |
| Final polynomial degree | 128 |
| Query repetitions | 27 |
| Folding proof of work | 4 bits |
| DEEP proof of work | 12 bits |
| Query proof of work | 17 bits |
| Declared query round target | 96 conjectured bits |

`Verifier::new()` does not enforce a minimum security level. An adapter must set an explicit acceptance floor and inspect authenticated parameters for every required STARK. The supplied estimator is conjectured and depends on relation shape and trace size. It is not a quantum knowledge extraction argument. [Verifier policy](https://github.com/0xMiden/miden-vm/blob/v0.36.2/verifier/src/lib.rs), [security estimator](https://github.com/0xMiden/miden-vm/blob/v0.36.2/air/src/security.rs).

### Witness privacy and deferred data

The inspected VM configuration uses ordinary `LmcsConfig` with zero salt elements. Its trace commitment function computes LDEs directly from the supplied trace matrices. No complete zero knowledge masking construction is established for that default path by the inspected source. Private advice alone cannot establish that the resulting proof hides the witness. [Trace commitments](https://github.com/0xMiden/miden-vm/blob/v0.36.2/crates/lifted-stark/src/prover/commit.rs), [default LMCS](https://github.com/0xMiden/miden-vm/blob/v0.36.2/crates/lifted-stark/src/lmcs/config.rs).

A separate `HidingLmcsConfig` adds leaf salts, but is not selected by the inspected VM defaults. Salting Merkle leaves alone does not hide polynomial evaluations exposed by an opening proof. Trace masks, quotient decomposition, auxiliary arguments and repeated proofs require a complete hiding construction and analysis. [Hiding LMCS source](https://github.com/0xMiden/miden-vm/blob/v0.36.2/crates/lifted-stark/src/lmcs/hiding_config.rs), [STARK zero knowledge analysis](https://eprint.iacr.org/2024/1037).

Proof transport can contain a deferred precompile witness. The default verifier can authenticate and evaluate that witness while reporting an outstanding obligation. This is distinct from a complete proof covering the deferred computation. Private transaction publication must exclude raw execution and precompile witnesses and require every obligation to be settled. A complete proof still needs its own hiding argument. [Proof lifecycle](https://github.com/0xMiden/miden-vm/blob/v0.36.2/prover/src/prover.rs), [transport representation](https://github.com/0xMiden/miden-vm/blob/v0.36.2/core/src/proof.rs).

### Exact primitive coverage

The release assembly library contains Falcon512 with Poseidon2 and ECDSA signature verification. Its inspected hash modules contain SHA256, BLAKE3, Keccak256 and Poseidon2. ML-DSA-87 verification, SHA3-512 note hashing and SHAKE256 were not found in those release modules. Development branch functionality cannot be attributed to the stable release. [Signature module inventory](https://github.com/0xMiden/miden-vm/tree/v0.36.2/crates/lib/core/asm/crypto/dsa), [hash module inventory](https://github.com/0xMiden/miden-vm/tree/v0.36.2/crates/lib/core/asm/crypto/hashes).

The required authorization, commitments, nullifiers and encryption relation therefore need measured guest implementations, constrained AIRs or fully verified precompiles. Native signature verification outside the proof does not establish hidden authorization. Selecting a different proof transcript hash also does not replace the VM's program and internal state commitments.

## Quantum security obligations

The security model must distinguish soundness from knowledge soundness. Existence of a valid spending witness does not establish that a prover possesses authorized evidence. The exact composition requires an extraction model, a quantum random oracle analysis where applicable, and a bound for the concrete transcript and relation. Results about FRI or a general transform do not automatically cover every implementation and parameter selection. [Fiat Shamir security of FRI](https://eprint.iacr.org/2023/1071), [soundness notions for interactive oracle proofs](https://eprint.iacr.org/2023/1256).

A digest length is not a quantum security level. Generic collision search has approximately cube root query complexity under the associated quantum black box model, with substantial memory and implementation qualifications. A 256 bit digest does not by itself establish a 128 bit quantum collision target. Algebraic hashes additionally require analysis for their exact permutation and field parameters. [Primary quantum collision result](https://arxiv.org/abs/quant-ph/9705002).

The target must account for program commitments, state commitments, transcript challenges, field sizes, proof of work grinding, proof aggregation and repeated observations. A stronger wallet signature does not compensate for a weaker ownership proof or an unbound public statement.

## Adopted isolated proof components

The [conservation proof laboratory](proof-lab.md) adopts exact `p3-* 0.8.0` packages at upstream source commit `a21e3ed42905040ad49c519e402f018381c12d0c`. Their workspace uses `MIT OR Apache-2.0` and edition 2024. The component builds and tests on the repository toolchain. Its fixed AIR proves $a_0+a_1=b_0+b_1+f$ with both totals at most $2^{64}-1$. The public fee and opaque context are transcript bound, but no authenticated note or asset binds the private amounts. [Pinned source manifest](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/Cargo.toml), [release record](https://github.com/Plonky3/Plonky3/releases/tag/p3-fri-v0.8.0).

The [canonical note laboratory](note-proof-lab.md) uses the same exact dependency release and distinct transcript and hash domains. Each 418 byte payment opening produces a 464 byte commitment preimage and seven SHA3-512 absorptions. The AIR constrains 28 permutations for four commitments, exact framing and padding, public chain and asset bindings, per note creation versions and the amount bytes. These amount bits also enter the checked integer equations. Owner, nullifier secret and recipient key bindings remain arbitrary private committed bytes in this component, without verification of their primitive derivations. The fee is expressed in the shared public asset and does not define production fee consensus. [Pinned permutation constraints](https://github.com/Plonky3/Plonky3/tree/a21e3ed42905040ad49c519e402f018381c12d0c/keccak-air).

| Profile | Original trace | FRI queries | Log blowup | Public statement scope |
|---|---|---|---|---|
| Unbound conservation | 256 rows, 77 columns | 64 | 2 | Fee and opaque 64 byte context |
| Canonical note conservation | 1024 rows, 4262 columns | 64 | 3 | Chain, shared asset, four creation versions, fee, four commitments and opaque 64 byte context |

The note profile is `thorum.note-proof-lab.v2-payment.sha3-512.serial.p3-0.8.0.v1`. Its pinned two adic symbolic degree is 4, with 8 quotient chunks and stored hiding degree bits 11. The two profiles are distinct experiments. Historical primitive and unbound conservation measurements retain their source and machine records and do not measure this note relation.

The exact hiding PCS requires both commitment layers to be hiding, unpredictable cryptographic RNG seeding, sufficient independent random codewords and one opening proof per private prover data instance, including across clones. Its conservative masking budget is

$$
N \ge 2\left(q_{\mathrm{FRI}} + d_{\mathrm{ext}}\,o\right)
$$

Here $N$ is the mask height, $q_{\mathrm{FRI}}$ the query count, $d_{\mathrm{ext}}$ the challenge extension degree, and $o$ the number of supplied opening points. Both profiles use 64 queries, extension degree 4 and at most two trace opening points. The original profile satisfies $144\le256$, while the note profile satisfies $144\le1024$. Both commitment layers use hiding Merkle schemes, and the PCS supplies four independent random codewords with fresh private proving randomness. These conditions do not replace the surrounding STARK's randomization and challenge sampling requirements. [Pinned hiding PCS contract](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/fri/src/hiding_pcs.rs), [pinned hiding Merkle implementation](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/merkle-tree/src/hiding_mmcs.rs).

The selected backend describes its STARK randomization as statistical rather than perfect zero knowledge. Application transcript chaining and Merkle digests retain all SHA3-512 output bits. Upstream typed transcript metadata also uses Keccak256 fingerprints for fixed interaction patterns and algebra identities. Exact hashing and transcript encodings, masking, fresh commitment rules and bounded canonical transport are recorded separately in the [unbound component](proof-lab.md) and [canonical note component](note-proof-lab.md). These inspected mechanisms do not supply an independent review of the local hash composition or a complete quantum knowledge bound. [Pinned randomization source](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/uni-stark/src/prover.rs#L344), [pattern fingerprint source](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/challenger/src/fs/pattern/sequence.rs#L103).

The pinned release retains the reported hiding RNG lock behavior during parallel work. The laboratory disables parallel execution. An upstream fix does not alter the exact release source selected here, and any dependency change needs new concurrency and composition checks. Serial execution avoids that specific concurrency path and does not establish general security. [Issue 2363](https://github.com/Plonky3/Plonky3/issues/2363), [upstream fix](https://github.com/Plonky3/Plonky3/pull/2368).

The experimental dependency graph also retains `paste 1.0.15`, covered by informational unmaintained advisory `RUSTSEC-2024-0436` with no patched version listed. This is an unresolved maintenance limitation, without a claim that the advisory demonstrates an exploit in this component. Advisory queries and source inspection are dated evidence rather than a security audit. [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2024-0436.html).

## Sequential implementation conditions

1. Establish canonical public statements and local witness semantics with valid and invalid reference fixtures. Include note openings, membership, exact authorization binding, deterministic nullifiers, integer conservation, output encryption and recipient recovery.
2. Reproduce a genuine hiding proof over the complete payment constraints. Every primitive result must be constrained. Neither isolated component proves ownership, hidden membership, nullifiers or recipient encryption. Public input commitment linkage in the note component must not become an implicit production privacy policy. Reject witness transport, missing proof obligations, unsupported relation versions and insufficient security parameters.
3. Establish the exact backend's hiding and knowledge soundness arguments in the declared quantum model. Record the dependency revisions, compiler, resource bounds and independent review status.
4. Complete confidential stake eligibility and checkpoint authority through a separate private relation before kernel integration. Prove weight from eligible locked notes, prevent duplicate weight, bind the snapshot and epoch, and separate voting from spending capability. Splitting the same stake among wallets must not create additional aggregate weight. Private payment evidence cannot satisfy this gate.
5. Integrate kernel root selection, spent nullifiers, fee policy, atomic state changes and rollback only after both private payment and confidential stake feasibility gates pass. Reference relation validity alone does not establish consensus acceptance.

The implementation currently includes primitive integration, transparent relation checks, an unbound hiding conservation proof and a canonical note commitment conservation proof. Both full private payment and confidential stake feasibility remain open under these conditions. No fallback verifier accepts an absent or placeholder proof.

The new component's independent references, fixed profile guard and release verification corpus are reproducible with:

```text
cargo test -p thorum-note-proof-lab --locked --offline
cargo test -p thorum-note-proof-lab --release --locked --offline
python research/note-proofs/reference_vectors.py --check
python research/note-proofs/profile_check.py
```
