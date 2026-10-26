# Proof backend feasibility

## Status and evidence boundary

The private ledger relation remains separate from the primitive laboratory and native reference validation. A local reference checker receives note openings, amounts, authorization evidence and encryption randomness in plaintext. Its result is not a proof, a privacy guarantee, or a network acceptance rule. The [research target](research-target.md) defines the required private relation and release gates. The [primitive laboratory](crypto-lab.md) records the current experimental signature and recipient envelope profile.

Backend evidence was inspected on October 26, 2026. No proof backend is selected for consensus. No new execution or proving dependency is added by this report. A dependency described as an execution candidate must still satisfy the exact relation, witness privacy, security model, resource bounds and independent review requirements.

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

The local note experiment delivers its nullifier secret inside the encrypted private opening. This preserves the data needed for later consumption, but the sender also knows that secret and can predict the resulting public nullifier. Exact ciphertext consistency therefore does not establish sender unlinkability. A production recipient capability must let the sender construct a valid output without learning its private nullifier derivation secret, while retaining verifiable binding and reliable recipient recovery. This construction remains unresolved.

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

## Hiding proof component candidate

The published `p3-fri 0.8.0` and `p3-uni-stark 0.8.0` sources expose a hiding PCS and hiding Merkle commitments. They are inspection candidates, without adoption in Thorum. Their workspace uses `MIT OR Apache-2.0` and edition 2024. Toolchain compatibility still requires an actual build and dependency review. [Published source manifest](https://github.com/Plonky3/Plonky3/blob/v0.8.0/Cargo.toml), [release record](https://github.com/Plonky3/Plonky3/releases/tag/p3-fri-v0.8.0).

The exact hiding PCS requires both commitment layers to be hiding, unpredictable cryptographic RNG seeding, sufficient independent random codewords and one opening proof per private prover data instance, including across clones. Its conservative masking budget is

$$
N \ge 2\left(q_{\mathrm{FRI}} + d_{\mathrm{ext}}\,o\right)
$$

Here $N$ is the mask height, $q_{\mathrm{FRI}}$ the query count, $d_{\mathrm{ext}}$ the challenge extension degree, and $o$ the number of supplied opening points. These conditions do not replace the surrounding STARK's randomization and challenge sampling requirements. [Hiding PCS contract](https://github.com/Plonky3/Plonky3/blob/v0.8.0/fri/src/hiding_pcs.rs), [hiding Merkle implementation](https://github.com/Plonky3/Plonky3/blob/v0.8.0/merkle-tree/src/hiding_mmcs.rs).

An upstream report describes a deadlock when hiding RNG locks remain held during parallel work. Its issue is closed, but a dependency selection must verify the actual release containing the relevant fixes. Serial execution avoids that specific concurrency path and does not establish general security. [Issue 2363](https://github.com/Plonky3/Plonky3/issues/2363).

## Sequential implementation conditions

1. Establish canonical public statements and local witness semantics with valid and invalid reference fixtures. Include note openings, membership, exact authorization binding, deterministic nullifiers, integer conservation, output encryption and recipient recovery.
2. Reproduce a genuine hiding proof over those constraints. Every primitive result must be constrained. Reject witness transport, missing proof obligations, unsupported relation versions and insufficient security parameters.
3. Establish the exact backend's hiding and knowledge soundness arguments in the declared quantum model. Record the dependency revisions, compiler, resource bounds and independent review status.
4. Complete confidential stake eligibility and checkpoint authority through a separate private relation before kernel integration. Prove weight from eligible locked notes, prevent duplicate weight, bind the snapshot and epoch, and separate voting from spending capability. Splitting the same stake among wallets must not create additional aggregate weight. Private payment evidence cannot satisfy this gate.
5. Integrate kernel root selection, spent nullifiers, fee policy, atomic state changes and rollback only after both private payment and confidential stake feasibility gates pass. Reference relation validity alone does not establish consensus acceptance.

Until these conditions are met, the implementation remains primitive integration and local relation research. No fallback verifier accepts an absent or placeholder proof.
