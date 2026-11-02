# Word proof privacy and complete verification boundary

This source and architectural decision reviews one historical word-oriented proof implementation as a possible successor for the complete private cash relation. It identifies its actual transparent and wrapped paths, the operations that must remain joined and the minimum missing construction before adoption. It selects no library dependency, executable root, production primitive, proof class, security profile or accepting payment API. The [source record](word-proof-sources.json) preserves exact identities and review limits.

The comparison is `binius-zk/binius64` at commit `6e75a2d1d2e716578ae3ccb62806413fb1615176`. It is not a claim about the latest release. The retained source has separate ordinary word, wrapped word and Iron Spartan entry points. Their source types and calls matter more than a project label or an example's proof size.

The [whole encrypted output relation](whole-encryption-completion.md) and [common private witness](private-witness-join.md) remain the required semantics. No upstream example, public statement match or independently accepted component supplies their missing complete proof.

## Actual privacy modes

The historical architecture table describes the ordinary word system as transparent and the separate Iron Spartan system as zero knowledge. The README and word entry-module documentation also describe zero knowledge. The actual implementation resolves the apparent ambiguity by providing different paths:

| Entry | Selected source behavior | Consequence for construction |
|---|---|---|
| `Verifier::setup` and ordinary `Prover` | Ordinary setup requests `oracle_specs(false)`. Its BaseFold prover creates a channel without ZK, draws no oracle masks and also offers a separate transparent WHIR path. | This path is not a candidate private-payment wrapper. Its successful verification or smaller opening cannot be relabeled as hiding. |
| `ZKVerifier` and `ZKProver` | Setup compiles an outer Iron Spartan circuit from the inner word verifier, combines oracle specifications in a BaseFold ZK compiler and runs the inner protocol through dedicated wrapped channels. | This is an actual source construction to review, not proof of its complete hiding, soundness, resource or quantum properties. |
| Standalone Iron Spartan | A different field multiplication constraint system, with separate public, precommit and private segments and masking operations. | Its field constraints cannot inherit the word system's AND/IMUL counts by an identity reinterpretation. |

Thus neither an unconditional claim that the project has no hiding nor an assumption that its default API is private follows from the top-level descriptions. The prospective private-cash route would require the actual wrapped path, its exact semantics and complete closure. No such route is adopted here.

The source uses `SECURITY_BITS = 96` in parameter selection. That identifier is not an achieved security level, a quantum bound or a Kova parameter choice. No value or rate is changed to obtain a convenient result. README timings, reduction claims, native CPU flags and parallel settings are not imported or executed.

## Whole verification includes the wiring claim

The word `IOPVerifier::verify` returns a `WiringEvalClaim`. It does not itself return a complete application authorization. The ordinary `verify_statement` observes the actual public words, runs the reduction and calls `check_native` on that claim. Its top-level verifier also calls the selected commitment channel's `finish`.

In wrapped setup, the inner verifier is executed symbolically to construct the outer circuit. The wiring evaluation is deliberately absent from that circuit. In actual wrapped verification, the claimed value and its inputs are retrieved as public wrapper values and the wiring claim is checked against the verifier's constraint system. The wrapper's `finish` then runs outer verification and the combined opening.

This public computation is a verifier equation derived from the fixed program. It is not a caller-supplied Boolean asserting that a hidden signature or encryption is valid. The omitted circuit equation still has an explicit verifier consumer. An integration that merely discards the returned wiring claim, stops before channel completion or accepts a partial inner result would not implement the complete path.

A Kova boundary must additionally finish canonical transcript consumption, enforce its actual supported program/profile and derive the expected public statement from actual child data and authenticated state. A generic verifier constructor or serialized verifier object cannot give peers authority to choose another constraint system, rate, public/private partition or proof mode.

## One combined wrapped construction

The captured wrapped setup constructs an inner word verifier and an outer padded constraint system and witness layout. It derives one ordered oracle specification: outer precommit first, inner oracles next, then remaining outer private and mask oracles. The wrapped prover records the inner computation through a channel and fills the outer witness using the corresponding verifier sequence. Its completion runs the outer proof through the same compilation route. The captured code shares a buffer pool between these sequential stages and retains it across calls.

This is different from accepting two unrelated proofs because their public statements match. It is also not enough to establish the required correspondence. The actual wrapped-channel bodies, classification of public and private messages, precommit binding, transcript operations, compiler constraints, oracle masks, field representation, hash implementation and opening arguments remain necessary. A replay helper's name or an `expect` in honest witness generation proves none of those properties.

A full argument must show that the actual outer accepted relation forces the exact inner verifier messages and equations for the same committed words. Conversely, every admitted original witness must produce that one uninterrupted wrapped proof, with exact failure behavior. Randomness, retries, denominator failures, parsing, cancellation and repeated or concurrent proofs need their own complete ownership and security analysis. The current Plonky3 owner, private flags and domain guards do not automatically transfer to this separate protocol.

## Word operations and source identity

The source `Word` is a `u64`. Its host arithmetic helpers are witness operations, not independently sufficient proof constraints. Carry input checks implemented only as `debug_assert` do not establish an adversarial range check. Fixed shifts, arithmetic shifts, rotations, masked 32-bit shifts, byte projections and high/low products retain their exact original meaning.

One concrete ordering difference must survive any compiler: `Word::imul` returns `(high, low)`, while the proving code assembles integer-multiplication operand columns as `[a, b, low, high]`. A wrapping low-word product requires a constrained complete unsigned product and the correct low projection. Taking the first host return value, supplying a free product or omitting range/overflow semantics changes the computation.

The ordinary prover commits only the nonpublic witness segment, packing consecutive low/high words into 128-bit elements with explicit final unpaired-word and zero-padding handling. It then reduces integer multiplication, optional binary multiplication, bitwise AND, zero and shift relations and queues the committed trace opening. These are source operations, not measured Kova circuit dimensions or an executed proof.

Bitwise AND's honest prover can derive its result column from the operands. Validity still needs the complete shift/wiring reduction tying that result to the actual referenced result word. The unreviewed called reduction must not be replaced by an honest host calculation. Fixed indexed operands are also not an implementation of arbitrary private mutable memory. Initialization, read-before-write, versions, repeated reads, terminal values, holds and padding remain part of the common relation.

An upstream binary-field multiplication gate is not automatically the retained represented GHASH operation. The existing byte reversals, scaling, wrapping products and ordered reduction require the [literal GCM correspondence](gcm-word-relation.md), or a separate complete equivalence argument. This review selects no such substitution and changes no KDF, hash, signature or encryption primitive.

## Why the field relation is not a free word replacement

Suppose an injective map from all 64-bit words into a field identified bitwise AND with field multiplication. Every word satisfies `w AND w = w`, so every image would satisfy `x*x = x`. In a field, `x(x-1)=0` has only roots zero and one. Two possible images cannot encode all 64-bit words injectively. Therefore that particular identity reinterpretation is impossible.

This elementary argument does not rule out a genuine constrained bit decomposition, encoding, ring switch or other complete word proof. It does rule out copying a word-count claim directly into the standalone field multiplication relation. The wrapped implementation instead constrains a verifier over field messages. Its correctness needs the actual wrapper argument, not that invalid identity map. Prime-field Boolean and full-adder equations also cannot simply be copied unchanged into characteristic two.

## Complete private-cash obligations remain one program

The prospective program must derive all original obligations from the same hidden sources:

1. Every input's actual canonical note, private commitment, verification key, real signature, nullifier secret and membership path connect eligible membership, owner binding, PaymentStatement-derived authorization, stable nullifier, range/policy and current spent state.
2. The actual committed native asset and checked value conservation remain constrained. Native-only scope does not permit an unbound asset field or a public private-input list.
3. Each actual 418-byte output opening supplies its commitment and all plaintext. The same recipient descriptor/key, private sender input, KEM output/shared key, context/full commitment/index, AAD, KDF, nonce, complete cipher body and tag remain linked. The sender does not acquire recipient spending secrets.
4. The program's public words are the actual supported statement, including complete delivery data. The cryptographic term “public key” does not require exposing an input verification key or recipient association on chain. Private source words must not be put in public inputs for convenience.
5. The verifier owns the exact program and supported policy. Actual eligibility/reward origin, maturity, finality, fresh authenticated state and atomic ledger application remain separate mandatory checks. Note creation version is not reward height.

The complete [ML-KEM sampling relation](whole-encryption-completion.md) still needs a practical supported completion/refusal domain. The finite bound for successful streams is not a practical profile or a proof that all canonical keys terminate. A different backend supplies no permission to truncate the original matrix, resample a seed, publish hidden routing or accept a host-produced matrix.

## Source and resource refusal

Adoption remains refused. No complete same-witness word program, accepted-relation correspondence, matching proof schema/parser, owner integration, production security argument or feasible combined resource record is provided. The existing full-signature refusal, small owner, stored/kernel limits and transport boundaries remain in force.

An actual proposal must account for both inner and outer circuits, padded words, operand columns, shift keys, wiring/tensor buffers, mask/dummy variables, additive transforms, codewords, commitment trees, claims, queries, complete openings, transcript/proof bytes, entropy, pooled allocations and simultaneous lifetimes. The pool's continued ownership does not make its contents disappear after a phase. Host word packing and a plain-prover benchmark do not bound the wrapped proof's peak or wire size. No old caps or security settings are raised.

The first source selection retained twelve files and both original licenses. A separate twelve-path called-body selection stopped at its tenth request, `crates/core/src/constraint_system.rs`, which returned 404. Nine actual files were retained. The last two paths were not requested, and no alternate path, retry or larger capture was used. All successfully captured bodies were read, including upstream tests as data. No test, example, compiler or library executed.

Minimum missing closure includes the actual constraint-system and compiler bodies, shifted operand and AND/IMUL/BMUL reductions, wrapped channels, ring switch, BaseFold/FRI masking/opening/parser, transcript/hash/field implementations, dependency/features/licenses and applicable classical/quantum hypotheses. Pinning the inspected files is not an audit or complete transitive review. The comparison is source evidence for one prospective architecture, not a selected executable class.

Only stock source identities, local links and whitespace checks run here. All previous candidate execution admissions remain consumed. The [minimum private-cash launch](../../docs/minimal-launch.md) still requires a real complete private payment proof/parser and confidential stake/bootstrap, atomic state, recovery and independent validation. The [full roadmap](../../docs/delivery-roadmap.md), including later private contracts and Safe, is unchanged.
